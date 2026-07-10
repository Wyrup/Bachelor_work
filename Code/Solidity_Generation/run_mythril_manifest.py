#!/usr/bin/env python3
import argparse
import csv
import json
import subprocess
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

SWC_TO_LABEL = {
    "SWC-116": "BN", "SWC-120": "BN",
    "SWC-112": "DE", "SWC-124": "DE", "SWC-127": "DE",
    "SWC-105": "EF", "SWC-106": "EF", "SWC-128": "EF",
    "SWC-115": "SE",
    "SWC-101": "OF", "SWC-110": "OF",
    "SWC-107": "RE",
    "SWC-104": "UC", "SWC-113": "UC",
}

KEYWORD_TO_LABEL = {
    "delegatecall": "DE", "delegate call": "DE", "storage collision": "DE",
    "reentrancy": "RE", "re-entrancy": "RE", "reentrant": "RE",
    "integer overflow": "OF", "overflow": "OF", "underflow": "OF",
    "unchecked call": "UC", "unchecked return": "UC", "call return value": "UC",
    "block.timestamp": "TP", "timestamp dependenc": "TP",
    "block.number": "BN", "block number": "BN",
    "tx.origin": "SE", "strict equality": "SE",
    "ether withdrawal": "EF", "selfdestruct": "EF",
}


def normalize_swc_id(value):
    if value is None:
        return ""
    value = str(value).strip().upper()
    if not value:
        return ""
    return value if value.startswith("SWC-") else f"SWC-{value}"


def parse_mythril_json_output(text):
    text = (text or "").strip()
    if not text:
        return {"issues": [], "logs": [], "parse_error": "empty_output"}
    try:
        data = json.loads(text)
    except json.JSONDecodeError:
        return {"issues": [], "logs": [], "parse_error": "invalid_json"}
    entries = data if isinstance(data, list) else [data] if isinstance(data, dict) else []
    issues, logs, seen = [], [], set()
    for entry in entries:
        if not isinstance(entry, dict):
            continue
        meta = entry.get("meta", {})
        if isinstance(meta, dict):
            for log in meta.get("logs", []) or []:
                if isinstance(log, dict):
                    logs.append({
                        "level": str(log.get("level", "")).lower(),
                        "hidden": bool(log.get("hidden", False)),
                        "msg": str(log.get("msg", "")).strip(),
                    })
        for issue in entry.get("issues", []) or []:
            if not isinstance(issue, dict):
                continue
            swc_id = normalize_swc_id(issue.get("swcID") or issue.get("swc_id") or issue.get("swc-id"))
            severity = str(issue.get("severity") or "Unknown").strip()
            title = str(issue.get("swcTitle") or issue.get("title") or "").strip()
            desc = issue.get("description", "")
            if isinstance(desc, dict):
                description = " ".join(x for x in [str(desc.get("head", "")).strip(), str(desc.get("tail", "")).strip()] if x).strip()
            else:
                description = str(desc).strip()
            key = (swc_id, severity, title, description[:200])
            if key in seen:
                continue
            seen.add(key)
            issues.append({"swc_id": swc_id, "severity": severity, "title": title, "description": description[:1000]})
    return {"issues": issues, "logs": logs, "parse_error": None}


def issues_to_vuln_labels(issues, status):
    if status == "timeout":
        return "TIMEOUT", "TIMEOUT"
    if status != "ok":
        return "ERROR", "ERROR"
    if not issues:
        return "SAFE", "SAFE"
    matched = set()
    for issue in issues:
        swc = issue.get("swc_id", "")
        mapped = SWC_TO_LABEL.get(swc)
        if mapped:
            matched.add(mapped)
        else:
            text = (issue.get("title", "") + " " + issue.get("description", "")).lower()
            for kw, lbl in KEYWORD_TO_LABEL.items():
                if kw in text:
                    matched.add(lbl)
                    break
    return (";".join(sorted(matched)) if matched else "OTHER"), "VULNERABLE"


def run_mythril(file_path, timeout, myth_cmd):
    cmd = [myth_cmd, "analyze", str(file_path), "-o", "jsonv2", "--execution-timeout", str(timeout)]
    start = time.time()
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout + 60)
        elapsed = round(time.time() - start, 2)
        parsed = parse_mythril_json_output(proc.stdout or "")
        has_traceback = ("Traceback" in (proc.stderr or "")) or ("Traceback" in (proc.stdout or ""))
        if parsed["parse_error"] is None:
            status = "ok"
        elif has_traceback:
            status = "error"
        else:
            status = "invalid_json" if proc.returncode == 0 else "error"
        return {
            "seconds": elapsed,
            "returncode": proc.returncode,
            "status": status,
            "issues": parsed["issues"],
            "logs": parsed["logs"],
            "parse_error": parsed["parse_error"],
            "stdout": (proc.stdout or "")[:4000],
            "stderr": (proc.stderr or "")[:2000],
        }
    except subprocess.TimeoutExpired as e:
        elapsed = round(time.time() - start, 2)
        parsed = parse_mythril_json_output(e.stdout if isinstance(e.stdout, str) else "")
        return {
            "seconds": elapsed,
            "returncode": None,
            "status": "timeout",
            "issues": parsed["issues"],
            "logs": parsed["logs"],
            "parse_error": parsed["parse_error"],
            "stdout": (e.stdout if isinstance(e.stdout, str) else "")[:4000],
            "stderr": (e.stderr if isinstance(e.stderr, str) else "")[:2000],
        }


def worker(row, timeout, myth_cmd):
    result = run_mythril(row["solidity_file"], timeout, myth_cmd)
    issues = result["issues"]
    vuln_class, detection_status = issues_to_vuln_labels(issues, result["status"])
    swc_ids = sorted(set(i.get("swc_id", "") for i in issues if i.get("swc_id")))
    return {
        "contract_id": row["contract_id"],
        "prompt_id": row["prompt_id"],
        "run": row["run"],
        "solidity_file": row["solidity_file"],
        "predicted_vuln_class": vuln_class,
        "detection_status": detection_status,
        "raw_swc_ids": ";".join(swc_ids),
        "issue_count": len(issues),
        "myth_status": result["status"],
        "seconds": result["seconds"],
        "stdout": result["stdout"],
        "stderr": result["stderr"],
    }


def main():
    ap = argparse.ArgumentParser(description="Run Mythril on generated dataset from manifest or compile results")
    ap.add_argument("input_csv", help="dataset_manifest.csv or compile_results.csv")
    ap.add_argument("--only-compilable", action="store_true", help="When input is compile_results.csv, analyze only compiles=yes")
    ap.add_argument("--timeout", type=int, default=120)
    ap.add_argument("--workers", type=int, default=2)
    ap.add_argument("--myth", default="myth")
    args = ap.parse_args()

    rows = list(csv.DictReader(open(args.input_csv, newline="", encoding="utf-8")))
    if args.only_compilable and rows and "compiles" in rows[0]:
        rows = [r for r in rows if r.get("compiles") == "yes"]
    dataset_root = Path(args.input_csv).resolve().parents[2] if "analysis" in Path(args.input_csv).parts else Path(args.input_csv).resolve().parent.parent
    outdir = dataset_root / "analysis" / "mythril"
    outdir.mkdir(parents=True, exist_ok=True)
    out_csv = outdir / "mythril_results.csv"

    results = []
    with ThreadPoolExecutor(max_workers=args.workers) as ex:
        futures = [ex.submit(worker, row, args.timeout, args.myth) for row in rows]
        for fut in as_completed(futures):
            results.append(fut.result())

    results.sort(key=lambda x: x["contract_id"])
    with open(out_csv, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=list(results[0].keys()) if results else ["contract_id"])
        writer.writeheader()
        writer.writerows(results)
    print(f"Mythril results written to: {out_csv}")


if __name__ == "__main__":
    main()
