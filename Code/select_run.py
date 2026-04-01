#!/usr/bin/env python3
import argparse
import csv
import json
import random
import re
import subprocess
import sys
import time
from pathlib import Path

LABELS = ["BN", "DE", "EF", "SE", "OF", "RE", "TP", "UC"]

SWC_TO_LABEL = {
    "SWC-116": "BN",
    "SWC-120": "BN",
    "SWC-112": "DE",
    "SWC-124": "DE",
    "SWC-127": "DE",
    "SWC-105": "EF",
    "SWC-106": "EF",
    "SWC-128": "EF",
    "SWC-115": "SE",
    "SWC-101": "OF",
    "SWC-110": "OF",
    "SWC-107": "RE",
    "SWC-104": "UC",
    "SWC-113": "UC",
    # Everything else Mythril reports → OTHER
    "SWC-100": "OTHER", "SWC-102": "OTHER", "SWC-103": "OTHER",
    "SWC-108": "OTHER", "SWC-109": "OTHER", "SWC-111": "OTHER",
    "SWC-114": "OTHER", "SWC-117": "OTHER", "SWC-118": "OTHER",
    "SWC-119": "OTHER", "SWC-121": "OTHER", "SWC-122": "OTHER",
    "SWC-123": "OTHER", "SWC-125": "OTHER", "SWC-126": "OTHER",
    "SWC-129": "OTHER", "SWC-130": "OTHER", "SWC-131": "OTHER",
    "SWC-132": "OTHER", "SWC-133": "OTHER", "SWC-134": "OTHER",
    "SWC-135": "OTHER", "SWC-136": "OTHER",
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


def collect_sol_files(folder):
    return sorted([p for p in Path(folder).rglob("*.sol") if p.is_file()])


def choose_n_per_folder(root, n):
    root = Path(root)
    picked, missing = [], []
    for label in LABELS:
        d = root / label
        if not d.exists() or not d.is_dir():
            missing.append(label)
            continue
        files = collect_sol_files(d)
        if not files:
            missing.append(label)
            continue
        k = min(n, len(files))
        if k < n:
            print(f"  [warn] {label}: only {len(files)} available, picking {k}", file=sys.stderr)
        for f in random.sample(files, k):
            picked.append((label, f))
    return picked, missing


def parse_text_output(text):
    issues = []
    seen = set()
    blocks = re.split(r'\n={3,}|\n-{3,}', text)
    if len(blocks) < 2:
        blocks = re.split(r'(?=SWC ID:)', text, flags=re.I)
    for block in blocks:
        block = block.strip()
        if len(block) < 20:
            continue
        swc_match = re.search(r'SWC[-_ ]?ID[:\s]*(SWC-\d+|\d+)', block, re.I)
        if not swc_match:
            continue
        raw_swc = swc_match.group(1).strip()
        if not raw_swc.upper().startswith("SWC-"):
            raw_swc = "SWC-" + raw_swc
        swc_id = raw_swc.upper()
        sev_match = re.search(r'Severity[:\s]*(\w+)', block, re.I)
        severity = sev_match.group(1).strip() if sev_match else "Unknown"
        title_match = re.search(r'Title[:\s]*(.+?)(?:\n|$)', block, re.I)
        title = title_match.group(1).strip() if title_match else ""
        desc_match = re.search(r'Description[:\s]*(.*?)(?:\n{2,}|$)', block, re.S | re.I)
        description = " ".join(desc_match.group(1).split())[:500] if desc_match else ""
        key = (swc_id, severity, title)
        if key in seen:
            continue
        seen.add(key)
        issues.append({"swc_id": swc_id, "severity": severity, "title": title, "description": description})
    return issues


def issues_to_vuln_labels(issues, status):
    if status == "timeout":
        return "TIMEOUT", "TIMEOUT"
    if not issues:
        return "SAFE", "SAFE"

    matched, has_other = set(), False
    for issue in issues:
        swc = issue.get("swc_id", "")
        mapped = SWC_TO_LABEL.get(swc)
        if mapped == "OTHER":
            has_other = True
        elif mapped:
            matched.add(mapped)
        else:
            text = (issue.get("title", "") + " " + issue.get("description", "")).lower()
            found = False
            for kw, lbl in KEYWORD_TO_LABEL.items():
                if kw in text:
                    matched.add(lbl)
                    found = True
                    break
            if not found and swc:
                has_other = True

    if has_other:
        matched.add("OTHER")
    vuln_class = ";".join(sorted(matched)) if matched else "OTHER"
    return vuln_class, "VULNERABLE"


def run_mythril(file_path, timeout, myth_cmd):
    cmd = [myth_cmd, "analyze", str(file_path), "--execution-timeout", str(timeout)]
    start = time.time()
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout + 60)
        elapsed = round(time.time() - start, 2)
        combined = (proc.stdout or "") + "\n" + (proc.stderr or "")
        issues = parse_text_output(combined)
        status = "ok" if proc.returncode == 0 else "error"
        if "Traceback" in combined:
            status = "runtime_error"
        return {"file": str(file_path), "seconds": elapsed, "returncode": proc.returncode,
                "status": status, "issues": issues,
                "stdout": proc.stdout[:4000], "stderr": proc.stderr[:2000]}
    except subprocess.TimeoutExpired as e:
        elapsed = round(time.time() - start, 2)
        out = (e.stdout or "") + "\n" + (e.stderr or "")
        return {"file": str(file_path), "seconds": elapsed, "returncode": None,
                "status": "timeout", "issues": parse_text_output(out),
                "stdout": (e.stdout or "")[:4000], "stderr": (e.stderr or "")[:2000]}


def format_duration(seconds):
    seconds = int(round(seconds))
    mins, secs = divmod(seconds, 60)
    hours, mins = divmod(mins, 60)
    if hours:
        return f"{hours}h {mins}m {secs}s"
    if mins:
        return f"{mins}m {secs}s"
    return f"{secs}s"


def progress_line(index, total, current, start_time, completed_times):
    pct = (index / total) * 100 if total else 0
    elapsed = time.time() - start_time
    avg = sum(completed_times) / len(completed_times) if completed_times else 0
    remaining = max(total - index, 0) * avg
    bar_len = 24
    filled = int((index / total) * bar_len) if total else 0
    bar = "#" * filled + "-" * (bar_len - filled)
    return (
        f"[{bar}] {index}/{total} ({pct:5.1f}%) | "
        f"elapsed: {format_duration(elapsed)} | "
        f"eta: {format_duration(remaining) if completed_times else 'unknown'} | "
        f"current: {current}"
    )


def main():
    ap = argparse.ArgumentParser(
        description="Randomly pick N Solidity files from each vulnerability folder, run Mythril, export evaluation data",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python3 select_run.py /path/to/vuln-root --n 3 --seed 42 --timeout 120
  python3 select_run.py /path/to/vuln-root --n 2 --myth /path/to/.venv/bin/myth
"""
    )
    ap.add_argument("root")
    ap.add_argument("--n", type=int, default=1, metavar="N")
    ap.add_argument("--timeout", type=int, default=120)
    ap.add_argument("--myth", default="myth")
    ap.add_argument("--outdir", default="output/multilabel_eval")
    ap.add_argument("--seed", type=int, default=None)
    args = ap.parse_args()

    if args.seed is not None:
        random.seed(args.seed)

    root = Path(args.root)
    outdir = Path(args.outdir)
    outdir.mkdir(parents=True, exist_ok=True)

    picked, missing = choose_n_per_folder(root, args.n)
    if missing:
        print(f"[warn] Missing or empty folders: {', '.join(missing)}", file=sys.stderr)
    if not picked:
        print("No files selected.", file=sys.stderr)
        sys.exit(2)

    total = len(picked)
    per_label = {}
    for label, f in picked:
        per_label.setdefault(label, []).append(f.name)

    print(f"\nPicking {args.n} file(s) per folder — {total} files total:")
    for label, names in sorted(per_label.items()):
        for name in names:
            print(f"  [{label}] {name}")
    print()

    runs, rows, completed_times = [], [], []
    start_all = time.time()

    for i, (label, path) in enumerate(picked, start=1):
        print(progress_line(i - 1, total, f"{label}/{path.name}", start_all, completed_times))
        result = run_mythril(path, timeout=args.timeout, myth_cmd=args.myth)
        issues = result["issues"]
        vuln_class, detection_status = issues_to_vuln_labels(issues, result["status"])
        swc_ids = sorted(set(iss.get("swc_id", "") for iss in issues if iss.get("swc_id")))
        completed_times.append(result["seconds"])

        runs.append({"true_label": label, "file": str(path), "result": result, "issues": issues})
        rows.append({
            "true_label": label,
            "file": path.name,
            "path": str(path),
            "predicted_vuln_class": vuln_class,
            "detection_status": detection_status,
            "raw_swc_ids": ";".join(swc_ids),
            "issue_count": len(issues),
            "myth_status": result["status"],
            "seconds": result["seconds"],
        })
        print(
            f"  -> done: {label}/{path.name} | myth_status={result['status']} | "
            f"issues={len(issues)} | class={vuln_class} | detection={detection_status} | "
            f"time={format_duration(result['seconds'])}\n"
        )

    print(progress_line(total, total, "finished", start_all, completed_times))
    print()

    with open(outdir / "picked_files.json", "w", encoding="utf-8") as f:
        json.dump(runs, f, indent=2)

    with open(outdir / "picked_files.csv", "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=[
            "true_label", "file", "path",
            "predicted_vuln_class", "detection_status",
            "raw_swc_ids", "issue_count", "myth_status", "seconds"
        ])
        w.writeheader()
        w.writerows(rows)

    with open(outdir / "eval_input.csv", "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["true_label", "predicted_vuln_class", "detection_status", "file", "seconds"])
        for r in rows:
            w.writerow([r["true_label"], r["predicted_vuln_class"], r["detection_status"], r["file"], r["seconds"]])

    print(f"Results written to: {outdir}/")
    print(f"  - picked_files.json")
    print(f"  - picked_files.csv")
    print(f"  - eval_input.csv")


if __name__ == "__main__":
    main()