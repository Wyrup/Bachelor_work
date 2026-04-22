#!/usr/bin/env python3
import argparse
import csv
import json
import random
import re
import subprocess
import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

LABELS = ["BN", "DE", "EF", "SE", "OF", "RE", "TP", "UC"]

SWC_TO_LABEL = {
    "SWC-116": "BN",  "SWC-120": "BN",
    "SWC-112": "DE",  "SWC-124": "DE",  "SWC-127": "DE",
    "SWC-105": "EF",  "SWC-106": "EF",  "SWC-128": "EF",
    "SWC-115": "SE",
    "SWC-101": "OF",  "SWC-110": "OF",
    "SWC-107": "RE",
    "SWC-104": "UC",  "SWC-113": "UC",
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

_print_lock = threading.Lock()


# ─────────────────────────────────────────────
# File collection & selection
# ─────────────────────────────────────────────

def collect_sol_files(folder):
    return sorted([p for p in Path(folder).rglob("*.sol") if p.is_file()])


def filename_numeric_key(path):
    m = re.search(r'(\d+)', path.stem)
    if m:
        return (int(m.group(1)), path.name.lower())
    return (10 ** 18, path.name.lower())


def choose_files(root, n=None, mode="random", batch_start=None, batch_end=None):
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

        if mode == "random":
            k = min(n, len(files))
            if k < n:
                print(f"  [warn] {label}: only {len(files)} files, picking {k}", file=sys.stderr)
            selected = random.sample(files, k)

        elif mode == "smallest":
            k = min(n, len(files))
            if k < n:
                print(f"  [warn] {label}: only {len(files)} files, picking {k}", file=sys.stderr)
            selected = sorted(files, key=filename_numeric_key)[:k]

        elif mode == "range":
            sorted_files = sorted(files, key=filename_numeric_key)
            start_idx = max(batch_start - 1, 0)
            end_idx   = min(batch_end, len(sorted_files))
            selected  = sorted_files[start_idx:end_idx]
            available = len(sorted_files)
            if batch_start > available:
                print(f"  [warn] {label}: start={batch_start} exceeds total files ({available}), skipping", file=sys.stderr)
            elif len(selected) < (batch_end - batch_start + 1):
                print(f"  [warn] {label}: range {batch_start}-{batch_end} → only {len(selected)} file(s) available", file=sys.stderr)
        else:
            raise ValueError(f"Unknown mode: {mode}")

        for f in selected:
            picked.append((label, f))

    return picked, missing


# ─────────────────────────────────────────────
# Mythril output parsing
# ─────────────────────────────────────────────

def parse_text_output(text):
    issues, seen = [], set()
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
        raw = swc_match.group(1).strip()
        swc_id = raw.upper() if raw.upper().startswith("SWC-") else "SWC-" + raw
        sev_m   = re.search(r'Severity[:\s]*(\w+)',                 block, re.I)
        title_m = re.search(r'Title[:\s]*(.+?)(?:\n|$)',            block, re.I)
        desc_m  = re.search(r'Description[:\s]*(.*?)(?:\n{2,}|$)', block, re.S | re.I)
        severity    = sev_m.group(1).strip()                  if sev_m   else "Unknown"
        title       = title_m.group(1).strip()                if title_m else ""
        description = " ".join(desc_m.group(1).split())[:500] if desc_m  else ""
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
        swc    = issue.get("swc_id", "")
        mapped = SWC_TO_LABEL.get(swc)
        if mapped == "OTHER":
            has_other = True
        elif mapped:
            matched.add(mapped)
        else:
            text  = (issue.get("title", "") + " " + issue.get("description", "")).lower()
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
    return (";".join(sorted(matched)) if matched else "OTHER"), "VULNERABLE"


# ─────────────────────────────────────────────
# Mythril runner
# ─────────────────────────────────────────────

def run_mythril(file_path, timeout, myth_cmd):
    cmd = [myth_cmd, "analyze", str(file_path), "--execution-timeout", str(timeout)]
    start = time.time()
    try:
        proc    = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout + 60)
        elapsed = round(time.time() - start, 2)
        combined = (proc.stdout or "") + "\n" + (proc.stderr or "")
        issues   = parse_text_output(combined)
        status   = "ok" if proc.returncode == 0 else "error"
        if "Traceback" in combined:
            status = "runtime_error"
        return {"file": str(file_path), "seconds": elapsed, "returncode": proc.returncode,
                "status": status, "issues": issues,
                "stdout": proc.stdout[:4000], "stderr": proc.stderr[:2000]}
    except subprocess.TimeoutExpired as e:
        elapsed = round(time.time() - start, 2)
        out     = (e.stdout or "") + "\n" + (e.stderr or "")
        return {"file": str(file_path), "seconds": elapsed, "returncode": None,
                "status": "timeout", "issues": parse_text_output(out),
                "stdout": (e.stdout or "")[:4000], "stderr": (e.stderr or "")[:2000]}


# ─────────────────────────────────────────────
# Progress & formatting helpers
# ─────────────────────────────────────────────

def format_duration(seconds):
    seconds = int(round(seconds))
    m, s = divmod(seconds, 60)
    h, m = divmod(m, 60)
    if h: return f"{h}h {m}m {s}s"
    if m: return f"{m}m {s}s"
    return f"{s}s"


def render_progress(done, total, start_time, active_files):
    pct    = (done / total) * 100 if total else 0
    elapsed = time.time() - start_time
    filled = int((done / total) * 24) if total else 0
    bar    = "#" * filled + "-" * (24 - filled)
    active = ", ".join(active_files) if active_files else "-"
    return (f"[{bar}] {done}/{total} ({pct:5.1f}%) | "
            f"elapsed: {format_duration(elapsed)} | running: {active}")


# ─────────────────────────────────────────────
# Per-file analysis (runs in a thread)
# ─────────────────────────────────────────────

def analyze_file(label, path, timeout, myth_cmd,
                 done_counter, total, start_time, active_set, active_lock):
    name = f"{label}/{path.name}"

    with active_lock:
        active_set.add(name)
    with _print_lock:
        with active_lock:
            print(render_progress(done_counter[0], total, start_time, sorted(active_set)))

    result  = run_mythril(path, timeout, myth_cmd)
    issues  = result["issues"]
    vuln_class, detection_status = issues_to_vuln_labels(issues, result["status"])
    swc_ids = sorted(set(i.get("swc_id", "") for i in issues if i.get("swc_id")))

    with active_lock:
        active_set.discard(name)
        done_counter[0] += 1

    with _print_lock:
        with active_lock:
            print(render_progress(done_counter[0], total, start_time, sorted(active_set)))
        print(f"  -> done: {name} | myth_status={result['status']} | "
              f"issues={len(issues)} | class={vuln_class} | "
              f"detection={detection_status} | time={format_duration(result['seconds'])}\n")

    return {
        "true_label": label,
        "file":       str(path),
        "result":     result,
        "issues":     issues,
        "row": {
            "true_label":           label,
            "file":                 path.name,
            "path":                 str(path),
            "predicted_vuln_class": vuln_class,
            "detection_status":     detection_status,
            "raw_swc_ids":          ";".join(swc_ids),
            "issue_count":          len(issues),
            "myth_status":          result["status"],
            "seconds":              result["seconds"],
        }
    }


# ─────────────────────────────────────────────
# Output helpers
# ─────────────────────────────────────────────

def write_outputs(runs, rows, outdir):
    outdir.mkdir(parents=True, exist_ok=True)

    with open(outdir / "picked_files.json", "w", encoding="utf-8") as f:
        json.dump(runs, f, indent=2)

    with open(outdir / "picked_files.csv", "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=[
            "true_label", "file", "path", "predicted_vuln_class",
            "detection_status", "raw_swc_ids", "issue_count", "myth_status", "seconds"])
        w.writeheader()
        w.writerows(rows)

    with open(outdir / "eval_input.csv", "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["true_label", "predicted_vuln_class", "detection_status", "file", "seconds"])
        for r in rows:
            w.writerow([r["true_label"], r["predicted_vuln_class"],
                        r["detection_status"], r["file"], r["seconds"]])

    print(f"Results written to: {outdir}/")
    print(f"  - picked_files.json")
    print(f"  - picked_files.csv")
    print(f"  - eval_input.csv")


# ─────────────────────────────────────────────
# Output directory naming
# ─────────────────────────────────────────────

def build_outdir(base, mode, n, batch_start, batch_end, seed):
    if mode == "range":
        suffix = f"range_{batch_start}_{batch_end}"
    elif mode == "smallest":
        suffix = f"smallest_{n}"
    else:
        suffix = f"random_{n}" + (f"_seed{seed}" if seed is not None else "")
    return Path(base) / suffix


# ─────────────────────────────────────────────
# Main
# ─────────────────────────────────────────────

def main():
    ap = argparse.ArgumentParser(
        description="Pick Solidity files per vulnerability folder, run Mythril in parallel, export results",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Modes
─────
  random   : randomly pick --n files per folder (reproducible with --seed)
  smallest : pick the --n files with the lowest numeric filename per folder
  range    : pick files at positions --start to --end (1-based) per folder,
             sorted numerically by filename

Examples
────────
  python3 select_run.py /data/vuln-root --mode random   --n 3  --seed 42 --workers 3
  python3 select_run.py /data/vuln-root --mode smallest --n 100           --workers 4
  python3 select_run.py /data/vuln-root --mode range --start   1 --end 100 --workers 4
  python3 select_run.py /data/vuln-root --mode range --start 101 --end 200 --workers 4
  python3 select_run.py /data/vuln-root --mode range --start 201 --end 300 --workers 4

Output folders are named automatically:
  results/range_1_100/
  results/range_101_200/
  results/random_3_seed42/
  results/smallest_100/
""")

    ap.add_argument("root",      help="Root folder containing BN, DE, EF, SE, OF, RE, TP, UC sub-folders")
    ap.add_argument("--mode",    choices=["random", "smallest", "range"], default="random",
                    help="File selection mode (default: random)")
    ap.add_argument("--n",       type=int, default=None,
                    help="Files per folder — required for random/smallest")
    ap.add_argument("--start",   type=int, default=None,
                    help="1-based start index per folder — required for range")
    ap.add_argument("--end",     type=int, default=None,
                    help="1-based end index per folder, inclusive — required for range")
    ap.add_argument("--timeout", type=int, default=120,
                    help="Mythril timeout per file in seconds (default: 120)")
    ap.add_argument("--workers", type=int, default=2,
                    help="Parallel Mythril processes (default: 2)")
    ap.add_argument("--myth",    default="myth",
                    help="Mythril executable name or full path (default: myth)")
    ap.add_argument("--outdir",  default="results",
                    help="Base output directory (default: results)")
    ap.add_argument("--seed",    type=int, default=None,
                    help="Random seed — mode=random only")
    args = ap.parse_args()

    if args.mode in {"random", "smallest"} and args.n is None:
        ap.error("--n is required when --mode is random or smallest")
    if args.mode == "range":
        if args.start is None or args.end is None:
            ap.error("--start and --end are required when --mode is range")
        if args.start < 1 or args.end < args.start:
            ap.error("Require 1 <= start <= end")

    if args.seed is not None:
        random.seed(args.seed)

    outdir = build_outdir(args.outdir, args.mode, args.n, args.start, args.end, args.seed)

    picked, missing = choose_files(
        args.root, n=args.n, mode=args.mode,
        batch_start=args.start, batch_end=args.end,
    )

    if missing:
        print(f"[warn] Missing or empty folders: {', '.join(missing)}", file=sys.stderr)
    if not picked:
        print("No files selected — nothing to do.", file=sys.stderr)
        sys.exit(2)

    total     = len(picked)
    per_label = {}
    for label, f in picked:
        per_label.setdefault(label, []).append(f.name)

    sel_info = (f"Mode=range ({args.start}–{args.end})" if args.mode == "range"
                else f"Mode={args.mode} | n={args.n}")
    print(f"\n{sel_info} | {total} files total | workers={args.workers} | output → {outdir}")
    for label, names in sorted(per_label.items()):
        preview = ", ".join(names[:5])
        extra   = f" ... +{len(names)-5} more" if len(names) > 5 else ""
        print(f"  [{label}] {len(names)} file(s): {preview}{extra}")
    print()

    start_all    = time.time()
    done_counter = [0]
    active_set   = set()
    active_lock  = threading.Lock()
    result_map   = {}

    with ThreadPoolExecutor(max_workers=args.workers) as executor:
        futures = {
            executor.submit(
                analyze_file,
                label, path, args.timeout, args.myth,
                done_counter, total, start_all, active_set, active_lock
            ): i
            for i, (label, path) in enumerate(picked)
        }
        for future in as_completed(futures):
            idx = futures[future]
            try:
                result_map[idx] = future.result()
            except Exception as e:
                label, path = picked[idx]
                with _print_lock:
                    print(f"  [ERROR] {label}/{path.name}: {e}\n")
                result_map[idx] = None

    runs, rows = [], []
    for i in range(len(picked)):
        res = result_map.get(i)
        if res:
            runs.append({"true_label": res["true_label"], "file": res["file"],
                         "result": res["result"], "issues": res["issues"]})
            rows.append(res["row"])

    elapsed_total = round(time.time() - start_all, 2)
    print(f"\n[########################] {total}/{total} (100.0%) | "
          f"elapsed: {format_duration(elapsed_total)} | done\n")

    write_outputs(runs, rows, outdir)


if __name__ == "__main__":
    main()