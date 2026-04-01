#!/usr/bin/env python3
import argparse
import csv
import json
import random
import subprocess
import sys
import time
from pathlib import Path

LABELS = ["BN", "DE", "EF", "SE", "OF", "RE", "TP", "UC"]


def collect_sol_files(folder):
    return sorted([p for p in Path(folder).rglob("*.sol") if p.is_file()])


def choose_n_per_folder(root, n):
    root = Path(root)
    picked = []
    missing = []
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
            print(f"  [warn] {label}: only {len(files)} file(s) available, picking {k} instead of {n}", file=sys.stderr)
        for f in random.sample(files, k):
            picked.append((label, f))
    return picked, missing


def run_mythril(file_path, timeout=120, myth_cmd="myth"):
    cmd = [myth_cmd, "analyze", str(file_path), "-o", "jsonv2", "--execution-timeout", str(timeout)]
    start = time.time()
    proc = subprocess.run(cmd, capture_output=True, text=True)
    elapsed = round(time.time() - start, 2)
    stdout = proc.stdout.strip()
    stderr = proc.stderr.strip()
    data = None
    if stdout:
        try:
            data = json.loads(stdout)
        except Exception:
            data = None
    return {
        "file": str(file_path),
        "seconds": elapsed,
        "returncode": proc.returncode,
        "stdout": stdout,
        "stderr": stderr,
        "json": data,
        "status": "ok" if proc.returncode == 0 else "error",
    }


def extract_findings(myth_json):
    if not myth_json:
        return []
    findings = []
    issues = myth_json.get("issues", []) if isinstance(myth_json, dict) else []
    for issue in issues:
        findings.append({
            "swc_id": issue.get("swcID") or issue.get("swc_id") or "",
            "title": issue.get("title") or "",
            "severity": issue.get("severity") or "",
            "description": issue.get("description") or "",
            "contract": issue.get("contract") or "",
            "function": issue.get("function") or "",
            "filename": issue.get("filename") or "",
        })
    return findings


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
        description="Randomly pick N Solidity files from each vulnerability folder, run Mythril, and export evaluation data",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # pick 1 file per folder (default)
  python3 select_and_run_mythril.py /path/to/vuln-root

  # pick 5 files per folder
  python3 select_and_run_mythril.py /path/to/vuln-root --n 5

  # pick 3, reproducible run
  python3 select_and_run_mythril.py /path/to/vuln-root --n 3 --seed 42

  # use a custom myth path and longer timeout
  python3 /home/tim/PycharmProjects/Bachelor_work/Code/select_run.py /home/tim/PycharmProjects/Bachelor_work/Data/Dataset_test --n 1 --seed 67 --timeout 120
"""
    )
    ap.add_argument("root", help="Folder containing BN, DE, EF, SE, OF, RE, TP, UC sub-folders")
    ap.add_argument("--n", type=int, default=1, metavar="N",
                    help="Number of files to randomly pick from each folder (default: 1)")
    ap.add_argument("--timeout", type=int, default=120, help="Mythril timeout in seconds per file (default: 120)")
    ap.add_argument("--myth", default="myth", help="Mythril executable name or full path (default: myth)")
    ap.add_argument("--outdir", default="output/multilabel_eval", help="Output directory")
    ap.add_argument("--seed", type=int, default=None,
                    help="Random seed for reproducibility (omit for a different pick each run)")
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

    runs = []
    rows = []
    completed_times = []
    start_all = time.time()

    for i, (label, path) in enumerate(picked, start=1):
        print(progress_line(i - 1, total, f"{label}/{path.name}", start_all, completed_times))
        result = run_mythril(path, timeout=args.timeout, myth_cmd=args.myth)
        findings = extract_findings(result.get("json"))
        predicted_labels = sorted(set(f.get("swc_id", "") for f in findings if f.get("swc_id")))
        completed_times.append(result["seconds"])

        runs.append({
            "true_label": label,
            "file": str(path),
            "mythril_raw": result,
            "findings": findings,
        })
        rows.append({
            "true_label": label,
            "file": path.name,
            "path": str(path),
            "predicted_labels": ";".join(predicted_labels),
            "finding_count": len(findings),
            "status": "ok" if result["returncode"] == 0 else "error",
            "seconds": result["seconds"],
        })
        print(f"  -> done: {label}/{path.name} | status={result['status']} | findings={len(findings)} | time={format_duration(result['seconds'])}\n")

    print(progress_line(total, total, "finished", start_all, completed_times))
    print()

    with open(outdir / "picked_files.json", "w", encoding="utf-8") as f:
        json.dump(runs, f, indent=2)

    with open(outdir / "picked_files.csv", "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=["true_label", "file", "path", "predicted_labels", "finding_count", "status", "seconds"])
        w.writeheader()
        w.writerows(rows)

    with open(outdir / "eval_input.csv", "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["true_label", "file", "predicted_labels", "seconds", "status"])
        for r in rows:
            w.writerow([r["true_label"], r["file"], r["predicted_labels"], r["seconds"], r["status"]])

    print(f"Results written to: {outdir}/")
    print(f"  - picked_files.json     (raw Mythril output)")
    print(f"  - picked_files.csv      (full summary)")
    print(f"  - eval_input.csv        (input for statistics program)")


if __name__ == "__main__":
    main()