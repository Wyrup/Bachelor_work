#!/usr/bin/env python3
import argparse, csv, json, re, subprocess, sys, time
from pathlib import Path

SEVERITY_ORDER = {"Unknown": 0, "Low": 1, "Medium": 2, "High": 3, "Critical": 4}

ISSUE_PATTERNS = [
    (re.compile(r"SWC ID:\s*(SWC-\d+)", re.I), "swc_id"),
    (re.compile(r"Severity:\s*(\w+)", re.I), "severity"),
    (re.compile(r"Title:\s*(.+)", re.I), "title"),
    (re.compile(r"Contract:\s*(.+)", re.I), "contract"),
    (re.compile(r"Function name:\s*(.+)", re.I), "function"),
    (re.compile(r"PC address:\s*(.+)", re.I), "pc_address"),
]


def parse_text_output(text):
    issues = []
    blocks = re.split(r"\n(?===== )", text)
    for block in blocks:
        if "SWC ID:" not in block and "Severity:" not in block and "Title:" not in block:
            continue
        issue = {
            "swc_id": "",
            "severity": "Unknown",
            "title": "",
            "contract": "",
            "function": "",
            "pc_address": "",
            "description": "",
        }
        for pattern, key in ISSUE_PATTERNS:
            m = pattern.search(block)
            if m:
                issue[key] = m.group(1).strip()
        desc_match = re.search(r"Description:\s*(.*?)(?:\n\n|\Z)", block, re.S | re.I)
        if desc_match:
            issue["description"] = " ".join(desc_match.group(1).split())[:500]
        issues.append(issue)
    return issues


def format_duration(seconds):
    seconds = int(round(seconds))
    mins, secs = divmod(seconds, 60)
    hours, mins = divmod(mins, 60)
    if hours:
        return f"{hours}h {mins}m {secs}s"
    if mins:
        return f"{mins}m {secs}s"
    return f"{secs}s"


def progress_line(index, total, file_name, start_time, completed_times):
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
        f"current: {file_name}"
    )


def run_myth(file_path, timeout, myth_cmd):
    cmd = myth_cmd + ["analyze", str(file_path), "--execution-timeout", str(timeout)]
    start = time.time()
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout + 30)
        elapsed = round(time.time() - start, 2)
        stdout = proc.stdout or ""
        stderr = proc.stderr or ""
        combined = stdout + ("\n" + stderr if stderr else "")
        issues = parse_text_output(combined)
        status = "ok" if proc.returncode == 0 else "error"
        if proc.returncode != 0 and "Traceback" in combined:
            status = "runtime_error"
        return {
            "file": str(file_path),
            "status": status,
            "returncode": proc.returncode,
            "seconds": elapsed,
            "issue_count": len(issues),
            "issues": issues,
            "stderr": stderr[:2000],
            "stdout": stdout[:4000],
        }
    except subprocess.TimeoutExpired as e:
        elapsed = round(time.time() - start, 2)
        out = (e.stdout or "") + "\n" + (e.stderr or "")
        return {
            "file": str(file_path),
            "status": "timeout",
            "returncode": None,
            "seconds": elapsed,
            "issue_count": 0,
            "issues": parse_text_output(out),
            "stderr": (e.stderr or "")[:2000],
            "stdout": (e.stdout or "")[:4000],
        }


def main():
    ap = argparse.ArgumentParser(description="Run Mythril on all .sol files in a folder and summarize findings")
    ap.add_argument("target", help="Folder containing .sol files")
    ap.add_argument("--timeout", type=int, default=120, help="Per-file Mythril execution timeout in seconds")
    ap.add_argument("--myth", default="myth", help="Mythril executable name or path")
    ap.add_argument("--outdir", default="output/mythril_batch", help="Output directory")
    args = ap.parse_args()

    target = Path(args.target)
    outdir = Path(args.outdir)
    outdir.mkdir(parents=True, exist_ok=True)

    if not target.exists() or not target.is_dir():
        print(f"Target folder not found or not a directory: {target}", file=sys.stderr)
        sys.exit(2)

    files = sorted(target.rglob("*.sol"))
    if not files:
        print(f"No .sol files found in {target}", file=sys.stderr)
        sys.exit(3)

    myth_cmd = [args.myth]
    results = []
    summary = {}
    completed_times = []
    batch_start = time.time()
    total_files = len(files)

    print(f"Found {total_files} Solidity files to analyze.\n")

    for idx, f in enumerate(files, start=1):
        print(progress_line(idx - 1, total_files, f.name, batch_start, completed_times))
        result = run_myth(f, args.timeout, myth_cmd)
        results.append(result)
        completed_times.append(result["seconds"])

        for issue in result["issues"]:
            key = (issue.get("swc_id") or "NO-SWC", issue.get("title") or "Untitled")
            entry = summary.setdefault(key, {
                "swc_id": key[0],
                "title": key[1],
                "count": 0,
                "max_severity": "Unknown",
                "files": set(),
            })
            entry["count"] += 1
            entry["files"].add(Path(result["file"]).name)
            sev = issue.get("severity", "Unknown")
            if SEVERITY_ORDER.get(sev, 0) > SEVERITY_ORDER.get(entry["max_severity"], 0):
                entry["max_severity"] = sev

        print(
            f"  -> done: {f.name} | status={result['status']} | "
            f"issues={result['issue_count']} | time={format_duration(result['seconds'])}\n"
        )

    print(progress_line(total_files, total_files, "finished", batch_start, completed_times))
    print()

    with open(outdir / "mythril_results.json", "w", encoding="utf-8") as f:
        json.dump(results, f, indent=2)

    with open(outdir / "per_file_summary.csv", "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["file", "status", "returncode", "seconds", "issue_count"])
        for r in results:
            w.writerow([Path(r["file"]).name, r["status"], r["returncode"], r["seconds"], r["issue_count"]])

    with open(outdir / "issues_summary.csv", "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["swc_id", "title", "count", "max_severity", "files"])
        for _, item in sorted(
            summary.items(),
            key=lambda kv: (
                -kv[1]["count"],
                -SEVERITY_ORDER.get(kv[1]["max_severity"], 0),
                kv[1]["swc_id"],
                kv[1]["title"]
            )
        ):
            w.writerow([
                item["swc_id"],
                item["title"],
                item["count"],
                item["max_severity"],
                "; ".join(sorted(item["files"]))
            ])

    with open(outdir / "README.md", "w", encoding="utf-8") as f:
        total = len(results)
        ok = sum(1 for r in results if r["status"] == "ok")
        timeouts = sum(1 for r in results if r["status"] == "timeout")
        errors = total - ok - timeouts
        f.write("# Mythril batch runner\n\n")
        f.write(f"Processed {total} Solidity files. Successful: {ok}, timeouts: {timeouts}, runtime/errors: {errors}.\n\n")
        f.write("## Run\n\n")
        f.write("```bash\n")
        f.write(f"python3 run_mythril_batch.py /path/to/sol-folder --timeout {args.timeout}\n")
        f.write("```\n\n")
        f.write("Outputs:\n\n")
        f.write("- `mythril_results.json`: raw per-file results and extracted issues\n")
        f.write("- `per_file_summary.csv`: one line per Solidity file\n")
        f.write("- `issues_summary.csv`: grouped weakness summary across all files\n")

    print(f"Results written to: {outdir}")


if __name__ == "__main__":
    main()