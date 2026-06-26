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

import pandas as pd
from sklearn.metrics import accuracy_score, precision_recall_fscore_support, confusion_matrix

LABELS = ["BN", "DE", "EF", "SE", "OF", "RE", "TP", "UC"]

SWC_TO_LABEL = {
    "SWC-116": "BN", "SWC-120": "BN",
    "SWC-112": "DE", "SWC-124": "DE", "SWC-127": "DE",
    "SWC-105": "EF", "SWC-106": "EF", "SWC-128": "EF",
    "SWC-115": "SE",
    "SWC-101": "OF", "SWC-110": "OF",
    "SWC-107": "RE",
    "SWC-104": "UC", "SWC-113": "UC",
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


def collect_sol_files(folder):
    return sorted([p for p in Path(folder).rglob("*.sol") if p.is_file()])


def filename_numeric_key(path):
    m = re.search(r"(\d+)", path.stem)
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
            end_idx = min(batch_end, len(sorted_files))
            selected = sorted_files[start_idx:end_idx]
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

    if isinstance(data, list):
        entries = data
    elif isinstance(data, dict):
        entries = [data]
    else:
        return {"issues": [], "logs": [], "parse_error": "unexpected_json_type"}

    issues, logs = [], []
    seen = set()

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
                head = str(desc.get("head", "")).strip()
                tail = str(desc.get("tail", "")).strip()
                description = " ".join(x for x in [head, tail] if x).strip()
            else:
                description = str(desc).strip()

            key = (swc_id, severity, title, description[:200])
            if key in seen:
                continue
            seen.add(key)
            issues.append({
                "swc_id": swc_id,
                "severity": severity,
                "title": title,
                "description": description[:1000],
            })

    return {"issues": issues, "logs": logs, "parse_error": None}


def issues_to_vuln_labels(issues, status):
    if status == "timeout":
        return "TIMEOUT", "TIMEOUT"
    if status != "ok":
        return "ERROR", "ERROR"
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
            if not found:
                has_other = True

    if has_other:
        matched.add("OTHER")
    return (";".join(sorted(matched)) if matched else "OTHER"), "VULNERABLE"


def run_mythril(file_path, timeout, myth_cmd):
    cmd = [myth_cmd, "analyze", str(file_path), "-o", "jsonv2", "--execution-timeout", str(timeout)]
    start = time.time()
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout + 60)
        elapsed = round(time.time() - start, 2)

        stdout = proc.stdout or ""
        stderr = proc.stderr or ""
        parsed = parse_mythril_json_output(stdout)
        issues = parsed["issues"]
        logs = parsed["logs"]
        parse_error = parsed["parse_error"]

        has_traceback = ("Traceback" in stderr) or ("Traceback" in stdout)

        if parse_error is None:
            status = "ok"
        elif has_traceback:
            status = "error"
        else:
            status = "invalid_json" if proc.returncode == 0 else "error"

        return {
            "file": str(file_path),
            "seconds": elapsed,
            "returncode": proc.returncode,
            "status": status,
            "issues": issues,
            "logs": logs,
            "parse_error": parse_error,
            "stdout": stdout[:4000],
            "stderr": stderr[:2000],
        }

    except subprocess.TimeoutExpired as e:
        elapsed = round(time.time() - start, 2)
        stdout = e.stdout if isinstance(e.stdout, str) else ""
        stderr = e.stderr if isinstance(e.stderr, str) else ""
        parsed = parse_mythril_json_output(stdout)
        return {
            "file": str(file_path),
            "seconds": elapsed,
            "returncode": None,
            "status": "timeout",
            "issues": parsed["issues"],
            "logs": parsed["logs"],
            "parse_error": parsed["parse_error"],
            "stdout": stdout[:4000],
            "stderr": stderr[:2000],
        }


def format_duration(seconds):
    seconds = int(round(seconds))
    m, s = divmod(seconds, 60)
    h, m = divmod(m, 60)
    if h:
        return f"{h}h {m}m {s}s"
    if m:
        return f"{m}m {s}s"
    return f"{s}s"


def render_progress(done, total, start_time, active_files):
    pct = (done / total) * 100 if total else 0
    elapsed = time.time() - start_time
    filled = int((done / total) * 24) if total else 0
    bar = "#" * filled + "-" * (24 - filled)
    active = ", ".join(active_files) if active_files else "-"
    return (f"[{bar}] {done}/{total} ({pct:5.1f}%) | "
            f"elapsed: {format_duration(elapsed)} | running: {active}")


def analyze_file(label, path, timeout, myth_cmd,
                 done_counter, total, start_time, active_set, active_lock):
    name = f"{label}/{path.name}"

    with active_lock:
        active_set.add(name)
    with _print_lock:
        with active_lock:
            print(render_progress(done_counter[0], total, start_time, sorted(active_set)))

    result = run_mythril(path, timeout, myth_cmd)
    issues = result["issues"]
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
        "file": str(path),
        "result": result,
        "issues": issues,
        "row": {
            "true_label": label,
            "file": path.name,
            "path": str(path),
            "predicted_vuln_class": vuln_class,
            "detection_status": detection_status,
            "raw_swc_ids": ";".join(swc_ids),
            "issue_count": len(issues),
            "myth_status": result["status"],
            "seconds": result["seconds"],
        }
    }


def write_outputs(runs, rows, outdir):
    outdir.mkdir(parents=True, exist_ok=True)

    with open(outdir / "picked_files.json", "w", encoding="utf-8") as f:
        json.dump(runs, f, indent=2)

    with open(outdir / "picked_files.csv", "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=[
            "true_label", "file", "path", "predicted_vuln_class",
            "detection_status", "raw_swc_ids", "issue_count", "myth_status", "seconds"
        ])
        w.writeheader()
        w.writerows(rows)

    with open(outdir / "eval_input.csv", "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["true_label", "predicted_vuln_class", "detection_status", "file", "seconds"])
        for r in rows:
            w.writerow([r["true_label"], r["predicted_vuln_class"],
                        r["detection_status"], r["file"], r["seconds"]])

    print(f"Results written to: {outdir}/")
    print("  - picked_files.json")
    print("  - picked_files.csv")
    print("  - eval_input.csv")


def compute_statistics(outdir):
    outdir = Path(outdir)
    stats_dir = outdir / "stats"
    stats_dir.mkdir(parents=True, exist_ok=True)

    csv_path = outdir / "picked_files.csv"
    if not csv_path.exists():
        print(f"  [warn] No {csv_path} found, skipping statistics")
        return False

    data = pd.read_csv(csv_path)
    data = data[data["myth_status"] == "ok"].copy()

    if len(data) == 0:
        print("  [warn] No data with myth_status == 'ok'")
        return False

    data["true_binary"] = data["true_label"].apply(lambda x: "SAFE" if x == "SAFE" else "UNSAFE")

    def pred_binary(pred_class):
        if pred_class == "SAFE":
            return "SAFE"
        return "UNSAFE"

    data["pred_binary"] = data["predicted_vuln_class"].apply(pred_binary)

    binary_labels = ["SAFE", "UNSAFE"]
    b_acc = accuracy_score(data["true_binary"], data["pred_binary"])
    b_prec, b_rec, b_f1, b_sup = precision_recall_fscore_support(
        data["true_binary"], data["pred_binary"], labels=binary_labels, zero_division=0
    )

    binary_metrics = pd.DataFrame({
        "label": binary_labels,
        "precision": b_prec,
        "recall": b_rec,
        "f1": b_f1,
        "support": b_sup,
    })
    binary_metrics.to_csv(stats_dir / "binary_metrics.csv", index=False)

    pd.DataFrame([{
        "accuracy": b_acc,
        "macro_f1": binary_metrics["f1"].mean(),
        "n_rows": len(data)
    }]).to_csv(stats_dir / "binary_summary.csv", index=False)

    binary_cm = confusion_matrix(data["true_binary"], data["pred_binary"], labels=binary_labels)
    pd.DataFrame(binary_cm, index=binary_labels, columns=binary_labels).to_csv(
        stats_dir / "binary_confusion_matrix.csv"
    )

    rows = []
    for label in LABELS:
        subset = data[data["true_label"].isin([label, "SAFE"])].copy()
        if len(subset) == 0:
            continue

        subset["true_onevsrest"] = subset["true_label"].apply(lambda x: label if x == label else "NOT_" + label)

        def pred_onevsrest(pred_class):
            if not isinstance(pred_class, str):
                return "NOT_" + label
            pred_labels = set(p.strip() for p in pred_class.split(";") if p.strip())
            if label in pred_labels:
                return label
            return "NOT_" + label

        subset["pred_onevsrest"] = subset["predicted_vuln_class"].apply(pred_onevsrest)

        labels_eval = [label, "NOT_" + label]
        acc = accuracy_score(subset["true_onevsrest"], subset["pred_onevsrest"])
        prec, rec, f1, sup = precision_recall_fscore_support(
            subset["true_onevsrest"], subset["pred_onevsrest"], labels=labels_eval, zero_division=0
        )

        rows.append({
            "label": label,
            "positive_class_precision": prec[0],
            "positive_class_recall": rec[0],
            "positive_class_f1": f1[0],
            "accuracy": acc,
            "support_positive": int(sup[0]),
            "support_negative": int(sup[1]),
        })

    one_vs_rest = pd.DataFrame(rows)
    one_vs_rest.to_csv(stats_dir / "one_vs_rest_metrics.csv", index=False)

    def pred_strict_multiclass(pred_class):
        if not isinstance(pred_class, str):
            return "SAFE"
        pred_labels = set(p.strip() for p in pred_class.split(";") if p.strip() and p.strip() in LABELS)
        if len(pred_labels) == 0:
            return "SAFE"
        if len(pred_labels) == 1:
            return pred_labels.pop()
        return "MULTI"

    data["pred_strict_multiclass"] = data["predicted_vuln_class"].apply(pred_strict_multiclass)
    multiclass_labels = ["SAFE", "BN", "DE", "EF", "OF", "RE", "SE", "TP", "UC", "MULTI"]

    mc_prec, mc_rec, mc_f1, mc_sup = precision_recall_fscore_support(
        data["true_label"], data["pred_strict_multiclass"], labels=multiclass_labels, zero_division=0
    )

    multiclass_metrics = pd.DataFrame({
        "label": multiclass_labels,
        "precision": mc_prec,
        "recall": mc_rec,
        "f1": mc_f1,
        "support": mc_sup,
    })
    multiclass_metrics.to_csv(stats_dir / "strict_multiclass_metrics.csv", index=False)

    mc_acc = accuracy_score(data["true_label"], data["pred_strict_multiclass"])
    pd.DataFrame([{
        "accuracy": mc_acc,
        "macro_f1_excluding_multi": multiclass_metrics[multiclass_metrics["label"] != "MULTI"]["f1"].mean(),
        "n_rows": len(data)
    }]).to_csv(stats_dir / "strict_multiclass_summary.csv", index=False)

    pd.DataFrame(
        confusion_matrix(data["true_label"], data["pred_strict_multiclass"], labels=multiclass_labels),
        index=multiclass_labels,
        columns=multiclass_labels,
    ).to_csv(stats_dir / "strict_multiclass_confusion_matrix.csv")

    print(f"Statistics written to: {stats_dir}/")
    return True


def build_outdir(base, mode, n, batch_start, batch_end, seed):
    if mode == "range":
        suffix = f"range_{batch_start}_{batch_end}"
    elif mode == "smallest":
        suffix = f"smallest_{n}"
    else:
        suffix = f"random_{n}" + (f"_seed{seed}" if seed is not None else "")
    return Path(base) / suffix


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

    ap.add_argument("root", help="Root folder containing BN, DE, EF, SE, OF, RE, TP, UC sub-folders")
    ap.add_argument("--mode", choices=["random", "smallest", "range"], default="random",
                    help="File selection mode (default: random)")
    ap.add_argument("--n", type=int, default=None,
                    help="Files per folder — required for random/smallest")
    ap.add_argument("--start", type=int, default=None,
                    help="1-based start index per folder — required for range")
    ap.add_argument("--end", type=int, default=None,
                    help="1-based end index per folder, inclusive — required for range")
    ap.add_argument("--timeout", type=int, default=120,
                    help="Mythril timeout per file in seconds (default: 120)")
    ap.add_argument("--workers", type=int, default=2,
                    help="Parallel Mythril processes (default: 2)")
    ap.add_argument("--myth", default="myth",
                    help="Mythril executable name or full path (default: myth)")
    ap.add_argument("--outdir", default="results",
                    help="Base output directory (default: results)")
    ap.add_argument("--seed", type=int, default=None,
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

    total = len(picked)
    per_label = {}
    for label, f in picked:
        per_label.setdefault(label, []).append(f.name)

    sel_info = (f"Mode=range ({args.start}–{args.end})" if args.mode == "range"
                else f"Mode={args.mode} | n={args.n}")
    print(f"\n{sel_info} | {total} files total | workers={args.workers} | output → {outdir}")
    for label, names in sorted(per_label.items()):
        preview = ", ".join(names[:5])
        extra = f" ... +{len(names)-5} more" if len(names) > 5 else ""
        print(f"  [{label}] {len(names)} file(s): {preview}{extra}")
    print()

    start_all = time.time()
    done_counter = [0]
    active_set = set()
    active_lock = threading.Lock()
    result_map = {}

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
            runs.append({
                "true_label": res["true_label"],
                "file": res["file"],
                "result": res["result"],
                "issues": res["issues"],
            })
            rows.append(res["row"])

    elapsed_total = round(time.time() - start_all, 2)
    print(f"\n[########################] {total}/{total} (100.0%) | "
          f"elapsed: {format_duration(elapsed_total)} | done\n")

    write_outputs(runs, rows, outdir)

    print("\n" + "=" * 60)
    print("📊 Generating statistics...")
    print("=" * 60 + "\n")

    try:
        if compute_statistics(outdir):
            print("✅ Statistics generated successfully!")
        else:
            print("⚠️  Unable to generate statistics (no valid data)")
    except Exception as e:
        print(f"❌ Error generating statistics: {e}")


if __name__ == "__main__":
    main()