#!/usr/bin/env python3
import argparse
import csv
import json
import shutil
import subprocess
from pathlib import Path


def detect_contract_name(code: str, fallback: str):
    import re
    m = re.search(r'\bcontract\s+([A-Za-z_][A-Za-z0-9_]*)', code)
    return m.group(1) if m else fallback


def compile_with_solc(solc_cmd: str, file_path: str):
    cmd = [solc_cmd, "--optimize", "--bin", file_path]
    proc = subprocess.run(cmd, capture_output=True, text=True)
    return proc.returncode == 0, proc.stdout[:4000], proc.stderr[:4000], proc.returncode


def main():
    ap = argparse.ArgumentParser(description="Compile-check generated Solidity dataset from manifest")
    ap.add_argument("manifest_csv", help="Path to dataset_manifest.csv")
    ap.add_argument("--solc", default="solc", help="solc executable name or full path")
    args = ap.parse_args()

    if shutil.which(args.solc) is None:
        raise SystemExit(f"solc not found: {args.solc}")

    manifest_path = Path(args.manifest_csv)
    dataset_root = manifest_path.parent.parent
    outdir = dataset_root / "analysis" / "compile"
    outdir.mkdir(parents=True, exist_ok=True)
    results_csv = outdir / "compile_results.csv"
    summary_json = outdir / "compile_summary.json"

    rows = list(csv.DictReader(open(manifest_path, newline="", encoding="utf-8")))
    results = []
    ok_count = 0

    for row in rows:
        fp = row["solidity_file"]
        code = Path(fp).read_text(encoding="utf-8", errors="ignore")
        ok, stdout, stderr, rc = compile_with_solc(args.solc, fp)
        if ok:
            ok_count += 1
        results.append({
            "contract_id": row["contract_id"],
            "prompt_id": row["prompt_id"],
            "run": row["run"],
            "contract_name": detect_contract_name(code, row["contract_id"]),
            "solidity_file": fp,
            "compiles": "yes" if ok else "no",
            "returncode": rc,
            "stdout": stdout,
            "stderr": stderr,
        })

    with open(results_csv, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=list(results[0].keys()) if results else ["contract_id"])
        writer.writeheader()
        writer.writerows(results)

    summary = {
        "manifest_csv": str(manifest_path),
        "total_contracts": len(results),
        "compilable_contracts": ok_count,
        "non_compilable_contracts": len(results) - ok_count,
        "compile_rate": round(ok_count / len(results), 4) if results else 0,
        "results_csv": str(results_csv),
    }
    summary_json.write_text(json.dumps(summary, indent=2), encoding="utf-8")
    print(json.dumps(summary, indent=2))


if __name__ == "__main__":
    main()
