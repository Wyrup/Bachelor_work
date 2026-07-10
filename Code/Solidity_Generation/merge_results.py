#!/usr/bin/env python3
import argparse
import csv
from pathlib import Path


def read_csv_by_key(path, key):
    rows = list(csv.DictReader(open(path, newline="", encoding="utf-8")))
    return {row[key]: row for row in rows}, rows


def first_nonempty(*values):
    for v in values:
        if v is not None and str(v).strip() != "":
            return v
    return ""


def ollama_predicted_class(row):
    if not row:
        return ""
    labels = []
    if str(row.get("timestamp_dependency", "")).lower() == "true":
        labels.append("TP")
    if str(row.get("block_number_dependency", "")).lower() == "true":
        labels.append("BN")
    if str(row.get("ether_strict_equality", "")).lower() == "true":
        labels.append("SE")
    if str(row.get("ether_frozen", "")).lower() == "true":
        labels.append("EF")
    if str(row.get("reentrancy", "")).lower() == "true":
        labels.append("RE")
    if str(row.get("integer_overflow", "")).lower() == "true":
        labels.append("OF")
    if str(row.get("dangerous_delegatecall", "")).lower() == "true":
        labels.append("DE")
    if str(row.get("unchecked_external_call", "")).lower() == "true":
        labels.append("UC")
    if labels:
        return ";".join(labels)
    safe = str(row.get("safe", "")).lower()
    if safe == "true":
        return "SAFE"
    return "UNKNOWN"


def binary_from_class(value):
    if not value:
        return ""
    value = str(value).strip().upper()
    if value == "SAFE":
        return "SAFE"
    if value in {"ERROR", "TIMEOUT", "UNKNOWN"}:
        return value
    return "UNSAFE"


def agreement(myth_bin, llm_bin):
    if not myth_bin or not llm_bin:
        return ""
    if myth_bin in {"ERROR", "TIMEOUT", "UNKNOWN"} or llm_bin in {"ERROR", "TIMEOUT", "UNKNOWN"}:
        return "N/A"
    return "agree" if myth_bin == llm_bin else "disagree"


def main():
    ap = argparse.ArgumentParser(description="Merge thesis pipeline outputs into one master CSV")
    ap.add_argument("manifest_csv", help="Path to dataset_manifest.csv")
    ap.add_argument("compile_csv", help="Path to compile_results.csv")
    ap.add_argument("mythril_csv", help="Path to mythril_results.csv")
    ap.add_argument("ollama_csv", help="Path to ollama_results_*.csv")
    ap.add_argument("--output", default=None, help="Optional output CSV path")
    args = ap.parse_args()

    manifest_by_id, manifest_rows = read_csv_by_key(args.manifest_csv, "contract_id")
    compile_by_id, _ = read_csv_by_key(args.compile_csv, "contract_id")
    myth_by_id, _ = read_csv_by_key(args.mythril_csv, "contract_id")
    ollama_by_id, _ = read_csv_by_key(args.ollama_csv, "contract_id")

    manifest_path = Path(args.manifest_csv)
    default_output = manifest_path.parent.parent / "analysis" / "master" / "master_dataset.csv"
    output_path = Path(args.output) if args.output else default_output
    output_path.parent.mkdir(parents=True, exist_ok=True)

    fieldnames = [
        "contract_id", "prompt_id", "run", "model", "temperature", "generation_seconds",
        "dataset_name", "solidity_file", "raw_file",
        "contract_name", "compiles", "compile_returncode", "compile_stdout", "compile_stderr",
        "myth_predicted_class", "myth_binary", "myth_detection_status", "myth_raw_swc_ids",
        "myth_issue_count", "myth_status", "myth_seconds",
        "llm_predicted_class", "llm_binary", "llm_safe", "llm_reason", "llm_seconds", "llm_status",
        "llm_timestamp_dependency", "llm_block_number_dependency", "llm_ether_strict_equality",
        "llm_ether_frozen", "llm_reentrancy", "llm_integer_overflow", "llm_dangerous_delegatecall",
        "llm_unchecked_external_call", "myth_llm_agreement"
    ]

    merged_rows = []
    for m in manifest_rows:
        cid = m["contract_id"]
        c = compile_by_id.get(cid, {})
        y = myth_by_id.get(cid, {})
        o = ollama_by_id.get(cid, {})

        myth_class = first_nonempty(y.get("predicted_vuln_class"))
        myth_bin = binary_from_class(myth_class if myth_class else y.get("detection_status", ""))
        llm_class = ollama_predicted_class(o)
        llm_bin = binary_from_class(llm_class)

        merged_rows.append({
            "contract_id": cid,
            "prompt_id": m.get("prompt_id", ""),
            "run": m.get("run", ""),
            "model": m.get("model", ""),
            "temperature": m.get("temperature", ""),
            "generation_seconds": m.get("seconds", ""),
            "dataset_name": m.get("dataset_name", ""),
            "solidity_file": m.get("solidity_file", ""),
            "raw_file": m.get("raw_file", ""),
            "contract_name": c.get("contract_name", ""),
            "compiles": c.get("compiles", ""),
            "compile_returncode": c.get("returncode", ""),
            "compile_stdout": c.get("stdout", ""),
            "compile_stderr": c.get("stderr", ""),
            "myth_predicted_class": myth_class,
            "myth_binary": myth_bin,
            "myth_detection_status": y.get("detection_status", ""),
            "myth_raw_swc_ids": y.get("raw_swc_ids", ""),
            "myth_issue_count": y.get("issue_count", ""),
            "myth_status": y.get("myth_status", ""),
            "myth_seconds": y.get("seconds", ""),
            "llm_predicted_class": llm_class,
            "llm_binary": llm_bin,
            "llm_safe": o.get("safe", ""),
            "llm_reason": o.get("reason", ""),
            "llm_seconds": o.get("seconds", ""),
            "llm_status": o.get("status", ""),
            "llm_timestamp_dependency": o.get("timestamp_dependency", ""),
            "llm_block_number_dependency": o.get("block_number_dependency", ""),
            "llm_ether_strict_equality": o.get("ether_strict_equality", ""),
            "llm_ether_frozen": o.get("ether_frozen", ""),
            "llm_reentrancy": o.get("reentrancy", ""),
            "llm_integer_overflow": o.get("integer_overflow", ""),
            "llm_dangerous_delegatecall": o.get("dangerous_delegatecall", ""),
            "llm_unchecked_external_call": o.get("unchecked_external_call", ""),
            "myth_llm_agreement": agreement(myth_bin, llm_bin),
        })

    with open(output_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(merged_rows)

    print(f"Master dataset written to: {output_path}")
    print(f"Rows: {len(merged_rows)}")


if __name__ == "__main__":
    main()
