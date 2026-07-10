#!/usr/bin/env python3
import argparse
import csv
import json
import re
import time
from pathlib import Path

import requests

OLLAMA_URL = "http://localhost:11434/api/chat"
DEFAULT_MODEL = "qwen2.5-coder:7b"


def load_prompt_template(prompt_path: str):
    prompt_file = Path(prompt_path)
    if not prompt_file.exists():
        raise FileNotFoundError(f"Prompt file not found: {prompt_file}")
    return prompt_file.read_text(encoding="utf-8")


def extract_json_candidate(text: str) -> str:
    t = text.strip()
    t = re.sub(r"^```[a-zA-Z0-9_-]*\s*", "", t)
    t = re.sub(r"\s*```$", "", t)
    start = t.find("{")
    end = t.rfind("}")
    if start != -1 and end != -1 and end > start:
        return t[start:end + 1].strip()
    raise ValueError("No JSON object found in response")


def repair_json_candidates(text: str):
    candidates = [
        text, text.replace('\\"', '"'), text.replace('""', '"'),
        text.replace("\\n", "\n"), text.replace("\\t", "\t"),
        text.replace('\\"', '"').replace('""', '"'),
    ]
    seen, unique = set(), []
    for c in candidates:
        if c not in seen:
            seen.add(c)
            unique.append(c)
    return unique


def parse_json_response(content: str):
    raw = (content or "").strip()
    if not raw:
        raise ValueError("Empty model response")
    for candidate in repair_json_candidates(raw):
        try:
            return json.loads(candidate)
        except Exception:
            pass
    extracted = extract_json_candidate(raw)
    for candidate in repair_json_candidates(extracted):
        try:
            return json.loads(candidate)
        except Exception:
            pass
    raise ValueError("Failed to parse JSON response")


def normalize_result(result: dict):
    keys = [
        "timestamp_dependency", "block_number_dependency", "ether_strict_equality",
        "ether_frozen", "reentrancy", "integer_overflow", "dangerous_delegatecall",
        "unchecked_external_call", "safe"
    ]
    normalized = {k: bool(result.get(k, False)) for k in keys}
    normalized["reason"] = str(result.get("reason", "")).strip()
    vuln_keys = [k for k in keys if k != "safe"]
    if any(normalized[k] for k in vuln_keys):
        normalized["safe"] = False
    elif "safe" not in result:
        normalized["safe"] = True
    return normalized


def ask_ollama(code: str, model: str, prompt_template: str):
    prompt = prompt_template.replace("{code}", code[:12000])
    payload = {
        "model": model,
        "messages": [{"role": "user", "content": prompt}],
        "stream": False,
        "options": {"temperature": 0},
    }
    response = requests.post(OLLAMA_URL, json=payload, timeout=600)
    response.raise_for_status()
    data = response.json()
    if "message" not in data or "content" not in data["message"]:
        raise ValueError(f"Unexpected API response: {data}")
    content = data["message"]["content"]
    parsed = parse_json_response(content)
    return normalize_result(parsed), content


def main():
    parser = argparse.ArgumentParser(description="Run Ollama vulnerability classifier on generated Solidity dataset from manifest")
    parser.add_argument("manifest_csv", help="Path to dataset_manifest.csv or compile_results.csv")
    parser.add_argument("--prompt", required=True, help="Path to LLM analysis prompt template with {code} placeholder")
    parser.add_argument("--model", type=str, default=DEFAULT_MODEL, help="Ollama model")
    parser.add_argument("--only-compilable", action="store_true", help="When input is compile_results.csv, analyze only compiles=yes")
    args = parser.parse_args()

    rows = list(csv.DictReader(open(args.manifest_csv, newline="", encoding="utf-8")))
    if args.only_compilable and rows and "compiles" in rows[0]:
        rows = [r for r in rows if r.get("compiles") == "yes"]

    prompt_template = load_prompt_template(args.prompt)
    dataset_root = Path(args.manifest_csv).resolve().parents[2] if "analysis" in Path(args.manifest_csv).parts else Path(args.manifest_csv).resolve().parent.parent
    outdir = dataset_root / "analysis" / "llm"
    outdir.mkdir(parents=True, exist_ok=True)
    model_name = args.model.replace(":", "-").replace("/", "-")
    out_csv = outdir / f"ollama_results_{model_name}.csv"

    with open(out_csv, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow([
            "contract_id", "prompt_id", "run", "solidity_file",
            "timestamp_dependency", "block_number_dependency", "ether_strict_equality",
            "ether_frozen", "reentrancy", "integer_overflow", "dangerous_delegatecall",
            "unchecked_external_call", "safe", "reason", "seconds", "status", "raw_response"
        ])
        for i, row in enumerate(rows, start=1):
            file_path = row["solidity_file"]
            print(f"[{i}/{len(rows)}] {row.get('contract_id','?')} {Path(file_path).name}")
            try:
                code = Path(file_path).read_text(encoding="utf-8", errors="ignore")
                start_time = time.time()
                result, raw_response = ask_ollama(code, args.model, prompt_template)
                elapsed = round(time.time() - start_time, 2)
                writer.writerow([
                    row.get("contract_id", ""), row.get("prompt_id", ""), row.get("run", ""), file_path,
                    result["timestamp_dependency"], result["block_number_dependency"], result["ether_strict_equality"],
                    result["ether_frozen"], result["reentrancy"], result["integer_overflow"], result["dangerous_delegatecall"],
                    result["unchecked_external_call"], result["safe"], result["reason"], elapsed, "ok", raw_response
                ])
            except Exception as e:
                writer.writerow([
                    row.get("contract_id", ""), row.get("prompt_id", ""), row.get("run", ""), file_path,
                    "", "", "", "", "", "", "", "", "", "", "", f"error: {e}", ""
                ])

    print(f"LLM results written to: {out_csv}")


if __name__ == "__main__":
    main()
