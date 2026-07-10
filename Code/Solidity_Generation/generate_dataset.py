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
DEFAULT_OUTPUT_DIR = "generated_contracts"
DEFAULT_PROMPTS_CSV = "solidity_prompts.csv"

SYSTEM_PROMPT = """You are a Solidity smart contract generator.
Return exactly one complete Solidity contract or set of contracts needed for compilation.
Rules:
- Return only Solidity code inside one markdown code block.
- Do not add explanations before or after the code block.
- Prefer compilable Solidity.
- Preserve prompt-specific Solidity version constraints when provided.
"""


def load_prompts(csv_path: str):
    prompts = []
    with open(csv_path, newline="", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        required = {"prompt_id", "prompt_text"}
        if not required.issubset(reader.fieldnames or []):
            raise ValueError(f"CSV must contain columns: {sorted(required)}")
        for row in reader:
            pid = (row.get("prompt_id") or "").strip()
            text = (row.get("prompt_text") or "").strip()
            if pid and text:
                prompts.append({"prompt_id": pid, "prompt_text": text})
    if not prompts:
        raise ValueError(f"No prompts loaded from {csv_path}")
    return prompts


def ask_ollama(prompt: str, model: str, temperature: float, system_prompt: str):
    payload = {
        "model": model,
        "messages": [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": prompt},
        ],
        "stream": False,
        "options": {"temperature": temperature},
    }
    response = requests.post(OLLAMA_URL, json=payload, timeout=1800)
    response.raise_for_status()
    data = response.json()
    if "message" not in data or "content" not in data["message"]:
        raise ValueError(f"Unexpected API response: {data}")
    return data["message"]["content"]


def extract_solidity(text: str) -> str:
    text = text.strip()
    blocks = re.findall(r"```(?:solidity)?\s*(.*?)```", text, flags=re.DOTALL | re.IGNORECASE)
    if blocks:
        return max(blocks, key=len).strip() + "\n"
    start = text.find("pragma solidity")
    if start != -1:
        return text[start:].strip() + "\n"
    return text + "\n"


def sanitize_model(model: str) -> str:
    return model.replace(":", "-").replace("/", "-")


def next_contract_id(existing_count: int) -> str:
    return f"SC{existing_count + 1:06d}"


def ensure_headers(csv_path: Path, fieldnames):
    if not csv_path.exists():
        csv_path.parent.mkdir(parents=True, exist_ok=True)
        with open(csv_path, "w", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=fieldnames)
            writer.writeheader()


def read_existing_manifest(csv_path: Path):
    if not csv_path.exists():
        return []
    with open(csv_path, newline="", encoding="utf-8") as f:
        return list(csv.DictReader(f))


def append_rows(csv_path: Path, fieldnames, rows):
    ensure_headers(csv_path, fieldnames)
    with open(csv_path, "a", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writerows(rows)


def main():
    parser = argparse.ArgumentParser(description="Generate a thesis dataset of Solidity contracts from prompt CSV using Ollama")
    parser.add_argument("--model", default=DEFAULT_MODEL, help="Ollama model name")
    parser.add_argument("--temperature", type=float, default=0.7, help="Sampling temperature")
    parser.add_argument("--output-dir", default=DEFAULT_OUTPUT_DIR, help="Base output directory")
    parser.add_argument("--prompts-csv", default=DEFAULT_PROMPTS_CSV, help="Path to prompts CSV")
    parser.add_argument("--prompt", default=None, help="Prompt id to run, e.g. P1. If omitted, run all prompts")
    parser.add_argument("--repeat", type=int, default=1, help="How many times to run each prompt")
    parser.add_argument("--dataset-name", default=None, help="Optional custom dataset folder name")
    args = parser.parse_args()

    if args.repeat < 1:
        raise ValueError("--repeat must be >= 1")

    prompts = load_prompts(args.prompts_csv)
    prompt_lookup = {p["prompt_id"]: p["prompt_text"] for p in prompts}
    prompt_ids = [args.prompt] if args.prompt else [p["prompt_id"] for p in prompts]
    for pid in prompt_ids:
        if pid not in prompt_lookup:
            raise ValueError(f"Unknown prompt id: {pid}")

    model_dir = sanitize_model(args.model)
    temp_dir = str(args.temperature).replace(".", "_")
    dataset_name = args.dataset_name or f"{model_dir}_temp_{temp_dir}"
    base_dir = Path(args.output_dir) / dataset_name
    contracts_dir = base_dir / "contracts"
    raw_dir = base_dir / "raw"
    metadata_dir = base_dir / "metadata"
    contracts_dir.mkdir(parents=True, exist_ok=True)
    raw_dir.mkdir(parents=True, exist_ok=True)
    metadata_dir.mkdir(parents=True, exist_ok=True)

    manifest_csv = metadata_dir / "dataset_manifest.csv"
    manifest_json = metadata_dir / "dataset_manifest.json"
    fieldnames = [
        "contract_id", "prompt_id", "run", "model", "temperature", "seconds",
        "solidity_file", "raw_file", "dataset_name"
    ]
    existing = read_existing_manifest(manifest_csv)
    rows = []
    count = len(existing)

    for pid in prompt_ids:
        for run_idx in range(1, args.repeat + 1):
            contract_id = next_contract_id(count)
            count += 1
            print(f"Generating {contract_id} | {pid} | run {run_idx}/{args.repeat} | model={args.model} | temp={args.temperature}")
            started = time.time()
            raw = ask_ollama(prompt_lookup[pid], args.model, args.temperature, SYSTEM_PROMPT)
            solidity = extract_solidity(raw)
            elapsed = round(time.time() - started, 2)

            prompt_contract_dir = contracts_dir / pid
            prompt_raw_dir = raw_dir / pid
            prompt_contract_dir.mkdir(parents=True, exist_ok=True)
            prompt_raw_dir.mkdir(parents=True, exist_ok=True)

            sol_path = prompt_contract_dir / f"{contract_id}_{pid}_run{run_idx}.sol"
            raw_path = prompt_raw_dir / f"{contract_id}_{pid}_run{run_idx}_raw.txt"
            sol_path.write_text(solidity, encoding="utf-8")
            raw_path.write_text(raw, encoding="utf-8")

            rows.append({
                "contract_id": contract_id,
                "prompt_id": pid,
                "run": run_idx,
                "model": args.model,
                "temperature": args.temperature,
                "seconds": elapsed,
                "solidity_file": str(sol_path),
                "raw_file": str(raw_path),
                "dataset_name": dataset_name,
            })

    append_rows(manifest_csv, fieldnames, rows)
    combined = read_existing_manifest(manifest_csv)
    manifest_json.write_text(json.dumps(combined, indent=2), encoding="utf-8")

    print(f"Done. Dataset written to: {base_dir}")
    print(f"Manifest CSV: {manifest_csv}")
    print(f"Manifest JSON: {manifest_json}")


if __name__ == "__main__":
    main()
