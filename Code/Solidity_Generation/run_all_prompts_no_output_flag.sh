#!/usr/bin/env bash
set -euo pipefail

BASE_DIR="generated_contracts/qwen2.5-coder-7b_temp_0_7"
MANIFEST="$BASE_DIR/metadata/dataset_manifest.csv"
COMPILE="$BASE_DIR/analysis/compile/compile_results.csv"
MYTHRIL="$BASE_DIR/analysis/mythril/mythril_results.csv"
MODEL="qwen2.5-coder:7b"
PROMPTS=(balanced evidence oneVuln precision)
DEFAULT_LLM_CSV="$BASE_DIR/analysis/llm/ollama_results_qwen2.5-coder-7b.csv"

for PROMPT_NAME in "${PROMPTS[@]}"; do
  PROMPT_FILE="prompts/${PROMPT_NAME}.txt"
  LLM_DIR="$BASE_DIR/analysis/llm_${PROMPT_NAME}"
  MASTER_DIR="$BASE_DIR/analysis/master_${PROMPT_NAME}"
  STATS_DIR="$BASE_DIR/analysis/statistics_${PROMPT_NAME}"
  OLLAMA_CSV="$LLM_DIR/ollama_results_qwen2.5-coder-7b.csv"
  MASTER_CSV="$MASTER_DIR/master_dataset.csv"

  mkdir -p "$LLM_DIR" "$MASTER_DIR" "$STATS_DIR"

  echo "=== Running prompt: $PROMPT_NAME ==="

  python3 Code/Solidity_Generation/ollama_batch_from_manifest.py \
    "$COMPILE" \
    --only-compilable \
    --prompt "$PROMPT_FILE" \
    --model "$MODEL"

  if [[ ! -f "$DEFAULT_LLM_CSV" ]]; then
    echo "Expected output file not found: $DEFAULT_LLM_CSV"
    echo "Check where ollama_batch_from_manifest.py writes its CSV."
    exit 1
  fi

  cp "$DEFAULT_LLM_CSV" "$OLLAMA_CSV"

  python3 Code/Solidity_Generation/merge_results.py \
    "$MANIFEST" \
    "$COMPILE" \
    "$MYTHRIL" \
    "$OLLAMA_CSV" \
    --output "$MASTER_CSV"

  python3 Code/Solidity_Generation/thesis_statistics.py \
    "$MASTER_CSV" \
    --output-dir "$STATS_DIR"

done

python3 Code/Solidity_Generation/compare_prompt_sets.py \
  --input balanced  "$BASE_DIR/analysis/master_balanced/master_dataset.csv" \
  --input evidence  "$BASE_DIR/analysis/master_evidence/master_dataset.csv" \
  --input oneVuln   "$BASE_DIR/analysis/master_oneVuln/master_dataset.csv" \
  --input precision "$BASE_DIR/analysis/master_precision/master_dataset.csv" \
  --output-dir "$BASE_DIR/analysis/prompt_comparison"

printf '\nAll prompt runs completed.\n'
printf 'Combined comparison: %s\n' "$BASE_DIR/analysis/prompt_comparison/prompt_stats_wide.csv"
