import argparse
import csv
import json
import re
import time
from pathlib import Path

import requests

OLLAMA_URL = "http://localhost:11434/api/chat"
DEFAULT_MODEL = "qwen2.5-coder:7b"
DEFAULT_OUTPUT = "ollama_outputs/ollama_batch_results.csv"


def load_prompt_template(prompt_path: str = None):
    if prompt_path is None:
        prompt_file = Path.home() / "PycharmProjects" / "Bachelor_work" / "prompts" / "test.txt"
    else:
        prompt_file = Path(prompt_path)

    if not prompt_file.exists():
        raise FileNotFoundError(f"Prompt file not found: {prompt_file}")

    return prompt_file.read_text(encoding="utf-8")




def get_true_label(file_path: Path) -> str:
    parts = file_path.parts

    if "SAFE" in parts:
        return "SAFE"

    if "UNSAFE" in parts:
        idx = parts.index("UNSAFE")
        if idx + 1 < len(parts):
            return parts[idx + 1]

    return "UNKNOWN"


def extract_json_candidate(text: str) -> str:
    t = text.strip()
    t = re.sub(r"^```[a-zA-Z0-9_-]*\s*", "", t)
    t = re.sub(r"\s*```$", "", t)
    t = t.strip()

    start = t.find("{")
    end = t.rfind("}")
    if start != -1 and end != -1 and end > start:
        return t[start:end + 1].strip()

    raise ValueError(f"No JSON object found in response: {text}")


def repair_json_candidates(text: str):
    candidates = [
        text,
        text.replace('\\"', '"'),
        text.replace('""', '"'),
        text.replace("\\n", "\n"),
        text.replace("\\t", "\t"),
        text.replace('\\"', '"').replace('""', '"'),
        text.replace("\\n", "\n").replace('\\"', '"').replace('""', '"'),
    ]

    seen = set()
    unique = []
    for c in candidates:
        if c not in seen:
            seen.add(c)
            unique.append(c)
    return unique


def parse_json_response(content: str):
    if not content or not content.strip():
        raise ValueError("Empty model response")

    raw = content.strip()

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

    raise ValueError(f"Failed to parse JSON response: {content}")


def normalize_result(result: dict):
    keys = [
        "timestamp_dependency",
        "block_number_dependency",
        "ether_strict_equality",
        "ether_frozen",
        "reentrancy",
        "integer_overflow",
        "dangerous_delegatecall",
        "unchecked_external_call",
        "safe",
    ]

    normalized = {}
    for k in keys:
        normalized[k] = bool(result.get(k, False))

    normalized["reason"] = str(result.get("reason", "")).strip()

    vuln_keys = [
        "timestamp_dependency",
        "block_number_dependency",
        "ether_strict_equality",
        "ether_frozen",
        "reentrancy",
        "integer_overflow",
        "dangerous_delegatecall",
        "unchecked_external_call",
    ]

    if any(normalized[k] for k in vuln_keys):
        normalized["safe"] = False
    elif "safe" not in result:
        normalized["safe"] = True

    return normalized


def ask_ollama(code: str, model: str, prompt_template: str):
    prompt = prompt_template.replace("{code}", code[:12000])

    payload = {
        "model": model,
        "messages": [
            {
                "role": "user",
                "content": prompt,
            }
        ],
        "stream": False,
        "options": {
            "temperature": 0
        }
    }

    response = requests.post(OLLAMA_URL, json=payload, timeout=600)
    response.raise_for_status()
    data = response.json()

    if "message" not in data or "content" not in data["message"]:
        raise ValueError(f"Unexpected API response: {data}")

    content = data["message"]["content"]
    parsed = parse_json_response(content)
    normalized = normalize_result(parsed)
    return normalized, content


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("dataset_dir", help="Folder containing .sol files")
    parser.add_argument("--start", type=int, default=1, help="1-based start index")
    parser.add_argument("--end", type=int, required=True, help="1-based end index inclusive")
    parser.add_argument("--model", type=str, default=DEFAULT_MODEL, help="Ollama model")
    parser.add_argument("--output", type=str, default=None, help="Output CSV file (overrides auto-generation)")
    parser.add_argument("--prompt", type=str, default=None, help="Path to prompt template file")
    args = parser.parse_args()

    prompt_template = load_prompt_template(args.prompt)

    # Déterminer les noms pour le fichier de sortie
    if args.prompt is None:
        prompt_name = "test"
    else:
        prompt_name = Path(args.prompt).stem

    model_name = args.model.replace(":", "-").replace("/", "-")

    if args.start < 1:
        raise ValueError("--start must be >= 1")
    if args.end < args.start:
        raise ValueError("--end must be >= --start")

    dataset_path = Path(args.dataset_dir)
    sol_files = sorted(dataset_path.rglob("*.sol"))
    selected_files = sol_files[args.start - 1:args.end]

    print(f"Total files found: {len(sol_files)}")
    print(f"Selected batch: {args.start} to {args.end}")
    print(f"Files to process: {len(selected_files)}")
    print(f"Model: {args.model}")

    # Grouper les fichiers par sous-dossier parent
    files_by_folder = {}
    for file_path in selected_files:
        # Récupérer le nom du sous-dossier (le parent direct du fichier)
        folder_name = file_path.parent.name
        if folder_name not in files_by_folder:
            files_by_folder[folder_name] = []
        files_by_folder[folder_name].append(file_path)

    # Traiter chaque sous-dossier
    for folder_name, folder_files in sorted(files_by_folder.items()):
        # Générer le nom du fichier de sortie
        if args.output:
            output_file = args.output
        else:
            output_file = f"ollama_outputs/{model_name}/{prompt_name}/ollama_batch_results_{folder_name}.csv"

        print(f"\nProcessing folder: {folder_name}")
        print(f"Output: {output_file}")
        print(f"Files: {len(folder_files)}")

        output_path = Path(output_file)
        output_path.parent.mkdir(parents=True, exist_ok=True)

        # Vérifier si le fichier existe déjà
        file_exists = output_path.exists()

        with open(output_file, "a", newline="", encoding="utf-8") as f:
            writer = csv.writer(f)

            # Écrire l'en-tête seulement si le fichier est nouveau
            if not file_exists:
                writer.writerow([
                    "file_path",
                    "true_label",
                    "timestamp_dependency",
                    "block_number_dependency",
                    "ether_strict_equality",
                    "ether_frozen",
                    "reentrancy",
                    "integer_overflow",
                    "dangerous_delegatecall",
                    "unchecked_external_call",
                    "safe",
                    "reason",
                    "seconds",
                    "status",
                    "raw_response"
                ])

            for i, file_path in enumerate(folder_files, start=1):
                print(f"  [{i}/{len(folder_files)}] {file_path.name}")
                try:
                    true_label = get_true_label(file_path)
                    code = file_path.read_text(encoding="utf-8", errors="ignore")
                    start_time = time.time()
                    result, raw_response = ask_ollama(code, args.model, prompt_template)
                    elapsed = round(time.time() - start_time, 2)

                    writer.writerow([
                        str(file_path),
                        true_label,
                        result["timestamp_dependency"],
                        result["block_number_dependency"],
                        result["ether_strict_equality"],
                        result["ether_frozen"],
                        result["reentrancy"],
                        result["integer_overflow"],
                        result["dangerous_delegatecall"],
                        result["unchecked_external_call"],
                        result["safe"],
                        result["reason"],
                        elapsed,
                        "ok",
                        raw_response
                    ])
                except Exception as e:
                    writer.writerow([
                        str(file_path),
                        get_true_label(file_path),
                        "", "", "", "", "", "", "", "", "", "",
                        "", f"error: {e}", ""
                    ])
    print("\n" + "=" * 60)
    print("📊 Génération des statistiques...")
    print("=" * 60)

    try:
        from ollama_statistics import compute_statistics

        # Déterminer le dossier contenant les CSV
        if args.output:
            # Si output personnalisé, utiliser son dossier parent
            stats_input_dir = Path(args.output).parent
        else:
            # Sinon, utiliser le dossier standard
            stats_input_dir = Path(f"ollama_outputs/{model_name}/{prompt_name}/")

        stats_output_dir = stats_input_dir / "stats"

        if compute_statistics(stats_input_dir, stats_output_dir):
            print(f"✅ Statistiques générées avec succès!")
        else:
            print("⚠️  Impossible de générer les statistiques (aucune donnée valide)")
    except ImportError:
        print("❌ Impossible d'importer ollama_statistics")
    except Exception as e:
        print(f"❌ Erreur lors de la génération des statistiques: {e}")

    print("\n" + "=" * 60)
    print("✅ Traitement complet terminé!")
    print("=" * 60)


if __name__ == "__main__":
    main()
