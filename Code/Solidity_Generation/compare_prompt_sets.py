#!/usr/bin/env python3
import argparse
import csv
from pathlib import Path

PROMPT_FLAGS = [
    ('timestamp_dependency', 'llm_timestamp_dependency'),
    ('block_number_dependency', 'llm_block_number_dependency'),
    ('ether_strict_equality', 'llm_ether_strict_equality'),
    ('ether_frozen', 'llm_ether_frozen'),
    ('reentrancy', 'llm_reentrancy'),
    ('integer_overflow', 'llm_integer_overflow'),
    ('dangerous_delegatecall', 'llm_dangerous_delegatecall'),
    ('unchecked_external_call', 'llm_unchecked_external_call'),
]


def read_csv(path):
    with open(path, newline='', encoding='utf-8') as f:
        return list(csv.DictReader(f))


def to_bool_yes(v):
    return str(v).strip().lower() in {'yes', 'true', '1'}


def pct(n, d):
    return round((n / d * 100.0), 2) if d else 0.0


def safe_div(n, d):
    return round(n / d, 4) if d else 0.0


def summarize(rows):
    total = len(rows)
    compilable = [r for r in rows if to_bool_yes(r.get('compiles'))]
    myth_ok = [r for r in rows if (r.get('myth_status') or '').strip().lower() == 'ok']
    llm_ok = [r for r in rows if (r.get('llm_status') or '').strip().lower() == 'ok']
    eligible = [r for r in rows if (r.get('myth_binary') or '').strip().upper() in {'SAFE', 'UNSAFE'} and (r.get('llm_binary') or '').strip().upper() in {'SAFE', 'UNSAFE'}]

    tp = sum(1 for r in eligible if r['myth_binary'].upper() == 'UNSAFE' and r['llm_binary'].upper() == 'UNSAFE')
    tn = sum(1 for r in eligible if r['myth_binary'].upper() == 'SAFE' and r['llm_binary'].upper() == 'SAFE')
    fp = sum(1 for r in eligible if r['myth_binary'].upper() == 'SAFE' and r['llm_binary'].upper() == 'UNSAFE')
    fn = sum(1 for r in eligible if r['myth_binary'].upper() == 'UNSAFE' and r['llm_binary'].upper() == 'SAFE')

    accuracy = safe_div(tp + tn, len(eligible))
    precision = safe_div(tp, tp + fp)
    recall = safe_div(tp, tp + fn)
    f1 = round(2 * precision * recall / (precision + recall), 4) if (precision + recall) else 0.0

    agree = sum(1 for r in rows if (r.get('myth_llm_agreement') or '').strip().lower() == 'agree')
    agree_eligible = sum(1 for r in rows if (r.get('myth_llm_agreement') or '').strip().lower() in {'agree', 'disagree'})

    summary = {
        'total_contracts': total,
        'compilable_contracts': len(compilable),
        'compile_rate_percent': pct(len(compilable), total),
        'mythril_ok_contracts': len(myth_ok),
        'mythril_ok_rate_percent': pct(len(myth_ok), total),
        'llm_ok_contracts': len(llm_ok),
        'llm_ok_rate_percent': pct(len(llm_ok), total),
        'myth_unsafe_count': sum(1 for r in rows if (r.get('myth_binary') or '').strip().upper() == 'UNSAFE'),
        'myth_unsafe_rate_percent': pct(sum(1 for r in rows if (r.get('myth_binary') or '').strip().upper() == 'UNSAFE'), total),
        'llm_unsafe_count': sum(1 for r in rows if (r.get('llm_binary') or '').strip().upper() == 'UNSAFE'),
        'llm_unsafe_rate_percent': pct(sum(1 for r in rows if (r.get('llm_binary') or '').strip().upper() == 'UNSAFE'), total),
        'agreement_count': agree,
        'agreement_eligible': agree_eligible,
        'agreement_rate_percent': pct(agree, agree_eligible),
        'binary_eval_rows': len(eligible),
        'binary_accuracy': accuracy,
        'binary_precision_unsafe': precision,
        'binary_recall_unsafe': recall,
        'binary_f1_unsafe': f1,
        'tp_unsafe': tp,
        'tn_safe': tn,
        'fp_unsafe': fp,
        'fn_unsafe': fn,
    }

    for label, col in PROMPT_FLAGS:
        c = sum(1 for r in llm_ok if str(r.get(col, '')).strip().lower() == 'true')
        summary[f'llm_flag_{label}_count'] = c
        summary[f'llm_flag_{label}_percent_of_llm_ok'] = pct(c, len(llm_ok))

    return summary


def write_csv(path, fieldnames, rows):
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, 'w', newline='', encoding='utf-8') as f:
        w = csv.DictWriter(f, fieldnames=fieldnames)
        w.writeheader()
        w.writerows(rows)


def main():
    ap = argparse.ArgumentParser(description='Compare multiple prompt-run master datasets in one wide statistics table')
    ap.add_argument('--input', action='append', nargs=2, metavar=('PROMPT_NAME', 'MASTER_CSV'), required=True,
                    help='Add one prompt result set: --input balanced path/to/master_dataset.csv')
    ap.add_argument('--output-dir', default='prompt_comparison_stats', help='Output directory')
    args = ap.parse_args()

    prompt_summaries = {}
    for prompt_name, path in args.input:
        rows = read_csv(path)
        prompt_summaries[prompt_name] = summarize(rows)

    metric_names = []
    seen = set()
    for prompt_name in prompt_summaries:
        for k in prompt_summaries[prompt_name].keys():
            if k not in seen:
                seen.add(k)
                metric_names.append(k)

    wide_rows = []
    prompt_names = [name for name, _ in args.input]
    for metric in metric_names:
        row = {'metric': metric}
        for prompt_name in prompt_names:
            row[prompt_name] = prompt_summaries[prompt_name].get(metric, '')
        wide_rows.append(row)

    outdir = Path(args.output_dir)
    write_csv(outdir / 'prompt_stats_wide.csv', ['metric'] + prompt_names, wide_rows)

    long_rows = []
    for prompt_name in prompt_names:
        for metric, value in prompt_summaries[prompt_name].items():
            long_rows.append({'prompt_name': prompt_name, 'metric': metric, 'value': value})
    write_csv(outdir / 'prompt_stats_long.csv', ['prompt_name', 'metric', 'value'], long_rows)

    print(f'Wrote {outdir / "prompt_stats_wide.csv"}')
    print(f'Wrote {outdir / "prompt_stats_long.csv"}')


if __name__ == '__main__':
    main()
