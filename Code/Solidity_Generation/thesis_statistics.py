#!/usr/bin/env python3
import argparse
import csv
from collections import Counter, defaultdict
from pathlib import Path


def read_csv(path):
    with open(path, newline='', encoding='utf-8') as f:
        return list(csv.DictReader(f))


def to_bool_yes(v):
    return str(v).strip().lower() in {'yes', 'true', '1'}


def to_float(v):
    try:
        return float(v)
    except Exception:
        return None


def pct(n, d):
    return round((n / d * 100.0), 2) if d else 0.0


def write_csv(path, fieldnames, rows):
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, 'w', newline='', encoding='utf-8') as f:
        w = csv.DictWriter(f, fieldnames=fieldnames)
        w.writeheader()
        w.writerows(rows)


def binary_confusion(rows):
    labels = ['SAFE', 'UNSAFE']
    matrix = {(a, b): 0 for a in labels for b in labels}
    used = 0
    for r in rows:
        a = (r.get('myth_binary') or '').strip().upper()
        b = (r.get('llm_binary') or '').strip().upper()
        if a in labels and b in labels:
            matrix[(a, b)] += 1
            used += 1
    out = []
    for a in labels:
        row = {'myth_binary': a}
        for b in labels:
            row[b] = matrix[(a, b)]
        out.append(row)
    return out, used


def binary_metrics(rows):
    eligible = [r for r in rows if (r.get('myth_binary') or '').upper() in {'SAFE', 'UNSAFE'} and (r.get('llm_binary') or '').upper() in {'SAFE', 'UNSAFE'}]
    tp = sum(1 for r in eligible if r['myth_binary'].upper() == 'UNSAFE' and r['llm_binary'].upper() == 'UNSAFE')
    tn = sum(1 for r in eligible if r['myth_binary'].upper() == 'SAFE' and r['llm_binary'].upper() == 'SAFE')
    fp = sum(1 for r in eligible if r['myth_binary'].upper() == 'SAFE' and r['llm_binary'].upper() == 'UNSAFE')
    fn = sum(1 for r in eligible if r['myth_binary'].upper() == 'UNSAFE' and r['llm_binary'].upper() == 'SAFE')
    total = len(eligible)
    accuracy = round((tp + tn) / total, 4) if total else 0.0
    precision = round(tp / (tp + fp), 4) if (tp + fp) else 0.0
    recall = round(tp / (tp + fn), 4) if (tp + fn) else 0.0
    f1 = round(2 * precision * recall / (precision + recall), 4) if (precision + recall) else 0.0
    return [{
        'eligible_rows': total,
        'tp_unsafe': tp,
        'tn_safe': tn,
        'fp_unsafe': fp,
        'fn_unsafe': fn,
        'accuracy': accuracy,
        'precision_unsafe': precision,
        'recall_unsafe': recall,
        'f1_unsafe': f1,
    }]


def main():
    ap = argparse.ArgumentParser(description='Generate thesis statistics from master_dataset.csv')
    ap.add_argument('master_csv', help='Path to master_dataset.csv')
    ap.add_argument('--output-dir', default=None, help='Optional output directory')
    args = ap.parse_args()

    rows = read_csv(args.master_csv)
    master_path = Path(args.master_csv)
    output_dir = Path(args.output_dir) if args.output_dir else master_path.parent / 'statistics'
    output_dir.mkdir(parents=True, exist_ok=True)

    total = len(rows)
    compilable_rows = [r for r in rows if to_bool_yes(r.get('compiles'))]
    myth_ok_rows = [r for r in rows if (r.get('myth_status') or '').strip().lower() == 'ok']
    llm_ok_rows = [r for r in rows if (r.get('llm_status') or '').strip().lower() == 'ok']
    agreement_rows = [r for r in rows if (r.get('myth_llm_agreement') or '').strip().lower() in {'agree', 'disagree'}]

    gen_times = [to_float(r.get('generation_seconds')) for r in rows]
    gen_times = [x for x in gen_times if x is not None]
    myth_times = [to_float(r.get('myth_seconds')) for r in myth_ok_rows]
    myth_times = [x for x in myth_times if x is not None]
    llm_times = [to_float(r.get('llm_seconds')) for r in llm_ok_rows]
    llm_times = [x for x in llm_times if x is not None]

    overview = [{
        'total_contracts': total,
        'compilable_contracts': len(compilable_rows),
        'compile_rate_percent': pct(len(compilable_rows), total),
        'non_compilable_contracts': total - len(compilable_rows),
        'mythril_ok_contracts': len(myth_ok_rows),
        'mythril_ok_rate_percent': pct(len(myth_ok_rows), total),
        'llm_ok_contracts': len(llm_ok_rows),
        'llm_ok_rate_percent': pct(len(llm_ok_rows), total),
        'agreement_eligible_contracts': len(agreement_rows),
        'agreement_count': sum(1 for r in agreement_rows if r['myth_llm_agreement'].lower() == 'agree'),
        'agreement_rate_percent': pct(sum(1 for r in agreement_rows if r['myth_llm_agreement'].lower() == 'agree'), len(agreement_rows)),
        'avg_generation_seconds': round(sum(gen_times) / len(gen_times), 2) if gen_times else 0.0,
        'avg_myth_seconds': round(sum(myth_times) / len(myth_times), 2) if myth_times else 0.0,
        'avg_llm_seconds': round(sum(llm_times) / len(llm_times), 2) if llm_times else 0.0,
    }]
    write_csv(output_dir / 'overview_summary.csv', list(overview[0].keys()), overview)

    compile_by_prompt = []
    prompt_groups = defaultdict(list)
    for r in rows:
        prompt_groups[r.get('prompt_id', '')].append(r)
    for prompt_id in sorted(prompt_groups):
        group = prompt_groups[prompt_id]
        comp = sum(1 for r in group if to_bool_yes(r.get('compiles')))
        compile_by_prompt.append({
            'prompt_id': prompt_id,
            'total_contracts': len(group),
            'compilable_contracts': comp,
            'compile_rate_percent': pct(comp, len(group)),
            'avg_generation_seconds': round(sum(x for x in [to_float(r.get('generation_seconds')) for r in group] if x is not None) / max(1, len([x for x in [to_float(r.get('generation_seconds')) for r in group] if x is not None])), 2)
        })
    write_csv(output_dir / 'compile_by_prompt.csv', list(compile_by_prompt[0].keys()) if compile_by_prompt else ['prompt_id'], compile_by_prompt)

    myth_class_counts = Counter((r.get('myth_predicted_class') or '').strip() or 'EMPTY' for r in myth_ok_rows)
    myth_rows = [{'myth_predicted_class': k, 'count': v, 'percent_of_myth_ok': pct(v, len(myth_ok_rows))} for k, v in sorted(myth_class_counts.items())]
    write_csv(output_dir / 'mythril_class_distribution.csv', ['myth_predicted_class', 'count', 'percent_of_myth_ok'], myth_rows)

    llm_class_counts = Counter((r.get('llm_predicted_class') or '').strip() or 'EMPTY' for r in llm_ok_rows)
    llm_rows = [{'llm_predicted_class': k, 'count': v, 'percent_of_llm_ok': pct(v, len(llm_ok_rows))} for k, v in sorted(llm_class_counts.items())]
    write_csv(output_dir / 'llm_class_distribution.csv', ['llm_predicted_class', 'count', 'percent_of_llm_ok'], llm_rows)

    swc_counter = Counter()
    for r in myth_ok_rows:
        swcs = (r.get('myth_raw_swc_ids') or '').strip()
        if swcs:
            for swc in [x.strip() for x in swcs.split(';') if x.strip()]:
                swc_counter[swc] += 1
    swc_rows = [{'swc_id': k, 'count': v, 'percent_of_myth_ok': pct(v, len(myth_ok_rows))} for k, v in sorted(swc_counter.items())]
    write_csv(output_dir / 'swc_distribution.csv', ['swc_id', 'count', 'percent_of_myth_ok'], swc_rows)

    agreement_counter = Counter((r.get('myth_llm_agreement') or '').strip() or 'EMPTY' for r in rows)
    agreement_dist = [{'agreement_label': k, 'count': v, 'percent_of_total': pct(v, total)} for k, v in sorted(agreement_counter.items())]
    write_csv(output_dir / 'agreement_distribution.csv', ['agreement_label', 'count', 'percent_of_total'], agreement_dist)

    conf_rows, eligible_used = binary_confusion(rows)
    write_csv(output_dir / 'binary_confusion_matrix.csv', ['myth_binary', 'SAFE', 'UNSAFE'], conf_rows)
    metrics_rows = binary_metrics(rows)
    metrics_rows[0]['eligible_used_for_confusion'] = eligible_used
    write_csv(output_dir / 'binary_metrics.csv', list(metrics_rows[0].keys()), metrics_rows)

    prompt_compare = []
    for prompt_id in sorted(prompt_groups):
        group = prompt_groups[prompt_id]
        comp_group = [r for r in group if to_bool_yes(r.get('compiles'))]
        myth_unsafe = sum(1 for r in group if (r.get('myth_binary') or '').upper() == 'UNSAFE')
        llm_unsafe = sum(1 for r in group if (r.get('llm_binary') or '').upper() == 'UNSAFE')
        agrees = sum(1 for r in group if (r.get('myth_llm_agreement') or '').lower() == 'agree')
        elig = sum(1 for r in group if (r.get('myth_llm_agreement') or '').lower() in {'agree', 'disagree'})
        prompt_compare.append({
            'prompt_id': prompt_id,
            'total_contracts': len(group),
            'compilable_contracts': len(comp_group),
            'compile_rate_percent': pct(len(comp_group), len(group)),
            'myth_unsafe_count': myth_unsafe,
            'myth_unsafe_rate_percent': pct(myth_unsafe, len(group)),
            'llm_unsafe_count': llm_unsafe,
            'llm_unsafe_rate_percent': pct(llm_unsafe, len(group)),
            'agreement_count': agrees,
            'agreement_eligible': elig,
            'agreement_rate_percent': pct(agrees, elig),
        })
    write_csv(output_dir / 'prompt_comparison.csv', list(prompt_compare[0].keys()) if prompt_compare else ['prompt_id'], prompt_compare)

    compile_error_counter = Counter()
    for r in rows:
        if not to_bool_yes(r.get('compiles')):
            err = (r.get('compile_stderr') or '').lower()
            if 'source ""@openzeppelin' in err or '@openzeppelin' in err:
                compile_error_counter['missing_openzeppelin_import'] += 1
            elif 'different compiler version' in err or 'pragma solidity ^0.5' in err or 'pragma solidity ^0.4' in err:
                compile_error_counter['compiler_version_mismatch'] += 1
            elif 'undeclared identifier' in err:
                compile_error_counter['undeclared_identifier'] += 1
            elif 'identifier already declared' in err:
                compile_error_counter['identifier_already_declared'] += 1
            elif 'expected' in err:
                compile_error_counter['syntax_error'] += 1
            elif 'not found or not visible' in err:
                compile_error_counter['member_not_found_or_not_visible'] += 1
            else:
                compile_error_counter['other_compile_error'] += 1
    compile_error_rows = [{'error_category': k, 'count': v, 'percent_of_non_compilable': pct(v, total - len(compilable_rows))} for k, v in sorted(compile_error_counter.items())]
    write_csv(output_dir / 'compile_error_categories.csv', ['error_category', 'count', 'percent_of_non_compilable'], compile_error_rows)

    llm_flag_cols = [
        ('timestamp_dependency', 'llm_timestamp_dependency'),
        ('block_number_dependency', 'llm_block_number_dependency'),
        ('ether_strict_equality', 'llm_ether_strict_equality'),
        ('ether_frozen', 'llm_ether_frozen'),
        ('reentrancy', 'llm_reentrancy'),
        ('integer_overflow', 'llm_integer_overflow'),
        ('dangerous_delegatecall', 'llm_dangerous_delegatecall'),
        ('unchecked_external_call', 'llm_unchecked_external_call'),
    ]
    llm_flag_rows = []
    for label, col in llm_flag_cols:
        count = sum(1 for r in llm_ok_rows if str(r.get(col, '')).strip().lower() == 'true')
        llm_flag_rows.append({'llm_flag': label, 'count': count, 'percent_of_llm_ok': pct(count, len(llm_ok_rows))})
    write_csv(output_dir / 'llm_flag_distribution.csv', ['llm_flag', 'count', 'percent_of_llm_ok'], llm_flag_rows)

    print(f'Statistics written to: {output_dir}')
    print('Files created:')
    for p in sorted(output_dir.glob('*.csv')):
        print(p.name)


if __name__ == '__main__':
    main()
