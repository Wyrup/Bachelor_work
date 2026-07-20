#!/usr/bin/env python3
import argparse
import re
from pathlib import Path
import pandas as pd

VULN_COLS = {
    'TP': 'llm_timestamp_dependency',
    'BN': 'llm_block_number_dependency',
    'SE': 'llm_ether_strict_equality',
    'EF': 'llm_ether_frozen',
    'RE': 'llm_reentrancy',
    'OF': 'llm_integer_overflow',
    'DE': 'llm_dangerous_delegatecall',
    'UC': 'llm_unchecked_external_call',
}


def norm_bool(s):
    return (
        s.astype(str)
         .str.strip()
         .str.lower()
         .map({
             'true': True,
             'false': False,
             'yes': True,
             'no': False,
             '1': True,
             '0': False,
         })
         .astype('boolean')
         .fillna(False)
         .astype(bool)
    )


def pct(n, d):
    return round((n / d) * 100, 2) if d else 0.0


def classify_compile_error(text: str) -> str:
    t = str(text or '').lower()
    if not t or t == 'nan':
        return 'unknown'
    if 'source ' in t and 'not found' in t:
        return 'missing_import'
    if 'undeclared identifier' in t or 'identifier not found' in t:
        return 'undeclared_identifier'
    if 'member ' in t and 'not found' in t:
        return 'invalid_member_access'
    if 'built-in binary operator' in t or 'invalid implicit conversion' in t or 'no matching declaration found' in t:
        return 'type_mismatch'
    if 'parsererror' in t or 'expected' in t:
        return 'syntax_error'
    if 'payable' in t:
        return 'payable_misuse'
    if 'warning:' in t and 'error:' not in t:
        return 'warning_only'
    return 'other_compile_error'


def ensure_cols(df):
    needed = [
        'contract_id', 'prompt_id', 'run', 'compiles', 'compile_stderr',
        'myth_predicted_class', 'myth_binary', 'myth_issue_count', 'myth_status', 'myth_seconds',
        'llm_predicted_class', 'llm_binary', 'llm_safe', 'llm_status', 'llm_seconds',
        'generation_seconds', 'myth_llm_agreement'
    ] + list(VULN_COLS.values())
    for c in needed:
        if c not in df.columns:
            df[c] = pd.NA
    return df


def add_derived(df):
    df = df.copy()
    df['compiles_bool'] = norm_bool(df['compiles'])
    df['llm_safe_bool'] = norm_bool(df['llm_safe'])
    for c in VULN_COLS.values():
        df[c] = norm_bool(df[c])
    df['myth_ok'] = df['myth_status'].astype(str).str.lower().eq('ok')
    df['llm_ok'] = df['llm_status'].astype(str).str.lower().eq('ok')
    df['agreement_known'] = df['myth_llm_agreement'].astype(str).str.lower().isin(['agree', 'disagree'])
    df['agreement_yes'] = df['myth_llm_agreement'].astype(str).str.lower().eq('agree')
    df['compile_error_category'] = df['compile_stderr'].apply(classify_compile_error)
    df['myth_binary_norm'] = df['myth_binary'].astype(str).str.upper()
    df['llm_binary_norm'] = df['llm_binary'].astype(str).str.upper()
    df['binary_eval_row'] = df['myth_binary_norm'].isin(['SAFE', 'UNSAFE']) & df['llm_binary_norm'].isin(['SAFE', 'UNSAFE'])
    return df


def summary_table(df, group_col=None):
    rows = []
    groups = [('overall', df)] if group_col is None else list(df.groupby(group_col, dropna=False))
    for key, g in groups:
        total = len(g)
        compilable = int(g['compiles_bool'].sum())
        myth_ok = int(g['myth_ok'].sum())
        llm_ok = int(g['llm_ok'].sum())
        myth_unsafe = int((g['myth_binary_norm'] == 'UNSAFE').sum())
        llm_unsafe = int((g['llm_binary_norm'] == 'UNSAFE').sum())
        agree_known = int(g['agreement_known'].sum())
        agree_yes = int(g['agreement_yes'].sum())
        rows.append({
            group_col or 'scope': key,
            'n_contracts': total,
            'n_compilable': compilable,
            'compile_rate_percent': pct(compilable, total),
            'n_myth_ok': myth_ok,
            'myth_ok_rate_percent': pct(myth_ok, total),
            'n_llm_ok': llm_ok,
            'llm_ok_rate_percent': pct(llm_ok, total),
            'n_myth_unsafe': myth_unsafe,
            'myth_unsafe_rate_percent': pct(myth_unsafe, total),
            'n_llm_unsafe': llm_unsafe,
            'llm_unsafe_rate_percent': pct(llm_unsafe, total),
            'n_agreement_known': agree_known,
            'n_agree': agree_yes,
            'agreement_rate_percent': pct(agree_yes, agree_known),
            'avg_generation_seconds': round(pd.to_numeric(g['generation_seconds'], errors='coerce').mean(), 2),
            'avg_myth_seconds': round(pd.to_numeric(g['myth_seconds'], errors='coerce').mean(), 2),
            'avg_llm_seconds': round(pd.to_numeric(g['llm_seconds'], errors='coerce').mean(), 2),
        })
    return pd.DataFrame(rows)


def compile_error_table(df, group_col=None):
    failed = df[~df['compiles_bool']].copy()
    key = group_col if group_col else 'scope'
    if group_col is None:
        failed['scope'] = 'overall'
    out = (
        failed.groupby([key, 'compile_error_category'])
        .size()
        .reset_index(name='count')
        .sort_values([key, 'count'], ascending=[True, False])
    )
    totals = failed.groupby(key).size().rename('group_total').reset_index()
    out = out.merge(totals, on=key, how='left')
    out['percent_within_failed'] = (out['count'] / out['group_total'] * 100).round(2)
    return out


def vuln_counts_table(df, source='myth', group_col=None):
    label_col = 'myth_predicted_class' if source == 'myth' else 'llm_predicted_class'
    key = group_col if group_col else 'scope'
    work = df.copy()
    if group_col is None:
        work['scope'] = 'overall'
    out = (
        work.groupby([key, label_col])
        .size()
        .reset_index(name='count')
        .sort_values([key, 'count'], ascending=[True, False])
    )
    totals = work.groupby(key).size().rename('group_total').reset_index()
    out = out.merge(totals, on=key, how='left')
    out['percent_of_group'] = (out['count'] / out['group_total'] * 100).round(2)
    return out


def llm_flag_table(df, group_col=None):
    rows = []
    groups = [('overall', df)] if group_col is None else list(df.groupby(group_col, dropna=False))
    for key, g in groups:
        denom = int(g['llm_ok'].sum())
        base = {group_col or 'scope': key, 'llm_ok_rows': denom}
        for short, col in VULN_COLS.items():
            count = int((g.loc[g['llm_ok'], col]).sum())
            base[f'{short}_count'] = count
            base[f'{short}_percent_of_llm_ok'] = pct(count, denom)
        rows.append(base)
    return pd.DataFrame(rows)


def agreement_table(df, group_col=None):
    work = df[df['binary_eval_row']].copy()
    key = group_col if group_col else 'scope'
    if group_col is None:
        work['scope'] = 'overall'
    out = (
        work.groupby([key, 'myth_binary_norm', 'llm_binary_norm'])
        .size()
        .reset_index(name='count')
        .sort_values([key, 'myth_binary_norm', 'llm_binary_norm'])
    )
    return out


def prompt_raw_export(df):
    return df[['contract_id', 'prompt_id', 'run', 'compiles', 'compile_error_category', 'myth_predicted_class', 'myth_binary', 'myth_status', 'llm_predicted_class', 'llm_binary', 'llm_status', 'myth_llm_agreement', 'generation_seconds', 'myth_seconds', 'llm_seconds'] + list(VULN_COLS.values())].copy()


def main():
    ap = argparse.ArgumentParser(description='Generate thesis-ready and raw statistics tables from master_dataset.csv')
    ap.add_argument('master_csv', help='Path to merged/master CSV')
    ap.add_argument('--output-dir', required=True, help='Output directory for tables')
    args = ap.parse_args()

    df = pd.read_csv(args.master_csv)
    df = ensure_cols(df)
    df = add_derived(df)

    outdir = Path(args.output_dir)
    outdir.mkdir(parents=True, exist_ok=True)

    summary_table(df).to_csv(outdir / 'summary_overall.csv', index=False)
    summary_table(df, 'prompt_id').to_csv(outdir / 'summary_by_prompt.csv', index=False)

    compile_error_table(df).to_csv(outdir / 'compile_errors_overall.csv', index=False)
    compile_error_table(df, 'prompt_id').to_csv(outdir / 'compile_errors_by_prompt.csv', index=False)

    vuln_counts_table(df, 'myth').to_csv(outdir / 'myth_class_counts_overall.csv', index=False)
    vuln_counts_table(df, 'myth', 'prompt_id').to_csv(outdir / 'myth_class_counts_by_prompt.csv', index=False)

    vuln_counts_table(df, 'llm').to_csv(outdir / 'llm_class_counts_overall.csv', index=False)
    vuln_counts_table(df, 'llm', 'prompt_id').to_csv(outdir / 'llm_class_counts_by_prompt.csv', index=False)

    llm_flag_table(df).to_csv(outdir / 'llm_flag_counts_overall.csv', index=False)
    llm_flag_table(df, 'prompt_id').to_csv(outdir / 'llm_flag_counts_by_prompt.csv', index=False)

    agreement_table(df).to_csv(outdir / 'agreement_confusion_overall.csv', index=False)
    agreement_table(df, 'prompt_id').to_csv(outdir / 'agreement_confusion_by_prompt.csv', index=False)

    prompt_raw_export(df).to_csv(outdir / 'raw_contract_level_table.csv', index=False)

    readme = outdir / 'README.txt'
    readme.write_text(
        'Generated tables from master_dataset.csv\n\n'
        'summary_overall.csv: overall pipeline summary\n'
        'summary_by_prompt.csv: same metrics split by prompt_id\n'
        'compile_errors_overall.csv / compile_errors_by_prompt.csv: failed compilation categories\n'
        'myth_class_counts_*.csv: Mythril predicted class distribution\n'
        'llm_class_counts_*.csv: LLM predicted class distribution\n'
        'llm_flag_counts_*.csv: LLM vulnerability flag counts among llm_status == ok\n'
        'agreement_confusion_*.csv: SAFE/UNSAFE cross-tab between Mythril and LLM\n'
        'raw_contract_level_table.csv: cleaned contract-level export for manual study\n',
        encoding='utf-8'
    )

    print(f'Wrote tables to: {outdir}')


if __name__ == '__main__':
    main()
