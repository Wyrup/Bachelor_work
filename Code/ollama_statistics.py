import pandas as pd
from pathlib import Path
from sklearn.metrics import accuracy_score, precision_recall_fscore_support, confusion_matrix


def compute_statistics(input_dir: Path, output_dir: Path = None):
    """
    Génère les statistiques à partir des fichiers CSV générés par ollama_batch.py

    Args:
        input_dir: Dossier contenant les fichiers ollama_batch_results_*.csv
        output_dir: Dossier de sortie pour les statistiques (par défaut: input_dir/stats)
    """
    INPUT_DIR = Path(input_dir)

    if output_dir is None:
        OUTPUT_DIR = INPUT_DIR / 'stats'
    else:
        OUTPUT_DIR = Path(output_dir)

    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

    csv_files = sorted(INPUT_DIR.glob('ollama_batch_results_*.csv'))

    if not csv_files:
        print(f"  Aucun fichier CSV trouvé dans {INPUT_DIR}")
        return False

    print(f" Traitement de {len(csv_files)} fichier(s) CSV...")

    dfs = []
    for f in csv_files:
        df = pd.read_csv(f)
        if 'true_label' not in df.columns:
            label = f.stem.replace('ollama_batch_results_', '')
            df['true_label'] = label
        dfs.append(df)

    data = pd.concat(dfs, ignore_index=True)
    data = data[data['status'] == 'ok'].copy()

    if len(data) == 0:
        print("  Aucune donnée valide (status == 'ok')")
        return False

    bool_cols = [
        'timestamp_dependency',
        'block_number_dependency',
        'ether_strict_equality',
        'ether_frozen',
        'reentrancy',
        'integer_overflow',
        'dangerous_delegatecall',
        'unchecked_external_call',
        'safe',
    ]

    for c in bool_cols:
        if c in data.columns:
            data[c] = data[c].astype(str).str.lower().map({'true': True, 'false': False}).fillna(False)

    vuln_map = {
        'BN': 'block_number_dependency',
        'DE': 'dangerous_delegatecall',
        'EF': 'ether_frozen',
        'SE': 'ether_strict_equality',
        'OF': 'integer_overflow',
        'RE': 'reentrancy',
        'TP': 'timestamp_dependency',
        'UC': 'unchecked_external_call',
    }

    # 1) Binary evaluation: SAFE vs UNSAFE
    data['true_binary'] = data['true_label'].apply(lambda x: 'SAFE' if x == 'SAFE' else 'UNSAFE')

    def pred_binary(row):
        vuln_pred = any(bool(row[c]) for c in vuln_map.values())
        safe_pred = bool(row.get('safe', False))
        if vuln_pred:
            return 'UNSAFE'
        if safe_pred:
            return 'SAFE'
        return 'UNSAFE'

    data['pred_binary'] = data.apply(pred_binary, axis=1)

    binary_labels = ['SAFE', 'UNSAFE']
    b_acc = accuracy_score(data['true_binary'], data['pred_binary'])
    b_prec, b_rec, b_f1, b_sup = precision_recall_fscore_support(
        data['true_binary'], data['pred_binary'], labels=binary_labels, zero_division=0
    )

    binary_metrics = pd.DataFrame({
        'label': binary_labels,
        'precision': b_prec,
        'recall': b_rec,
        'f1': b_f1,
        'support': b_sup,
    })
    binary_metrics.to_csv(OUTPUT_DIR / 'binary_metrics.csv', index=False)

    binary_summary = pd.DataFrame([{
        'accuracy': b_acc,
        'macro_f1': binary_metrics['f1'].mean(),
        'n_rows': len(data)
    }])
    binary_summary.to_csv(OUTPUT_DIR / 'binary_summary.csv', index=False)

    binary_cm = confusion_matrix(data['true_binary'], data['pred_binary'], labels=binary_labels)
    pd.DataFrame(binary_cm, index=binary_labels, columns=binary_labels).to_csv(
        OUTPUT_DIR / 'binary_confusion_matrix.csv')

    # 2) One-vs-rest evaluation for each vulnerability
    rows = []
    for label, col in vuln_map.items():
        subset = data[data['true_label'].isin([label, 'SAFE'])].copy()

        if len(subset) == 0:
            print(f" Pas de données pour {label}, ignoré")
            continue

        subset['true_onevsrest'] = subset['true_label'].apply(lambda x: label if x == label else 'NOT_' + label)
        subset['pred_onevsrest'] = subset[col].apply(lambda x: label if bool(x) else 'NOT_' + label)

        labels_eval = [label, 'NOT_' + label]
        acc = accuracy_score(subset['true_onevsrest'], subset['pred_onevsrest'])
        prec, rec, f1, sup = precision_recall_fscore_support(
            subset['true_onevsrest'], subset['pred_onevsrest'], labels=labels_eval, zero_division=0
        )

        rows.append({
            'label': label,
            'positive_class_precision': prec[0],
            'positive_class_recall': rec[0],
            'positive_class_f1': f1[0],
            'accuracy': acc,
            'support_positive': int(sup[0]),
            'support_negative': int(sup[1]),
        })

    one_vs_rest = pd.DataFrame(rows)
    if len(one_vs_rest) == 0:
        print("  Aucune donnée one-vs-rest, création d'un DataFrame vide")
        one_vs_rest = pd.DataFrame(
            columns=['label', 'positive_class_precision', 'positive_class_recall', 'positive_class_f1', 'accuracy',
                     'support_positive', 'support_negative'])

    one_vs_rest.to_csv(OUTPUT_DIR / 'one_vs_rest_metrics.csv', index=False)

    # 3) Strict multiclass evaluation (single-label only, MULTI when several predicted)
    def pred_strict_multiclass(row):
        active = [lbl for lbl, col in vuln_map.items() if bool(row[col])]
        if len(active) == 0:
            return 'SAFE'
        if len(active) == 1:
            return active[0]
        return 'MULTI'

    data['pred_strict_multiclass'] = data.apply(pred_strict_multiclass, axis=1)
    multiclass_labels = ['SAFE', 'BN', 'DE', 'EF', 'OF', 'RE', 'SE', 'TP', 'UC', 'MULTI']

    mc_prec, mc_rec, mc_f1, mc_sup = precision_recall_fscore_support(
        data['true_label'], data['pred_strict_multiclass'], labels=multiclass_labels, zero_division=0
    )
    multiclass_metrics = pd.DataFrame({
        'label': multiclass_labels,
        'precision': mc_prec,
        'recall': mc_rec,
        'f1': mc_f1,
        'support': mc_sup,
    })
    multiclass_metrics.to_csv(OUTPUT_DIR / 'strict_multiclass_metrics.csv', index=False)

    mc_acc = accuracy_score(data['true_label'], data['pred_strict_multiclass'])
    pd.DataFrame([{
        'accuracy': mc_acc,
        'macro_f1_excluding_multi': multiclass_metrics[multiclass_metrics['label'] != 'MULTI']['f1'].mean(),
        'n_rows': len(data)
    }]).to_csv(OUTPUT_DIR / 'strict_multiclass_summary.csv', index=False)

    pd.DataFrame(
        confusion_matrix(data['true_label'], data['pred_strict_multiclass'], labels=multiclass_labels),
        index=multiclass_labels,
        columns=multiclass_labels,
    ).to_csv(OUTPUT_DIR / 'strict_multiclass_confusion_matrix.csv')

    print(f" Statistiques sauvegardées dans: {OUTPUT_DIR}")
    return True


if __name__ == "__main__":
    # Usage direct (legacy support)
    import sys

    if len(sys.argv) > 1:
        input_path = Path(sys.argv[1])
        output_path = Path(sys.argv[2]) if len(sys.argv) > 2 else None
        compute_statistics(input_path, output_path)
    else:
        # Comportement par défaut si exécuté directement
        default_input = Path('~/PycharmProjects/Bachelor_work/ollama_outputs/qwen2.5-coder:7b')
        compute_statistics(default_input)