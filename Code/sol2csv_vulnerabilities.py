import csv
from pathlib import Path

SAFE_ROOT = Path('/home/tim/PycharmProjects/Bachelor_work/Data/Dataset_test/SAFE')
UNSAFE_ROOT = Path('/home/tim/PycharmProjects/Bachelor_work/Data/Dataset_test/UNSAFE')
OUTPUT_CSV = Path('/home/tim/PycharmProjects/Bachelor_work/Data/Dataset_test/master_dataset.csv')


def detect_true_label(file_path: Path, root: Path, binary_label: str) -> str:
    if binary_label == 'SAFE':
        return 'SAFE'
    rel_parts = file_path.relative_to(root).parts
    if len(rel_parts) >= 2:
        return rel_parts[0]
    return 'UNSAFE'


def iter_sol_files(root: Path):
    if not root.exists():
        return
    yield from root.rglob('*.sol')


rows = []

for fp in iter_sol_files(SAFE_ROOT):
    try:
        content = fp.read_text(encoding='utf-8', errors='ignore')
    except Exception:
        content = ''
    rows.append({
        'file_path': str(fp),
        'true_label': 'SAFE',
        'binary_label': 'SAFE',
        'content': content,
    })

for fp in iter_sol_files(UNSAFE_ROOT):
    true_label = detect_true_label(fp, UNSAFE_ROOT, 'UNSAFE')
    try:
        content = fp.read_text(encoding='utf-8', errors='ignore')
    except Exception:
        content = ''
    rows.append({
        'file_path': str(fp),
        'true_label': true_label,
        'binary_label': 'UNSAFE',
        'content': content,
    })

OUTPUT_CSV.parent.mkdir(parents=True, exist_ok=True)
with OUTPUT_CSV.open('w', newline='', encoding='utf-8') as f:
    writer = csv.DictWriter(f, fieldnames=['file_path', 'true_label', 'binary_label', 'content'])
    writer.writeheader()
    writer.writerows(rows)

print(f'Wrote {len(rows)} rows to {OUTPUT_CSV}')