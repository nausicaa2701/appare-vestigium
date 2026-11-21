"""Replay archived D6 and three-fold MCC points without dependencies."""
import csv
import json
import math
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

def mcc(rows):
    c = Counter((int(r['label']), int(r['pred'])) for r in rows)
    tp, fn, fp, tn = c[1, 1], c[1, 0], c[0, 1], c[0, 0]
    denominator = (tp + fp) * (tp + fn) * (tn + fp) * (tn + fn)
    return (tp * tn - fp * fn) / math.sqrt(denominator) if denominator else 0.0

gate = json.loads((ROOT / 'artifacts/results/pilot/d6/gate.json').read_text())
groups = {}
for run in sorted((ROOT / 'artifacts/results/pilot/d6').iterdir()):
    if not run.is_dir():
        continue
    info = json.loads((run / 'train_summary.json').read_text())
    for row in csv.DictReader((run / 'predictions.csv').open()):
        if row['role'] == 'assessment':
            groups.setdefault(f"{info['variant']}/{row['model']}/{row['view']}", []).append(row)
if len(groups) != 6:
    raise SystemExit(f'expected six D6 outcome groups, found {len(groups)}')
for name, rows in sorted(groups.items()):
    expected = gate['report'][name]
    actual = mcc(rows)
    if len(rows) != expected['records'] or abs(actual - expected['mcc']) > 1e-12:
        raise SystemExit(f'D6 mismatch: {name}')
    print(f'D6 {name}: {len(rows)} records, MCC {actual:.6f}')
base = ROOT / 'artifacts/results/diagnostics/p7-independent-qualification-20261120/v19-fresh-mps-three-fold'
summary = json.loads((base / 'summary.json').read_text())
for arm in ('exact_fit', 'llm_expanded_fit'):
    rows = json.loads((base / f'{arm}-oof-predictions.json').read_text())
    if len(rows) != 758 or len({r['sample_id'] for r in rows}) != 758:
        raise SystemExit(f'OOF coverage mismatch: {arm}')
    actual = mcc(rows)
    if abs(actual - summary['pooled_oof'][arm]['mcc']) > 1e-12:
        raise SystemExit(f'OOF MCC mismatch: {arm}')
    print(f'OOF {arm}: {len(rows)} records, MCC {actual:.6f}')
print('Point estimates reproduced; bootstrap intervals and retraining are not replayed here.')
