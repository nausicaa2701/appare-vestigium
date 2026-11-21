"""Scenario-only precision planning, no main outcomes. New immutable artifact on every call."""
from __future__ import annotations

import json
from pathlib import Path

import numpy as np

from raven.config import load_config
from raven.p7inputs import write_json, write_rows
from raven.runlog import start_run


def mcc(c):
    tp, fp, tn, fn = np.moveaxis(np.asarray(c, dtype=float), -1, 0)
    denominator = np.sqrt((tp + fp) * (tp + fn) * (tn + fp) * (tn + fn))
    return np.divide(tp * tn - fp * fn, denominator, out=np.zeros_like(tp), where=denominator > 0)


def simulate():
    rng = np.random.default_rng(20261117)
    results = []
    for n in (20, 40, 80, 160):
        for imbalance in (False, True):
            for yield_rate in (1., .7):
                for benefit in (0., .05):
                    widths, covered, realized, true_deltas = [], [], [], []
                    for _ in range(50):
                        sizes = np.clip(rng.lognormal(.7, 1.2, n).astype(int), 1, 16) if imbalance else np.full(n, 2)
                        keep = rng.random(n) < yield_rate
                        sizes = sizes[keep]
                        k = len(sizes)
                        shift = rng.normal(0., .12, k)
                        tpr = np.clip(.7 + shift, .05, .95)
                        fpr = np.clip(.2 + shift, .02, .8)
                        ta = np.clip(tpr + benefit, 0, .98)
                        actual_b, actual_a, expected_b, expected_a = [], [], [], []
                        for size, pb, pa, fp in zip(sizes, tpr, ta, fpr, strict=True):
                            y = np.tile([1, 0], size)
                            ub = rng.random(2 * size)
                            ua = np.where(rng.random(2 * size) < .7, ub, rng.random(2 * size))
                            pred_b = ub < np.where(y, pb, fp)
                            pred_a = ua < np.where(y, pa, fp)
                            def confusion(pred, y=y):
                                return [sum(pred & (y == 1)), sum(pred & (y == 0)), sum(~pred & (y == 0)), sum(~pred & (y == 1))]
                            actual_b.append(confusion(pred_b)); actual_a.append(confusion(pred_a))
                            expected_b.append([size*pb, size*fp, size*(1-fp), size*(1-pb)])
                            expected_a.append([size*pa, size*fp, size*(1-fp), size*(1-pa)])
                        a, b = np.array(actual_a), np.array(actual_b)
                        weights = rng.multinomial(k, np.full(k, 1/k), size=1000)
                        deltas = mcc(weights @ a) - mcc(weights @ b)
                        low, high = np.quantile(deltas, [.025, .975], method='inverted_cdf')
                        truth = float(mcc(np.sum(expected_a, axis=0)) - mcc(np.sum(expected_b, axis=0)))
                        widths.append(float(high-low)); covered.append(low <= truth <= high); realized.append(k); true_deltas.append(truth)
                    results.append({'candidate_families':n,'unequal_family_sizes':imbalance,'qualification_yield':yield_rate,
                        'tpr_improvement_scenario':benefit,'replicates':50,'bootstrap_per_replicate':1000,
                        'median_qualified_families':float(np.median(realized)),'mean_conditional_expected_mcc_delta':float(np.mean(true_deltas)),
                        'median_ci_width':float(np.median(widths)),'p90_ci_width':float(np.quantile(widths,.9)),
                        'fraction_width_le_020':float(np.mean(np.array(widths)<=.20)),'empirical_coverage':float(np.mean(covered))})
    return results


def main():
    cfg=load_config(Path('artifacts/configs/pilot/p7-evidence-first.yaml'))
    with start_run(cfg,'precision-scenarios') as run:
        (run.path/'driver.py').write_bytes(Path(__file__).read_bytes())
        rows=simulate()
        write_rows(run.path/'scenarios.jsonl',rows)
        write_json(run.path/'summary.json',{'seed':20261117,'rows':len(rows),'precision_goal':'95% interval full width <=0.20',
            'limits':['hypothetical complete-pair populations, not an achieved main N or power certification',
                      'single budget/seed simulation; main dependence and graph/evidence strata need empirical qualification',
                      '50 replications only: coverage estimates have substantial Monte Carlo error',
                      'random qualification loss assumes missingness unrelated to outcome; selection bias not solved by CI'],
            'scenarios':rows})
        from raven.p7inputs import dbg
        write_json(run.path/'output_hashes.json',{p.name:dbg.sha_file(p) for p in run.path.iterdir() if p.is_file() and p.name not in {'stdout.log','stderr.log','status.json','output_hashes.json'}})
        print(json.dumps({'run':str(run.path),'scenarios':len(rows)}))


if __name__=='__main__':
    main()
