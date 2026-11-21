"""Strict Stage-1 primary MCC analysis. No dataset/model/source loading or cohort selection.

Metadata declares the frozen common cohort, budgets, seeds and pair/family identities.
Predictions CSV must cover its Cartesian grid exactly. Missing rows are errors, not exclusions.
"""
from __future__ import annotations

import argparse
import csv
import hashlib
import json
import random
from collections import Counter
from pathlib import Path

import numpy as np

METHODS = ('appare', 'gated_mmr')


def metric(counts):
    tp, fp, tn, fn = np.moveaxis(np.asarray(counts,dtype=float),-1,0)
    denominator=np.sqrt((tp+fp)*(tp+fn)*(tn+fp)*(tn+fn))
    return np.divide(tp*tn-fp*fn,denominator,out=np.zeros_like(tp),where=denominator>0),denominator==0


def analyse(metadata, rows, draws=10000):
    samples={r['sample_id']:r for r in metadata['samples']}
    if len(samples)!=len(metadata['samples']) or not samples:raise ValueError('missing/duplicate cohort IDs')
    if len({r['dataset'] for r in samples.values()})!=1:raise ValueError('datasets must not be pooled')
    pairs={p:[r for r in samples.values() if r['pair_id']==p] for p in {r['pair_id'] for r in samples.values()}}
    if any(len(p)!=2 or {int(r['label']) for r in p}!={0,1} or len({r['family'] for r in p})!=1 for p in pairs.values()):
        raise ValueError('primary cohort must retain complete opposite-label within-family pairs')
    budgets=metadata['budgets'];seeds=metadata['seeds'];families=sorted({r['family'] for r in samples.values()})
    if len(budgets)<3 or len(set(budgets))!=len(budgets) or len(set(seeds))!=len(seeds):
        raise ValueError('invalid frozen budget/seed grid')
    expected={(s,m,b,e) for s in samples for m in METHODS for b in budgets for e in seeds}
    got=set();thresholds={};checkpoints={};contracts=set()
    counts=np.zeros((2,len(budgets),len(seeds),len(families),4),dtype=np.int64)
    for r in rows:
        sid=r['sample_id'];m=r['method'];b=int(r['budget']);e=int(r['seed']);key=(sid,m,b,e)
        if key not in expected or key in got:raise ValueError('extra/duplicate prediction or undeclared method/configuration')
        got.add(key);meta=samples[sid];y=int(r['label'])
        if y!=int(meta['label']) or r['pair_id']!=meta['pair_id'] or r['family']!=meta['family']:
            raise ValueError('prediction identity differs from the frozen cohort')
        probability=float(r['prob']);threshold=float(r['threshold'])
        if not np.isfinite(probability) or not np.isfinite(threshold) or not 0<=probability<=1:
            raise ValueError('nonfinite or invalid probability/threshold')
        if e in thresholds and thresholds[e]!=threshold:raise ValueError('threshold must be shared across views of a checkpoint')
        if e in checkpoints and checkpoints[e]!=r['checkpoint_sha256']:raise ValueError('methods must share the frozen detector')
        thresholds[e]=threshold;checkpoints[e]=r['checkpoint_sha256'];contracts.add(r['input_contract_sha256'])
        pred=probability>=threshold
        if 'pred' in r and int(r['pred'])!=int(pred):raise ValueError('full-precision CSV replay mismatch')
        index=0 if pred and y else 1 if pred else 3 if y else 2
        counts[METHODS.index(m),budgets.index(b),seeds.index(e),families.index(meta['family']),index]+=1
    if got!=expected:raise ValueError('incomplete common cohort; no silent population changes')
    if len(contracts)!=1 or next(iter(contracts))!=metadata['input_contract_sha256']:
        raise ValueError('mixed input contracts')
    point,undefined=metric(counts.sum(axis=3))
    rng=random.Random(42);weights=np.zeros((draws,len(families)),dtype=np.int64)
    for i in range(draws):
        for f,k in Counter(rng.randrange(len(families)) for _ in families).items():weights[i,f]=k
    boot,degenerate=metric(np.einsum('df,mbsfc->dmbsc',weights,counts,optimize=True))
    contrasts=boot[:,0].mean(axis=(1,2))-boot[:,1].mean(axis=(1,2))
    low,high=np.sort(contrasts)[[int(.025*draws),min(draws-1,int(.975*draws))]]
    delta=float(point[0].mean()-point[1].mean())
    return {'contrast':'appare-minus-gated_mmr','delta_mcc':delta,'ci_low':float(low),'ci_high':float(high),
            'ci_full_width':float(high-low),'precision_goal_full_width':.20,'precision_goal_met':bool(high-low<=.20),
            'cohort_records':len(samples),'pairs':len(pairs),'families':len(families),'budgets':budgets,'seeds':seeds,
            'bootstrap_draws':draws,'bootstrap_seed':42,'aggregation':'pooled-target MCC, then equal mean metrics over paired seeds and budgets',
            'undefined_point_evaluations':int(undefined.sum()),'degenerate_bootstrap_evaluations':int(degenerate.sum()),
            'bootstrap_draws_with_any_degenerate_metric':int(np.any(degenerate,axis=(1,2,3)).sum()),
            'secondary_by_budget':[{'budget':b,'delta_mcc':float(point[0,i].mean()-point[1,i].mean())} for i,b in enumerate(budgets)],
            'interpretation':'estimation; narrow intervals with very few families do not establish population adequacy'}


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--metadata',type=Path,required=True);parser.add_argument('--predictions',type=Path,required=True)
    parser.add_argument('--output',type=Path,required=True);args=parser.parse_args()
    metadata=json.loads(args.metadata.read_text())
    if metadata['seeds']!=[0,1,2,3,4]:raise ValueError('main seed grid differs from registered five-seed rule')
    result=analyse(metadata,list(csv.DictReader(args.predictions.open())))
    args.output.mkdir(parents=True,exist_ok=False)
    for src,name in [(Path(__file__),'analysis.py'),(args.metadata,'metadata.json'),(args.predictions,'predictions.csv')]:
        (args.output/name).write_bytes(src.read_bytes())
    (args.output/'result.json').write_text(json.dumps(result,indent=2,allow_nan=False)+'\n')
    (args.output/'output_hashes.json').write_text(json.dumps({p.name:hashlib.sha256(p.read_bytes()).hexdigest() for p in args.output.iterdir() if p.is_file()},indent=2)+'\n')
    print(json.dumps(result))


if __name__=='__main__':main()
