"""Explicit staged detector rerun on a frozen D3 bundle. No historical workflow fallback."""
from __future__ import annotations

import argparse
import copy
import gc
import json
import math
import subprocess
import sys
import time
from datetime import UTC, datetime
from pathlib import Path

import torch

from raven import detector, p5, p7a, p7debug
from raven import p7inputs as I
from raven.config import config_hash, load_config
from raven.runlog import source_snapshot, start_run


def fingerprint(cfg):
    return {"config_hash": config_hash(cfg), "source": source_snapshot()["source_sha256"],
            "driver": I.dbg.sha_file(Path(__file__)),
            "decision": I.dbg.sha_file(Path('docs/p7-evidence-first-decisions-2026-11-17.md')),
            "bundle": cfg['p7']['detector']['input_bundle']['sha256'],
            "required_checks": p7debug.readiness_fingerprint()}


def verify(record, cfg, kind):
    record=Path(record)
    data=json.loads((record/f'{kind}.json').read_text())
    if not data['passed'] or data['fingerprint'] != fingerprint(cfg):
        raise RuntimeError(f'{kind} is failed or stale')
    for name, sha in data.get('files',{}).items():
        if I.dbg.sha_file(record/name) != sha:
            raise RuntimeError(f'{kind} evidence changed: {name}')
    return data


def run_stage(cfg, command, callback):
    with start_run(cfg,command) as run:
        (run.path/'driver.py').write_bytes(Path(__file__).read_bytes())
        result=callback(run)
        gc.collect()
        if torch.backends.mps.is_available():
            torch.mps.empty_cache()
        I.write_json(run.path/'output_hashes.json',{
            str(p.relative_to(run.path)):I.dbg.sha_file(p) for p in run.path.rglob('*')
            if p.is_file() and p.name not in {'output_hashes.json','stdout.log','stderr.log','status.json'}})
        print(json.dumps({'run':str(run.path),'result':result}),flush=True)
    return run.path,result


def check(run):
    cfg=run.config
    initial=fingerprint(cfg)
    statuses=[]
    commands=[[sys.executable,'-m','pytest','-q'],[sys.executable,'-m','ruff','check','artifacts/code','artifacts/scripts','artifacts/tests']]
    for i,cmd in enumerate(commands):
        with (run.path/f'check-{i}.log').open('w') as log:
            status=subprocess.run(cmd,stdout=log,stderr=subprocess.STDOUT,check=False)
        statuses.append(status.returncode)
    I.load_bundle(cfg,'0',run.path,lambda:p5.load_tokenizer(cfg))
    data={'passed':all(s==0 for s in statuses) and initial==fingerprint(cfg),'fingerprint':initial,
          'statuses':statuses,'files':{f'check-{i}.log':I.dbg.sha_file(run.path/f'check-{i}.log') for i in range(len(commands))}}
    I.write_json(run.path/'readiness.json',data)
    return data


def profile(run):
    cfg=run.config;d=cfg['p7']['detector'];device=cfg['compute']['device']
    roles,texts,_=I.load_bundle(cfg,'0',run.path,lambda:p5.load_tokenizer(cfg))
    if device!='mps' or not torch.backends.mps.is_available():
        raise RuntimeError('registered MPS hardware unavailable; no CPU training fallback')
    
    longest=max(r['tokens'] for r in roles.values())
    ids=[]
    for label in (0,1):
        ids += sorted((s for s,r in roles.items() if r['role']=='fit' and r['label']==label),
                      key=lambda s:(-roles[s]['tokens'],s))[:2]
    
    
    tok=p5.load_tokenizer(cfg)
    def encode(t):
        tokens=tok(t,add_special_tokens=False)['input_ids']
        return tokens+[tok.pad_token_id]*(longest-len(tokens))
    torch.manual_seed(d['train']['seed'])
    det=p7a.load_qwen(cfg,device)
    logs=[];start=time.time()
    items=[p7a.TrainItem(s,roles[s]['label'],[texts[s]['reference']]) for s in ids]
    tc=copy.deepcopy(d['train']);tc['epochs']=3
    result=p7a.train(det,items,encode,tc,device,logs.append,max_steps=3,swap_stop_mib=cfg['compute']['swap_growth_stop_mib'])
    I.write_rows(run.path/'profile_steps.jsonl',logs)
    finite=all(bool(torch.isfinite(t).all()) for t in result['state'].values())
    steps=[]
    rows=I.guarded_rows(cfg)
    for f in ('0','1','2','final'):
        fit=[r for r in rows if p7debug.fold_role(r,f)=='fit'];pos=sum(r['label'] for r in fit);neg=len(fit)-pos
        updates=3*math.ceil(2*max(pos,neg)/tc['effective_batch'])
        steps.append({'fold':f,'variants':len(d['variants']) if f!='final' else 1,'updates_per_cell':updates})
    worst=max((r['step_s'] for r in logs),default=float('inf'))
    estimate=sum(r['variants']*r['updates_per_cell'] for r in steps)*worst/3600
    
    used=0.;ledger=[]
    for status in Path('artifacts/results/pilot/P7').rglob('status.json'):
        ident=status.parent/'run.json'
        if not ident.exists():continue
        try:
            meta=json.loads(ident.read_text());st=json.loads(status.read_text())
            begin=datetime.fromisoformat(meta['timestamp_utc']);end=datetime.fromisoformat(st['finished_utc'])
            hours=max(0.,(end-begin).total_seconds()/3600);used+=hours
            ledger.append({'run':str(status.parent),'hours':hours,'status':st['status']})
        except (ValueError,KeyError):continue
    I.write_rows(run.path/'cumulative_job_ledger.jsonl',ledger)
    deadline=datetime(2026,11,20,11,tzinfo=UTC) 
    calendar=max(0.,(deadline-datetime.now(UTC)).total_seconds()/3600)
    remaining=min(max(0.,216-used),calendar)
    
    data={'passed':result['status']=='completed' and result['steps']==3 and finite and result['gradients_finite'] and estimate*2<remaining,
          'fingerprint':fingerprint(cfg),'max_profile_tokens':longest,'profile_ids':ids,'steps':result['steps'],
          'elapsed_s':time.time()-start,'longest_step_s':worst,'finite':finite,'matrix':steps,
          'train_hours_upper':estimate,'detector_workflow_allowance_hours':estimate*2,
          'historical_P7_cumulative_wall_hours_upper':used,'remaining_envelope_hours':remaining,
          'selector_teacher_budget':'not priced; no D7 launch authorized by this detector-only profile',
          'profile_input':'fit-only source padded to maximum cohort shape; not used for model evaluation',
          'files':{'profile_steps.jsonl':I.dbg.sha_file(run.path/'profile_steps.jsonl')}}
    I.write_json(run.path/'profile.json',data)
    del det,result;gc.collect();torch.mps.empty_cache()
    return data


def main():
    ap=argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--config',required=True,type=Path)
    ap.add_argument('--stage',required=True,choices=['check','profile','smoke','crossfit'])
    ap.add_argument('--readiness',type=Path);ap.add_argument('--profile',type=Path);ap.add_argument('--smoke',type=Path)
    args=ap.parse_args();cfg=load_config(args.config)
    if args.stage=='check':
        _,r=run_stage(cfg,'evidence-readiness',check);return 0 if r['passed'] else 2
    verify(args.readiness,cfg,'readiness')
    if args.stage=='profile':
        _,r=run_stage(cfg,'evidence-profile',profile);return 0 if r['passed'] else 2
    verify(args.profile,cfg,'profile')
    pack=Path('artifacts/results/pilot/P6/runs/20261107T132948Z-raven-pilot-p6-pack-cells-e09f7885')
    
    if args.stage=='smoke':
        smoke=copy.deepcopy(cfg);smoke['p7']['detector']['recovery_smoke']=True
        smoke['p7']['detector']['train']['epochs']=16
        p,full=run_stage(smoke,'detector-train',lambda run:detector.run_train(run,pack,'final','no_dropout'))
        paused_path,paused=run_stage(smoke,'detector-train',lambda run:detector.run_train(run,pack,'final','no_dropout',stop_after=8))
        if paused.get('status')!='paused' or I.dbg.sha_file(Path(paused['resume_path']))!=paused['resume_sha256']:
            raise RuntimeError('pause checkpoint missing or changed')
        resumed_path,resumed=run_stage(smoke,'detector-train',lambda run:detector.run_train(run,pack,'final','no_dropout',resume=Path(paused['resume_path'])))
        same_ids=full['fit_ids']==resumed['fit_ids']
        difference=max(abs(a-b) for a,b in zip(full['probabilities'],resumed['probabilities'],strict=True)) if same_ids else float('inf')
        passed=full['go'] and resumed['go'] and same_ids and difference<=cfg['p7']['detector']['gate']['roundtrip_tolerance']
        def proof(run):
            data={'passed':bool(passed),'fingerprint':fingerprint(cfg),'uninterrupted':str(p),'paused':str(paused_path),
                  'resumed':str(resumed_path),'resume_max_probability_error':difference,'same_fit_ids':same_ids,
                  'files':{str((p/'smoke_summary.json').resolve()):I.dbg.sha_file(p/'smoke_summary.json'),
                           str((paused_path/'paused_summary.json').resolve()):I.dbg.sha_file(paused_path/'paused_summary.json'),
                           str((resumed_path/'smoke_summary.json').resolve()):I.dbg.sha_file(resumed_path/'smoke_summary.json')}}
            I.write_json(run.path/'smoke.json',data)
            return data
        _,r=run_stage(cfg,'evidence-smoke-proof',proof)
        return 0 if r['passed'] else 2
    verify(args.smoke,cfg,'smoke')
    def matrix(workflow):
        paths=[]
        journal={'status':'running','readiness':str(args.readiness),'profile':str(args.profile),'smoke':str(args.smoke),
                 'fingerprint':fingerprint(cfg),'completed':[],'planned_cells':[
                    {'fold':f,'variant':v} for f in ('0','1','2') for v in cfg['p7']['detector']['variants']]}
        I.write_json(workflow.path/'workflow.json',journal)
        for cell in journal['planned_cells']:
            verify(args.readiness,cfg,'readiness');verify(args.profile,cfg,'profile');verify(args.smoke,cfg,'smoke')
            journal['current_cell']=cell;I.write_json(workflow.path/'workflow.json',journal)
            p,r=run_stage(cfg,'detector-train',lambda run,cell=cell:detector.run_train(run,pack,cell['fold'],cell['variant']))
            paths.append(p);journal['completed'].append({**cell,'run':str(p),'steps':r['steps']})
            I.write_json(workflow.path/'workflow.json',journal)
        gate_path,gate=run_stage(cfg,'detector-gate',lambda run:p7a.run_gate(run,paths))
        decision=gate['decisions'][cfg['p7']['detector']['primary_variant']]['decision']
        journal.update(status='completed',gate_run=str(gate_path),primary_decision=decision)
        I.write_json(workflow.path/'workflow.json',journal)
        return {'gate_run':str(gate_path),'primary_decision':decision,'training_runs':list(map(str,paths))}
    _,result=run_stage(cfg,'evidence-crossfit-workflow',matrix)
    return 0 if result['primary_decision']=='go' else 2


if __name__=='__main__':
    raise SystemExit(main())
