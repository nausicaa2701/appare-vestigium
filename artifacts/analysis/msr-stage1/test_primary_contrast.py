"""Independent hand-computable fixture and invalid-data guards; no real main outcomes."""
import copy
import importlib.util
from pathlib import Path

import pytest

spec=importlib.util.spec_from_file_location('primary_contrast',Path(__file__).with_name('primary_contrast.py'))
module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)


def fixture():
    samples=[{'sample_id':f'f{f}-{y}','pair_id':f'p{f}','family':f'f{f}','label':y,'dataset':'synthetic-test-only'} for f in range(4) for y in (0,1)]
    meta={'samples':samples,'budgets':[512,1024,2048],'seeds':[0,1,2,3,4],'input_contract_sha256':'fixture'}
    rows=[]
    for s in samples:
        for method in module.METHODS:
            for budget in meta['budgets']:
                for seed in meta['seeds']:
                    prob=.9 if method=='gated_mmr' or s['label'] else .1
                    rows.append({**s,'method':method,'budget':budget,'seed':seed,'prob':prob,'pred':int(prob>=.5),
                                 'threshold':.5,'checkpoint_sha256':f'checkpoint-{seed}','input_contract_sha256':'fixture'})
    return meta,rows


def test_hand_computable_difference_and_degeneracy():
    m,r=fixture();out=module.analyse(m,r,draws=200)
    
    assert out['delta_mcc']==1 and out['ci_low']==out['ci_high']==1
    assert out['undefined_point_evaluations']==15
    assert out['families']==4 and out['pairs']==4


@pytest.mark.parametrize('mutation', ['missing','duplicate','threshold','checkpoint','label','contract','replay'])
def test_rejects_unregistered_population_or_contract_changes(mutation):
    m,r=fixture();r=copy.deepcopy(r)
    if mutation=='missing':r.pop()
    elif mutation=='duplicate':r.append(r[0])
    elif mutation=='threshold':r[-1]['threshold']=.6
    elif mutation=='checkpoint':r[-1]['checkpoint_sha256']='other'
    elif mutation=='label':r[-1]['label']=1-r[-1]['label']
    elif mutation=='contract':r[-1]['input_contract_sha256']='other'
    else:r[-1]['pred']=1-r[-1]['pred']
    with pytest.raises(ValueError):module.analyse(m,r,draws=20)
