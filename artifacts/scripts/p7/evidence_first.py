"""Immutable E0/D3 and detector-free E1/E2 runs. Explicit parents, no 'latest' discovery."""
from __future__ import annotations

import argparse
import json
import shutil
from pathlib import Path

from raven import p7inputs as I
from raven.config import load_config
from raven.runlog import start_run


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--config', required=True)
    ap.add_argument('--stage', choices=['inputs', 'selection'], required=True)
    ap.add_argument('--parent', type=Path)
    ap.add_argument('--supersedes', type=Path)
    args = ap.parse_args()
    cfg = load_config(Path(args.config))
    with start_run(cfg, 'evidence-first-' + args.stage) as run:
        shutil.copyfile(__file__, run.path / 'driver.py')
        decision = Path('docs/p7-evidence-first-decisions-2026-11-17.md')
        shutil.copyfile(decision, run.path / 'decisions.md')
        print('RUN', run.path, flush=True)
        if args.supersedes:
            I.write_json(run.path / 'rerun_lineage.json', {'supersedes': str(args.supersedes),
                'previous_run_sha256': I.dbg.sha_file(args.supersedes / 'run.json'),
                'reason': 'implementation correction; previous artifacts preserved'})
        if args.stage == 'inputs':
            result = I.build(run)
        else:
            if args.parent is None:
                raise ValueError('selection requires an explicit immutable --parent')
            from raven import p7evidence
            result = p7evidence.execute(run, args.parent)
        I.write_json(run.path / 'result.json', result)
        files = {str(p.relative_to(run.path)): I.dbg.sha_file(p) for p in sorted(run.path.rglob('*'))
                 if p.is_file() and p.name not in ('stdout.log', 'stderr.log', 'status.json', 'output_hashes.json')}
        I.write_json(run.path / 'output_hashes.json', files)
        print(json.dumps(result, indent=2), flush=True)
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
