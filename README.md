<div align="center">

<img src="assets/appare-vestigium-logo.png" alt="Appare Vestigium logo" width="300" />

**Budgeted, traceable repository-context selection for vulnerability detection.**

<p>
  <img src="https://img.shields.io/badge/Status-Local%20Artifact-ff6b35?style=for-the-badge" alt="Status: Local Artifact" />
  <img src="https://img.shields.io/badge/Type-Registered%20Report-7c3aed?style=for-the-badge" alt="Registered Report artifact" />
  <img src="https://img.shields.io/badge/Platform-Python-3776ab?style=for-the-badge&logo=python&logoColor=white" alt="Python" />
  <img src="https://img.shields.io/badge/Python-3.12+-3776ab?style=for-the-badge&logo=python&logoColor=white" alt="Python 3.12 or later" />
  <img src="https://img.shields.io/badge/License-MIT-16a34a?style=for-the-badge" alt="License: MIT" />
</p>

<p>
  <img src="https://skillicons.dev/icons?i=py,pytorch" alt="Python, PyTorch" />
</p>

</div>

## Overview

Appare Vestigium (`raven` 0.1.0) is the local artifact candidate for an MSR 2027 Registered Report. It selects repository context for vulnerability detection under an exact serialized-token budget, then packs that context with a traceable source map. The snapshot holds the implementation, measurement rules, historical synthetic fixtures, and the pilot results cited in the report.

The package is for researchers checking the pilot method, replaying included point estimates, and inspecting the draft Stage-2 contract. It is a local artifact candidate. Public release and DOI deposit are still ahead. Raw source archives, model weights, checkpoints, caches, individual reviewer sheets, and main-study results are outside this tree.

## Repository Layout

```text
git-repo/
├── artifacts/
│   ├── analysis/msr-stage1/          # Planned primary MCC contrast and analytic checks
│   ├── code/raven/                   # Installable raven package
│   ├── configs/pilot/                # Phase YAML and the draft Stage-2 contract
│   ├── data/manifest.csv             # Pinned source archives, licenses, and SHA-256
│   ├── results/diagnostics/          # Synthetic fixtures, audits, three-fold development results
│   ├── results/pilot/d6/             # Historical D6 gate, predictions, and training summaries
│   ├── scripts/p7/                   # Exploratory, evidence, and alignment scripts
│   └── tests/                        # Fixture checks for selectors, packing, and P7 gates
├── tools/                            # Snapshot, pilot replay, archive and model fetch
├── LICENSE                           # MIT
├── pyproject.toml                    # Package metadata; package root is artifacts/code
├── requirements-pilot-local.txt      # Direct pins for the measured pilot stack
├── requirements-pilot-local.lock.txt # Full lock from macOS ARM64, Python 3.12.6
├── SNAPSHOT_SHA256.json              # Local file inventory for this snapshot
└── README.md
```

## Current App Structure

Inside [`artifacts/code/raven/`](./artifacts/code/raven/):

- `cli.py` and `__main__.py` expose `raven <subcommand>` and `python -m raven`. Phases cover inventory and recovery (P2), overlap and splits (P3), pair alignment (P4), unit extraction and review (P5/P5C), packing and leakage probes (P6), and detector, selector, and evidence commands (P7).
- `selectors.py`, `selector_train.py`, `packer.py`, and `encoder.py` implement budgeted evidence selection, matched controls, `raven-pack-v1` serialization, and the pinned CodeT5-small unit encoder.
- `detector.py` and `p7a.py` train and score the pilot detector. Scoring is limited to `pilot_dev`. `confirmatory_reserved` and `external` roles are refused.
- `baselines.py` holds truncation, relevance, MMR, DPP, CPG-slice, and LongCodeZip comparators.
- `context.py`, `analysis.py`, `pairs.py`, `overlap.py`, `inventory.py`, `identities.py`, and `provenance.py` cover unit extraction, the dependency graph, pair alignment, purge and splits, inventory, and snapshot recovery.
- `config.py`, `manifest.py`, and `runlog.py` load YAML, hash the data manifest, and write per-run directories.
- `judge.py`, `leakage.py`, and `p7evidence.py` cover the auxiliary LLM judge, leakage probes, and detector-free evidence checks.
- Phase modules `p2.py` through `p7s4.py` are the command implementations behind the CLI.

Inside [`artifacts/scripts/p7/`](./artifacts/scripts/p7/):

- Exploratory MPS runners, marked-bundle construction, the evidence-first path, and the target-alignment LLM judge.
- These scripts support method inspection. Several still expect signed input bundles and paths from the original working environment.

Inside [`artifacts/analysis/msr-stage1/`](./artifacts/analysis/msr-stage1/):

- `primary_contrast.py` computes the planned AV minus gated-MMR pooled-target MCC contrast.
- `test_primary_contrast.py` checks that analysis on synthetic inputs. It does not load datasets or select a cohort.

Inside [`artifacts/results/`](./artifacts/results/):

- `pilot/d6/` keeps the historical gate, six prediction sets, and training summaries.
- `diagnostics/` keeps the v4 synthetic mechanism fixture, evidence-retention and encoder-window audits, and the three-fold development results. The v4 probe and packer retain the historical behavior with comments and non-module docstrings removed; `comment-trim-provenance.json` records original and current source checksums. Its ninth scenario was added after earlier results were inspected.

## Current Status

Implemented:

- `raven` 0.1.0 CLI for P2–P7, including config checks, manifest verification, packing, selector learning, and the pilot detector gate.
- Budgeted selection with a mandatory target and structural closure. Optional units compete under an exact serialized-token budget. AV and gated MMR share the candidate pool, initial relevance, dependency graph, budget, and detector, and use different selection and packing procedures.
- Primary MCC contrast in `artifacts/analysis/msr-stage1/primary_contrast.py`.
- Archive download and SHA-256 checks (`tools/acquire_data.py`, `raven verify-manifest`) and pinned model download (`tools/download_models.py`).
- Snapshot inventory (`SNAPSHOT_SHA256.json`) and stdlib replay of the six D6 groups plus two pooled out-of-fold MCC point estimates (`tools/verify_pilot.py`).
- Historical D6 result on record: primary reference-view MCC `0.056835` (95% family-bootstrap interval `[-0.007907, 0.114385]`) on 232 records from 69 families. The recorded decision is `restrict`. Source: [`artifacts/results/pilot/d6/gate.json`](./artifacts/results/pilot/d6/gate.json), group `context_dropout/detector/reference`.
- Three-fold development results on record: 758 records from 379 families under `exact_fit` and `llm_expanded_fit`. That run does not change the historical D6 decision. Source: [`artifacts/results/diagnostics/p7-independent-qualification-20261120/v19-fresh-mps-three-fold/summary.json`](./artifacts/results/diagnostics/p7-independent-qualification-20261120/v19-fresh-mps-three-fold/summary.json).
- Focused fixture checks. In the measured macOS ARM64 pilot environment those checks reported 86 passing tests, including regression against 10,368 archived synthetic unit-cost outcomes.
- Final development detector and D7 engineering pilot: the detector completed 195 steps and passed checkpoint reload; the selector pilot used two fit records and one validation record. One of two policy updates had nonzero gradients, and the frozen detector stayed unchanged. Selected logs and summaries are in [`artifacts/results/diagnostics/p7-d7-exploratory-20261121/`](./artifacts/results/diagnostics/p7-d7-exploratory-20261121/). This is an execution check before independent qualification, not a main-study effectiveness result. Model and policy weights are excluded from this snapshot, so archived output hashes referring to them cannot be rechecked here.

Still pending:

- Public release and DOI deposit. In-principle acceptance, if granted, fixes the accepted scientific protocol. Later deviations need a written justification. Code, provenance, and permitted derived data are intended for deposit after acceptance.
- Production end-to-end acquisition, full source qualification, and the remaining Stage-2 exploratory analysis pipeline.
- A frozen detector-qualification protocol, family-separated main cohorts, compute profiles, and experiment manifest before main scoring.
- Draft contract fields still open in [`artifacts/configs/pilot/msr-stage1-draft-manifest.yaml`](./artifacts/configs/pilot/msr-stage1-draft-manifest.yaml): main family count, ethics determination, main pair allocation, reviewer availability for Stage 2, and booked GPU hours. Contract status is `amended-draft-before-main-assessment-qualification-and-resources-open`.
- A clean install on a machine other than the measured macOS ARM64, Python 3.12.6 environment. The lock records that environment only.
- Stage-2 main outcomes and five independently trained main checkpoints. Those results are prospective and are not in this snapshot.
- CI, and the design notes cited by module docstrings (`docs/unit-spec.md` and related files). Those notes are not in this tree.

## Quickstart

Commands assume the current directory is this snapshot root.

### Prerequisites

- Python 3.12 or later. `requires-python` is `>=3.12`. The lock was taken on Python 3.12.6, macOS ARM64.
- `pip` and a virtual environment.
- Network access, and license compliance, only when downloading pinned archives or model revisions.
- `huggingface_hub`, installed from the pilot lock, for `tools/download_models.py`.

Snapshot verification and the MCC point-estimate replay use the Python standard library only.

### Install

Stdlib checks need no install. For the package, tests, and model download:

```bash
python3.12 -m venv .venv
. .venv/bin/activate
python -m pip install -r requirements-pilot-local.lock.txt
python -m pip install --no-deps -e .
```

Core package dependencies declared in `pyproject.toml` are `numpy`, `pandas`, and `pyyaml`. The lock also pins the measured pilot stack, including `torch`, `transformers`, `peft`, `accelerate`, `huggingface-hub`, `sentence-transformers`, `tree-sitter` (JavaScript, TypeScript, PHP), `tiktoken`, `pytest`, and `ruff`.

### Verify

```bash
python tools/snapshot_manifest.py
python tools/verify_pilot.py
```

The first command checks SHA-256 and size for every file listed in `SNAPSHOT_SHA256.json`. Extra files are ignored. The second replays six D6 MCC point estimates and two pooled out-of-fold MCC point estimates from the included predictions. It does not rerun training or bootstrap intervals.

Synthetic and analytic checks, from the activated environment:

```bash
python -m pytest -q artifacts/analysis/msr-stage1/test_primary_contrast.py \
  artifacts/tests/test_selectors.py artifacts/tests/test_selector_train.py
```

`python -m pytest` alone collects `artifacts/tests` (`testpaths` in `pyproject.toml`). The primary-contrast test lives outside that path, so the command above names it explicitly. `ruff` is pinned for development and is not wired to a CI job.

### Run Locally

There is no web server. After the editable install:

```bash
python -m raven --version
python -m raven check-config --config artifacts/configs/pilot/base.yaml
```

`check-config` validates required fields and does not create a run directory. Phase commands (`inventory`, `pack-cells`, `detector-train`, and the rest) need prior run directories and local data. `raven --help` lists them.

Retrieve pinned archives and the two development model revisions when a local copy is required:

```bash
export RAVEN_DATA_ROOT="$PWD/local-data"
export RAVEN_MODEL_CACHE="$PWD/local-models/hub"
python tools/acquire_data.py             # verify local source archives
python tools/acquire_data.py --download  # download missing pinned archives
python tools/download_models.py          # download pinned model revisions
```

Archive versions and checksums are in [`artifacts/data/manifest.csv`](./artifacts/data/manifest.csv). Model revisions pinned in `tools/download_models.py`:

- `Qwen/Qwen2.5-Coder-1.5B` at `df3ce67c0e24480f20468b6ef2894622d69eb73b`
- `Salesforce/codet5-small` at `b1ee9570c289f21b5922b9c768a1ce12957bf968`

`local-data/` and `local-models/` are gitignored. These commands do not rebuild signed inputs and do not rerun the study.

## Useful Docs

Standalone documentation is not in this snapshot. The contract and pins that are present:

- Draft Stage-2 design, controls, and analysis rules: [`artifacts/configs/pilot/msr-stage1-draft-manifest.yaml`](./artifacts/configs/pilot/msr-stage1-draft-manifest.yaml)
- Historical phase configs: [`artifacts/configs/pilot/`](./artifacts/configs/pilot/)
- Source archive pins: [`artifacts/data/manifest.csv`](./artifacts/data/manifest.csv)
- Target-alignment judge prompt: [`artifacts/scripts/p7/target_alignment_llm_judge_prompt.md`](./artifacts/scripts/p7/target_alignment_llm_judge_prompt.md)
- License: [`LICENSE`](./LICENSE)

## CI And Review

CI workflow is not configured yet. This snapshot has no `.github/workflows/` directory.

Local review commands are the snapshot check, `tools/verify_pilot.py`, the focused `pytest` invocation above, and `ruff` against `artifacts/code`, `artifacts/scripts`, and `artifacts/tests`. Ruff excludes `artifacts/scripts/prerequisites` and `artifacts/scripts/compute` when those trees are present, because their published hashes are frozen evidence. Neither tree is in this snapshot.

## Additional Teammate Context

### Project Overview

The installable package lives at `artifacts/code` (`tool.setuptools.package-dir`). The console script is `raven = raven.cli:main`. Package version is `0.1.0`. License is MIT, copyright 2026 Hồng Cúc Lê Thị.

There is no frontend and no hosted service. The runtime is a Python CLI plus batch scripts. Pilot compute notes in `artifacts/configs/pilot/base.yaml` record an MPS device profile. The draft manifest records an H100 40GB plan for Stage 2, with booking still open.

Data pins cover JsVul (Zenodo 10.5281/zenodo.18195839), SecBench.js, and SARD PHP suite 103. SecBench is marked external. Detector training and scoring refuse `external` and `confirmatory_reserved` roles.

Shared measurement rules, as implemented and as recorded for the planned primary comparison:

- **Selection.** The target and its required structural closure are mandatory. Optional units are chosen under an exact serialized-token budget. Matched static controls compare AV with gated subtraction and ungated divisive normalization.
- **Primary comparison.** The planned endpoint is AV minus gated MMR pooled-target MCC at L1. The primary cohort is the intersection of qualified complete pairs that are feasible at every frozen budget. Excluded coverage and larger per-budget cohorts are reported separately. Average paired MCC differences over the five planned detector seeds, then equally across budgets. A 10,000-draw family bootstrap resamples families jointly across twins, methods, budgets, and seeds. Zero-denominator MCC is defined as zero, with a sensitivity check.
- **Pair flip accuracy.** Fraction of complete pairs whose vulnerable revision is predicted positive and whose fixed revision is predicted negative at the frozen threshold. Score ordering within a pair is a separate threshold-free measure.
- **Evidence retention.** Fraction of annotated decisive components present in a serialized pack, over cases with completed annotations. All-components-retained and candidate availability are separate measures. Source maps record spans received. Expert review assigns evidence roles.

`msr-stage1-draft-manifest.yaml` records the remaining qualification, budget, calibration, and fallback rules. Candidate budgets are 512, 1024, 2048, 4096, and 8192. At least three feasible frontier points are required before a budget claim is kept.

### Primary Entry Points

- CLI: [`artifacts/code/raven/cli.py`](./artifacts/code/raven/cli.py)
- Module entry: [`artifacts/code/raven/__main__.py`](./artifacts/code/raven/__main__.py)
- Selectors: [`artifacts/code/raven/selectors.py`](./artifacts/code/raven/selectors.py)
- Packer: [`artifacts/code/raven/packer.py`](./artifacts/code/raven/packer.py)
- Detector role guard: [`artifacts/code/raven/detector.py`](./artifacts/code/raven/detector.py)
- Primary contrast: [`artifacts/analysis/msr-stage1/primary_contrast.py`](./artifacts/analysis/msr-stage1/primary_contrast.py)
- Snapshot check: [`tools/snapshot_manifest.py`](./tools/snapshot_manifest.py)
- Pilot point-estimate replay: [`tools/verify_pilot.py`](./tools/verify_pilot.py)
- Archive fetch: [`tools/acquire_data.py`](./tools/acquire_data.py)
- Model fetch: [`tools/download_models.py`](./tools/download_models.py)
- Draft Stage-2 contract: [`artifacts/configs/pilot/msr-stage1-draft-manifest.yaml`](./artifacts/configs/pilot/msr-stage1-draft-manifest.yaml)
