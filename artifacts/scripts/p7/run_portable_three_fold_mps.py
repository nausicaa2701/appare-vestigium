"""Three family-disjoint exploratory folds; prior assessment has already been observed."""
from __future__ import annotations

import argparse
import fcntl
import hashlib
import json
import math
import random
from collections import Counter
from pathlib import Path

import torch
from run_exploratory_mps import ARMS, CONFIG, evaluate, load_bundle, run_arm, save_json, sha

from raven.config import load_config
from raven.runlog import config_hash, source_snapshot

ROOT = Path("artifacts/results/diagnostics/p7-independent-qualification-20261120")
BUNDLE = ROOT / "v3-mps-marked-bundle"
PREVIOUS = ROOT / "v20-portable-smoke"
OUT = ROOT / "v20-portable-three-fold"


def rank(namespace, family):
    return hashlib.sha256(f"p7-fold-v1|42|{namespace}|{family}".encode()).hexdigest()


def build_plan(rows):
    families = sorted({r["family"] for r in rows}, key=lambda f: (rank("outer", f), f))
    outer = {family: index % 3 for index, family in enumerate(families)}
    folds = {}
    for fold in range(3):
        pool = [f for f in families if outer[f] != fold]
        calibration = set(sorted(pool, key=lambda f: (rank(f"cal-{fold}", f), f))[:math.ceil(len(pool) * 0.15)])
        roles = {family: "assessment" if outer[family] == fold else
                 "calibration" if family in calibration else "fit" for family in families}
        counts = Counter(roles.values())
        fit_exact = {r["family"] for r in rows if roles[r["family"]] == "fit" and r["strict_fit"]}
        if not all(counts[role] > 1 for role in ("fit", "calibration", "assessment")) or len(fit_exact) < 2:
            raise RuntimeError("insufficient fold families")
        folds[str(fold)] = {"roles": roles, "family_counts": dict(counts), "exact_fit_families": len(fit_exact)}
    return folds


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--execute", action="store_true")
    parser.add_argument("--segment-steps", type=int, default=12)
    args = parser.parse_args()
    if args.segment_steps < 1:
        raise RuntimeError("segment steps must be positive")
    _, rows = load_bundle(BUNDLE)
    cfg = load_config(CONFIG)
    original = Path("artifacts/scripts/p7/run_exploratory_mps.py")
    smoke = json.loads((PREVIOUS / "smoke.json").read_text())
    current_source = source_snapshot()["source_sha256"]
    if (smoke["contract"]["bundle_sha256"] != sha(BUNDLE / "manifest.json")
            or smoke["contract"]["script_sha256"] != sha(original)
            or smoke["contract"]["source_sha256"] != current_source
            or smoke["contract"]["config_sha256"] != config_hash(cfg)):
        raise RuntimeError("previous MPS smoke does not match current source, config or bundle")
    plan = {"scope": "exploratory only; prior assessment was observed; no new D6 gate",
            "bundle_sha256": sha(BUNDLE / "manifest.json"), "source_sha256": current_source,
            "runner_sha256": sha(original), "driver_sha256": sha(Path(__file__)), "config_sha256": config_hash(cfg),
            "seed": 42, "fold_rule": "hash-ordered families round-robin; 15% hash-ordered remaining families calibration",
            "arms": list(ARMS), "epochs": cfg["p7"]["detector"]["train"]["epochs"],
            "segment_steps": args.segment_steps, "folds": build_plan(rows)}
    overview = {k: v for k, v in plan.items() if k != "folds"}
    overview["folds"] = {f: {k: v for k, v in data.items() if k != "roles"} for f, data in plan["folds"].items()}
    print(json.dumps(overview, indent=2), flush=True)
    if not args.execute:
        return
    if not torch.backends.mps.is_available():
        raise RuntimeError("MPS unavailable; no fallback")
    OUT.mkdir(parents=True, exist_ok=True)
    with (PREVIOUS / "workflow.lock").open("a") as shared_lock, (ROOT / "v4-mps-exploratory-three-fold/workflow.lock").open("a") as debug_lock, (OUT / "workflow.lock").open("a") as lock:
        fcntl.flock(shared_lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        fcntl.flock(debug_lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        plan_path = OUT / "plan.json"
        if plan_path.exists() and json.loads(plan_path.read_text()) != plan:
            raise RuntimeError("fold plan differs; refusing to resume")
        if not plan_path.exists():
            save_json(plan_path, plan)
        for fold, data in plan["folds"].items():
            fold_out = OUT / f"fold-{fold}"
            fold_out.mkdir(exist_ok=True)
            fold_rows = [{**r, "role": data["roles"][r["family"]]} for r in rows]
            if (fold_out / "evaluation.json").exists():
                continue
            for arm in ARMS:
                print(f"fold {fold}: {arm}", flush=True)
                run_arm(arm, fold_rows, BUNDLE, fold_out, cfg, plan["bundle_sha256"], current_source, args.segment_steps)
            marker = fold_out / "evaluation-started.json"
            if marker.exists():
                raise RuntimeError(f"fold {fold} evaluation previously started; inspect before retry")
            save_json(marker, {"plan_sha256": sha(plan_path), "fold": fold})
            evaluate(fold_rows, BUNDLE, fold_out, cfg)
        result = {"scope": plan["scope"], "folds": {}, "plan_sha256": sha(plan_path)}
        oof = {arm: [] for arm in ARMS}
        for fold in plan["folds"]:
            folder = OUT / f"fold-{fold}"
            evaluation = json.loads((folder / "evaluation.json").read_text())
            result["folds"][fold] = {"evaluation_sha256": sha(folder / "evaluation.json"), **evaluation}
            for arm in ARMS:
                path = folder / f"{arm}-predictions.json"
                if sha(path) != evaluation["arms"][arm]["predictions_sha256"]:
                    raise RuntimeError("fold prediction hash mismatch")
                oof[arm].extend(r for r in json.loads(path.read_text()) if r["role"] == "assessment")
        from raven.p7a import family_bootstrap_mcc

        result["pooled_oof"] = {}
        for arm, predictions in oof.items():
            if len(predictions) != len(rows) or len({r["sample_id"] for r in predictions}) != len(rows):
                raise RuntimeError("OOF coverage differs from the bundle")
            save_json(OUT / f"{arm}-oof-predictions.json", predictions)
            result["pooled_oof"][arm] = {**family_bootstrap_mcc(predictions, 10000, int(cfg["seed"])),
                                         "predictions_sha256": sha(OUT / f"{arm}-oof-predictions.json")}
        left, right = ({r["sample_id"]: r for r in oof[arm]} for arm in ARMS)
        groups = {}
        for sid, row in left.items():
            groups.setdefault(row["family"], []).append(sid)
        keys = sorted(groups)

        def mcc(ids, arm):
            from raven.p7a import mcc as metric

            vals = [arm[sid] for sid in ids]
            return metric(sum(r["pred"] == 1 and r["label"] == 1 for r in vals),
                          sum(r["pred"] == 1 and r["label"] == 0 for r in vals),
                          sum(r["pred"] == 0 and r["label"] == 0 for r in vals),
                          sum(r["pred"] == 0 and r["label"] == 1 for r in vals))

        rng = random.Random(int(cfg["seed"]))
        diffs = []
        for _ in range(10000):
            sampled = [sid for _ in keys for sid in groups[rng.choice(keys)]]
            diffs.append(mcc(sampled, right) - mcc(sampled, left))
        diffs.sort()
        result["paired_oof_mcc_difference"] = {"estimate": mcc(list(left), right) - mcc(list(left), left),
                                                "ci_low": diffs[250], "ci_high": diffs[9750], "draws": 10000}
        save_json(OUT / "summary.json", result)
        print("three-fold exploratory comparison completed", flush=True)


if __name__ == "__main__":
    main()
