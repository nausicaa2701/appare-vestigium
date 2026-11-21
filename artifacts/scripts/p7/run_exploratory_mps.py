"""Run a resumable, two-arm exploratory comparison on a pinned marked bundle."""
from __future__ import annotations

import argparse
import fcntl
import hashlib
import json
import math
import random
import sys
from pathlib import Path

import torch
from sklearn.metrics import roc_auc_score

from raven import p5, p7a
from raven.config import load_config
from raven.runlog import config_hash, source_snapshot

CONFIG = Path("artifacts/configs/pilot/p7-epoch6-qualification.yaml")
ARMS = ("exact_fit", "llm_expanded_fit")


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def save_json(path, obj):
    temp = path.with_suffix(path.suffix + ".tmp")
    temp.write_text(json.dumps(obj, indent=2, sort_keys=True) + "\n")
    temp.replace(path)


def finite_tree(value):
    if isinstance(value, torch.Tensor):
        return bool(torch.isfinite(value).all())
    if isinstance(value, dict):
        return all(finite_tree(v) for v in value.values())
    if isinstance(value, (list, tuple)):
        return all(finite_tree(v) for v in value)
    return True


def load_bundle(bundle):
    manifest = json.loads((bundle / "manifest.json").read_text())
    if manifest.get("schema") != "exploratory-marked-v1":
        raise RuntimeError("unexpected bundle schema")
    for name, expected in manifest["files"].items():
        path = (bundle / name).resolve()
        if not path.is_relative_to(bundle.resolve()) or not path.is_file() or sha(path) != expected:
            raise RuntimeError(f"bundle artifact changed: {name}")
    rows = [json.loads(line) for line in (bundle / "cohort.jsonl").read_text().splitlines()]
    if len({r["sample_id"] for r in rows}) != len(rows):
        raise RuntimeError("duplicate sample ID")
    families = {}
    pairs = {}
    for row in rows:
        if row["role"] not in {"fit", "calibration", "assessment"} or row["label"] not in {0, 1}:
            raise RuntimeError("invalid role or label")
        if row["family"] in families and families[row["family"]] != row["role"]:
            raise RuntimeError("family leaks across roles")
        families[row["family"]] = row["role"]
        pairs.setdefault(row["pair_id"], []).append(row)
        if manifest["files"].get(row["pack"]) != row["pack_sha256"] or not 0 < row["tokens"] <= manifest["budget"]:
            raise RuntimeError("pack missing from bundle inventory")
    if any(len(v) != 2 or {r["label"] for r in v} != {0, 1} or len({r["family"] for r in v}) != 1
           or len({r["role"] for r in v}) != 1 or len({r["strict_fit"] for r in v}) != 1 for v in pairs.values()):
        raise RuntimeError("pair integrity failure")
    return manifest, rows


def run_arm(arm, rows, bundle, out, cfg, bundle_sha, source_sha, segment_steps):
    selected = sorted((r for r in rows if r["role"] == "fit" and (arm != "exact_fit" or r["strict_fit"])),
                      key=lambda r: r["sample_id"])
    if {r["label"] for r in selected} != {0, 1}:
        raise RuntimeError("fit requires both classes")
    tok = p5.load_tokenizer(cfg)
    items = []
    for r in selected:
        text = (bundle / r["pack"]).read_bytes().decode("utf-8")
        if p5.count_tokens(tok, text) != r["tokens"]:
            raise RuntimeError("tokenizer differs from marked bundle")
        items.append(p7a.TrainItem(r["sample_id"], r["label"], [text]))
    contract = {"arm": arm, "bundle_sha256": bundle_sha, "source_sha256": source_sha,
                "fit_ids": [r["sample_id"] for r in selected], "train": cfg["p7"]["detector"]["train"],
                "tokenizer_revision": cfg["tokenizer_revision"], "device": "mps"}
    checkpoint = out / f"{arm}-resume.pt"
    finished = out / f"{arm}-finished.json"
    if finished.exists():
        data = json.loads(finished.read_text())
        if data["contract"] != contract or sha(checkpoint) != data["checkpoint_sha256"]:
            raise RuntimeError("completed checkpoint contract mismatch")
        return
    state = None
    if checkpoint.exists():
        if not checkpoint.with_suffix(".sha256").exists() or sha(checkpoint) != checkpoint.with_suffix(".sha256").read_text().strip():
            raise RuntimeError("checkpoint digest mismatch")
        saved = torch.load(checkpoint, map_location="cpu", weights_only=True)
        if saved["contract"] != contract:
            raise RuntimeError("resume contract differs")
        state = saved["training"]
    torch.manual_seed(int(cfg["p7"]["detector"]["train"]["seed"]))
    torch.mps.set_per_process_memory_fraction(float(cfg["compute"]["mps_memory_fraction"]))
    model = p7a.load_qwen(cfg, "mps")
    log_path = out / f"{arm}-train.jsonl"
    while True:
        if source_snapshot()["source_sha256"] != source_sha:
            raise RuntimeError("production source changed during training")
        stop = (state["step"] if state else 0) + segment_steps
        with log_path.open("a") as log:
            def record(row):
                log.write(json.dumps(row) + "\n")
                log.flush()
                if not math.isfinite(row["swap_mib"]):
                    raise RuntimeError("swap monitoring became unavailable")

            result = p7a.train(model, items, lambda t: tok(t, add_special_tokens=False)["input_ids"],
                               cfg["p7"]["detector"]["train"], "mps", record, resume=state, stop_after=stop,
                               swap_stop_mib=cfg["compute"]["swap_growth_stop_mib"])
        state = {"state": result["state"], "optimizer": result["optimizer"], "step": result["steps"],
                 "torch_rng": result["torch_rng"], "mps_rng": result["mps_rng"]}
        if not finite_tree(state["state"]) or not finite_tree(state["optimizer"]):
            raise FloatingPointError("nonfinite model or optimizer checkpoint")
        tmp = checkpoint.with_suffix(".tmp")
        torch.save({"contract": contract, "training": state}, tmp)
        tmp.replace(checkpoint)
        checkpoint.with_suffix(".sha256").write_text(sha(checkpoint) + "\n")
        if result["status"] == "stopped_swap_guard":
            raise RuntimeError("swap guard stopped training; checkpoint saved")
        if result["steps"] == result["planned_steps"]:
            save_json(finished, {"contract": contract, "checkpoint_sha256": sha(checkpoint),
                                 "steps": result["steps"], "planned_steps": result["planned_steps"]})
            break
        if result["status"] != "paused" or not result["losses_finite"] or not result["gradients_finite"]:
            raise RuntimeError("training did not complete a finite segment")
    del model
    torch.mps.empty_cache()


def evaluate(rows, bundle, out, cfg):
    tok = p5.load_tokenizer(cfg)
    encode = lambda text: tok(text, add_special_tokens=False)["input_ids"]
    results, by_arm = {}, {}
    for arm in ARMS:
        finished = json.loads((out / f"{arm}-finished.json").read_text())
        path = out / f"{arm}-resume.pt"
        if sha(path) != finished["checkpoint_sha256"]:
            raise RuntimeError("checkpoint changed before evaluation")
        saved = torch.load(path, map_location="cpu", weights_only=True)
        model = p7a.load_qwen(cfg, "mps")
        p7a.load_trainable(model, saved["training"]["state"])
        scored = {}
        for role in ("calibration", "assessment"):
            subset = sorted((r for r in rows if r["role"] == role), key=lambda r: r["sample_id"])
            if not subset or {r["label"] for r in subset} != {0, 1}:
                raise RuntimeError(f"{role} requires both classes")
            probs = p7a.score(model, [(bundle / r["pack"]).read_bytes().decode("utf-8") for r in subset], encode, "mps")
            if any(not math.isfinite(p) for p in probs):
                raise RuntimeError("nonfinite score")
            scored[role] = [(r, p) for r, p in zip(subset, probs, strict=True)]
        threshold = p7a.select_threshold([p for _, p in scored["calibration"]], [r["label"] for r, _ in scored["calibration"]])["threshold"]
        predictions = [{"sample_id": r["sample_id"], "family": r["family"], "role": role, "label": r["label"],
                        "prob": p, "threshold": threshold, "pred": int(p >= threshold)}
                       for role, entries in scored.items() for r, p in entries]
        assessment = [r for r in predictions if r["role"] == "assessment"]
        metrics = p7a.family_bootstrap_mcc(assessment, 10000, int(cfg["seed"]))
        metrics["auroc"] = float(roc_auc_score([r["label"] for r in assessment], [r["prob"] for r in assessment]))
        metrics["confusion"] = list(p7a.confusion([r["prob"] for r in assessment], [r["label"] for r in assessment], threshold))
        save_json(out / f"{arm}-predictions.json", predictions)
        by_arm[arm] = {r["sample_id"]: r for r in assessment}
        results[arm] = {"threshold": threshold, "assessment": metrics,
                        "predictions_sha256": sha(out / f"{arm}-predictions.json")}
        del model
        torch.mps.empty_cache()
    left, right = (by_arm[arm] for arm in ARMS)
    if set(left) != set(right):
        raise RuntimeError("assessment IDs differ between arms")
    families = sorted({r["family"] for r in left.values()})
    groups = {f: [sid for sid, r in left.items() if r["family"] == f] for f in families}

    def mcc_for(ids, arm):
        vals = [arm[sid] for sid in ids]
        tp = sum(r["pred"] == 1 and r["label"] == 1 for r in vals)
        fp = sum(r["pred"] == 1 and r["label"] == 0 for r in vals)
        tn = sum(r["pred"] == 0 and r["label"] == 0 for r in vals)
        fn = sum(r["pred"] == 0 and r["label"] == 1 for r in vals)
        return p7a.mcc(tp, fp, tn, fn)

    rng = random.Random(int(cfg["seed"]))
    deltas = []
    for _ in range(10000):
        draw = [rng.choice(families) for _ in families]
        ids = [sid for family in draw for sid in groups[family]]
        deltas.append(mcc_for(ids, right) - mcc_for(ids, left))
    deltas.sort()
    ids = list(left)
    save_json(out / "evaluation.json", {"scope": "exploratory; no change to historical D6 gate", "arms": results,
              "paired_mcc_difference": {"estimate": mcc_for(ids, right) - mcc_for(ids, left),
                                        "ci_low": deltas[250], "ci_high": deltas[9750], "draws": 10000}})


def smoke(rows, bundle, out, cfg, summary):
    tok = p5.load_tokenizer(cfg)
    result = {}
    for arm in ARMS:
        fit = sorted((r for r in rows if r["role"] == "fit" and (arm != "exact_fit" or r["strict_fit"])),
                     key=lambda r: (-r["tokens"], r["sample_id"]))
        batch = int(cfg["p7"]["detector"]["train"]["effective_batch"])
        selected = [r for label in (0, 1) for r in [x for x in fit if x["label"] == label][:batch // 2]]
        if len(selected) != batch:
            raise RuntimeError("insufficient fit records for the full smoke batch")
        items = [p7a.TrainItem(r["sample_id"], r["label"], [(bundle / r["pack"]).read_bytes().decode("utf-8")]) for r in selected]
        if any(p5.count_tokens(tok, item.texts[0]) != row["tokens"] for item, row in zip(items, selected, strict=True)):
            raise RuntimeError("smoke inputs differ from pinned token counts")
        torch.manual_seed(int(cfg["p7"]["detector"]["train"]["seed"]))
        torch.mps.set_per_process_memory_fraction(float(cfg["compute"]["mps_memory_fraction"]))
        model = p7a.load_qwen(cfg, "mps")
        logs = []
        train = p7a.train(model, items, lambda text: tok(text, add_special_tokens=False)["input_ids"],
                          cfg["p7"]["detector"]["train"], "mps", logs.append, max_steps=1,
                          swap_stop_mib=cfg["compute"]["swap_growth_stop_mib"])
        if (train["status"] != "completed" or train["steps"] != 1 or not train["losses_finite"]
                or not train["gradients_finite"] or not all(math.isfinite(row["swap_mib"]) for row in logs)):
            raise RuntimeError(f"{arm} smoke failed")
        result[arm] = {"sample_ids": [r["sample_id"] for r in selected], "logs": logs}
        del model, train
        torch.mps.empty_cache()
    out.mkdir(parents=True, exist_ok=True)
    path = out / "smoke.json"
    if path.exists():
        raise RuntimeError("smoke result already exists")
    save_json(path, {"contract": summary, "scope": "fit-only one-step smoke; no assessment", "arms": result})
    print(json.dumps({"smoke": str(path), "status": "completed"}), flush=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--bundle", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--execute", action="store_true")
    parser.add_argument("--smoke", action="store_true")
    parser.add_argument("--segment-steps", type=int, default=12)
    args = parser.parse_args()
    if args.segment_steps < 1:
        raise SystemExit("segment steps must be positive")
    manifest, rows = load_bundle(args.bundle)
    cfg = load_config(CONFIG)
    if manifest["tokenizer_revision"] != cfg["tokenizer_revision"]:
        raise RuntimeError("tokenizer revision differs")
    summary = {"mode": "exploratory", "bundle_sha256": sha(args.bundle / "manifest.json"),
               "source_sha256": source_snapshot()["source_sha256"], "script_sha256": sha(Path(__file__)),
               "config_sha256": config_hash(cfg),
               "train_config": cfg["p7"]["detector"]["train"], "pair_counts": manifest["pair_counts"],
               "arms": {"exact_fit": sum(r["role"] == "fit" and r["strict_fit"] for r in rows),
                        "llm_expanded_fit": sum(r["role"] == "fit" for r in rows)},
               "execution": "MPS", "segment_steps": args.segment_steps}
    print(json.dumps(summary, indent=2), flush=True)
    if args.execute and args.smoke:
        raise SystemExit("select either --smoke or --execute")
    if not args.execute and not args.smoke:
        return
    if not torch.backends.mps.is_available():
        raise RuntimeError("MPS unavailable; no device fallback")
    if not math.isfinite(p7a._swap_mib()):
        raise RuntimeError("swap monitoring unavailable; cannot safely run MPS")
    if args.smoke:
        smoke(rows, args.bundle, args.output, cfg, summary)
        return
    args.output.mkdir(parents=True, exist_ok=True)
    smoke_path = args.output / "smoke.json"
    if not smoke_path.is_file() or json.loads(smoke_path.read_text()).get("contract") != summary:
        raise RuntimeError("matching two-arm fit-only smoke is required before full execution")
    contract = args.output / "contract.json"
    if contract.exists() and json.loads(contract.read_text()) != summary:
        raise RuntimeError("existing run contract differs")
    if not contract.exists():
        save_json(contract, summary)
    if (args.output / "evaluation.json").exists():
        raise RuntimeError("assessment already scored; use existing results")
    with (args.output / "workflow.lock").open("a") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        if (args.output / "evaluation.json").exists():
            raise RuntimeError("assessment already scored; use existing results")
        for arm in ARMS:
            run_arm(arm, rows, args.bundle, args.output, cfg, summary["bundle_sha256"], summary["source_sha256"], args.segment_steps)
        if (args.output / "evaluation-started.json").exists():
            raise RuntimeError("assessment evaluation previously started; inspect partial outputs before any retry")
        save_json(args.output / "evaluation-started.json", {"contract_sha256": sha(contract)})
        evaluate(rows, args.bundle, args.output, cfg)


if __name__ == "__main__":
    sys.exit(main())
