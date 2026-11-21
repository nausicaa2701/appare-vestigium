"""P7A: detector training, threshold calibration, scoring and the pre-registered gate.

Frozen before outcomes (``p7.yaml`` and ``docs/pilot-decisions.md``, 2026-11-12):

* **model:** pinned Qwen2.5-Coder-1.5B base with LoRA r16/alpha32 on q/k/v/o and a 2-class fp32 head
  on the last-token hidden state. BF16, SDPA, gradient checkpointing, batch 1, AdamW lr 1e-4.
  Training runs a fixed 3 epochs over the fit records, with no early stopping.
* **variants:** ``no_dropout`` sees the canonical P6 random pack (L1, B=2048, SHA-checked) every
  epoch. ``context_dropout`` (primary) sees, each epoch, a fresh seeded random pack after each
  optional unit is kept with probability 0.5. Target and closure are always kept.
* **class weighting:** ``w_pos = n_neg / n_pos`` on the fit records only.
* **threshold:** the max-MCC threshold on inner-calibration families using the reference
  (P6 random) pack. Ties go to lower FPR, then closeness to 0.5, then the larger threshold.
* **gate:** pooled outer-assessment MCC over 3 folds, with a 95% family-bootstrap interval
  (10,000 resamples). Go requires lower bound > 0, finite losses, a checkpoint round-trip, and
  predictions in both classes.

Only ``pilot_dev`` JsVul records with the right manifest role are loaded. The role guard and the
manifest checks run before any source text is read.
"""

from __future__ import annotations

import csv
import hashlib
import json
import math
import os
import random
import subprocess
import time
from collections import defaultdict
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import torch

from raven import inventory as inv
from raven.p2 import LineageError, _digest, _from_run, _json




def confusion(probs: Sequence[float], labels: Sequence[int], t: float) -> tuple[int, int, int, int]:
    tp = fp = tn = fn = 0
    for p, y in zip(probs, labels, strict=True):
        pred = p >= t
        if pred and y:
            tp += 1
        elif pred:
            fp += 1
        elif y:
            fn += 1
        else:
            tn += 1
    return tp, fp, tn, fn


def mcc(tp: int, fp: int, tn: int, fn: int) -> float:
    den = math.sqrt((tp + fp) * (tp + fn) * (tn + fp) * (tn + fn))
    return (tp * tn - fp * fn) / den if den else 0.0


def select_threshold(probs: Sequence[float], labels: Sequence[int]) -> dict[str, Any]:
    pass

    if len(probs) != len(labels) or not all(math.isfinite(p) and 0 <= p <= 1 for p in probs):
        raise ValueError("threshold calibration requires matching finite probabilities and labels")
    cands = sorted(set(probs) | {0.5} | ({math.nextafter(max(probs), math.inf)} if probs else set()))
    best = None
    for t in cands:
        tp, fp, tn, fn = confusion(probs, labels, t)
        fpr = fp / (fp + tn) if fp + tn else 0.0
        key = (-mcc(tp, fp, tn, fn), fpr, abs(t - 0.5), -t)
        if best is None or key < best[0]:
            best = (key, t, (tp, fp, tn, fn))
    if best is None:
        return {"threshold": 0.5, "mcc": 0.0, "confusion": [0, 0, 0, 0], "candidates": 0}
    return {"threshold": best[1], "mcc": -best[0][0], "fpr": best[0][1], "confusion": list(best[2]),
            "candidates": len(cands)}


def family_bootstrap_mcc(rows: list[dict], n_boot: int, seed: int) -> dict[str, Any]:
    pass
    fams = defaultdict(list)
    for r in rows:
        fams[r["family"]].append((int(r["pred"]), int(r["label"])))

    def stat(groups) -> float:
        tp = fp = tn = fn = 0
        for g in groups:
            for p, y in g:
                tp += p and y
                fp += p and not y
                fn += (not p) and y
                tn += (not p) and not y
        return mcc(tp, fp, tn, fn)

    keys = sorted(fams)
    est = stat(fams[k] for k in keys)
    rng = random.Random(seed)
    boots = sorted(stat(fams[rng.choice(keys)] for _ in keys) for _ in range(n_boot)) if keys else []
    lo = boots[int(0.025 * n_boot)] if boots else float("nan")
    hi = boots[min(n_boot - 1, int(0.975 * n_boot))] if boots else float("nan")
    preds = [int(r["pred"]) for r in rows]
    return {"mcc": est, "ci_low": lo, "ci_high": hi, "families": len(keys), "records": len(rows),
            "positives": sum(int(r["label"]) for r in rows), "predicted_positive": sum(preds),
            "collapsed": len(set(preds)) < 2, "bootstrap": n_boot}



class Detector(torch.nn.Module):
    pass

    def __init__(self, backbone, hidden: int):
        super().__init__()
        self.backbone = backbone
        self.head = torch.nn.Linear(hidden, 2, dtype=torch.float32)
        
        
        torch.nn.init.zeros_(self.head.weight)
        torch.nn.init.zeros_(self.head.bias)

    def forward(self, ids: torch.Tensor) -> torch.Tensor:
        h = self.backbone(input_ids=ids).last_hidden_state[:, -1, :]
        return self.head(h.float())


def wrap_lora(base, cfg: dict) -> Detector:
    from peft import LoraConfig, get_peft_model

    base.config.use_cache = False
    lc = cfg["lora"]
    peft_model = get_peft_model(base, LoraConfig(r=lc["r"], lora_alpha=lc["alpha"], lora_dropout=lc["dropout"],
                                                 target_modules=list(lc["targets"])))
    return Detector(peft_model, base.config.hidden_size)


def load_qwen(config: dict, device: str) -> Detector:
    from transformers import AutoModel

    from raven import p5

    base = AutoModel.from_pretrained(p5.QWEN_REPO, revision=config["tokenizer_revision"], dtype=torch.bfloat16,
                                     attn_implementation="sdpa", local_files_only=True,
                                     cache_dir=os.environ.get("RAVEN_MODEL_CACHE"))
    base.gradient_checkpointing_enable(gradient_checkpointing_kwargs={"use_reentrant": False})
    base.enable_input_require_grads()
    det = wrap_lora(base, config["p7"]["detector"]["train"])
    return det.to(device)


def trainable_state(det: Detector) -> dict[str, torch.Tensor]:
    pass
    from peft import get_peft_model_state_dict

    out = {f"adapter.{k}": v.detach().cpu().clone() for k, v in get_peft_model_state_dict(det.backbone, save_embedding_layers=False).items()}
    out.update({f"head.{k}": v.detach().cpu().clone() for k, v in det.head.state_dict().items()})
    return out


def load_trainable(det: Detector, state: dict[str, torch.Tensor]) -> None:
    from peft import set_peft_model_state_dict

    set_peft_model_state_dict(det.backbone, {k[8:]: v for k, v in state.items() if k.startswith("adapter.")})
    det.head.load_state_dict({k[5:]: v for k, v in state.items() if k.startswith("head.")})


def state_sha256(state: dict[str, torch.Tensor]) -> str:
    h = hashlib.sha256()
    for k in sorted(state):
        h.update(k.encode())
        h.update(state[k].to(torch.float32).contiguous().numpy().tobytes())
    return h.hexdigest()


@dataclass
class TrainItem:
    sample_id: str
    label: int
    texts: list[str]  

    def text_for_epoch(self, epoch: int) -> str:
        return self.texts[epoch % len(self.texts)]


def _consumed_views(record, fold, variant, items, views):
    pass
    epoch = record["epoch"]
    consumed = []
    for sid in record["sample_ids"]:
        item = items[sid]
        text = item.text_for_epoch(epoch)
        view = "dropout" if variant == "context_dropout" else "reference"
        consumed.append({
            "sample_id": sid,
            "fold": fold,
            "epoch": epoch,
            "view": view,
            "pack_sha256": hashlib.sha256(text.encode()).hexdigest(),
            "reference_equal": text == views[sid]["reference"],
        })
    return consumed


def _sync(device: str) -> None:
    if device == "mps":
        torch.mps.synchronize()
    elif device == "cuda":
        torch.cuda.synchronize()


def _swap_mib() -> float:
    try:
        out = subprocess.run(["sysctl", "-n", "vm.swapusage"], capture_output=True, text=True, check=False).stdout
        return float(out.split("used =")[1].split("M")[0])
    except (OSError, IndexError, ValueError):
        return float("nan")


def weighted_ce(logits: torch.Tensor, label: int, weight: torch.Tensor) -> torch.Tensor:
    pass




    nll = torch.nn.functional.cross_entropy(logits, torch.tensor([label], device=logits.device), reduction="none")
    return (weight[label] * nll).sum()


def train(det: Detector, items: list[TrainItem], encode: Callable[[str], list[int]], cfg: dict, device: str,
          log: Callable[[dict], None], *, resume: dict | None = None, max_steps: int | None = None,
          swap_stop_mib: float = float("inf"), stop_after: int | None = None) -> dict[str, Any]:
    pass

    params = [p for p in det.parameters() if p.requires_grad]
    opt = torch.optim.AdamW(params, lr=float(cfg["lr"]), weight_decay=float(cfg["weight_decay"]))
    n_pos = sum(it.label for it in items)
    n_neg = len(items) - n_pos
    w_pos = n_neg / n_pos if n_pos else 1.0
    weight = torch.tensor([1.0, w_pos], dtype=torch.float32, device=device)
    balanced = cfg.get("sampling") == "balanced"
    if balanced and (not n_pos or not n_neg):
        raise ValueError("balanced training requires both classes")
    if balanced:
        weight = torch.ones(2, device=device)
    effective_batch = int(cfg.get("effective_batch", 1))
    if effective_batch < 1 or (balanced and effective_batch % 2):
        raise ValueError("balanced training requires an even positive effective batch")
    epochs = int(cfg["epochs"])
    schedule = []
    for e in range(epochs):
        order = list(range(len(items)))
        random.Random(f"{cfg['seed']}|epoch|{e}").shuffle(order)
        if balanced:
            positive = [i for i in order if items[i].label]
            negative = [i for i in order if not items[i].label]
            order = [i for k in range(max(len(positive), len(negative)))
                     for i in (positive[k % len(positive)], negative[k % len(negative)])]
        schedule.extend((e, order[k:k + effective_batch]) for k in range(0, len(order), effective_batch))
    if max_steps is not None:
        schedule = schedule[:max_steps]
    step = 0
    if resume:
        load_trainable(det, resume["state"])
        opt.load_state_dict(resume["optimizer"])
        step = int(resume.get("step", resume.get("steps", 0)))
        torch.set_rng_state(resume["torch_rng"])
        if device == "mps" and resume.get("mps_rng") is not None:
            torch.mps.set_rng_state(resume["mps_rng"].cpu())
    det.train()
    swap0 = _swap_mib()
    losses = []
    gradients_finite = True
    status = "completed"
    for e, indices in schedule[step:]:
        t0 = time.time()
        opt.zero_grad(set_to_none=True)
        micro_losses, token_counts = [], []
        for i in indices:
            it = items[i]
            ids = torch.tensor([encode(it.text_for_epoch(e))], device=device)
            loss = weighted_ce(det(ids), it.label, weight)
            lv = float(loss.detach())
            if not math.isfinite(lv):
                opt.zero_grad(set_to_none=True)
                raise FloatingPointError("nonfinite detector loss before optimizer update")
            (loss / len(indices)).backward()
            micro_losses.append(lv)
            token_counts.append(int(ids.shape[1]))
        try:
            gnorm = torch.nn.utils.clip_grad_norm_(params, float(cfg["grad_clip"]), error_if_nonfinite=True)
        except RuntimeError:
            opt.zero_grad(set_to_none=True)
            raise FloatingPointError("nonfinite detector gradient before optimizer update") from None
        opt.step()
        opt.zero_grad(set_to_none=True)
        _sync(device)
        if device == "mps":
            
            
            torch.mps.empty_cache()
        step += 1
        lv = sum(micro_losses) / len(micro_losses)
        losses.append(lv)
        sw = _swap_mib()
        log({"step": step, "epoch": e, "sample_id": it.sample_id, "label": it.label, "tokens": int(ids.shape[1]),
             "sample_ids": [items[i].sample_id for i in indices], "labels": [items[i].label for i in indices],
             "micro_losses": micro_losses, "token_counts": token_counts, "effective_batch": len(indices),
             "loss": lv, "grad_norm": float(gnorm), "finite": math.isfinite(lv) and math.isfinite(float(gnorm)),
             "step_s": round(time.time() - t0, 3), "swap_mib": sw,
             "driver_gib": round(torch.mps.driver_allocated_memory() / 2**30, 3) if device == "mps" else None})
        if sw - swap0 > swap_stop_mib:
            status = "stopped_swap_guard"
            break
        if stop_after is not None and step >= stop_after:
            status = "paused"
            break
    return {"status": status, "steps": step, "planned_steps": len(schedule), "w_pos": 1.0 if balanced else w_pos,
            "fit_class_ratio": w_pos, "n_pos": n_pos,
            "n_neg": n_neg, "losses_finite": all(math.isfinite(x) for x in losses),
            "gradients_finite": gradients_finite, "sampling": "balanced" if balanced else "natural",
            "state": trainable_state(det), "optimizer": opt.state_dict(), "torch_rng": torch.get_rng_state(),
            "mps_rng": torch.mps.get_rng_state().cpu() if device == "mps" else None}


def score(det: Detector, texts: list[str], encode: Callable[[str], list[int]], device: str) -> list[float]:
    det.eval()
    out = []
    with torch.inference_mode():
        for t in texts:
            ids = torch.tensor([encode(t)], device=device)
            out.append(float(torch.softmax(det(ids).float(), dim=-1)[0, 1]))
    return out



def _keep(seed: int, epoch: int, sample_id: str, uid: str, p: float) -> bool:
    h = hashlib.sha256(f"dropout|{seed}|{epoch}|{sample_id}|{uid}".encode()).digest()
    return (int.from_bytes(h[:8], "big") + 1) / 2**64 <= p


def build_texts(config: dict, extract_run: Path, build_run: Path, pack_cells: dict, wanted: set[str],
                epochs: int, seed: int, keep_prob: float, logger=None) -> dict[str, dict]:
    pass

    from raven import p5, p6, packer

    d = config["p7"]["detector"]
    level, budget = d["level"], int(d["budget"])
    tok = p5.load_tokenizer(config)
    count = lambda t: p5.count_tokens(tok, t)
    slack = int(config["p6"]["estimate_slack_tokens"])
    prompt = config["p6"]["prompt_prefix"]
    out = {}
    for s in p6.iter_samples(config, extract_run, build_run, logger, only=wanted):
        sid = s["sample_id"]
        tf = s["target_file"]
        mandatory = {tf: s["levels"]["L0"][tf]}
        pool = s["pools"][level]
        est = {c.uid: count(b"".join(s["texts"][c.file][a:b] for a, b in packer._merge(c.span_set))
                            .decode("utf-8", "replace")) for c in pool}

        def pack(cands, sid=sid, s=s, tf=tf, mandatory=mandatory, est=est):
            return packer.pack(s["texts"], tf, mandatory, cands, budget, count, labels=s["labels"], prompt=prompt,
                               estimates=est, slack=slack)

        ref = pack(p6.method_scores("random", config["seed"], sid, pool))
        tgt = pack(p6.method_scores("zero_mask", config["seed"], sid, pool))
        for name, res in (("random", ref), ("zero_mask", tgt)):
            cell = pack_cells[(sid, name)]
            if p6._sha(res.text) != cell["pack_sha256"]:
                raise LineageError(f"{sid}: rebuilt {name} pack differs from canonical P6")
        drop = []
        for e in range(epochs):
            sub = [c for c in pool if _keep(seed, e, sid, c.uid, keep_prob)]
            drop.append(pack(p6.method_scores("random", seed * 1000 + e + 1, sid, sub)).text)
        out[sid] = {"reference": ref.text, "target_only": tgt.text, "dropout": drop}
    missing = wanted - set(out)
    if missing:
        raise LineageError(f"samples not rebuilt: {sorted(missing)[:3]}")
    return out


def _pack_cells(pack_run: Path, level: str, budget: str) -> dict:
    return {(r["sample_id"], r["method"]): r for r in inv.read_rows(pack_run / "pack_cells.csv")
            if r["level"] == level and r["budget_name"] == budget}


def fold_roles(manifest_run: Path, fold: str) -> dict[str, dict]:
    pass

    rows = [r for r in inv.read_rows(manifest_run / "cohort_manifest.csv") if r["level"] == "L1"]
    out = {}
    for r in rows:
        if r["source"] != "jsvul" or r["eligible"] != "true" or r["role"] != "pilot_dev":
            continue
        if r["scoring_eligible_2048"] != "true":
            continue
        if r["original_split"] == "train":
            role = r["inner_role"] if fold == "final" else r[f"fold{fold}_role"]
        elif fold == "final":
            role = "temporal"
        else:
            continue
        if role:
            out[r["sample_id"]] = {"role": role, "label": int(r["label"]), "family": r["family"],
                                   "split": r["original_split"]}
    return out


def bow_reference(fit: list[tuple[str, int]], cal: list[tuple[str, int]], test: list[str], seed: int):
    pass
    from sklearn.feature_extraction.text import CountVectorizer
    from sklearn.linear_model import LogisticRegression

    if len({y for _, y in fit}) < 2:
        return None, [0.5] * len(cal), [0.5] * len(test)
    vec = CountVectorizer(token_pattern=r"[A-Za-z_][A-Za-z0-9_]+", min_df=1, max_features=20000)
    x = vec.fit_transform([t for t, _ in fit])
    clf = LogisticRegression(class_weight="balanced", max_iter=2000, random_state=seed).fit(x, [y for _, y in fit])
    return clf, clf.predict_proba(vec.transform([t for t, _ in cal]))[:, 1].tolist(), \
        clf.predict_proba(vec.transform(test))[:, 1].tolist() if test else []


def checkpoint_root(run_id: str) -> Path:
    root = Path(os.environ.get("RAVEN_CHECKPOINT_ROOT",
                               Path(os.environ.get("RAVEN_DATA_ROOT", "artifacts/cache")).parent / "checkpoints"))
    return root / run_id



def run_train(run, pack_run: Path, fold: str, variant: str, extract_run: Path, build_run: Path,
              max_steps: int | None = None, resume: Path | None = None,
              stop_after: int | None = None) -> dict[str, Any]:
    pass
    from raven import detector, p5

    cfg = run.config
    d = cfg["p7"]["detector"]
    tcfg = d["train"]
    if variant not in d["variants"]:
        raise ValueError(f"unknown variant {variant!r}")
    operation = "operation_manifest" in d
    if operation:
        
        from raven import p7debug

        if d.get("input_bundle"):
            from raven import p7inputs

            roles, texts, guard = p7inputs.load_bundle(cfg, fold, run.path, lambda: p5.load_tokenizer(cfg))
        else:
            roles, _reference_texts, guard = p7debug.operation_cohort(cfg, fold, run.path, lambda: p5.load_tokenizer(cfg))
        manifest_name = detector_manifest_identity(cfg)
    else:
        _families, guard = detector.guarded_cohort(cfg, pack_run)  
        manifest_run = _from_run(Path(d["manifest_run"]), "p7-manifest")
        msum = json.loads((manifest_run / "manifest_summary.json").read_text())
        if _digest(manifest_run, tuple(msum["output_files"])) != msum["output_files"]:
            raise LineageError("manifest outputs changed after the run")
        roles = fold_roles(manifest_run, fold)
        manifest_name = manifest_run.name
    detector.assert_scorable(roles, {s: "pilot_dev" for s in roles})
    fams = defaultdict(set)
    for r in roles.values():
        fams[r["role"]].add(r["family"])
    for a in fams:
        for b in fams:
            if a < b and fams[a] & fams[b]:
                raise LineageError(f"families overlap between {a} and {b}")
    (run.path / "cohort_guard.json").write_text(json.dumps({**guard, "fold": fold, "variant": variant,
                                                            "roles": {k: len(v) for k, v in fams.items()}},
                                                           indent=2, sort_keys=True) + "\n")
    if not d.get("training_enabled", False):
        raise RuntimeError("detector training is not enabled (p7.detector.training_enabled=false)")
    if operation and not d.get("input_bundle"):
        
        
        raise LineageError("operation-manifest inputs for target_only/context_dropout are not defined "
                           "(D3 input contract); refusing to load the model")
    if variant not in d["variants"]:
        raise LineageError("unregistered detector variant")
    epochs, seed = int(tcfg["epochs"]), int(tcfg["seed"])
    cells = {} if operation else _pack_cells(pack_run, d["level"], str(d["budget"]))
    smoke = bool(d.get("recovery_smoke", False))
    if smoke:
        rcfg = cfg["p7"]["recovery"]
        chosen = []
        for label in (0, 1):
            candidates = [s for s, r in roles.items() if r["role"] == "fit" and r["label"] == label
                          and int(r["tokens"] if operation else cells[(s, "random")]["tokens"]) <= rcfg["smoke_max_tokens"]]
            candidates.sort(key=lambda s: (int(roles[s]["tokens"] if operation else cells[(s, "random")]["tokens"]), s))
            needed = int(rcfg["smoke_fit_per_class"])
            if len(candidates) < needed:
                raise LineageError("insufficient fit-only short packs for the recovery smoke")
            chosen.extend(candidates[:needed])
        roles = {s: roles[s] for s in chosen}
    if not operation:
        texts = build_texts(cfg, extract_run, build_run, cells, set(roles), epochs, seed,
                            float(tcfg["context_dropout"]["keep_prob"]), run.logger)
    by_role = defaultdict(list)
    for sid in sorted(roles):
        by_role[roles[sid]["role"]].append(sid)
    fit = by_role["fit"]
    if d.get("require_calibration_classes", False) and not smoke:
        counts = [sum(roles[s]["label"] == label for s in by_role["calibration"]) for label in (0, 1)]
        if min(counts) < 2:
            raise LineageError(f"recovery calibration needs at least two records per class, got {counts}")
    items = [TrainItem(s, roles[s]["label"],
                       (texts[s]["dropout"] * math.ceil(epochs / len(texts[s]["dropout"])))[:epochs]
                        if variant == "context_dropout" else [texts[s]["reference"]]) for s in fit]
    resume_contract = {"manifest": manifest_name, "fold": fold, "variant": variant,
                       "fit_ids": fit, "train_config": tcfg, "tokenizer_revision": cfg["tokenizer_revision"],
                       "max_steps": max_steps, "device": cfg["compute"]["device"],
                       "input_bundle": d.get("input_bundle"),
                       "cohort_sha256": d.get("operation_manifest", {}).get("sha256")}
    resume_state = None
    if resume is not None:
        resume_path = Path(resume)
        expected_sha = resume_path.with_suffix(".sha256").read_text().strip()
        if hashlib.sha256(resume_path.read_bytes()).hexdigest() != expected_sha:
            raise LineageError("resume checkpoint SHA-256 mismatch")
        payload = torch.load(resume_path, map_location="cpu", weights_only=True)
        if payload.get("contract") != resume_contract:
            raise LineageError("resume checkpoint has a different cohort/input/fold/variant/training contract")
        resume_state = payload["training"]
        _json(run.path / "resume_lineage.json", {"path": str(resume_path),
                  "sha256": hashlib.sha256(resume_path.read_bytes()).hexdigest(), "step": resume_state["step"]})
    torch.manual_seed(seed)
    device = cfg["compute"]["device"]
    if device == "mps":
        torch.mps.set_per_process_memory_fraction(float(cfg["compute"]["mps_memory_fraction"]))
    tok = p5.load_tokenizer(cfg)
    encode = lambda t: tok(t, add_special_tokens=False)["input_ids"]
    t0 = time.time()
    det = load_qwen(cfg, device)
    log_fh = (run.path / "train_log.jsonl").open("w")
    items_by_id = {item.sample_id: item for item in items}

    def log(rec):
        if operation:
            rec["consumed_views"] = _consumed_views(rec, fold, variant, items_by_id, texts)
        log_fh.write(json.dumps(rec) + "\n")
        log_fh.flush()

    out = train(det, items, encode, tcfg, device, log, max_steps=max_steps, resume=resume_state,
                stop_after=stop_after, swap_stop_mib=float(cfg["compute"]["swap_growth_stop_mib"]))
    log_fh.close()
    train_s = time.time() - t0
    ck = checkpoint_root(run.path.name)
    ck.mkdir(parents=True, exist_ok=True)
    torch.save(out["state"], ck / "trainable.pt")
    torch.save({"optimizer": out["optimizer"], "step": out["steps"], "torch_rng": out["torch_rng"]}, ck / "resume.pt")
    training_resume = {"state": out["state"], "optimizer": out["optimizer"], "step": out["steps"],
                       "torch_rng": out["torch_rng"], "mps_rng": out.get("mps_rng")}
    resume_path = ck / "training_resume.pt"
    torch.save({"contract": resume_contract, "training": training_resume}, resume_path)
    resume_path.with_suffix(".sha256").write_text(hashlib.sha256(resume_path.read_bytes()).hexdigest() + "\n")
    def finite_tree(value):
        if isinstance(value, torch.Tensor):
            return bool(torch.isfinite(value).all())
        if isinstance(value, dict):
            return all(finite_tree(v) for v in value.values())
        if isinstance(value, (tuple, list)):
            return all(finite_tree(v) for v in value)
        return True
    if not finite_tree(out["optimizer"]):
        raise FloatingPointError("nonfinite optimizer state")
    if out["status"] == "paused":
        paused = {"status": "paused", "steps": out["steps"], "planned_steps": out["planned_steps"],
                  "resume_path": str(resume_path), "resume_sha256": hashlib.sha256(resume_path.read_bytes()).hexdigest(),
                  "contract": resume_contract, "optimizer_finite": True}
        _json(run.path / "paused_summary.json", paused)
        return paused
    sha = state_sha256(out["state"])
    
    probe = (by_role["calibration"] + by_role["assessment"] + fit)[:4]
    before = score(det, [texts[s]["reference"] for s in probe], encode, device)
    if operation:
        import gc

        del det
        gc.collect()
        if device == "mps":
            torch.mps.empty_cache()
        det = load_qwen(cfg, device)
    load_trainable(det, torch.load(ck / "trainable.pt"))
    after = score(det, [texts[s]["reference"] for s in probe], encode, device)
    roundtrip = max((abs(a - b) for a, b in zip(before, after, strict=True)), default=0.0)
    if smoke:
        probabilities = score(det, [texts[s]["reference"] for s in fit], encode, device)
        labels = [roles[s]["label"] for s in fit]
        final_loss = sum(-math.log(max(p if y else 1 - p, 1e-12))
                         for p, y in zip(probabilities, labels, strict=True)) / len(labels)
        statistic = mcc(*confusion(probabilities, labels, 0.5))
        checks = {"loss_improved": final_loss <= math.log(2) * cfg["p7"]["recovery"]["smoke_loss_ratio"],
                  "fit_mcc": statistic >= cfg["p7"]["recovery"]["smoke_mcc"],
                  "noncollapsed": len({p >= 0.5 for p in probabilities}) == 2,
                  "roundtrip": roundtrip <= float(d["gate"]["roundtrip_tolerance"]),
                  "finite_state": all(bool(torch.isfinite(v).all()) for v in out["state"].values()),
                  "completed": out["status"] == "completed" and out["steps"] == out["planned_steps"]}
        result = {"smoke": True, "scope": "fit_only", "checks": checks, "go": all(checks.values()),
                  "fit_ids": fit, "labels": labels, "probabilities": probabilities, "initial_loss": math.log(2),
                  "final_loss": final_loss, "mcc_at_0_5": statistic, "steps": out["steps"],
                  "train_s": train_s, "checkpoint_dir": str(ck), "trainable_sha256": sha}
        result["output_files"] = _digest(run.path, ("train_log.jsonl", "cohort_guard.json"))
        _json(run.path / "smoke_summary.json", result)
        return result
    preds = []
    thresholds = {}
    cal = by_role["calibration"]
    reference_p = score(det, [texts[s]["reference"] for s in cal], encode, device)
    reference_threshold = select_threshold(reference_p, [roles[s]["label"] for s in cal])
    for view in ("reference", "target_only"):
        cal_p = reference_p if view == "reference" else score(det, [texts[s][view] for s in cal], encode, device)
        th = dict(reference_threshold)
        th["selected_on"] = "reference"
        thresholds[view] = th
        for s, p in zip(cal, cal_p, strict=True):
            preds.append(_pred(s, roles, "detector", view, "calibration", p, th["threshold"]))
        for role in ("assessment", "temporal"):
            ss = by_role.get(role, [])
            ps = score(det, [texts[s][view] for s in ss], encode, device)
            for s, p in zip(ss, ps, strict=True):
                preds.append(_pred(s, roles, "detector", view, role, p, th["threshold"]))
    
    others = by_role.get("assessment", []) + by_role.get("temporal", [])
    _, bcal, btest = bow_reference([(texts[s]["reference"], roles[s]["label"]) for s in fit],
                                   [(texts[s]["reference"], roles[s]["label"]) for s in by_role["calibration"]],
                                   [texts[s]["reference"] for s in others], seed)
    bth = select_threshold(bcal, [roles[s]["label"] for s in by_role["calibration"]])
    thresholds["bow"] = bth
    for s, p in zip(by_role["calibration"], bcal, strict=True):
        preds.append(_pred(s, roles, "bow", "reference", "calibration", p, bth["threshold"]))
    for s, p in zip(others, btest, strict=True):
        preds.append(_pred(s, roles, "bow", "reference", roles[s]["role"], p, bth["threshold"]))
    inv.write_rows(run.path / "predictions.csv", PRED_FIELDS, preds)
    tol = float(d["gate"]["roundtrip_tolerance"])
    result = {"fold": fold, "variant": variant, "status": out["status"], "steps": out["steps"],
              "planned_steps": out["planned_steps"], "train_s": round(train_s, 1), "w_pos": out["w_pos"],
              "fit_records": len(fit), "fit_positives": out["n_pos"], "roles": {k: len(v) for k, v in by_role.items()},
              "losses_finite": out["losses_finite"], "gradients_finite": out["gradients_finite"],
              "sampling": out["sampling"], "roundtrip_max_abs_diff": roundtrip,
              "roundtrip_ok": roundtrip <= tol, "thresholds": thresholds, "checkpoint_dir": str(ck),
              "trainable_sha256": sha, "trainable_file_sha256": hashlib.sha256((ck / "trainable.pt").read_bytes()).hexdigest(),
              "manifest_run": manifest_name, "pack_run": Path(pack_run).name, "train_config": tcfg,
              "max_steps": max_steps, "tokenizer_revision": cfg["tokenizer_revision"],
              "input_bundle": d.get("input_bundle")}
    result["output_files"] = _digest(run.path, ("predictions.csv", "train_log.jsonl", "cohort_guard.json"))
    _json(run.path / "train_summary.json", result)
    if out["status"] != "completed":
        raise RuntimeError(f"training stopped: {out['status']}")
    return result


PRED_FIELDS = ("sample_id", "family", "split", "label", "model", "view", "role", "prob", "threshold", "pred")


def _pred(s, roles, model, view, role, p, t) -> dict:
    r = roles[s]
    return {"sample_id": s, "family": r["family"], "split": r["split"], "label": r["label"], "model": model,
            "view": view, "role": role, "prob": float(p), "threshold": t, "pred": int(p >= t)}


def detector_manifest_identity(cfg):
    d = cfg["p7"]["detector"]
    if "operation_manifest" in d:
        identity = f"{Path(d['operation_manifest']['path']).name}@{d['operation_manifest']['sha256'][:12]}"
        if d.get("input_bundle"):
            identity += f"/inputs@{d['input_bundle']['sha256'][:12]}"
        return identity
    return Path(d["manifest_run"]).name


def validate_operation_predictions(cfg, summary, rows):
    pass
    from raven import p7inputs

    cohort = {r["sample_id"]: r for r in p7inputs.guarded_rows(cfg)}
    fold = summary["fold"]
    if fold not in {"0", "1", "2"}:
        raise LineageError("invalid cross-fit fold")
    expected = {role: {sid for sid, row in cohort.items() if row[f"fold{fold}_role"] == role}
                for role in ("calibration", "assessment")}
    groups = defaultdict(list)
    for row in rows:
        key = (row["model"], row["view"], row["role"])
        if key not in {(model, view, role) for model, view in
                       (("detector", "reference"), ("detector", "target_only"), ("bow", "reference"))
                       for role in expected}:
            raise LineageError("unexpected prediction model/view/role")
        identity = cohort.get(row["sample_id"])
        if identity is None or row["family"] != identity["family"] or int(row["label"]) != identity["label"]:
            raise LineageError("prediction differs from signed sample/family/label")
        if int(float(row["prob"]) >= float(row["threshold"])) != int(row["pred"]):
            raise LineageError("full-precision prediction replay mismatch")
        groups[key].append(row["sample_id"])
    for model, view in (("detector", "reference"), ("detector", "target_only"), ("bow", "reference")):
        for role, ids in expected.items():
            actual = groups[(model, view, role)]
            if len(actual) != len(set(actual)) or set(actual) != ids:
                raise LineageError("prediction IDs do not match exact signed fold roles")


def run_gate(run, train_runs: list[Path]) -> dict[str, Any]:
    pass
    g = run.config["p7"]["detector"]["gate"]
    primary = run.config["p7"]["detector"]["primary_variant"]
    by = defaultdict(list)
    meta = defaultdict(list)
    for tr in train_runs:
        tr = _from_run(Path(tr), "detector-train")
        s = json.loads((tr / "train_summary.json").read_text())
        if run.config["p7"]["detector"].get("input_bundle"):
            expected = json.loads((run.path / "run.json").read_text())["source_sha256"]
            actual = json.loads((tr / "run.json").read_text())["source_sha256"]
            if actual != expected or s.get("input_bundle") != run.config["p7"]["detector"]["input_bundle"]:
                raise LineageError("detector gate refuses mixed source snapshots or input bundles")
        if (run.config["p7"].get("split_version") == "stratified-recovery-v1"
                and (s["manifest_run"] != detector_manifest_identity(run.config)
                    or s["train_config"] != run.config["p7"]["detector"]["train"]
                    or not s.get("gradients_finite", False)
                    or s["steps"] != s["planned_steps"]
                    or s["thresholds"]["reference"]["threshold"] != s["thresholds"]["target_only"]["threshold"])):
            raise LineageError("recovery gate received an incomplete or mismatched detector contract")
        if _digest(tr, tuple(s["output_files"])) != s["output_files"]:
            raise LineageError(f"{tr.name} outputs changed after the run")
        if s["fold"] == "final" or s["max_steps"] is not None:
            continue
        prediction_rows = inv.read_rows(tr / "predictions.csv")
        if run.config["p7"]["detector"].get("input_bundle"):
            validate_operation_predictions(run.config, s, prediction_rows)
        meta[s["variant"]].append({"run": tr.name, "fold": s["fold"], "losses_finite": s["losses_finite"],
                                   "roundtrip_ok": s["roundtrip_ok"], "steps": s["steps"],
                                   "planned_steps": s["planned_steps"], "thresholds": s["thresholds"]})
        for r in prediction_rows:
            if r["role"] == "assessment":
                by[(s["variant"], r["model"], r["view"])].append(r)
    report = {}
    for (variant, model, view), rows in sorted(by.items()):
        folds = sorted({m["fold"] for m in meta[variant]})
        stats = family_bootstrap_mcc(rows, int(g["bootstrap"]), int(run.config["seed"]))
        report[f"{variant}/{model}/{view}"] = {**stats, "folds": folds}
    decisions = {}
    for variant in meta:
        key = f"{variant}/detector/reference"
        st = report.get(key)
        folds_ok = sorted(m["fold"] for m in meta[variant]) == ["0", "1", "2"]
        checks = {"all_folds": folds_ok, "losses_finite": all(m["losses_finite"] for m in meta[variant]),
                  "roundtrip_ok": all(m["roundtrip_ok"] for m in meta[variant]),
                  "not_collapsed": bool(st) and not st["collapsed"],
                  "ci_lower_above_0": bool(st) and st["ci_low"] > 0}
        if not checks["all_folds"]:
            decision = "incomplete"
        elif all(checks.values()):
            decision = "go"
        elif checks["losses_finite"] and checks["roundtrip_ok"] and st and st["mcc"] > 0:
            decision = "restrict"
        else:
            decision = "revise"
        decisions[variant] = {"decision": decision, "checks": checks, "primary": variant == primary}
    result = {"train_runs": [Path(t).name for t in train_runs], "primary_variant": primary, "gate": g,
              "manifest_run": detector_manifest_identity(run.config) if run.config["p7"]["detector"].get("input_bundle") else run.config["p7"]["detector"]["manifest_run"],
              "input_bundle": run.config["p7"]["detector"].get("input_bundle"),
              "train_config": run.config["p7"]["detector"]["train"],
              "report": report, "decisions": decisions, "folds": dict(meta)}
    _json(run.path / "gate.json", result)
    with (run.path / "gate.csv").open("w", newline="") as fh:
        w = csv.writer(fh)
        w.writerow(["key", "mcc", "ci_low", "ci_high", "families", "records", "positives", "predicted_positive",
                    "collapsed"])
        for k, v in report.items():
            w.writerow([k, round(v["mcc"], 4), round(v["ci_low"], 4), round(v["ci_high"], 4), v["families"],
                        v["records"], v["positives"], v["predicted_positive"], v["collapsed"]])
    return result


def run_score(run, pack_run: Path, train_run: Path) -> dict[str, Any]:
    pass

    from raven import p5

    cfg = run.config
    d = cfg["p7"]["detector"]
    operation = "operation_manifest" in d
    if operation:
        if not d.get("input_bundle"):
            raise LineageError("operation-manifest scoring must go through detector.run_score with a pinned D3 input bundle")
        from raven import p7inputs

        roles, texts, guard = p7inputs.load_bundle(cfg, "final", run.path, lambda: p5.load_tokenizer(cfg))
        _json(run.path / "cohort_guard.json", guard)
    train_run = _from_run(Path(train_run), "detector-train")
    ts = json.loads((train_run / "train_summary.json").read_text())
    if _digest(train_run, tuple(ts["output_files"])) != ts["output_files"]:
        raise LineageError(f"{train_run.name} outputs changed after the run")
    ck = Path(ts["checkpoint_dir"]) / "trainable.pt"
    if hashlib.sha256(ck.read_bytes()).hexdigest() != ts["trainable_file_sha256"]:
        raise LineageError("checkpoint file differs from the hash recorded at training time")
    if operation:
        if ts["manifest_run"] != detector_manifest_identity(cfg):
            raise LineageError("frozen scorer checkpoint belongs to another input contract")
    else:
        manifest_run = _from_run(Path(d["manifest_run"]), "p7-manifest")
        rows = [r for r in inv.read_rows(manifest_run / "cohort_manifest.csv") if r["level"] == "L1"
                and r["source"] == "jsvul" and r["eligible"] == "true" and r["scoring_eligible_2048"] == "true"]
        roles = {r["sample_id"]: {"role": r["original_split"], "label": int(r["label"]), "family": r["family"],
                                  "split": r["original_split"]} for r in rows}
        cells = _pack_cells(pack_run, d["level"], str(d["budget"]))
        texts = build_texts(cfg, Path(d["extract_run"]), Path(d["build_run"]), cells, set(roles), 1, 0, 1.0, run.logger)
    device = cfg["compute"]["device"]
    det = load_qwen(cfg, device)
    load_trainable(det, torch.load(ck))
    if state_sha256(trainable_state(det)) != ts["trainable_sha256"]:
        raise LineageError("loaded trainable tensors differ from the frozen checkpoint")
    tok = p5.load_tokenizer(cfg)
    encode = lambda t: tok(t, add_special_tokens=False)["input_ids"]
    preds = []
    ids = sorted(roles)
    for view in ("reference", "target_only"):
        th = float(ts["thresholds"][view]["threshold"])
        for s, p in zip(ids, score(det, [texts[s][view] for s in ids], encode, device), strict=True):
            preds.append(_pred(s, roles, "detector", view, roles[s]["role"], p, th))
    inv.write_rows(run.path / "scores.csv", PRED_FIELDS, preds)
    result = {"train_run": train_run.name, "trainable_sha256": ts["trainable_sha256"], "records": len(ids),
              "thresholds": {v: ts["thresholds"][v]["threshold"] for v in ("reference", "target_only")}}
    result["output_files"] = _digest(run.path, ("scores.csv",))
    _json(run.path / "score_summary.json", result)
    return result
