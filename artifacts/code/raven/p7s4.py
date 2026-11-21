"""S4 minimal run (plan §8, step 1): one inner fit/calibration split, seed 0, B=2048, frozen unit
embeddings, a frozen detector and a detached full-input teacher.

Steps:
1. Guard. Load the frozen ``fold=final`` detector checkpoint and verify its hash.
2. Fit cohort: inner-fit JsVul records whose full L1 input is <= the teacher limit (7,836).
   Validation: the inner-calibration records.
3. Cache detached teacher probabilities on the full L1 input.
4. Train the policy with ``selector_train.train_step`` against an exact packer environment. Each
   step retokenises every feasible extension.
5. On validation, compare sampled and deterministic (response-per-cost, ``packer.pack``) packs.
   Also confirm the detector hash is unchanged and that the selector optimizer holds no detector
   parameters.
"""

from __future__ import annotations

import hashlib
import json
import time
from pathlib import Path
from typing import Any

import torch

from raven import inventory as inv
from raven import packer
from raven import selector_train as T
from raven import selectors as S
from raven.p2 import LineageError, _digest, _from_run, _json


class PackEnv(T.Env):
    pass

    def __init__(self, texts, target_file, mandatory, cands: list[packer.Candidate], budget, count, labels,
                 *, serializer=packer.serialise):
        self.texts, self.tf, self.cands, self.budget, self.count, self.labels = texts, target_file, cands, budget, count, labels
        self.base = {f: packer._merge(r) for f, r in mandatory.items()}
        self.serializer = serializer
        self._tok: dict[tuple, int] = {}
        self.retokenized = 0

    def files(self, state: tuple) -> dict:
        files = {f: list(r) for f, r in self.base.items()}
        for i in state:
            c = self.cands[i]
            files[c.file] = packer._merge(files.get(c.file, []) + c.span_set)
        return files

    def text(self, state: tuple) -> str:
        return self.serializer({f: (self.texts[f], r) for f, r in self.files(state).items()}, self.tf, self.labels)

    def tokens(self, state: tuple) -> int:
        key = tuple(sorted(state))
        if key not in self._tok:
            self._tok[key] = self.count(self.text(key))
            self.retokenized += 1
        return self._tok[key]

    def feasible(self, state):
        used = self.tokens(state)
        out = {}
        for i in range(len(self.cands)):
            if i in state:
                continue
            n = self.tokens((*state, i))
            if n <= self.budget:
                out[i] = max(1, n - used)
        return out


def _check_inventory(run_path, proof_files):
    inventory = json.loads((run_path / "output_hashes.json").read_text())
    if any(name not in inventory for name in proof_files) or _digest(run_path, proof_files) != {
        name: inventory[name] for name in proof_files
    }:
        raise LineageError(f"D7 detector output hashes changed: {run_path.name}")


def _selector_output_hashes(run_path: Path, *, marked: bool) -> dict[str, str]:
    pass
    files = ["s4_log.jsonl", "s4_validation.csv", "policy.pt"]
    if marked:
        files.append("s4_input_contract.json")
    missing = [name for name in files if not (run_path / name).is_file()]
    if missing:
        raise FileNotFoundError(f"selector run is missing required outputs: {', '.join(missing)}")
    return _digest(run_path, tuple(files))


def _require_marked_gate(cfg: dict) -> None:
    pass
    from raven.p7a import detector_manifest_identity

    d = cfg["p7"]["detector"]
    bundle = d.get("input_bundle")
    gate_path = cfg["p7"]["s4"].get("gate_run")
    if not d.get("operation_manifest") or not bundle or not gate_path:
        raise LineageError("D7 requires a pinned input bundle and a completed detector gate")

    gate_run = _from_run(Path(gate_path), "detector-gate")
    _check_inventory(gate_run, ("gate.json", "run.json"))
    result = json.loads((gate_run / "gate.json").read_text())
    primary = d["primary_variant"]
    if (
        result.get("primary_variant") != primary
        or result.get("input_bundle") != bundle
        or result.get("manifest_run") != detector_manifest_identity(cfg)
        or result.get("train_config") != d["train"]
        or result.get("gate") != d["gate"]
    ):
        raise LineageError("D7 detector gate belongs to a different input or training contract")
    decision = result.get("decisions", {}).get(primary, {}).get("decision")
    if decision != "go":
        raise LineageError(f"D7 requires primary detector gate go (found {decision or 'missing'})")


def _marked_inputs(cfg: dict):
    from raven import p7inputs as I

    if cfg["p7"].get("input_serializer") != I.SERIALIZER:
        raise LineageError("D7 requires the configured marked serializer")
    parent, hashes, rows = I.verify_bundle(cfg)
    entries = {}
    for entry in I.dbg._jsonl(parent / "input_manifest.jsonl"):
        if entry["view"] != "teacher":
            continue
        sid = entry["sample_id"]
        if (
            sid in entries or entry["fold"] != "" or entry["epoch"] != -1
            or entry["serializer"] != I.SERIALIZER
            or hashes.get(entry["pack_path"]) != entry["pack_sha256"]
        ):
            raise LineageError("D7 teacher manifest has invalid lineage")
        entries[sid] = entry
    if set(entries) != {row["sample_id"] for row in rows}:
        raise LineageError("D7 teacher IDs differ from the signed cohort")
    limit = int(cfg["p7"]["detector"]["teacher_context_limit"])
    roles = {row["sample_id"]: {"role": I.dbg.fold_role(row, "final"), "label": row["label"]} for row in rows}
    if any(entry["teacher_eligible"] != (0 < entry["tokens"] <= limit) for entry in entries.values()):
        raise LineageError("D7 teacher eligibility differs from the signed token limit")
    fit, val = (
        sorted(sid for sid, row in roles.items() if row["role"] == role and entries[sid]["teacher_eligible"])
        for role in ("fit", "calibration")
    )
    if not fit or not val:
        raise LineageError("D7 requires teacher-eligible fit and calibration records")
    return parent, hashes, entries, roles, fit, val


def _marked_sample(parent, hashes, sid, entry, count):
    from raven import p7inputs as I

    rel = f"samples/{I.digest(sid)}.json"
    if rel not in hashes or I.dbg.sha_file(parent / rel) != hashes[rel]:
        raise LineageError("D7 source snapshot differs from the signed inventory")
    sample = I.read_sample(parent / rel)
    raw = (parent / entry["pack_path"]).read_bytes()
    full = raw.decode()
    files = {f: list(ranges) for f, ranges in sample["levels"]["L0"].items()}
    for candidate in sample["pools"]["L1"]:
        files[candidate.file] = packer._merge(files.get(candidate.file, []) + candidate.span_set)
    if (
        sample["sample_id"] != sid or I.digest(raw) != entry["pack_sha256"]
        or count(full) != entry["tokens"] or I.render_files(sample, files)[0] != full
    ):
        raise LineageError("D7 teacher text differs from the marked source snapshot")
    return sample, full


def run_selector(run, train_run: Path, pack_run: Path | None, resume: Path | None = None) -> dict[str, Any]:
    cfg = run.config
    settings = cfg["p7"]
    d = settings["detector"]
    s4 = settings["s4"]
    marked = "operation_manifest" in d or "input_bundle" in d or "input_serializer" in settings
    if marked:
        _require_marked_gate(cfg)

    from raven import encoder, p5, p7, p7a

    if not marked and s4.get("require_useful_gate", False):
        gate_run = _from_run(Path(s4.get("gate_run", "")), "detector-gate")
        gate_result = json.loads((gate_run / "gate.json").read_text())
        primary = cfg["p7"]["detector"]["primary_variant"]
        if gate_result["decisions"].get(primary, {}).get("decision") != "go":
            raise LineageError("S4 is blocked until the primary detector gate is go")
        if gate_result.get("manifest_run") != d["manifest_run"] or gate_result.get("train_config") != d["train"]:
            raise LineageError("S4 useful gate belongs to a different manifest/training contract")
    if not marked:
        from raven import detector

        if pack_run is None:
            raise LineageError("Legacy S4 requires --pack-run")
        detector.guarded_cohort(cfg, pack_run)
    train_run = _from_run(Path(train_run), "detector-train")
    if marked:
        _check_inventory(train_run, ("train_summary.json", "run.json"))
    ts = json.loads((train_run / "train_summary.json").read_text())
    if not marked and ts.get("input_bundle") is not None:
        raise LineageError("Legacy S4 cannot consume a marked detector checkpoint")
    if marked and (
        ts.get("input_bundle") != d["input_bundle"]
        or ts.get("manifest_run") != p7a.detector_manifest_identity(cfg)
        or ts.get("variant") != d["primary_variant"]
        or ts.get("train_config") != d["train"]
        or ts.get("tokenizer_revision") != cfg["tokenizer_revision"]
        or ts.get("max_steps") is not None
        or not all(ts.get(key) is True for key in ("losses_finite", "gradients_finite", "roundtrip_ok"))
        or not ts.get("steps") or ts["steps"] != ts.get("planned_steps")
    ):
        raise LineageError("D7 requires the complete final primary detector on the signed inputs")
    if not marked and s4.get("require_useful_gate", False) and (ts["manifest_run"] != Path(d["manifest_run"]).name
                                               or ts["train_config"] != d["train"]):
        raise LineageError("S4 final detector differs from the recovery manifest/training contract")
    if ts["fold"] != "final" or _digest(train_run, tuple(ts["output_files"])) != ts["output_files"]:
        raise LineageError("S4 needs an unchanged fold=final detector run")
    ck = Path(ts["checkpoint_dir"]) / "trainable.pt"
    if hashlib.sha256(ck.read_bytes()).hexdigest() != ts["trainable_file_sha256"]:
        raise LineageError("detector checkpoint differs from the recorded hash")
    if marked:
        from raven import p7inputs as I

        if settings.get("packer_version") != "density-v2":
            raise LineageError("D7 marked selector requires density-v2 packing")
        parent, hashes, entries, roles, fit, val = _marked_inputs(cfg)
    else:
        manifest_run = _from_run(Path(d["manifest_run"]), "p7-manifest")
        rows = {r["sample_id"]: r for r in inv.read_rows(manifest_run / "cohort_manifest.csv") if r["level"] == "L1"}
        roles = p7a.fold_roles(manifest_run, "final")
        fit = sorted(s for s, r in roles.items() if r["role"] == "fit" and rows[s]["full_forward_eligible"] == "true")
        val = sorted(s for s, r in roles.items() if r["role"] == "calibration" and rows[s]["full_forward_eligible"] == "true")
    limit = int(d["teacher_context_limit"])
    budget = int(s4["budget"])
    tok = p5.load_tokenizer(cfg)
    count = lambda t: p5.count_tokens(tok, t)
    encode = lambda t: tok(t, add_special_tokens=False)["input_ids"]
    enc = encoder.EncoderCache(device="cpu")
    if marked:
        source_views = (_marked_sample(parent, hashes, sid, entries[sid], count) for sid in fit + val)
    else:
        from raven.p6 import iter_samples

        eidx = p7.edges_index(Path(d["build_run"]))
        source_views = (
            (sample, None)
            for sample in iter_samples(cfg, Path(d["extract_run"]), Path(d["build_run"]), run.logger,
                                       only=set(fit) | set(val))
        )
    params = S.MessageParams(**cfg["p7"]["s3"]["params"])
    items = {}
    for s, full in source_views:
        sid = s["sample_id"]
        tf = s["target_file"]
        mandatory = s["levels"]["L0"] if marked else {tf: s["levels"]["L0"][tf]}
        opt, _ = packer.optional_candidates(s["texts"], mandatory, s["pools"]["L1"])
        opt = sorted(opt, key=lambda c: c.uid)
        uids = [c.uid for c in opt]
        t_text = b"".join(s["texts"][tf][a:b] for a, b in s["target"][tf]).decode("utf-8", "replace")
        h_all, _ = enc.embed([t_text] + [b"".join(s["texts"][c.file][a:b] for a, b in c.ranges)
                                          .decode("utf-8", "replace") for c in opt])
        if marked:
            graph = {frozenset(edge): {"resolved"} for edge in s["edges"]}
            serializer = I.renderer(s)
        else:
            graph = p7.unit_graph(s, uids, eidx)
            serializer = packer.serialise
            full = serializer({f: (s["texts"][f], r) for f, r in s["levels"]["L1"].items()}, tf, s["labels"])
        gate = p7.gate_matrix(uids, graph)
        if count(full) > limit:
            raise LineageError(f"{sid}: full input exceeds the teacher limit")
        env = PackEnv(s["texts"], tf, mandatory, opt, budget, count, s["labels"], serializer=serializer)
        if marked and env.tokens(()) > budget:
            raise LineageError(f"{sid}: mandatory marked input exceeds the selector budget")
        items[sid] = {"ht": h_all[0], "h": h_all[1:], "gate": gate,
                      "mask": S.knn_mask(S.similarity(h_all[1:]), uids, params.k),
                      "env": env,
                      "label": roles[sid]["label"], "full": full, "cands": opt, "texts": s["texts"], "tf": tf,
                      "mandatory": mandatory, "labels": s["labels"]}
    input_contract = {}
    if marked:
        input_contract = {
            "bundle": d["input_bundle"], "serializer": I.SERIALIZER, "packer": "density-v2",
            "teacher": {sid: entries[sid]["pack_sha256"] for sid in fit + val},
            "calibration_ids": val,
        }
        _json(run.path / "s4_input_contract.json", input_contract)
    device = cfg["compute"]["device"]
    det = p7a.load_qwen(cfg, device)
    p7a.load_trainable(det, torch.load(ck))
    det.eval()
    for p in det.parameters():
        p.requires_grad_(False)
    det_hash = p7a.state_sha256(p7a.trainable_state(det))
    if det_hash != ts["trainable_sha256"]:
        raise LineageError("loaded detector differs from the frozen checkpoint")

    def probs(text: str) -> torch.Tensor:
        with torch.inference_mode():
            return torch.softmax(det(torch.tensor([encode(text)], device=device)).float(), -1)[0].cpu().double()

    t0 = time.time()
    for it in items.values():
        it["p_full"] = probs(it["full"])  
    teacher_s = time.time() - t0
    torch.manual_seed(int(s4["seed"]))
    net = T.PolicyNet(512, hidden=int(s4["hidden"]), sigma=params.sigma, gamma=params.gamma,
                      stop_logit=float(s4["stop_logit"]))
    opt = torch.optim.Adam(net.parameters(), lr=float(s4["lr"]))
    T.assert_isolated(opt, det)
    base = T.LaggedBaseline(float(s4["baseline_decay"]))
    gen = torch.Generator().manual_seed(int(s4["seed"]))
    start_epoch, start_batch = 0, 0
    if resume:
        saved = torch.load(resume, weights_only=True)
        if (saved["detector_sha256"] != det_hash or saved["config"] != s4 or saved["fit_ids"] != fit
                or saved.get("input_contract", {}) != input_contract):
            raise LineageError("selector resume checkpoint has different inputs/configuration")
        net.load_state_dict(saved["net"])
        opt.load_state_dict(saved["optimizer"])
        base.load_state_dict(saved["baseline"])
        gen.set_state(saved["generator"])
        start_epoch, start_batch = saved["next_epoch"], saved["next_batch"]
    log = (run.path / "s4_log.jsonl").open("w")
    calls = 0
    for epoch in range(int(s4["epochs"])):
        if epoch < start_epoch:
            continue
        order = list(fit)
        torch.manual_seed(int(s4["seed"]) + epoch)
        order = [order[i] for i in torch.randperm(len(order)).tolist()]
        for k in range(0, len(order), int(s4["batch"])):
            if epoch == start_epoch and k < start_batch:
                continue
            batch = [items[s] for s in order[k:k + int(s4["batch"])]]
            consumed = []

            def score_pack(it, actions, consumed=consumed):
                text = it["env"].text(tuple(actions))
                if marked:
                    consumed.append(I.digest(text))
                return probs(text)

            t1 = time.time()
            out = T.train_step(net, opt, base, batch, score_pack,
                               float(s4["temperature"]), float(s4["lambda_y"]), gen,
                               action_cap=int(s4["action_cap"]), stop_mode=s4.get("stop_mode", "legacy_density"))
            if marked:
                out["consumed_packs"] = dict(zip(order[k:k + int(s4["batch"])], consumed, strict=True))
            calls += out["detector_calls"]
            log.write(json.dumps({"epoch": epoch, "batch": k // int(s4["batch"]), **out,
                                  "step_s": round(time.time() - t1, 2),
                                  "sigma": float(S.sigma_from_raw(net.s_raw.detach())),
                                  "gamma": float(S.gamma_from_raw(net.c_raw.detach())),
                                  "stop_logit": float(net.stop.detach())}) + "\n")
            log.flush()
            next_batch = k + int(s4["batch"])
            payload = {"net": net.state_dict(), "optimizer": opt.state_dict(), "baseline": base.state_dict(),
                       "generator": gen.get_state(), "detector_sha256": det_hash, "config": s4, "fit_ids": fit,
                       "input_contract": input_contract,
                       "next_epoch": epoch + 1 if next_batch >= len(order) else epoch,
                       "next_batch": 0 if next_batch >= len(order) else next_batch}
            torch.save(payload, run.path / "policy.pt.tmp")
            (run.path / "policy.pt.tmp").replace(run.path / "policy.pt")
    log.close()
    
    val_rows = []
    gen_v = torch.Generator().manual_seed(12345)
    with torch.no_grad():
        for sid in val:
            it = items[sid]
            r = net.responses(it["ht"], it["h"], it["gate"], it["mask"])
            tr = T.sample(r, it["env"], net.stop, float(s4["temperature"]), gen_v, int(s4["action_cap"]),
                          s4.get("stop_mode", "legacy_density"))
            scored = [packer.Candidate(c.uid, c.file, c.ranges, c.closure, float(r[i]), c.order)
                      for i, c in enumerate(it["cands"])]
            if marked:
                res = packer.pack_density_v2(it["texts"], it["tf"], it["mandatory"], scored, budget, count,
                                              labels=it["labels"], serializer=it["env"].serializer)
            else:
                pack_fn = packer.for_version(cfg["p7"].get("packer_version", "legacy-v1"))
                res = pack_fn(it["texts"], it["tf"], it["mandatory"], scored, budget, count, labels=it["labels"])
            sampled_text = it["env"].text(tuple(tr.actions))
            q_s, q_d = probs(sampled_text), probs(res.text)
            det_sel = {c.uid for c in it["cands"]} & set(res.selected)
            smp_sel = {it["cands"][i].uid for i in tr.actions}
            val_rows.append({"sample_id": sid, "label": it["label"], "p_full": round(float(it["p_full"][1]), 6),
                             "p_sampled": round(float(q_s[1]), 6), "p_deterministic": round(float(q_d[1]), 6),
                             "kl_sampled": round(T.distill_loss(it["p_full"], q_s, it["label"], 0.0), 6),
                             "kl_deterministic": round(T.distill_loss(it["p_full"], q_d, it["label"], 0.0), 6),
                             "tokens_sampled": it["env"].tokens(tuple(tr.actions)), "tokens_deterministic": res.tokens,
                             "selected_jaccard": round(len(det_sel & smp_sel) / len(det_sel | smp_sel), 4)
                             if det_sel | smp_sel else 1.0})
            if marked:
                val_rows[-1].update(sampled_sha256=I.digest(sampled_text), deterministic_sha256=I.digest(res.text))
            calls += 2
    inv.write_rows(run.path / "s4_validation.csv", tuple(val_rows[0]) if val_rows else ("sample_id",), val_rows)
    if not (run.path / "policy.pt").exists() and resume:
        torch.save(saved, run.path / "policy.pt")
    after = p7a.state_sha256(p7a.trainable_state(det))
    result = {"train_run": train_run.name, "detector_sha256_before": det_hash, "detector_sha256_after": after,
              "detector_unchanged": det_hash == after, "fit_records": len(fit), "validation_records": len(val),
              "teacher_s": round(teacher_s, 1), "detector_calls": calls,
              "retokenized": sum(it["env"].retokenized for it in items.values()), "s4_config": s4,
              "sigma_final": float(S.sigma_from_raw(net.s_raw.detach())),
              "gamma_final": float(S.gamma_from_raw(net.c_raw.detach()))}
    if marked:
        result["teacher_calls"] = len(items)
    result["output_files"] = _selector_output_hashes(run.path, marked=marked)
    _json(run.path / "s4_summary.json", result)
    if not result["detector_unchanged"]:
        raise AssertionError("detector changed during selector training")
    return result
