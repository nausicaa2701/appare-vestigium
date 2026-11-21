"""Corrected E1/E2 on frozen D3 evidence cases. No detector and no annotation-fed scorer."""
from __future__ import annotations

import json
from collections import defaultdict

import torch

from raven import analysis, context, encoder, p5, p6, p7, packer
from raven import p7inputs as I
from raven import selectors as S
from raven.p2 import LineageError


def verify_parent(parent):
    status = json.loads((parent / "status.json").read_text())
    if status["status"] != "completed":
        raise LineageError("parent run did not complete")
    manifest = json.loads((parent / "output_hashes.json").read_text())
    for name, sha in manifest.items():
        if I.dbg.sha_file(parent / name) != sha:
            raise LineageError(f"immutable parent changed: {name}")
    return manifest


def reconstruct_l1_graph(sample, uids):
    pass
    tf = sample["target_file"]
    fu = context.extract(sample["texts"][tf], context.grammar_for(tf))
    if fu.status != "parsed":
        raise LineageError("E2 local graph source no longer parses")
    analyser = analysis.JsAnalyser(tf, fu)
    analyser.analyse()
    analysis.link({tf: analyser}, {tf}, {})
    names = {i: p6._uid(tf, u) for i, u in enumerate(fu.units)}
    allowed = set(uids)
    pairs = {}
    for edge in analyser.g.edges:
        a, b = names.get(edge.src_unit), names.get(edge.dst_unit)
        if edge.status == "resolved" and edge.dst_file == tf and a in allowed and b in allowed and a != b:
            pairs.setdefault(frozenset((a, b)), set()).add(edge.type)
    return pairs, [e.__dict__ for e in analyser.g.edges]


def execute(run, parent):
    hashes = verify_parent(parent)
    I.write_json(run.path / "parent.json", {"path": str(parent), "inventory_sha256": I.dbg.sha_file(parent / "output_hashes.json"),
                                          "files": hashes})
    cases = I.dbg._jsonl(parent / "evidence_cases.jsonl")
    annotations = {r["sample_id"]: r["components"] for r in I.dbg._jsonl(parent / "evidence_annotations.jsonl")}
    
    selected_cases = [c for c in cases if c["annotation_count"] > 0]
    I.write_rows(run.path / "frozen_evaluation_cases.jsonl", selected_cases)
    I.write_json(run.path / "protocol.json", {"case_rule": "all signed-cohort cases with existing human components",
                 "case_sha256": I.dbg.sha_file(run.path / "frozen_evaluation_cases.jsonl"),
                 "annotator_limit": "single-reviewer historical and calibration annotations; no new semantic adjudication",
                 "graph_regimes": ["legacy_resolved_graph", "reconstructed_same_file_only"],
                 "policy_scope": "untuned controlled development diagnostic", "serializer": I.SERIALIZER})
    cfg = run.config["p7"]["s3"]
    tok = p5.load_tokenizer(run.config)
    enc = encoder.EncoderCache(device="cpu")
    params = S.MessageParams(**cfg["params"])
    cells = []
    (run.path / "packs").mkdir()
    for case in selected_cases:
        sid = case["sample_id"]
        sample = I.read_sample(parent / "samples" / f"{I.digest(sid)}.json")
        comps = I.evidence_positions(sample, annotations[sid])
        opt, _ = packer.optional_candidates(sample["texts"], sample["levels"]["L0"], sample["pools"]["L1"])
        opt = sorted(opt, key=lambda c: c.uid)
        uids = [c.uid for c in opt]
        tf = sample["target_file"]
        target_text = b"".join(sample["texts"][tf][a:b] for a, b in sample["target"][tf]).decode()
        texts = [b"".join(sample["texts"][c.file][a:b] for a, b in c.ranges).decode() for c in opt]
        embeddings, clipped = enc.embed([target_text, *texts])
        ht, h = embeddings[0], embeddings[1:]
        v = (h @ ht).clamp_min(0) + params.relevance_floor if opt else torch.zeros(0, dtype=S.DTYPE)
        pairs = {frozenset(e): {"resolved"} for e in sample["edges"]}
        if sample["graph_status"] == "unavailable_l1_raw":
            pairs, edge_audit = reconstruct_l1_graph(sample, uids)
            I.write_json(run.path / f"graph-{I.digest(sid)}.json", edge_audit)
            sample["graph_status"] = "reconstructed_same_file_only"
            sample["edges"] = [sorted(e) for e in pairs]

        arrays = {"uids": uids, "h": h.tolist(), "v": v.tolist(), "edges": sample["edges"],
                  "encoder_clipped": clipped, "graph_status": sample["graph_status"]}
        I.write_json(run.path / f"arrays-{I.digest(sid)}.json", arrays)
        arrays_sha = I.dbg.sha_file(run.path / f"arrays-{I.digest(sid)}.json")
        conditions = [("detected", "", 0., 0, pairs, 0, 0)]
        if sample["graph_status"] in {"legacy_resolved_graph", "reconstructed_same_file_only"}:
            for kind in ("delete", "add"):
                for rate in cfg["perturbation_rates"]:
                    if rate == 0:
                        continue
                    for seed in cfg["perturbation_seeds"]:
                        pp, nd, na = p7.perturb(pairs, uids, kind, rate, seed, f"{sid}|L1")
                        conditions.append(("controlled", kind, rate, seed, pp, nd, na))
        memo = {}

        def count(t, memo=memo):
            sha = I.digest(t)
            if sha not in memo:
                memo[sha] = p5.count_tokens(tok, t)
            return memo[sha]

        for condition, kind, rate, seed, pp, nd, na in conditions:
            view = S.View(uids, h, v, p7.gate_matrix(uids, pp), [c.order for c in opt])
            scores, fields = S.static_scores(view, params, seed=run.config["seed"], sample_id=sid)
            budgets = cfg["budgets"] if condition == "detected" else [cfg["perturbation_budget"]]
            policies = S.POLICIES if condition == "detected" else ("appare", "dn_ungated", "gated_subtraction", "gated_mmr", "dependency_mean", "dn_support")
            for budget in budgets:
                for policy in policies:
                    drives = scores[policy].tolist() if policy in S.STATIC_POLICIES else v.tolist()
                    cs = [packer.Candidate(c.uid, c.file, c.ranges, c.closure, drives[i], c.order) for i, c in enumerate(opt)]
                    if policy in S.STATIC_POLICIES:
                        result = I.make_pack(sample, count, budget, cs)
                    else:
                        result = packer.pack_sequential(sample["texts"], tf, sample["levels"]["L0"], cs, budget, count,
                                  S.proposer(policy, view, params, fields.sim), labels=sample.get("labels"), serializer=I.renderer(sample))
                    pack_sha, map_sha = "", ""
                    if result.target_fits_budget:
                        if result.tokens > budget:
                            raise AssertionError("budget violation")
                        segments = I.validate_map(sample, result.files, result.text)
                        pack_sha = I.digest(result.text)
                        (run.path / "packs" / f"{pack_sha}.txt").write_text(result.text)
                        I.write_json(run.path / "packs" / f"{pack_sha}.map.json", segments)
                        map_sha = I.dbg.sha_file(run.path / "packs" / f"{pack_sha}.map.json")
                    is_retained = I.retained(comps, result.files)
                    cells.append({"sample_id": sid, "family": case["family"], "level": "L1", "budget": budget,
                         "policy": policy, "condition": condition, "kind": kind, "rate": rate, "seed": seed,
                         "graph_status": sample["graph_status"], "edges": len(pp), "deleted": nd, "added": na,
                         "arrays_sha256": arrays_sha, "tokens": result.tokens, "feasible": result.target_fits_budget,
                         "selected": result.selected, "pack_sha256": pack_sha, "source_map_sha256": map_sha,
                         "component_count": len(comps), "optional_components": case["optional_components"],
                         "retained_components": sum(status == "reviewed" and p7.covered(pos, result.files.get(f, [])) for f, pos, status in comps),
                         "all_retained": is_retained, "opportunity": case["opportunity"][str(budget)],
                         "joint_feasibility": case["feasibility"][str(budget)]})
        run.logger.info("E1/E2 %s graph=%s edges=%d", sid, sample["graph_status"], len(pairs))
    I.write_rows(run.path / "selection_cells.jsonl", cells)
    summary = {"stage": "E1-E2", "parent": str(parent), "cells": len(cells), "cases": len(selected_cases),
               "families": len({c["family"] for c in selected_cases}), "encoder": enc.info(),
               "budget_violations": 0, "source_map_failures": 0, "conditions": sorted({c["condition"] for c in cells}),
               "graph_pipeline_perturbation": "not_run_no_reconstructed_expansion_graph",
               "decisive_edge_removal": "not_run_no_reviewer_confirmed_edge_annotations",
               "inference": "descriptive development measurements; no superiority or power claim"}
    rows = []
    for budget in cfg["budgets"]:
        for policy in S.POLICIES:
            subset = [c for c in cells if c["budget"] == budget and c["policy"] == policy and c["condition"] == "detected"]
            opportunity = [c for c in subset if c["opportunity"]]
            rows.append({"budget": budget, "policy": policy, "records": len(subset),
                         "feasible": sum(c["feasible"] for c in subset),
                         "all_retained": sum(c["all_retained"] for c in subset),
                         "opportunity_records": len(opportunity), "opportunity_retained": sum(c["all_retained"] for c in opportunity),
                         "opportunity_families": len({c["family"] for c in opportunity})})
    I.write_rows(run.path / "retention_summary.jsonl", rows)
    
    paired = []
    for budget in cfg["budgets"]:
        base = {c["sample_id"]: c for c in cells if c["condition"] == "detected" and c["budget"] == budget and c["policy"] == "appare"}
        for policy in S.REQUIRED_CONTROLS:
            fam = defaultdict(list)
            for c in cells:
                if c["condition"] != "detected" or c["budget"] != budget or c["policy"] != policy or not c["opportunity"]:
                    continue
                fam[c["family"]].append(float(base[c["sample_id"]]["all_retained"]) - float(c["all_retained"]))
            point, lo, hi = p7._boot_diff(fam, cfg.get("bootstrap", 2000), run.config["seed"]) if fam else (None, None, None)
            paired.append({"budget": budget, "contrast": f"appare-minus-{policy}", "families": len(fam),
                           "difference": point, "ci_low": lo, "ci_high": hi, "scope": "descriptive conditional opportunity stratum"})
    I.write_rows(run.path / "paired_retention.jsonl", paired)
    baseline = {(c["sample_id"], c["policy"]): c for c in cells
                if c["condition"] == "detected" and c["budget"] == cfg["perturbation_budget"]}
    graph_rows = []
    for policy in ("appare", "dn_ungated", "gated_subtraction", "gated_mmr", "dependency_mean", "dn_support"):
        for kind in ("delete", "add"):
            for rate in (.1, .25, .5):
                subset = [c for c in cells if c["condition"] == "controlled" and c["policy"] == policy
                          and c["kind"] == kind and c["rate"] == rate]
                fam = defaultdict(list)
                for c in subset:
                    if c["opportunity"]:
                        fam[c["family"]].append(float(c["all_retained"]) - float(baseline[(c["sample_id"], policy)]["all_retained"]))
                point, lo, hi = p7._boot_diff(fam, cfg.get("bootstrap", 2000), run.config["seed"]) if fam else (None, None, None)
                graph_rows.append({"policy": policy, "kind": kind, "rate": rate, "cells": len(subset),
                      "families": len(fam), "realized_edge_changes": sum(c["deleted"]+c["added"] for c in subset),
                      "retention_difference": point, "ci_low": lo, "ci_high": hi,
                      "seed_scope": "within-family repetitions, not independent samples"})
    I.write_rows(run.path / "graph_sensitivity.jsonl", graph_rows)
    return summary
