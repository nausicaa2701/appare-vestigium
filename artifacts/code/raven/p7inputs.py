"""Versioned marked inputs and outcome-blind evidence audit; no model inference.

D1 is immutable. All model-facing bytes are in a separate, hashed input manifest.
Evidence annotations are evaluator-only except the registered fit-only dropout fallback.
"""
from __future__ import annotations

import hashlib
import itertools
import json
from collections import defaultdict
from pathlib import Path

from raven import context, p5, p6, p7, p7a, packer
from raven import inventory as inv
from raven import p7debug as dbg
from raven.p2 import LineageError

SERIALIZER = "raven-target-v2"
COHORT_FIELDS = ("sample_id", "family", "label", "tier", "role", "original_split", *dbg.ROLE_FIELDS)


def digest(value):
    return hashlib.sha256(value.encode() if isinstance(value, str) else value).hexdigest()


def write_json(path, data):
    Path(path).write_text(json.dumps(data, indent=2, sort_keys=True) + "\n")


def write_rows(path, rows):
    with Path(path).open("w") as stream:
        stream.writelines(json.dumps(row, sort_keys=True) + "\n" for row in rows)


def marked(files, target_file, target, labels=None):
    pass




    labels = labels or {}
    parts, segments, pos = [], [], 0

    def add(text):
        nonlocal pos
        parts.append(text)
        pos += len(text)

    targets = packer._merge(target.get(target_file, []))
    if not targets or target_file not in files:
        raise LineageError("marked serializer requires the known target")
    if not all(p7.covered(list(range(a, b)), files[target_file][1]) for a, b in targets):
        raise LineageError("target omitted from serialized input")
    for path in [target_file] + sorted(f for f in files if f != target_file):
        if path not in files:
            continue
        raw, ranges = files[path]
        spans = packer.merge_adjacent(raw, ranges)
        if not spans:
            continue
        if parts:
            add("\n")
        add(f"// file: {labels.get(path, path)}\n")
        boundaries = {x for ab in targets for x in ab} if path == target_file else set()
        for j, (a, b) in enumerate(spans):
            if j:
                add("\n// ...\n")
            points = sorted({a, b} | {x for x in boundaries if a < x < b})
            for start, end in itertools.pairwise(points):
                if path == target_file and any(start == x for x, _ in targets):
                    add("\n/* <av-target> */\n")
                text = raw[start:end].decode("utf-8")
                segments.append({"file": path, "src": [start, end], "out": [pos, pos + len(text)]})
                add(text)
                if path == target_file and any(end == y for _, y in targets):
                    add("\n/* </av-target> */\n")
    add("\n")
    return "".join(parts), segments


def renderer(sample):
    return lambda files, tf, labels=None: marked(files, tf, sample["target"], labels)[0]


def render_files(sample, files):
    return marked({f: (sample["texts"][f], r) for f, r in files.items()}, sample["target_file"],
                  sample["target"], sample.get("labels"))


def validate_map(sample, files, text):
    rebuilt, segments = render_files(sample, files)
    if rebuilt != text:
        raise LineageError("marked pack is not reproducible")
    for seg in segments:
        a, b = seg["src"]
        x, y = seg["out"]
        if text[x:y] != sample["texts"][seg["file"]][a:b].decode():
            raise LineageError("marked source mapping mismatch")
    return segments


def guarded_rows(cfg):
    d = cfg["p7"]["detector"]
    spec = d["operation_manifest"]
    rows = dbg.load_operation_manifest(Path(spec["path"]), spec["sha256"], Path(d["pilot_groups"]),
                                       d["pilot_groups_sha256"])
    src = spec["source_manifest"]
    source = dbg.load_operation_manifest(Path(src["path"]), src["sha256"], Path(d["pilot_groups"]),
                                         d["pilot_groups_sha256"])
    dbg.check_against_source(rows, source)
    dbg.check_funnel(rows, source, json.loads(Path(spec["funnel"]).read_text()), spec["sha256"], src["sha256"])
    if len(rows) != 232 or sum(r["label"] for r in rows) != 78:
        raise LineageError("signed cohort identity changed")
    return rows


def load_samples(cfg, rows, logger=None):
    pass
    spec = cfg["p7"]["detector"]["operation_manifest"]
    records = {r["sample_id"]: r for r in dbg._jsonl(Path(spec["records"])) if r.get("status") == "qualified_l1"}
    wanted = {r["sample_id"] for r in rows}
    for row in rows:
        sid = row["sample_id"]
        if row["source_mode"] == "legacy_snapshot":
            continue
        r = records[sid]
        raw = Path(r["source_path"]).read_bytes()
        if digest(raw) != r["source_sha256"]:
            raise LineageError(f"{sid}: original source hash mismatch")
        path = sid.split("::")[2]
        fu = context.extract(raw, context.grammar_for(path))
        if fu.status != "parsed":
            raise LineageError(f"{sid}: source no longer parses")
        pool = [packer.Candidate(p6._uid(path, u), path, tuple(u.ranges), tuple(u.closure),
                                 order=(0, u.start)) for u in fu.units]
        yield {"sample_id": sid, "texts": {path: raw}, "target_file": path,
               "target": {path: r["target_ranges"]}, "levels": {"L0": {path: r["target_ranges"] + r["closure_ranges"]}},
               "pools": {"L1": pool}, "labels": None, "snapshot": "", "graph_status": "unavailable_l1_raw"}
    legacy = {r["sample_id"] for r in rows if r["source_mode"] == "legacy_snapshot"}
    d = cfg["p7"]["detector"]
    for sample in p6.iter_samples(cfg, Path(d["extract_run"]), Path(d["build_run"]), logger, only=legacy):
        if sample["sample_id"] not in wanted:
            raise LineageError("legacy source outside signed cohort")
        sample["graph_status"] = "legacy_resolved_graph"
        yield sample


def annotations(cfg, rows):
    pass
    d = cfg["p7"]["detector"]
    existing = defaultdict(list)
    for r in inv.read_rows(Path(d["manifest_run"]) / "evidence_components.csv"):
        if r["level"] == "L1":
            existing[r["sample_id"]].append(r)
    return {r["sample_id"]: r.get("review_components") or existing.get(r["sample_id"], []) for r in rows}


def evidence_positions(sample, comps):
    pass
    out = []
    for c in comps:
        f = c["file"]
        if f not in sample["texts"]:
            out.append((f, [], "source_unavailable"))
            continue
        raw = sample["texts"][f]
        a, b = p7.line_span(raw, int(c["start_line"]), int(c["end_line"]))
        pos = p7.nonws(raw, a, b)
        out.append((f, pos, "reviewed" if pos else "empty_annotation"))
    return out


def retained(components, files):
    return bool(components) and all(status == "reviewed" and p7.covered(pos, files.get(f, []))
                                    for f, pos, status in components)


def feasibility(sample, components, count, budgets, max_states=20000):
    pass



    mandatory = sample["levels"]["L0"]
    opt, _ = packer.optional_candidates(sample["texts"], mandatory, sample["pools"]["L1"])
    opt = sorted(opt, key=lambda c: c.uid)
    if not components:
        return {str(b): "unreviewed" for b in budgets}, {}, 0
    if any(status != "reviewed" for _, _, status in components):
        return {str(b): "annotation_unavailable" for b in budgets}, {}, 0
    required = {(f, p) for f, pos, _ in components for p in pos if not p7.covered([p], mandatory.get(f, []))}
    cover = [{x for x in required if x[0] == c.file and any(a <= x[1] < b for a, b in c.span_set)} for c in opt]
    all_cover = set().union(*cover) if cover else set()
    if required - all_cover:
        return {str(b): "absent_from_pool" for b in budgets}, {}, 0
    states = [frozenset()]
    seen, witnesses, minimum = set(), {}, None
    while states and len(seen) < max_states:
        chosen = states.pop()
        if chosen in seen:
            continue
        seen.add(chosen)
        covered = set().union(*(cover[i] for i in chosen)) if chosen else set()
        missing = required - covered
        if missing:
            byte = min(missing)
            states.extend(chosen | {i} for i in range(len(opt)) if byte in cover[i] and i not in chosen)
            continue
        files = {f: list(r) for f, r in mandatory.items()}
        for i in chosen:
            c = opt[i]
            files[c.file] = packer._merge(files.get(c.file, []) + c.span_set)
        text, _ = render_files(sample, files)
        n = count(text)
        minimum = n if minimum is None else min(minimum, n)
        for b in budgets:
            if n <= b and str(b) not in witnesses:
                witnesses[str(b)] = {"tokens": n, "units": [opt[i].uid for i in sorted(chosen)]}
    
    
    status = {str(b): "feasible_witness" if str(b) in witnesses else
              "unknown_search_cap" if states else "no_fitting_minimal_cover" for b in budgets}
    return status, witnesses, len(seen)


def make_pack(sample, count, budget, cands):
    return packer.pack_density_v2(sample["texts"], sample["target_file"], sample["levels"]["L0"],
                                  cands, budget, count, labels=sample.get("labels"), serializer=renderer(sample))


def build(run):
    cfg = run.config
    dbg.verify_baseline(json.loads(Path("artifacts/results/pilot/P7/debug-20261115/debug_baseline.json").read_text()))
    rows = guarded_rows(cfg)  
    d = cfg["p7"]["detector"]
    spec = d["operation_manifest"]
    cohort = [{k: r[k] for k in COHORT_FIELDS} for r in rows]
    write_rows(run.path / "cohort_manifest.jsonl", cohort)
    ann = annotations(cfg, rows)
    write_rows(run.path / "evidence_annotations.jsonl", [{"sample_id": r["sample_id"], "components": ann[r["sample_id"]],
                "evidence_status": r["evidence_status"]} for r in rows])
    tok = p5.load_tokenizer(cfg)
    memo = {}

    def count(t):
        key = digest(t)
        if key not in memo:
            memo[key] = p5.count_tokens(tok, t)
        return memo[key]

    by_id = {r["sample_id"]: r for r in rows}
    inputs, audits, cases, errors = [], [], [], []
    pool_cache = run.path / "samples"
    pool_cache.mkdir()
    (run.path / "packs").mkdir()
    sample_ids = set()
    for s in load_samples(cfg, rows, run.logger):
        sid = s["sample_id"]
        if sid in sample_ids:
            raise LineageError("duplicate source sample")
        sample_ids.add(sid)
        row = by_id[sid]
        
        payload = {"sample_id": sid, "texts": {f: raw.hex() for f, raw in s["texts"].items()},
                   "target_file": s["target_file"], "target": s["target"], "mandatory": s["levels"]["L0"],
                   "labels": s.get("labels"), "graph_status": s["graph_status"],
                   "candidates": [c.__dict__ for c in s["pools"]["L1"]]}
        
        opt, _ = packer.optional_candidates(s["texts"], s["levels"]["L0"], s["pools"]["L1"])
        edges = p7.unit_graph(s, [c.uid for c in opt], p7.edges_index(Path(d["build_run"]))) if s["graph_status"] == "legacy_resolved_graph" else {}
        payload["edges"] = [sorted(e) for e in edges]
        key = digest(sid)
        write_json(pool_cache / f"{key}.json", payload)
        comps = evidence_positions(s, ann[sid])
        budgets = cfg["p7"]["s3"]["budgets"]
        fs, witness, states = feasibility(s, comps, count, budgets)
        full_files = {f: list(r) for f, r in s["levels"]["L0"].items()}
        for c in s["pools"]["L1"]:
            full_files[c.file] = packer._merge(full_files.get(c.file, []) + c.span_set)
        full, _ = render_files(s, full_files)
        full_tokens = count(full)
        target_tokens = count(render_files(s, s["levels"]["L0"])[0])
        optional = sum(status == "reviewed" and not p7.covered(pos, s["levels"]["L0"].get(f, [])) for f, pos, status in comps)
        case = {"sample_id": sid, "family": row["family"], "label": row["label"], "annotation_count": len(comps),
                "optional_components": optional, "target_tokens": target_tokens, "full_tokens": full_tokens,
                "graph_status": s["graph_status"], "edges": len(edges), "feasibility": fs, "witnesses": witness,
                "search_states": states, "opportunity": {str(b): bool(optional and target_tokens <= b < full_tokens
                                                               and fs[str(b)] == "feasible_witness") for b in budgets}}
        cases.append(case)

        def save(view, text, files, fold="", epoch=-1, fallback="", s=s, sid=sid, key=key, full_tokens=full_tokens):
            if not text:
                errors.append({"sample_id": sid, "view": view, "reason": "mandatory_over_budget"})
                return
            n = count(text)
            segments = validate_map(s, files, text)
            h = digest(text)
            path = Path("packs") / f"{h}.txt"
            (run.path / path).write_text(text)
            map_path = Path("packs") / f"{h}.map.json"
            map_data = {"serializer": SERIALIZER, "sample_id": sid, "segments": segments}
            
            map_path = Path("packs") / f"{key}-{view}-{fold}-{epoch}.map.json"
            write_json(run.path / map_path, map_data)
            inputs.append({"sample_id": sid, "view": view, "fold": fold, "epoch": epoch, "pack_path": str(path),
                           "pack_sha256": h, "tokens": n, "source_map": str(map_path),
                           "source_map_sha256": dbg.sha_file(run.path / map_path), "serializer": SERIALIZER,
                           "fallback": fallback, "teacher_eligible": full_tokens <= d["teacher_context_limit"]})

        ref = make_pack(s, count, d["budget"], p6.method_scores("random", cfg["seed"], sid, s["pools"]["L1"]))
        target = make_pack(s, count, d["budget"], [])
        save("reference", ref.text, ref.files)
        save("target_only", target.text, target.files)
        save("teacher", full, full_files)
        for fold in ("0", "1", "2", "final"):
            if dbg.fold_role(row, fold) != "fit":
                continue
            for epoch in range(d["train"]["epochs"]):
                seed = int(d["train"]["seed"])
                subset = [c for c in s["pools"]["L1"] if p7a._keep(seed, epoch, sid, c.uid, .5)]
                if not comps:
                    drop, reason = ref, "unreviewed_reference"
                else:
                    drop = make_pack(s, count, d["budget"], p6.method_scores("random", seed * 1000 + epoch + 1, sid, subset))
                    reason = ""
                    if not retained(comps, drop.files):
                        drop, reason = ref, "required_evidence_not_retained"
                reference_retained = retained(comps, ref.files)
                save("dropout", drop.text, drop.files, fold, epoch, reason)
                audits.append({"sample_id": sid, "family": row["family"], "label": row["label"], "fold": fold,
                               "epoch": epoch, "fallback": reason, "reviewed": bool(comps),
                               "reference_evidence_retained": reference_retained,
                               "accepted_protected": bool(comps) and not reason,
                               "evidence_retained": retained(comps, drop.files),
                               "changed": drop.text != ref.text, "pack_sha256": digest(drop.text)})
        run.logger.info("D3 input %s; optional=%s graph=%s", sid, optional, s["graph_status"])
    if sample_ids != set(by_id):
        raise LineageError("source reconstruction does not match exact signed IDs")
    
    buckets = defaultdict(set)
    for r in inputs:
        buckets[(r["view"], r["fold"], r["epoch"], r["pack_sha256"])].add(by_id[r["sample_id"]]["label"])
    if any(len(labels) > 1 for labels in buckets.values()):
        errors.append({"reason": "opposing_label_input_conflict"})
    write_rows(run.path / "input_manifest.jsonl", inputs)
    write_rows(run.path / "evidence_cases.jsonl", cases)
    write_rows(run.path / "augmentation_audit.jsonl", audits)
    summary = {"stage": "E0-D3", "serializer": SERIALIZER, "d1_manifest_sha256": spec["sha256"],
               "records": len(rows), "input_rows": len(inputs), "errors": errors, "passed": not errors,
               "cases_reviewed": sum(c["annotation_count"] > 0 for c in cases),
               "graph_available_records": sum(c["graph_status"] == "legacy_resolved_graph" for c in cases),
               "opportunity": {str(b): {"records": sum(c["opportunity"][str(b)] for c in cases),
                      "families": len({c["family"] for c in cases if c["opportunity"][str(b)]})} for b in budgets},
               "annotation_limit": "existing human spans only; no new independent semantic review",
               "model_training_enabled": False}
    write_json(run.path / "input_preflight.json", summary)
    return summary


def read_sample(path):
    row = json.loads(Path(path).read_text())
    return {**row, "texts": {f: bytes.fromhex(raw) for f, raw in row["texts"].items()},
            "levels": {"L0": row["mandatory"]},
            "pools": {"L1": [packer.Candidate(**c) for c in row["candidates"]]}}


def verify_bundle(cfg):
    pass
    rows = guarded_rows(cfg)
    d = cfg["p7"]["detector"]
    spec = d.get("input_bundle")
    if not spec:
        raise LineageError("D3 input bundle is not pinned")
    parent = Path(spec["path"])
    hashes_path = parent / "output_hashes.json"
    if dbg.sha_file(hashes_path) != spec["sha256"]:
        raise LineageError("D3 bundle inventory SHA mismatch")
    hashes = json.loads(hashes_path.read_text())
    required = {"input_preflight.json", "cohort_manifest.jsonl", "input_manifest.jsonl", "config.yaml"}
    if not required.issubset(hashes):
        raise LineageError("D3 bundle inventory is missing required inputs")
    
    for path, sha in hashes.items():
        if dbg.sha_file(parent / path) != sha:
            raise LineageError(f"D3 bundle changed: {path}")
    preflight = json.loads((parent / "input_preflight.json").read_text())
    if not preflight["passed"] or preflight["d1_manifest_sha256"] != d["operation_manifest"]["sha256"]:
        raise LineageError("D3 preflight failed or belongs to another signed cohort")
    projection = dbg._jsonl(parent / "cohort_manifest.jsonl")
    expected = [{k: r[k] for k in COHORT_FIELDS} for r in rows]
    if projection != expected:
        raise LineageError("D3 cohort projection differs from signed identities/roles")
    return parent, hashes, rows


def load_bundle(cfg, fold, out_dir, load_tokenizer):
    pass
    parent, _, rows = verify_bundle(cfg)
    d = cfg["p7"]["detector"]
    spec = d["input_bundle"]
    import yaml

    parent_cfg = yaml.safe_load((parent / "config.yaml").read_text())
    input_epochs = parent_cfg["p7"]["detector"]["train"]["epochs"]
    if not d.get("recovery_smoke") and d["train"]["epochs"] != input_epochs:
        raise LineageError("training epochs differ from frozen input masks")
    inputs = dbg._jsonl(parent / "input_manifest.jsonl")
    by_id = {r["sample_id"]: r for r in rows}
    keyed = {}
    for r in inputs:
        sid = r["sample_id"]
        key = (sid, r["view"], r["fold"], r["epoch"])
        if sid not in by_id or key in keyed or r["serializer"] != SERIALIZER:
            raise LineageError("duplicate/extra input ID or serializer mismatch")
        if r["view"] not in {"reference", "target_only", "teacher", "dropout"}:
            raise LineageError("unauthorized input view")
        if r["view"] == "dropout":
            if r["fold"] not in {"0", "1", "2", "final"} or dbg.fold_role(by_id[sid], r["fold"]) != "fit":
                raise LineageError("dropout mask outside current fold fit")
            if r["epoch"] not in range(input_epochs):
                raise LineageError("dropout epoch outside registered allowance")
        elif r["fold"] != "" or r["epoch"] != -1:
            raise LineageError("reference view has unauthorized fold/epoch")
        keyed[key] = r
    required = {(sid, view, "", -1) for sid in by_id for view in ("reference", "target_only", "teacher")}
    required |= {(sid, "dropout", f, e) for sid, r in by_id.items() for f in ("0", "1", "2", "final")
                 if dbg.fold_role(r, f) == "fit" for e in range(input_epochs)}
    if set(keyed) != required:
        raise LineageError("D3 views are missing or extra")
    tok = load_tokenizer()
    texts, roles = {}, {}
    for sid, row in by_id.items():
        views = {}
        for view in ("reference", "target_only"):
            entry = keyed[(sid, view, "", -1)]
            data = (parent / entry["pack_path"]).read_bytes()
            if digest(data) != entry["pack_sha256"]:
                raise LineageError("pack changed after inventory verification")
            text = data.decode()
            if p5.count_tokens(tok, text) != entry["tokens"] or entry["tokens"] > d["budget"]:
                raise LineageError("actual tokenizer count differs or exceeds detector budget")
            views[view] = text
        views["dropout"] = []
        if dbg.fold_role(row, fold) == "fit":
            for e in range(input_epochs):
                entry = keyed[(sid, "dropout", fold, e)]
                data = (parent / entry["pack_path"]).read_bytes()
                if digest(data) != entry["pack_sha256"]:
                    raise LineageError("dropout pack hash mismatch")
                text = data.decode()
                if p5.count_tokens(tok, text) != entry["tokens"] or entry["tokens"] > d["budget"]:
                    raise LineageError("dropout token budget mismatch")
                views["dropout"].append(text)
        texts[sid] = views
        ref = keyed[(sid, "reference", "", -1)]
        roles[sid] = {"family": row["family"], "label": row["label"], "role": dbg.fold_role(row, fold),
                      "split": row["original_split"], "tokens": ref["tokens"], "full_forward_eligible": ref["teacher_eligible"]}
    out_dir = Path(out_dir)
    write_rows(out_dir / "actual_input_ids.jsonl", [{"sample_id": sid, "role": roles[sid]["role"],
                 "reference_sha256": digest(texts[sid]["reference"])} for sid in sorted(roles)])
    guard = {"cohort_source": "signed_D1_plus_input_bundle", "manifest_sha256": d["operation_manifest"]["sha256"],
             "input_bundle_sha256": spec["sha256"], "serializer": SERIALIZER, "records": len(rows),
             "actual_input_ids_sha256": dbg.sha_file(out_dir / "actual_input_ids.jsonl")}
    write_json(out_dir / "input_preflight.json", {**guard, "passed": True})
    return roles, texts, guard
