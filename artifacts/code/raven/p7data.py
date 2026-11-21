"""Development-only L1 pair qualification and prediction-blind dropout evidence audit."""

from __future__ import annotations

import hashlib
import json
import os
import re
import time
import urllib.error
import urllib.parse
import urllib.request
import zipfile
from collections import Counter, defaultdict
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

from raven import context, overlap, p5, p6, p7, p7a, packer, pairs
from raven import inventory as inv
from raven.p2 import LineageError, _digest, _json

INVENTORY = Path("artifacts/results/pilot/P2/runs/20261025T150240Z-raven-pilot-p2-inventory-e94ad689")
GROUPING = Path("artifacts/results/pilot/P4/runs/20261104T195303Z-raven-pilot-p3-overlap-f553e9bd")
PACK = Path("artifacts/results/pilot/P6/runs/20261107T132948Z-raven-pilot-p6-pack-cells-e09f7885")
MANIFEST = Path("artifacts/results/pilot/P7/recovery-runs/20261113T041648Z-raven-pilot-p7-recovery-p7-manifest-f2631850")
MAX_FILE = 1 << 20


def sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def allowed_pairs(inventory, assignments):
    pass
    found = set()
    for rid, row in inventory.items():
        partner = inventory.get(row["paired_id"])
        if partner is None or row["label"] == partner["label"]:
            continue
        ids = tuple(sorted((rid, partner["record_id"])))
        groups = [assignments.get("jsvul:" + x, {}) for x in ids]
        if all(g.get("role") == "pilot_dev" and g.get("split") == "train" for g in groups):
            if groups[0]["group_id"] != groups[1]["group_id"]:
                raise LineageError("paired records cross families")
            found.add(ids)
    return sorted(found, key=lambda pair: sha(("p7-data-v1|42|" + "|".join(pair)).encode()))


def selected_bodies(path, wanted):
    pass
    out = {}
    pattern = re.compile(rb'(?<!\\)"id"\s*:\s*("(?:\\.|[^"\\])*")')
    with zipfile.ZipFile(path) as archive:
        for split in inv.JSVUL_SPLITS:
            for raw in archive.open(split + ".jsonl"):
                match = pattern.search(raw)
                if match and json.loads(match[1]) in wanted:
                    record = json.loads(raw)
                    out[record["id"]] = record.get("body") or ""
    return out


def conflict_pair_closure(pair_results, conflicting_samples):
    pass
    excluded = set(conflicting_samples)
    changed = True
    while changed:
        changed = False
        for pair in pair_results:
            ids = {"jsvul:" + rid for rid in pair["pair"]}
            if pair["status"] in {"qualified_pair_l1", "input_conflict_excluded"} and ids & excluded:
                changed |= bool(ids - excluded)
                excluded.update(ids)
                pair["status"] = "input_conflict_excluded"
    return excluded


def fetch_original(row, data_root, cache, allow_network):
    pass
    rid, project, revision, file = (row[k] for k in ("record_id", "project", "revision", "file"))
    if not re.fullmatch(r"[0-9a-f]{40}", revision) or not re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", project):
        return {"record_id": rid, "status": "invalid_revision_or_project"}
    if Path(file).is_absolute() or ".." in Path(file).parts:
        return {"record_id": rid, "status": "invalid_file_path"}
    url = f"https://raw.githubusercontent.com/{project}/{revision}/{urllib.parse.quote(file)}"
    destination = cache / (sha(url.encode()) + ".source")
    snapshot = data_root / "snapshots/jsvul" / project.replace("/", "__") / (revision + ".tar.gz")
    from raven.provenance import _tar_member

    body, mode = None, ""
    if snapshot.is_file():
        body, _ = _tar_member(snapshot, file)
        if body is not None:
            mode = "cached_snapshot_member"
    if body is None and destination.is_file():
        body, mode = destination.read_bytes(), "pinned_raw_cache"
    if body is None and allow_network:
        for attempt in range(2):
            try:
                request = urllib.request.Request(url, headers={"User-Agent": "Appare-Vestigium-pilot-qualification"})
                with urllib.request.urlopen(request, timeout=20) as response:
                    body = response.read(MAX_FILE + 1)
                mode = "pinned_raw_download"
                break
            except (OSError, urllib.error.URLError) as error:
                if attempt:
                    return {"record_id": rid, "status": "fetch_failed", "detail": str(error), "url": url}
                time.sleep(0.5)
    if body is None:
        return {"record_id": rid, "status": "source_missing_offline", "url": url}
    if len(body) > MAX_FILE:
        return {"record_id": rid, "status": "file_over_cap", "url": url}
    destination.write_bytes(body)
    return {"record_id": rid, "status": "source_recovered", "url": url, "source_mode": mode,
            "source_sha256": sha(body), "source_bytes": len(body), "source_path": str(destination),
            "snapshot_available": snapshot.is_file()}


def qualify_record(row, body, source, tokenizer, alignment, *, reviewed_near_span=None):
    result = {**source, "label": int(row["label"]), "sample_id": "jsvul:" + row["record_id"]}
    if source["status"] != "source_recovered":
        return result
    if sha(body.encode()) != row["body_sha256"]:
        raise LineageError("curated body differs from pinned inventory")
    raw = Path(source["source_path"]).read_bytes()
    candidates = list(overlap.functions_in(raw, row["extension"], 1))
    tokens, _ = overlap.snippet_tokens(body.encode(), row["extension"])
    matched = pairs.align_body(tokens, candidates, alignment)
    result["alignment"] = matched
    near_accepted = (matched["status"] == "unique_near" and reviewed_near_span is not None
                     and (matched["start_line"], matched["end_line"]) == tuple(reviewed_near_span))
    if matched["status"] != "unique_exact" and not near_accepted:
        return {**result, "status": "alignment_" + matched["status"]}
    grammar = context.grammar_for(row["file"])
    if grammar is None:
        return {**result, "status": "unsupported_grammar"}
    fu = context.extract(raw, grammar)
    if fu.status != "parsed":
        return {**result, "status": fu.status}
    target = context.map_target(fu, int(matched["start_line"]), int(matched["end_line"]))
    if target.status not in {"coincides", "nested"}:
        return {**result, "status": target.status}
    mandatory = {row["file"]: target.target + target.closure}
    
    cs = [packer.Candidate(p6._uid(row["file"], u), row["file"], tuple(u.ranges), tuple(u.closure),
                           order=(0, u.start)) for u in fu.units]
    count = lambda text: p5.count_tokens(tokenizer, text)
    estimates = {c.uid: count(b"".join(raw[a:b] for a, b in packer._merge(c.span_set)).decode()) for c in cs}
    packed = packer.pack({row["file"]: raw}, row["file"], mandatory,
                         p6.method_scores("random", 42, result["sample_id"], cs), 2048, count, estimates=estimates)
    if not packed.target_fits_budget:
        return {**result, "status": "target_over_budget", "target_tokens": packed.mandatory_tokens}
    if re.search(r"\b(?:CVE-\d{4}-\d+|GHSA-[a-z0-9-]+)\b", packed.text, re.IGNORECASE):
        return {**result, "status": "input_marker_review_required"}
    full = packer.serialise({row["file"]: (raw, [r for c in cs for r in c.span_set])}, row["file"])
    return {**result, "status": "qualified_l1", "target_name": target.unit.name,
            "target_mapping": target.status, "target_ranges": target.target, "closure_ranges": target.closure,
            "reference_sha256": sha(packed.text.encode()), "tokens": packed.tokens,
            "target_tokens": packed.mandatory_tokens, "full_tokens": count(full), "pack_text": packed.text,
            "source_map_ok": p7.source_map_ok(packed, {row["file"]: raw}, {row["file"]: target.target}, None)}


def run_qualification(run, allow_network=False):
    data_root = Path(os.environ["RAVEN_DATA_ROOT"])
    for path, filename in [(INVENTORY, "inventory_summary.json"), (GROUPING, "overlap_summary.json")]:
        summary = json.loads((path / filename).read_text())
        if "output_files" in summary and _digest(path, tuple(summary["output_files"])) != summary["output_files"]:
            raise LineageError(f"{path} outputs differ from their pinned manifest")
    role_digest = sha(Path(run.config["p7"]["detector"]["pilot_groups"]).read_bytes())
    if role_digest != run.config["p7"]["detector"]["pilot_groups_sha256"]:
        raise LineageError("pilot group-role file changed")
    inventory = {r["record_id"]: r for r in inv.read_rows(INVENTORY / "inventory_jsvul.csv.gz")}
    assignments = {r["node"]: r for r in inv.read_rows(GROUPING / "split_assignment.csv.gz")}
    candidates = allowed_pairs(inventory, assignments)
    wanted = {rid for pair in candidates for rid in pair}
    bodies = selected_bodies(data_root / "raw/jsvul/js_vul.zip", wanted)
    if set(bodies) != wanted:
        raise LineageError("curated bodies missing for allowed records")
    cache = Path("artifacts/cache/p7-data-source")
    cache.mkdir(parents=True, exist_ok=True)
    records = [inventory[rid] for rid in sorted(wanted)]
    with ThreadPoolExecutor(max_workers=4) as pool:
        fetched = list(pool.map(lambda r: fetch_original(r, data_root, cache, allow_network), records))
    tok = p5.load_tokenizer(run.config)
    qualified = {}
    for row, source in zip(records, fetched, strict=True):
        result = qualify_record(row, bodies[row["record_id"]], source, tok, run.config["p4"]["alignment"])
        if result["status"] == "qualified_l1" and not result["source_map_ok"]:
            raise LineageError("qualified pack has invalid source mapping")
        result["family"] = assignments["jsvul:" + row["record_id"]]["group_id"]
        qualified[row["record_id"]] = result
    pair_results, ready = [], {}
    for pair in candidates:
        a, b = (qualified[rid] for rid in pair)
        status = "qualified_pair_l1"
        if any(r["status"] != "qualified_l1" for r in (a, b)):
            status = "side_not_qualified"
        elif a["target_name"] != b["target_name"]:
            status = "target_name_review_required"
        elif a["reference_sha256"] == b["reference_sha256"]:
            status = "opposite_labels_identical_input"
        pair_results.append({"pair": list(pair), "family": a["family"], "status": status,
                             "side_statuses": [a["status"], b["status"]]})
        if status == "qualified_pair_l1":
            ready.update({r["sample_id"]: r for r in (a, b)})
    legacy = {r["sample_id"]: r for r in inv.read_rows(MANIFEST / "cohort_manifest.csv")
              if r["source"] == "jsvul" and r["level"] == "L1" and r["eligible"] == "true"
              and r["original_split"] == "train" and r["scoring_eligible_2048"] == "true"}
    merged = {s: {"sample_id": s, "family": r["family"], "label": int(r["label"]), "tier": "legacy_pilot"}
              for s, r in legacy.items()}
    for sid, row in ready.items():
        merged[sid] = {"sample_id": sid, "family": row["family"], "label": row["label"],
                       "tier": "exact_aligned_pair_not_reproduced", "reference_sha256": row["reference_sha256"]}
    buckets = defaultdict(list)
    cells = {(r["sample_id"], r["method"]): r for r in inv.read_rows(PACK / "pack_cells.csv")
             if r["level"] == "L1" and r["budget_name"] == "2048"}
    for sid, row in merged.items():
        digest = row.get("reference_sha256", cells.get((sid, "random"), {}).get("pack_sha256"))
        if digest:
            buckets[digest].append(sid)
    conflicts = {sid for ids in buckets.values() if len({merged[s]["label"] for s in ids}) > 1 for sid in ids}
    excluded = conflict_pair_closure(pair_results, conflicts)
    for sid in excluded:
        merged.pop(sid)
        ready.pop(sid, None)
    labels = defaultdict(set)
    for row in merged.values():
        labels[row["family"]].add(row["label"])
    split = p7.stratified_split_families(labels)
    (run.path / "packs").mkdir()
    legacy_only = set(merged) - set(ready)
    d = run.config["p7"]["detector"]
    legacy_texts = p7a.build_texts(run.config, Path(d["extract_run"]), Path(d["build_run"]), cells,
                                 legacy_only, 1, 0, 1.0, run.logger) if legacy_only else {}
    reviewed_ids = {r["sample_id"] for r in inv.read_rows(MANIFEST / "evidence_components.csv") if r["level"] == "L1"}
    exports = []
    for sid, row in sorted(merged.items()):
        text = ready[sid]["pack_text"] if sid in ready else legacy_texts[sid]["reference"]
        path = run.path / "packs" / (sha(sid.encode()) + ".txt")
        path.write_text(text)
        exports.append({**row, "role": "pilot_dev", "original_split": "train", **split[row["family"]],
                        "reference_sha256": sha(text.encode()), "pack_path": str(path),
                        "tokens": ready[sid]["tokens"] if sid in ready else int(cells[(sid, "random")]["tokens"]),
                        "full_tokens": ready[sid]["full_tokens"] if sid in ready else int(legacy[sid]["full_tokens"]),
                        "full_forward_eligible": (ready[sid]["full_tokens"] if sid in ready
                                                  else int(legacy[sid]["full_tokens"])) <= 7836,
                        "source_mode": ready[sid]["source_mode"] if sid in ready else "legacy_snapshot",
                        "evidence_status": "existing_reviewed_spans" if sid in reviewed_ids else "evidence_unreviewed"})
    counts = {}
    for field in ("inner_role", "fold0_role", "fold1_role", "fold2_role"):
        counts[field] = {role: {"records": sum(r[field] == role for r in exports),
                                "positives": sum(r[field] == role and r["label"] == 1 for r in exports),
                                "families": len({r["family"] for r in exports if r[field] == role})}
                         for role in ("fit", "calibration", "assessment")}
    for sid, row in ready.items():
        path = run.path / "packs" / (sha(sid.encode()) + ".txt")
        path.write_text(row["pack_text"])
        row["pack_path"] = str(path)
    def dump_lines(path, rr):
        path.write_text("".join(json.dumps(r) + "\n" for r in rr))
    dump_lines(run.path / "records.jsonl", [{k: v for k, v in r.items() if k != "pack_text"} for r in qualified.values()])
    dump_lines(run.path / "pairs.jsonl", pair_results)
    dump_lines(run.path / "operation_manifest.jsonl", exports)
    dump_lines(run.path / "review_queue.jsonl", [r for r in qualified.values()
                                                if r["status"] != "qualified_l1"])
    result = {"candidate_pairs": len(candidates), "candidate_records": len(wanted),
              "candidate_families": len({assignments['jsvul:' + p[0]]["group_id"] for p in candidates}),
              "source_statuses": dict(Counter(r["status"] for r in fetched)),
              "record_statuses": dict(Counter(r["status"] for r in qualified.values())),
              "pair_statuses": dict(Counter(r["status"] for r in pair_results)),
              "new_records": len(set(ready) - set(legacy)), "new_positives": sum(r["label"] for s, r in ready.items() if s not in legacy),
              "merged_records": len(merged), "merged_positives": sum(r["label"] for r in merged.values()),
              "conflicting_input_records_excluded": sorted(conflicts), "split_counts": counts,
              "pair_closure_exclusions": sorted(excluded),
              "net_positive_change": sum(r["label"] for r in merged.values()) - sum(int(r["label"]) for r in legacy.values()),
              "network_allowed": allow_network, "behaviour_reproduced": False, "training_started": False}
    result["output_files"] = _digest(run.path, ("records.jsonl", "pairs.jsonl", "operation_manifest.jsonl", "review_queue.jsonl"))
    _json(run.path / "qualification_summary.json", result)
    print(json.dumps(result, indent=2))
    return result


def audit_dropout(run):
    pass
    manifest = inv.read_rows(MANIFEST / "cohort_manifest.csv")
    eligible = {r["sample_id"]: r for r in manifest if r["source"] == "jsvul" and r["level"] == "L1"
                and r["role"] == "pilot_dev" and r["original_split"] == "train" and r["label"] == "1"
                and r["eligible"] == "true" and r["scoring_eligible_2048"] == "true"}
    components = defaultdict(list)
    case_meta = {r["sample_id"]: r for r in inv.read_rows(MANIFEST / "evidence_cases.csv") if r["level"] == "L1"}
    for r in inv.read_rows(MANIFEST / "evidence_components.csv"):
        if r["sample_id"] in eligible and r["level"] == "L1":
            components[r["sample_id"]].append(r)
    cfg = run.config
    d = cfg["p7"]["detector"]
    tok = p5.load_tokenizer(cfg)
    count = lambda text: p5.count_tokens(tok, text)
    cells = p7a._pack_cells(PACK, "L1", "2048")
    rebuilt, cases = [], []
    (run.path / "packs").mkdir()
    for sample in p6.iter_samples(cfg, Path(d["extract_run"]), Path(d["build_run"]), run.logger,
                                   only=set(eligible)):
        sid = sample["sample_id"]
        if sid not in components:
            cases.append({"sample_id": sid, "family": eligible[sid]["family"], "status": "evidence_unreviewed"})
            continue
        tf = sample["target_file"]
        mandatory = {tf: sample["levels"]["L0"][tf]}
        pool = sample["pools"]["L1"]
        estimates = {c.uid: count(b"".join(sample["texts"][c.file][a:b] for a, b in packer._merge(c.span_set)).decode())
                     for c in pool}

        def build(candidates, seed, sample=sample, tf=tf, mandatory=mandatory, sid=sid, estimates=estimates):
            return packer.pack(sample["texts"], tf, mandatory,
                               p6.method_scores("random", seed, sid, candidates), 2048, count,
                               labels=sample["labels"], prompt=cfg["p6"]["prompt_prefix"], estimates=estimates,
                               slack=int(cfg["p6"]["estimate_slack_tokens"]))

        ref = build(pool, cfg["seed"])
        if sha(ref.text.encode()) != cells[(sid, "random")]["pack_sha256"]:
            raise LineageError("audit reference differs from canonical P6")
        views = [("reference", -1, ref)]
        for epoch in range(3):
            kept = [c for c in pool if p7a._keep(0, epoch, sid, c.uid, 0.5)]
            views.append(("dropout", epoch, build(kept, epoch + 1)))
        optional = [r for r in components[sid] if r["provenance"] != "mandatory"]
        cases.append({"sample_id": sid, "family": eligible[sid]["family"], "status": "reviewed",
                      "components": len(components[sid]), "optional_components": len(optional),
                      "joint_fits_2048": case_meta[sid]["joint_fits_2048"],
                      **{f"fold{f}_role": eligible[sid][f"fold{f}_role"] for f in range(3)}})
        for view, epoch, packed in views:
            if not packed.target_fits_budget or packed.tokens > 2048:
                raise LineageError("audited dropout pack violates its feasibility contract")
            if not p7.source_map_ok(packed, sample["texts"], sample["target"], sample["labels"]):
                raise LineageError("audited dropout source mapping failed")
            pack_name = sha((sid + "|" + view + "|" + str(epoch)).encode()) + ".txt"
            (run.path / "packs" / pack_name).write_text(packed.text)
            for comp in components[sid]:
                file = comp["file"]
                positions = (p7.effective_positions(sample, file, int(comp["start_line"]), int(comp["end_line"]))
                             if file in sample["texts"] else [])
                present = comp["pool_present"] == "true"
                retained = bool(positions) and p7.covered(positions, packed.files.get(file, []))
                ref_retained = bool(positions) and p7.covered(positions, ref.files.get(file, []))
                is_mandatory = comp["provenance"] == "mandatory"
                if is_mandatory and positions and not retained:
                    raise LineageError("dropout removed a reviewed mandatory component")
                reason = ("retained" if retained else "absent_from_L1_pool" if not present else
                          "lost_in_reference" if not ref_retained else "lost_by_dropout")
                rebuilt.append({"sample_id": sid, "family": eligible[sid]["family"], "view": view,
                                "epoch": epoch, "span_index": comp["span_index"], "file": file,
                                "start_line": comp["start_line"], "end_line": comp["end_line"],
                                "evidence_role": comp["role"], "mandatory": is_mandatory,
                                "pool_present": present, "retained": retained, "reference_retained": ref_retained,
                                "effective_bytes": len(positions), "loss_reason": reason, "tokens": packed.tokens,
                                "pack_sha256": sha(packed.text.encode()), "pack_path": str(run.path / "packs" / pack_name)})
    optional_rows = [r for r in rebuilt if not r["mandatory"] and r["view"] == "dropout"]
    result = {"eligible_positive_records": len(eligible), "reviewed_positive_records": sum(r["status"] == "reviewed" for r in cases),
              "unreviewed_positive_records": sum(r["status"] == "evidence_unreviewed" for r in cases),
              "reviewed_optional_evidence_cases": sum(r.get("optional_components", 0) > 0 for r in cases),
              "optional_component_dropout_views": len(optional_rows),
              "optional_loss_reasons": dict(Counter(r["loss_reason"] for r in optional_rows)),
              "optional_component_fit_fold_views": sum(eligible[r["sample_id"]][f"fold{f}_role"] == "fit"
                                                        for r in optional_rows for f in range(3)),
              "lost_optional_fit_fold_views": sum(r["loss_reason"] == "lost_by_dropout"
                                                   and eligible[r["sample_id"]][f"fold{f}_role"] == "fit"
                                                   for r in optional_rows for f in range(3)),
              "mandatory_dropout_views": sum(r["mandatory"] and r["view"] == "dropout" for r in rebuilt),
              "mandatory_components_lost": sum(r["mandatory"] and not r["retained"] for r in rebuilt),
              "budget": 2048, "epochs": 3, "seed": 0, "keep_probability": 0.5, "training_started": False}
    if rebuilt:
        inv.write_rows(run.path / "component_audit.csv", tuple(rebuilt[0]), rebuilt)
    (run.path / "case_audit.jsonl").write_text("".join(json.dumps(r) + "\n" for r in cases))
    result["output_files"] = _digest(run.path, ("component_audit.csv", "case_audit.jsonl"))
    _json(run.path / "dropout_audit_summary.json", result)
    print(json.dumps(result, indent=2))
    return result
