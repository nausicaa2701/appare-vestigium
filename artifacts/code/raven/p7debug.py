"""P7 debug gates D0-D2: pinned baseline, calibration-pair review validation, operation-manifest loader.

Nothing here reads a model input before its guard passes, and nothing here trains or scores.

* **D0** ``pin_baseline`` / ``verify_baseline``: run IDs, decisions and file digests of the old gate,
  qualification, dropout audit, role file and review package. ``readiness_fingerprint`` covers source,
  configs, P7 scripts/tests, decision docs and the pinned manifest/review files, so any edit makes an
  earlier readiness stale (``assert_ready``).
* **D1** ``validate_review``: structure/consistency of the human review CSV (one row per component)
  against packets, source and manifest hashes. ``apply_review``: pair-complete exclusion, recomputed
  role counts and the registered calibration coverage floor; existing operation roles are kept.
* **D2** ``load_operation_manifest``: path + SHA-256 pin, then the role guard (``pilot_groups.csv``,
  pinned SHA) on metadata only. ``preflight`` reads pack text only after the guard passes.
"""

from __future__ import annotations

import csv
import hashlib
import json
from collections import Counter, defaultdict
from datetime import date
from pathlib import Path
from typing import Any

from raven.p2 import LineageError

ROOT = Path(__file__).resolve().parents[3]
P7 = Path("artifacts/results/pilot/P7")
GATE_RUN = P7 / "recovery-runs/20261113T064441Z-raven-pilot-p7-recovery-detector-gate-a964ddda"
RECOVERY_MANIFEST_RUN = P7 / "recovery-runs/20261113T041648Z-raven-pilot-p7-recovery-p7-manifest-f2631850"
QUALIFICATION_RUN = P7 / "data-runs/20261113T133336Z-raven-p7-data-p7-data-qualification-8c230c04"
DROPOUT_AUDIT_RUN = P7 / "data-runs/20261113T133337Z-raven-p7-dropout-audit-p7-dropout-audit-1a2605f5"
REVIEW_DIR = P7 / "data-reviews/calibration-20261113"
PILOT_GROUPS = Path("artifacts/data/pilot_groups.csv")
PILOT_GROUPS_SHA256 = "46d0d35ce48b6541278ddd6207e3e0bf0a51147f5e807bee1123824e838c6d49"
RECOVERY_CONFIG = Path("artifacts/configs/pilot/p7-recovery.yaml")

FOLD_FIELDS = ("fold0_role", "fold1_role", "fold2_role")
ROLE_FIELDS = ("inner_role", *FOLD_FIELDS)
OPERATION_ROLES = {"fit", "calibration", "assessment"}

VERDICTS = {"accept", "reject", "needs_context"}
YES_NO = {"yes", "no"}
EVIDENCE_ROLES = {"source", "sink", "validation", "precondition", "dependency"}
EVIDENCE_SCOPES = {"target", "same_file"}
REVIEWER_KINDS = {"human", "llm"}
REVIEW_FIELDS = ("pair_key", "sample_id", "label", "verdict", "label_scope_valid", "context_sufficient",
                 "evidence_file", "start_line", "end_line", "evidence_role", "evidence_scope",
                 "reviewer", "reviewer_kind", "date", "notes")


COVERAGE_FLOOR = {"min_positive": 5, "min_positive_families": 3, "min_negative": 5}


def sha_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sha_file(path: Path) -> str:
    return sha_bytes(Path(path).read_bytes())


def _tree(path: Path) -> dict[str, str]:
    pass
    path = Path(path)
    return {str(p.relative_to(path)): sha_file(p) for p in sorted(path.rglob("*")) if p.is_file()}


def _tree_sha(files: dict[str, str]) -> str:
    return sha_bytes(json.dumps(files, sort_keys=True).encode())


def _jsonl(path: Path) -> list[dict]:
    return [json.loads(line) for line in Path(path).read_text().splitlines() if line.strip()]



def _check_summary(run: Path, summary_name: str) -> dict:
    summary = json.loads((run / summary_name).read_text())
    for name, expected in summary.get("output_files", {}).items():
        if sha_file(run / name) != expected:
            raise LineageError(f"{run.name}/{name} differs from its recorded digest")
    return summary


def pin_baseline(root: Path = ROOT) -> dict[str, Any]:
    pass
    r = Path(root)
    gate = json.loads((r / GATE_RUN / "gate.json").read_text())
    folds = {}
    for variant, rows in gate["folds"].items():
        folds[variant] = [{"fold": f["fold"], "run": f["run"], "steps": f["steps"], "planned_steps": f["planned_steps"],
                           "reference_confusion_tp_fp_tn_fn": f["thresholds"]["reference"]["confusion"],
                           "reference_threshold": f["thresholds"]["reference"]["threshold"]} for f in rows]
    train_runs = {}
    for name in gate["train_runs"]:
        run = r / P7 / "recovery-runs" / name
        train_runs[name] = {k: sha_file(run / k) for k in ("train_summary.json", "predictions.csv", "config.yaml")
                            if (run / k).exists()}
    qual = _check_summary(r / QUALIFICATION_RUN, "qualification_summary.json")
    audit = _check_summary(r / DROPOUT_AUDIT_RUN, "dropout_audit_summary.json")
    _check_summary(r / RECOVERY_MANIFEST_RUN, "manifest_summary.json")
    groups_sha = sha_file(r / PILOT_GROUPS)
    if groups_sha != PILOT_GROUPS_SHA256:
        raise LineageError("pilot_groups.csv differs from the pinned SHA-256")
    selection = json.loads((r / REVIEW_DIR / "selection.json").read_text())
    for pair in selection["selected_pairs"]:
        if sha_file(r / REVIEW_DIR / f"{pair['pair_key']}.md") != pair["packet_sha256"]:
            raise LineageError(f"review packet {pair['pair_key']} changed")
    packs = {p.name: sha_file(p) for p in sorted((r / QUALIFICATION_RUN / "packs").glob("*.txt"))}
    runs = {"gate": GATE_RUN, "recovery_manifest": RECOVERY_MANIFEST_RUN, "qualification": QUALIFICATION_RUN,
            "dropout_audit": DROPOUT_AUDIT_RUN}
    return {
        "version": "p7-debug-baseline-v1",
        "created": date.today().isoformat(),
        "runs": {k: {"path": str(v), "run_id": v.name, "tree_sha256": _tree_sha(_tree(r / v))} for k, v in runs.items()},
        "old_gate": {"primary_variant": gate["primary_variant"],
                     "decisions": {k: v["decision"] for k, v in gate["decisions"].items()},
                     "checks": {k: v["checks"] for k, v in gate["decisions"].items()},
                     "report": gate["report"], "gate_config": gate["gate"], "train_config": gate["train_config"],
                     "folds": folds, "train_runs": train_runs,
                     "gate_files": {k: sha_file(r / GATE_RUN / k) for k in ("gate.json", "gate.csv", "config.yaml")}},
        "qualification": {"output_files": qual["output_files"], "merged_records": qual["merged_records"],
                          "merged_positives": qual["merged_positives"], "pair_statuses": qual["pair_statuses"],
                          "pair_closure_exclusions": qual["pair_closure_exclusions"],
                          "split_counts": qual["split_counts"], "packs": len(packs), "packs_sha256": _tree_sha(packs)},
        "dropout_audit": {k: audit[k] for k in ("output_files", "optional_component_dropout_views",
                                                "optional_loss_reasons", "optional_component_fit_fold_views",
                                                "lost_optional_fit_fold_views", "mandatory_components_lost")},
        "pilot_groups": {"path": str(PILOT_GROUPS), "sha256": groups_sha},
        "review_package": {"path": str(REVIEW_DIR),
                           "selection_sha256": sha_file(r / REVIEW_DIR / "selection.json"),
                           "worksheet_sha256": sha_file(r / REVIEW_DIR / "review_worksheet.csv"),
                           "packets": {p["pair_key"]: p["packet_sha256"] for p in selection["selected_pairs"]},
                           "review_complete": selection["review_complete"]},
        "recovery_config": {"path": str(RECOVERY_CONFIG), "sha256": sha_file(r / RECOVERY_CONFIG)},
        "thresholds": {
            "measured_old": {"primary_mcc": gate["report"][f"{gate['primary_variant']}/detector/reference"]["mcc"],
                             "primary_ci": [gate["report"][f"{gate['primary_variant']}/detector/reference"]["ci_low"],
                                            gate["report"][f"{gate['primary_variant']}/detector/reference"]["ci_high"]]},
            "registered_old": {"gate": gate["gate"], "smoke": {"fit_per_class": 2, "max_tokens": 1024, "epochs": 16,
                                                               "fit_mcc_at_0_5": 0.5, "loss_ratio": 0.9,
                                                               "roundtrip": 0.001}},
            "proposed_new": [
                {"item": "calibration_coverage_floor", "value": COVERAGE_FLOOR, "date": "2026-11-15",
                 "reason": "two positives per outer calibration made the old threshold unstable",
                 "claim_effect": "operational floor only; not evidence of statistical power"},
                {"item": "evidence_preserving_dropout", "value": "reviewed fit masks keep confirmed components; "
                 "otherwise reference fallback; unreviewed fit records use the reference input",
                 "date": "2026-11-15", "reason": "audit lost a reviewed sink (Avo epoch 0)",
                 "claim_effect": "augmentation change; needs version and disclosure"}]},
    }




BASELINE_SECTIONS = ("runs", "old_gate", "qualification", "dropout_audit", "pilot_groups", "review_package",
                     "recovery_config")


def verify_baseline(baseline: dict, root: Path = ROOT) -> dict[str, Any]:
    pass
    fresh = pin_baseline(root)
    for key in BASELINE_SECTIONS:
        if fresh[key] != baseline[key]:
            raise LineageError(f"baseline section {key!r} differs from the pinned state")
    return {"verified": True, "sections": len(BASELINE_SECTIONS)}


def readiness_fingerprint(root: Path = ROOT, pinned: tuple[Path, ...] = ()) -> dict[str, str]:
    pass
    from raven.runlog import source_snapshot

    r = Path(root)
    paths = sorted({*(r / "artifacts/scripts/p7").glob("*.py"), *(r / "artifacts/tests").glob("test_p7*.py"),
                    *(r / "docs").glob("p7-*decisions*.md"), *(r / p for p in pinned)})
    out = {str(p.relative_to(r)): sha_file(p) for p in paths}
    out["production_source"] = source_snapshot(r)["source_sha256"]
    return out


def assert_ready(ready: dict | None, current: dict[str, str]) -> None:
    if not ready:
        raise RuntimeError("no readiness record; run the readiness check first")
    if not ready.get("passed"):
        raise RuntimeError("readiness failed")
    if ready.get("fingerprint") != current:
        changed = sorted(k for k in set(current) | set(ready.get("fingerprint", {}))
                         if current.get(k) != ready.get("fingerprint", {}).get(k))
        raise RuntimeError(f"readiness is stale; changed since check: {changed[:5]}")



def _read_csv(path: Path) -> list[dict]:
    with Path(path).open(newline="") as stream:
        return list(csv.DictReader(stream))


def validate_review(review_csv: Path, review_dir: Path, qualification_run: Path,
                    today: date | None = None) -> dict[str, Any]:
    pass
    today = today or date.today()
    review_dir, qualification_run = Path(review_dir), Path(qualification_run)
    errors: list[str] = []
    selection = json.loads((review_dir / "selection.json").read_text())
    worksheet = {r["sample_id"]: r for r in _read_csv(review_dir / "review_worksheet.csv")}
    manifest_sha = sha_file(qualification_run / "operation_manifest.jsonl")
    records = {r["sample_id"]: r for r in _jsonl(qualification_run / "records.jsonl")}
    pair_of = {sid: p["pair_key"] for p in selection["selected_pairs"] for sid in p["records"]}
    for pair in selection["selected_pairs"]:
        if sha_file(review_dir / f"{pair['pair_key']}.md") != pair["packet_sha256"]:
            errors.append(f"{pair['pair_key']}: packet hash differs from selection.json")
    rows = _read_csv(review_csv)
    missing_cols = [c for c in REVIEW_FIELDS if rows and c not in rows[0]]
    if missing_cols:
        return {"valid": False, "errors": [f"missing columns: {missing_cols}"], "records": {}}
    by_sample: dict[str, list[dict]] = defaultdict(list)
    for i, row in enumerate(rows, 2):
        sid = row["sample_id"].strip()
        if sid not in pair_of:
            errors.append(f"line {i}: {sid!r} is not a selected review record")
            continue
        by_sample[sid].append({**row, "_line": i})
    decisions = {}
    sources: dict[str, list[str]] = {}
    for sid, pair_key in pair_of.items():
        group = by_sample.get(sid, [])
        where = f"{sid.split('::')[0]}…{sid[-12:]}"
        if not group:
            errors.append(f"{where}: no review row")
            continue
        sheet, rec = worksheet[sid], records[sid]
        if sheet["manifest_sha256"] != manifest_sha:
            errors.append(f"{where}: worksheet manifest hash differs from the qualification manifest")
        source = ROOT / rec["source_path"]
        if not source.exists() or sha_file(source) != rec["source_sha256"] or rec["source_sha256"] != sheet["source_sha256"]:
            errors.append(f"{where}: source missing or hash differs")
            continue
        if sid not in sources:
            sources[sid] = source.read_text(errors="replace").splitlines()
        lines = sources[sid]
        record_file = sid.split("::")[2]
        shared = {}
        for field in ("verdict", "label_scope_valid", "context_sufficient", "reviewer", "reviewer_kind", "date", "label",
                      "pair_key"):
            values = {g[field].strip() for g in group}
            if len(values) != 1:
                errors.append(f"{where}: inconsistent {field} across component rows")
            shared[field] = min(values)
        if shared["pair_key"] != pair_key or shared["label"] != str(rec["label"]):
            errors.append(f"{where}: pair_key or label differs from the selection")
        verdict = shared["verdict"]
        if verdict not in VERDICTS:
            errors.append(f"{where}: verdict must be one of {sorted(VERDICTS)}")
        for field in ("label_scope_valid", "context_sufficient"):
            if shared[field] not in YES_NO:
                errors.append(f"{where}: {field} must be yes/no")
        if not shared["reviewer"]:
            errors.append(f"{where}: reviewer missing")
        if shared["reviewer_kind"] not in REVIEWER_KINDS:
            errors.append(f"{where}: reviewer_kind must be human or llm")
        try:
            reviewed_on = date.fromisoformat(shared["date"])
            if reviewed_on > today:
                errors.append(f"{where}: date is in the future")
        except ValueError:
            errors.append(f"{where}: date must be YYYY-MM-DD")
        if verdict == "accept" and (shared["label_scope_valid"] != "yes" or shared["context_sufficient"] != "yes"):
            errors.append(f"{where}: accept needs label_scope_valid=yes and context_sufficient=yes")
        if verdict == "needs_context" and shared["context_sufficient"] != "no":
            errors.append(f"{where}: needs_context needs context_sufficient=no")
        spans = []
        for g in group:
            has_span = any(g[k].strip() for k in ("evidence_file", "start_line", "end_line", "evidence_role", "evidence_scope"))
            if not has_span:
                continue
            line = g["_line"]
            if g["evidence_file"].strip() != record_file:
                errors.append(f"line {line}: evidence_file must be {record_file!r} (only this file is pinned); "
                              "evidence elsewhere means verdict needs_context")
                continue
            try:
                start, end = int(g["start_line"]), int(g["end_line"])
            except ValueError:
                errors.append(f"line {line}: start_line/end_line must be integers")
                continue
            if not 1 <= start <= end <= len(lines):
                errors.append(f"line {line}: span {start}-{end} outside the file (1-{len(lines)})")
                continue
            text = "\n".join(lines[start - 1:end])
            if not text.strip():
                errors.append(f"line {line}: span {start}-{end} is blank")
            if g["evidence_role"].strip() not in EVIDENCE_ROLES:
                errors.append(f"line {line}: evidence_role must be one of {sorted(EVIDENCE_ROLES)}")
            if g["evidence_scope"].strip() not in EVIDENCE_SCOPES:
                errors.append(f"line {line}: evidence_scope must be one of {sorted(EVIDENCE_SCOPES)}")
            spans.append({"file": record_file, "start_line": start, "end_line": end,
                          "role": g["evidence_role"].strip(), "scope": g["evidence_scope"].strip(),
                          "text_sha256": sha_bytes(text.encode())})
        if len(spans) != len({(s["start_line"], s["end_line"], s["role"]) for s in spans}):
            errors.append(f"{where}: duplicate component rows")
        if verdict == "accept" and not spans:
            errors.append(f"{where}: accept needs at least one evidence component")
        decisions[sid] = {"pair_key": pair_key, "label": rec["label"], "verdict": verdict,
                          "label_scope_valid": shared["label_scope_valid"],
                          "context_sufficient": shared["context_sufficient"], "reviewer": shared["reviewer"],
                          "reviewer_kind": shared["reviewer_kind"], "date": shared["date"], "components": spans}
    human = {s for s, d in decisions.items() if d["reviewer_kind"] == "human"}
    if decisions and human != set(decisions):
        errors.append(f"{len(set(decisions) - human)} record(s) without a human review; LLM rows are recorded "
                      "separately and cannot decide inclusion")
    return {"valid": not errors and len(decisions) == len(pair_of), "errors": errors,
            "selected_records": len(pair_of), "reviewed_records": len(decisions),
            "verdicts": dict(Counter(d["verdict"] for d in decisions.values())),
            "review_csv_sha256": sha_file(review_csv), "manifest_sha256": manifest_sha,
            "selection_sha256": sha_file(review_dir / "selection.json"), "records": decisions}


def role_counts(rows: list[dict]) -> dict[str, dict]:
    out = {}
    for field in ROLE_FIELDS:
        out[field] = {}
        for role in sorted(OPERATION_ROLES):
            sel = [r for r in rows if r[field] == role]
            pos = [r for r in sel if int(r["label"]) == 1]
            out[field][role] = {"records": len(sel), "positives": len(pos), "negatives": len(sel) - len(pos),
                                "families": len({r["family"] for r in sel}),
                                "positive_families": len({r["family"] for r in pos})}
    return out


def coverage_floor(counts: dict, floor: dict = COVERAGE_FLOOR) -> dict[str, Any]:
    checks = {}
    for field in FOLD_FIELDS:
        c = counts[field]["calibration"]
        checks[field] = {"positives": c["positives"], "positive_families": c["positive_families"],
                         "negatives": c["negatives"],
                         "pass": c["positives"] >= floor["min_positive"]
                         and c["positive_families"] >= floor["min_positive_families"]
                         and c["negatives"] >= floor["min_negative"]}
    return {"floor": floor, "folds": checks, "pass": all(v["pass"] for v in checks.values())}


def apply_review(validation: dict, manifest_rows: list[dict]) -> dict[str, Any]:
    pass

    if not validation["valid"]:
        raise LineageError("review validation has errors; nothing applied")
    decisions = validation["records"]
    pairs = defaultdict(list)
    for sid, d in decisions.items():
        pairs[d["pair_key"]].append(sid)
    excluded, table = set(), []
    for key, ids in sorted(pairs.items()):
        keep = all(decisions[s]["verdict"] == "accept" for s in ids)
        if not keep:
            excluded.update(ids)
        table.append({"pair_key": key, "records": sorted(ids), "verdicts": [decisions[s]["verdict"] for s in sorted(ids)],
                      "kept": keep, "reason": "" if keep else "pair_complete_review_exclusion"})
    kept = []
    for row in manifest_rows:
        if row["sample_id"] in excluded:
            continue
        row = dict(row)
        if row["sample_id"] in decisions:
            row["evidence_status"] = "calibration_review_accepted"
            row["review_components"] = decisions[row["sample_id"]]["components"]
        kept.append(row)
    counts = role_counts(kept)
    return {"rule": "pair kept only if both records are human accept; roles unchanged", "pairs": table,
            "excluded_records": sorted(excluded), "records": len(kept),
            "positives": sum(int(r["label"]) for r in kept), "families": len({r["family"] for r in kept}),
            "counts": counts, "coverage_floor": coverage_floor(counts), "manifest_rows": kept}


def checked_apply(review_csv: Path, validation: dict, review_dir: Path, qualification_run: Path,
                  pinned_manifest_sha256: str, today: date | None = None, groups_path: Path = PILOT_GROUPS,
                  groups_sha256: str = PILOT_GROUPS_SHA256) -> dict[str, Any]:
    pass


    review_csv, review_dir, qualification_run = Path(review_csv), Path(review_dir), Path(qualification_run)
    manifest = qualification_run / "operation_manifest.jsonl"
    current = {"review_csv_sha256": sha_file(review_csv), "selection_sha256": sha_file(review_dir / "selection.json"),
               "manifest_sha256": sha_file(manifest)}
    for key, value in current.items():
        if validation.get(key) != value:
            raise LineageError(f"stale validation: {key} differs from the file being applied; validate again")
    if current["manifest_sha256"] != pinned_manifest_sha256:
        raise LineageError("source operation manifest differs from its D0 pin")
    fresh = json.loads(json.dumps(validate_review(review_csv, review_dir, qualification_run, today=today)))
    if fresh != validation:
        raise LineageError("stored validation does not match a fresh validation of the review CSV")
    rows = load_operation_manifest(manifest, pinned_manifest_sha256, groups_path, groups_sha256)
    result = apply_review(validation, rows)
    result.update(review_csv=str(review_csv), review_csv_sha256=current["review_csv_sha256"],
                  selection_sha256=current["selection_sha256"], source_manifest_sha256=current["manifest_sha256"])
    return result



class InputGuardError(LineageError):
    pass


def load_groups(path: Path, sha256: str) -> dict[str, dict]:
    data = Path(path).read_bytes()
    if sha_bytes(data) != sha256:
        raise InputGuardError(f"{path} SHA-256 differs from the pinned value")
    return {r["group_id"]: r for r in csv.DictReader(data.decode().splitlines())}


def load_operation_manifest(path: Path, sha256: str, groups_path: Path = PILOT_GROUPS,
                            groups_sha256: str = PILOT_GROUPS_SHA256) -> list[dict]:
    pass
    path = Path(path)
    data = path.read_bytes()
    if sha_bytes(data) != sha256:
        raise InputGuardError(f"operation manifest {path} SHA-256 differs from the pinned value")
    rows = [json.loads(line) for line in data.decode().splitlines() if line.strip()]
    groups = load_groups(groups_path, groups_sha256)
    seen = set()
    for row in rows:
        sid = row.get("sample_id", "")
        if not sid or sid in seen:
            raise InputGuardError(f"missing or duplicate sample_id {sid!r}")
        seen.add(sid)
        group = groups.get(row.get("family"))
        if group is None:
            raise InputGuardError(f"{sid}: family {row.get('family')!r} not in the original assignment")
        if group["role"] != "pilot_dev" or group["split"] != "train":
            raise InputGuardError(f"{sid}: family role {group['role']}/{group['split']} is not pilot_dev/train")
        if row.get("role") != "pilot_dev" or row.get("original_split") != "train":
            raise InputGuardError(f"{sid}: record role {row.get('role')}/{row.get('original_split')} is not pilot_dev/train")
        for field in ROLE_FIELDS:
            allowed = {"fit", "calibration"} if field == "inner_role" else OPERATION_ROLES
            if row.get(field) not in allowed:
                raise InputGuardError(f"{sid}: {field}={row.get(field)!r} is not a valid operation role")
        if int(row.get("label", -1)) not in (0, 1):
            raise InputGuardError(f"{sid}: label must be 0/1")
    return rows


def resolve_pack(manifest_path: Path, row: dict, packs_dir: Path | None = None) -> Path:
    pass

    return Path(packs_dir or Path(manifest_path).parent / "packs") / Path(row["pack_path"]).name


def preflight(manifest_path: Path, manifest_sha256: str, count_tokens, budget: int = 2048,
              records_path: Path | None = None, pairs_path: Path | None = None, groups_path: Path = PILOT_GROUPS,
              groups_sha256: str = PILOT_GROUPS_SHA256, expect: dict | None = None,
              packs_dir: Path | None = None) -> dict[str, Any]:
    pass
    rows = load_operation_manifest(manifest_path, manifest_sha256, groups_path, groups_sha256)
    errors = []
    texts = {}
    for row in rows:
        pack = resolve_pack(manifest_path, row, packs_dir)
        if not pack.is_file():
            errors.append(f"{row['sample_id']}: pack missing at {pack}")
            continue
        data = pack.read_bytes()
        if sha_bytes(data) != row["reference_sha256"]:
            errors.append(f"{row['sample_id']}: pack hash differs")
            continue
        text = data.decode()
        texts[row["sample_id"]] = text
        n = count_tokens(text)
        if n != int(row["tokens"]):
            errors.append(f"{row['sample_id']}: {n} tokens, metadata says {row['tokens']}")
        if n > budget:
            errors.append(f"{row['sample_id']}: {n} tokens over budget {budget}")
    target_checked = 0
    if records_path is not None:
        records = {r["sample_id"]: r for r in _jsonl(records_path)}
        for row in rows:
            rec = records.get(row["sample_id"])
            
            if row["tier"] != "exact_aligned_pair_not_reproduced" or row["sample_id"] not in texts:
                continue
            if rec is None or rec.get("status") != "qualified_l1":
                errors.append(f"{row['sample_id']}: exported pair member without a qualified record")
                continue
            raw = (ROOT / rec["source_path"]).read_bytes()
            for a, b in rec["target_ranges"] + rec.get("closure_ranges", []):
                chunk = raw[a:b].decode("utf-8", "replace")
                if any(line.strip() and line not in texts[row["sample_id"]] for line in chunk.splitlines()):
                    errors.append(f"{row['sample_id']}: target/closure line missing from the pack")
                    break
            target_checked += 1
    
    incomplete, pair_count = [], 0
    if pairs_path is not None:
        present = {r["sample_id"]: r for r in rows}
        for pair in _jsonl(pairs_path):
            if pair["status"] != "qualified_pair_l1":
                continue
            members = [present.get("jsvul:" + rid) for rid in pair["pair"]]
            if not any(members):
                continue
            pair_count += 1
            if not all(members) or {int(m["label"]) for m in members} != {0, 1} or \
                    len({m["family"] for m in members}) != 1 or len({tuple(m[f] for f in ROLE_FIELDS) for m in members}) != 1:
                incomplete.append(pair["pair"][0])
        exact = {r["sample_id"] for r in rows if r["tier"] == "exact_aligned_pair_not_reproduced"}
        paired = {"jsvul:" + rid for p in _jsonl(pairs_path) if p["status"] == "qualified_pair_l1" for rid in p["pair"]}
        if exact - paired:
            incomplete.extend(sorted(exact - paired))
    if incomplete:
        errors.append(f"{len(incomplete)} incomplete/non-opposing pair(s): {incomplete[:3]}")
    overlap = {}
    for field in ROLE_FIELDS:
        fams = defaultdict(set)
        for row in rows:
            fams[row[field]].add(row["family"])
        bad = [(a, b) for a in fams for b in fams if a < b and fams[a] & fams[b]]
        overlap[field] = len(bad)
        if bad:
            errors.append(f"{field}: families shared between {bad}")
    by_hash = defaultdict(set)
    for row in rows:
        by_hash[row["reference_sha256"]].add(int(row["label"]))
    conflicts = sum(len(v) > 1 for v in by_hash.values())
    if conflicts:
        errors.append(f"{conflicts} opposing-label input hash conflict(s)")
    counts = {"records": len(rows), "positives": sum(int(r["label"]) for r in rows),
              "families": len({r["family"] for r in rows})}
    if expect and {k: counts[k] for k in expect} != expect:
        errors.append(f"cohort {counts} differs from expected {expect}; a funnel must explain the change")
    return {"passed": not errors, "errors": errors, "manifest": str(manifest_path), "manifest_sha256": manifest_sha256,
            "pilot_groups_sha256": groups_sha256, "budget": budget, "counts": counts,
            "packs_checked": len(texts), "target_checked": target_checked, "pairs_checked": pair_count,
            "family_overlap": overlap, "input_conflicts": conflicts, "role_counts": role_counts(rows),
            "full_forward_eligible": sum(bool(r["full_forward_eligible"]) for r in rows),
            "sample_ids": sorted(r["sample_id"] for r in rows)}



IDENTITY_FIELDS = ("family", "label", "tier", "role", "original_split", *ROLE_FIELDS, "reference_sha256", "tokens",
                   "full_forward_eligible")
COHORT_ID_FIELDS = ("sample_id", "family", "label", "tier", "inner_role", *FOLD_FIELDS, "reference_sha256", "tokens",
                    "full_forward_eligible")


def check_against_source(rows: list[dict], source_rows: list[dict]) -> None:
    pass

    source = {r["sample_id"]: r for r in source_rows}
    for row in rows:
        src = source.get(row["sample_id"])
        if src is None:
            raise InputGuardError(f"{row['sample_id']}: ID not in the source operation manifest")
        changed = [f for f in IDENTITY_FIELDS if row.get(f) != src.get(f)]
        if changed:
            raise InputGuardError(f"{row['sample_id']}: {changed} differ from the source manifest "
                                  f"(family mismatch or re-split)")


def check_funnel(rows: list[dict], source_rows: list[dict], funnel: dict, manifest_sha256: str,
                 source_sha256: str) -> dict[str, Any]:
    pass
    if funnel.get("reviewed_manifest_sha256") != manifest_sha256 or funnel.get("source_manifest_sha256") != source_sha256:
        raise InputGuardError("review exclusions do not belong to this source/reviewed manifest pair")
    dropped = {r["sample_id"] for r in source_rows} - {r["sample_id"] for r in rows}
    if dropped != set(funnel["excluded_records"]):
        raise InputGuardError(f"{len(dropped)} record(s) dropped without a listed exclusion")

    def count(rs):
        return {"records": len(rs), "positives": sum(int(r["label"]) for r in rs),
                "families": len({r["family"] for r in rs})}

    return {"source": count(source_rows), "reviewed": count(rows), "excluded": sorted(dropped),
            "rule": funnel.get("rule", "")}


def fold_role(row: dict, fold: str) -> str:
    return row["inner_role"] if fold == "final" else row[f"fold{fold}_role"]


def operation_cohort(cfg: dict, fold: str, out_dir: Path, load_tokenizer) -> tuple[dict, dict, dict]:
    pass




    from raven import p5

    d = cfg["p7"]["detector"]
    spec = d["operation_manifest"]
    groups, groups_sha = Path(d["pilot_groups"]), d["pilot_groups_sha256"]
    path, sha = Path(spec["path"]), spec["sha256"]
    rows = load_operation_manifest(path, sha, groups, groups_sha)
    source_path, source_sha = Path(spec["source_manifest"]["path"]), spec["source_manifest"]["sha256"]
    source_rows = load_operation_manifest(source_path, source_sha, groups, groups_sha)
    check_against_source(rows, source_rows)
    funnel_path = Path(spec["funnel"])
    funnel = check_funnel(rows, source_rows, json.loads(funnel_path.read_text()), sha, source_sha)
    out_dir = Path(out_dir)
    with (out_dir / "cohort_ids.csv").open("w", newline="") as stream:
        writer = csv.DictWriter(stream, fieldnames=COHORT_ID_FIELDS, extrasaction="ignore")
        writer.writeheader()
        writer.writerows(sorted(rows, key=lambda r: r["sample_id"]))
    tok = load_tokenizer()
    packs_dir = Path(spec["packs_dir"]) if spec.get("packs_dir") else None
    result = preflight(path, sha, lambda t: p5.count_tokens(tok, t), budget=int(d["budget"]),
                       records_path=Path(spec["records"]) if spec.get("records") else None,
                       pairs_path=Path(spec["pairs"]) if spec.get("pairs") else None,
                       groups_path=groups, groups_sha256=groups_sha, expect=spec.get("expect"), packs_dir=packs_dir)
    (out_dir / "input_preflight.json").write_text(json.dumps(result, indent=2, sort_keys=True) + "\n")
    if not result["passed"]:
        raise LineageError(f"input preflight failed: {result['errors'][:3]}")
    roles, texts = {}, {}
    for row in rows:
        data = resolve_pack(path, row, packs_dir).read_bytes()
        if sha_bytes(data) != row["reference_sha256"]:
            raise LineageError(f"{row['sample_id']}: pack changed after preflight")
        roles[row["sample_id"]] = {"role": fold_role(row, fold), "label": int(row["label"]), "family": row["family"],
                                   "split": row["original_split"], "tokens": int(row["tokens"]),
                                   "full_forward_eligible": bool(row["full_forward_eligible"])}
        texts[row["sample_id"]] = data.decode()
    guard = {"cohort_source": "operation_manifest", "manifest": str(path), "manifest_sha256": sha,
             "source_manifest_sha256": source_sha, "funnel_sha256": sha_file(funnel_path), "funnel": funnel,
             "pilot_groups": str(groups), "pilot_groups_sha256": groups_sha, "samples": len(rows),
             "cohort_ids_sha256": sha_file(out_dir / "cohort_ids.csv"),
             "input_preflight_sha256": sha_file(out_dir / "input_preflight.json"),
             "full_forward_eligible": sum(r["full_forward_eligible"] for r in roles.values()),
             "full_forward_policy": "teacher/distillation only; the budgeted detector cohort keeps every record"}
    return roles, texts, guard
