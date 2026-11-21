"""P7 S0 (cohort/evidence manifests) and S3 (real-code evidence and graph-sensitivity probe).

Plan: ``docs/p7-selector-implementation-and-experiments-2026-11-12.md`` §3 and §6; decisions in
``docs/pilot-decisions.md`` ("P7A pre-outcome decisions").

S0 writes the operation manifest before any policy outcome exists:

* ``cohort_manifest.csv``: one row per (sample, level), with roles, splits, eligibility, pool and
  graph hashes and feasibility;
* ``split_manifest.csv``: the family-level inner split and outer folds (hash rule);
* ``evidence_components.csv`` (evaluator-only) and ``evidence_cases.csv``: the frozen case list.

S3 runs every selector in ``selectors.POLICIES`` on the frozen eligible cases with no
vulnerability detector. Scores come from the pinned CodeT5 encoder via
``v_i = max(0, cos(h_t, h_i)) + 1e-6``. Evidence annotations are read only by the evaluator,
after packing.
"""

from __future__ import annotations

import gzip
import hashlib
import json
import math
import random
import time
from collections import defaultdict
from pathlib import Path
from typing import Any

import torch

from raven import inventory as inv
from raven import packer
from raven import selectors as S
from raven.p2 import LineageError, _digest, _from_run, _json
from raven.p6 import _sha, find_run, iter_samples
from raven.runlog import Run

ALLOWED_SOURCES = ("jsvul", "sard_php")
OPERATIONAL_SPLITS = ("train", "val", "test")
LEVELS = ("L1", "L2", "L3")
BUDGETS = (512, 1024, 2048, 4096, 8192)
INNER_SALT = "pilot-inner-split-v1|42|"



def inner_hash(group_id: str) -> str:
    return hashlib.sha256(f"{INNER_SALT}{group_id}".encode()).hexdigest()


def split_families(families: list[str], calib_share: float = 0.2, folds: int = 3) -> dict[str, dict]:
    pass




    order = sorted(set(families), key=lambda g: (inner_hash(g), g))
    n_cal = math.ceil(calib_share * len(order))
    out = {g: {"rank": i, "hash": inner_hash(g), "inner_role": "calibration" if i < n_cal else "fit",
               "outer_fold": i % folds} for i, g in enumerate(order)}
    for f in range(folds):
        rest = [g for g in order if out[g]["outer_fold"] != f]
        cal = set(rest[:math.ceil(calib_share * len(rest))])
        for g in rest:
            out[g][f"fold{f}_role"] = "calibration" if g in cal else "fit"
        for g in order:
            if out[g]["outer_fold"] == f:
                out[g][f"fold{f}_role"] = "assessment"
    return out


def stratified_split_families(family_labels: dict[str, set[int]], folds: int = 3) -> dict[str, dict]:
    pass





    key = lambda g: hashlib.sha256(f"recovery-split-v1|42|{g}".encode()).hexdigest()
    strata = [sorted((g for g, y in family_labels.items() if 1 in y), key=key),
              sorted((g for g, y in family_labels.items() if 1 not in y), key=key)]
    out = {g: {"rank": i, "hash": key(g), "outer_fold": i % folds}
           for group in strata for i, g in enumerate(group)}

    def calibration(groups):
        chosen = set()
        for stratum in strata:
            available = [g for g in stratum if g in groups]
            n = max(2, math.ceil(0.2 * len(available)))
            if len(available) - n < 2:
                raise LineageError("insufficient class-bearing families for recovery fit/calibration")
            chosen.update(available[:n])
        return chosen

    cal = calibration(set(out))
    for g, row in out.items():
        row["inner_role"] = "calibration" if g in cal else "fit"
    for f in range(folds):
        rest = {g for g in out if out[g]["outer_fold"] != f}
        cal = calibration(rest)
        for g, row in out.items():
            row[f"fold{f}_role"] = ("assessment" if g not in rest else
                                    "calibration" if g in cal else "fit")
    return out


def line_span(text: bytes, start_line: int, end_line: int) -> tuple[int, int]:
    starts = [0] + [i + 1 for i, ch in enumerate(text) if ch == 10]
    a = starts[start_line - 1]
    b = starts[end_line] if end_line < len(starts) else len(text)
    return a, b


def nonws(text: bytes, a: int, b: int) -> list[int]:
    return [i for i in range(a, b) if text[i] not in b" \t\r\n"]


def covered(positions: list[int], ranges: list[tuple[int, int]]) -> bool:
    if not positions:
        return False
    rs = packer._merge(list(ranges))
    j = 0
    for p in positions:
        while j < len(rs) and rs[j][1] <= p:
            j += 1
        if j >= len(rs) or not rs[j][0] <= p < rs[j][1]:
            return False
    return True


def effective_positions(sample: dict, f: str, start_line: int, end_line: int) -> list[int]:
    pass



    text = sample["texts"][f]
    a, b = line_span(text, start_line, end_line)
    universe = list(sample["levels"]["L0"].get(f, []))
    for c in sample["pools"]["L3"]:
        if c.file == f:
            universe.extend(x for x in c.span_set if x[0] < b and a < x[1])
    return [i for i in nonws(text, a, b) if any(x <= i < y for x, y in universe)]


def edges_index(build_run: Path) -> dict[tuple[str, str, int], list[tuple[str, int, str, str]]]:
    pass
    out = defaultdict(list)
    for r in inv.read_rows(build_run / "edges.csv.gz"):
        if r["status"] != "resolved" or int(r["dst_unit"]) < 0:
            continue
        snap = r["snapshot"] if r["source"] == "jsvul" else ""
        out[(snap, r["file"], int(r["src_unit"]))].append((r["dst_file"], int(r["dst_unit"]), r["type"], r["confidence"]))
    return out


def unit_graph(sample: dict, uids: list[str], eidx) -> dict[frozenset, set[str]]:
    pass
    snap = sample.get("snapshot", "")
    key_of = {sample["unit_index"][u]: u for u in uids if u in sample["unit_index"]}
    pairs: dict[frozenset, set[str]] = defaultdict(set)
    for (path, k), u in key_of.items():
        for dst_file, dst_unit, typ, _conf in eidx.get((snap, path, k), ()):
            v = key_of.get((dst_file, dst_unit))
            if v is not None and v != u:
                pairs[frozenset((u, v))].add(typ)
    return dict(pairs)


def gate_matrix(uids: list[str], pairs) -> torch.Tensor:
    idx = {u: i for i, u in enumerate(uids)}
    g = torch.zeros((len(uids), len(uids)), dtype=torch.bool)
    for p in pairs:
        a, b = tuple(p)
        g[idx[a], idx[b]] = g[idx[b], idx[a]] = True
    return g


def _pool_hash(pool: list[packer.Candidate]) -> str:
    return _sha(json.dumps([[c.uid, c.file, list(c.ranges), list(c.closure)] for c in sorted(pool, key=lambda c: c.uid)]))


def _graph_hash(pairs) -> str:
    return _sha(json.dumps(sorted([sorted(p) + sorted(t) for p, t in pairs.items()])))


def _check_runs(extract_run: Path, build_run: Path, p5c_run: Path, pack_run: Path) -> dict:
    psum = json.loads((pack_run / "pack_summary.json").read_text())
    if _digest(pack_run, tuple(psum["output_files"])) != psum["output_files"]:
        raise LineageError(f"{pack_run.name} outputs changed after the run")
    if psum["build_run"] != build_run.name or psum["extract_run"] != extract_run.name:
        raise LineageError("P6 pack run does not descend from the given P5 runs")
    csum = json.loads((p5c_run / "correction_summary.json").read_text())
    if _digest(p5c_run, tuple(csum["output_files"])) != csum["output_files"]:
        raise LineageError(f"{p5c_run.name} outputs changed after the run")
    return {"pack_outputs": psum["output_files"], "p5c_outputs": csum["output_files"]}



MANIFEST_FIELDS = (
    "sample_id", "source", "source_track", "family", "role", "original_split", "label", "eligible", "exclusion_reason",
    "inner_role", "outer_fold", "fold0_role", "fold1_role", "fold2_role", "level", "pool_units", "optional_units",
    "pool_sha256", "graph_edges", "graph_sha256", "target_tokens", "full_tokens", "full_forward_eligible",
    *[f"target_fits_{b}" for b in BUDGETS], "training_eligible_2048", "scoring_eligible_2048")
COMPONENT_FIELDS = ("effective_bytes", "case_id", "twin_id", "sample_id", "source", "span_index", "file", "start_line", "end_line", "role",
                    "selectability", "level", "provenance", "pool_present", "covering_units")
CASE_FIELDS = ("case_id", "twin_id", "sample_id", "source", "family", "original_split", "eligible", "exclusion_reason",
               "level", "decisive_optional", "decisive_in_pool", "decisive_mandatory", "full_tokens", "joint_tokens",
               *[f"joint_fits_{b}" for b in BUDGETS], *[f"opportunity_{b}" for b in BUDGETS])


def _cells(pack_run: Path) -> tuple[dict, dict]:
    per_sample, per_level = {}, defaultdict(dict)
    for r in inv.read_rows(pack_run / "pack_cells.csv"):
        if r["method"] != "random":
            continue
        per_sample[r["sample_id"]] = r
        lv = per_level[(r["sample_id"], r["level"])]
        lv["full_tokens"] = int(r["full_tokens"])
        lv["target_tokens"] = int(r["mandatory_tokens"])
        if r["budget_name"].isdigit():
            lv[int(r["budget_name"])] = r["target_fits_budget"] == "true"
    return per_sample, per_level


def eligibility(cell: dict) -> tuple[bool, str]:
    if cell["source"] not in ALLOWED_SOURCES:
        return False, "source_not_allowed"
    if cell["role"] != "pilot_dev":
        return False, f"role_{cell['role'] or 'missing'}"
    if cell["split"] not in OPERATIONAL_SPLITS:
        return False, f"split_{cell['split'] or 'missing'}"
    if cell["label"] not in ("0", "1"):
        return False, "label_invalid"
    return True, ""


def run_manifest(run: Run, extract_run: Path, build_run: Path, p5c_run: Path, pack_run: Path) -> dict[str, Any]:
    from raven.detector import ScoringRoleError

    extract_run = _from_run(extract_run, "extract-units")
    build_run = _from_run(build_run, "build-contexts")
    p5c_run = _from_run(p5c_run, "p5c-correction")
    pack_run = _from_run(pack_run, "pack-cells")
    lineage = _check_runs(extract_run, build_run, p5c_run, pack_run)
    d = run.config["p7"]["detector"]
    groups_path = Path(d["pilot_groups"])
    gsha = hashlib.sha256(groups_path.read_bytes()).hexdigest()
    if gsha != d["pilot_groups_sha256"]:
        raise ScoringRoleError(f"{groups_path} SHA-256 differs from the pinned value")
    group_role = {r["group_id"]: r["role"] for r in inv.read_rows(groups_path)}
    limit = int(d["teacher_context_limit"])
    per_sample, per_level = _cells(pack_run)

    
    for sid, c in per_sample.items():
        if group_role.get(c["family"], "") != c["role"]:
            raise LineageError(f"{sid}: role in pilot_groups.csv differs from P6")
    elig = {sid: eligibility(c) for sid, c in per_sample.items()}
    train_fams = sorted({c["family"] for sid, c in per_sample.items()
                         if elig[sid][0] and c["source"] == "jsvul" and c["split"] == "train"})
    fam_split = split_families(train_fams)
    if run.config["p7"].get("split_version") == "stratified-recovery-v1":
        labels_by_family = defaultdict(set)
        for sid, c in per_sample.items():
            if (elig[sid][0] and c["source"] == "jsvul" and c["split"] == "train"
                    and per_level[(sid, "L1")].get(2048, False)):
                labels_by_family[c["family"]].add(int(c["label"]))
        fam_split = stratified_split_families(labels_by_family)
        train_fams = sorted(fam_split)

    ev_rows = inv.read_rows(p5c_run / "evidence_selectability.csv")
    by_sample = defaultdict(list)
    for r in ev_rows:
        sid = ("jsvul:" if r["source"] == "jsvul" else "sard_php:") + r["record_id"]
        by_sample[sid].append(r)

    eidx = edges_index(build_run)
    from raven import p5
    tokenizer = p5.load_tokenizer(run.config)
    count = lambda text: p5.count_tokens(tokenizer, text)

    manifest, comps, cases = [], [], []
    for s in iter_samples(run.config, extract_run, build_run, run.logger):
        sid = s["sample_id"]
        c = per_sample[sid]
        ok, why = elig[sid]
        fam = fam_split.get(c["family"], {})
        track = c["source"] if c["source"] != "jsvul" else ("jsvul_ts" if s["target_file"].endswith((".ts", ".tsx"))
                                                              else "jsvul_js")
        mandatory = s["levels"]["L0"]
        inv_labels = {v: k for k, v in (s["labels"] or {}).items()}
        for lv in LEVELS:
            pool = s["pools"][lv]
            opt, _ = packer.optional_candidates(s["texts"], mandatory, pool)
            pairs = unit_graph(s, sorted(c2.uid for c2 in opt), eidx)
            cell = per_level[(sid, lv)]
            train_ok = ok and c["source"] == "jsvul" and c["split"] == "train" and cell.get(2048, False)
            manifest.append({
                "sample_id": sid, "source": c["source"], "source_track": track, "family": c["family"],
                "role": c["role"], "original_split": c["split"], "label": c["label"], "eligible": str(ok).lower(),
                "exclusion_reason": why, "inner_role": fam.get("inner_role", ""),
                "outer_fold": fam.get("outer_fold", ""),
                **{f"fold{f}_role": fam.get(f"fold{f}_role", "") for f in range(3)},
                "level": lv, "pool_units": len(pool), "optional_units": len(opt), "pool_sha256": _pool_hash(pool),
                "graph_edges": len(pairs), "graph_sha256": _graph_hash(pairs), "target_tokens": cell["target_tokens"],
                "full_tokens": cell["full_tokens"], "full_forward_eligible": str(cell["full_tokens"] <= limit).lower(),
                **{f"target_fits_{b}": str(cell.get(b, False)).lower() for b in BUDGETS},
                "training_eligible_2048": str(train_ok).lower(),
                "scoring_eligible_2048": str(ok and cell.get(2048, False)).lower(),
            })
            if sid not in by_sample:
                continue
            
            n_opt = n_in = n_mand = 0
            joint_units: list[packer.Candidate] = []
            for r in by_sample[sid]:
                f = inv_labels.get(r["file_id"], r["file_id"])
                if f not in s["texts"]:
                    prov, present, cover = "file_absent", False, []
                else:
                    text = s["texts"][f]
                    a, b = line_span(text, int(r["start_line"]), int(r["end_line"]))
                    pos = effective_positions(s, f, int(r["start_line"]), int(r["end_line"]))
                    cover = [c2 for c2 in pool if c2.file == f and any(x < b and a < y for x, y in c2.span_set)]
                    if not pos:
                        prov, present = "outside_units", False
                    elif covered(pos, mandatory.get(f, [])):
                        prov, present = "mandatory", True
                    elif covered(pos, mandatory.get(f, []) + [x for c2 in cover for x in c2.ranges]):
                        prov, present = "direct", True
                    elif covered(pos, mandatory.get(f, []) + [x for c2 in cover for x in c2.span_set]):
                        prov, present = "closure_added", True
                    else:
                        prov, present = "absent", False
                if r["selectability"] == "mandatory" or prov == "mandatory":
                    n_mand += 1
                else:
                    n_opt += 1
                    if present:
                        n_in += 1
                        joint_units.extend(cover)
                eff = len(pos) if f in s["texts"] else 0
                comps.append({"effective_bytes": eff, "case_id": r["case_id"], "twin_id": r["twin_id"], "sample_id": sid, "source": r["source"],
                              "span_index": r["span_index"], "file": r["file_id"], "start_line": r["start_line"],
                              "end_line": r["end_line"], "role": r["role"], "selectability": r["selectability"],
                              "level": lv, "provenance": prov, "pool_present": str(present).lower(),
                              "covering_units": json.dumps(sorted(c2.uid for c2 in cover))})
            files = {f: list(rr) for f, rr in mandatory.items()}
            for c2 in joint_units:
                files[c2.file] = packer._merge(files.get(c2.file, []) + c2.span_set)
            joint = count(packer.serialise({f: (s["texts"][f], rr) for f, rr in files.items()}, s["target_file"],
                                           s["labels"]))
            r0 = by_sample[sid][0]
            cases.append({"case_id": r0["case_id"], "twin_id": r0["twin_id"], "sample_id": sid, "source": c["source"],
                          "family": c["family"], "original_split": c["split"], "eligible": str(ok).lower(),
                          "exclusion_reason": why, "level": lv, "decisive_optional": n_opt, "decisive_in_pool": n_in,
                          "decisive_mandatory": n_mand, "full_tokens": cell["full_tokens"], "joint_tokens": joint,
                          **{f"joint_fits_{b}": str(joint <= b and n_in == n_opt).lower() for b in BUDGETS},
                          **{f"opportunity_{b}": str(n_in >= 1 and cell["full_tokens"] > b).lower() for b in BUDGETS}})
    inv.write_rows(run.path / "cohort_manifest.csv", MANIFEST_FIELDS, manifest)
    inv.write_rows(run.path / "split_manifest.csv",
                   ("group_id", "hash", "rank", "inner_role", "outer_fold", "fold0_role", "fold1_role", "fold2_role"),
                   [{"group_id": g, **v} for g, v in sorted(fam_split.items(), key=lambda kv: kv[1]["rank"])])
    inv.write_rows(run.path / "evidence_components.csv", COMPONENT_FIELDS, comps)
    inv.write_rows(run.path / "evidence_cases.csv", CASE_FIELDS, cases)

    
    fam_roles = defaultdict(set)
    for r in manifest:
        if r["inner_role"]:
            fam_roles[r["family"]].add(r["inner_role"])
    overlap = [f for f, rs in fam_roles.items() if len(rs) > 1]
    if overlap:
        raise LineageError(f"families in more than one inner role: {overlap[:3]}")
    l1 = [r for r in manifest if r["level"] == "L1"]
    elig_cases = [c for c in cases if c["eligible"] == "true"]
    result = {
        "inputs": {"extract_run": extract_run.name, "build_run": build_run.name, "p5c_run": p5c_run.name,
                   "pack_run": pack_run.name, "pilot_groups_sha256": gsha, **lineage},
        "teacher_context_limit": limit,
        "samples": len(l1),
        "eligible_samples": sum(r["eligible"] == "true" for r in l1),
        "exclusions": dict(sorted(_count(r["exclusion_reason"] for r in l1 if r["eligible"] != "true").items())),
        "jsvul_train_families": len(train_fams),
        "inner_split": {"calibration_families": sum(v["inner_role"] == "calibration" for v in fam_split.values()),
                        "fit_families": sum(v["inner_role"] == "fit" for v in fam_split.values()),
                        "outer_folds": {f: sum(v["outer_fold"] == f for v in fam_split.values()) for f in range(3)}},
        "training_eligible_2048": {lv: sum(r["training_eligible_2048"] == "true" for r in manifest if r["level"] == lv)
                                   for lv in LEVELS},
        "evidence": {
            "annotated_samples": len(by_sample),
            "eligible_cases": len({c["sample_id"] for c in elig_cases}),
            "eligible_families": len({c["family"] for c in elig_cases}),
            "cases_with_optional_decisive": {src: len({c["sample_id"] for c in elig_cases if c["source"] == src
                                                       and int(c["decisive_optional"]) > 0}) for src in ALLOWED_SOURCES},
            "families_with_optional_decisive": {src: len({c["family"] for c in elig_cases if c["source"] == src
                                                          and int(c["decisive_optional"]) > 0}) for src in ALLOWED_SOURCES},
        },
        "frozen_case_list_sha256": hashlib.sha256((run.path / "evidence_cases.csv").read_bytes()).hexdigest(),
    }
    result["output_files"] = _digest(run.path, ("cohort_manifest.csv", "split_manifest.csv", "evidence_components.csv",
                                                "evidence_cases.csv"))
    _json(run.path / "manifest_summary.json", result)
    run.logger.info("p7 manifest: %s", json.dumps({k: result[k] for k in ("samples", "eligible_samples", "inner_split")}))
    return result


def _count(it) -> dict:
    out: dict = defaultdict(int)
    for x in it:
        out[x] += 1
    return dict(out)



GATED_POLICIES = ("appare", "gated_subtraction", "dependency_mean", "dn_support", "dependency_expansion", "gated_mmr")
S3_LEVELS = {"jsvul": ("L1", "L2"), "sard_php": ("L1", "L3")}
CELL_FIELDS_S3 = ("sample_id", "case_id", "source", "family", "level", "budget", "policy", "condition", "kind", "rate",
                  "seed", "edges", "edges_deleted", "edges_added", "arrays_sha256", "optional_units", "tokens",
                  "strategy", "selected", "decisive_optional", "decisive_in_pool", "retained", "retained_direct",
                  "retained_closure", "all_retained", "joint_fits", "opportunity", "selected_uids", "pack_sha256",
                  "source_map_ok", "pack_s")


def perturb(pairs: dict, uids: list[str], kind: str, rate: float, seed: int, tag: str) -> tuple[dict, int, int]:
    pass

    edges = sorted(tuple(sorted(p)) for p in pairs)
    n = math.floor(rate * len(edges) + 0.5)
    rng = random.Random(f"{seed}|{tag}|{kind}|{rate}")
    out = {frozenset(e): set(pairs[frozenset(e)]) for e in edges}
    if kind == "delete" and n:
        for e in rng.sample(edges, n):
            out.pop(frozenset(e))
        return out, n, 0
    if kind == "add" and n:
        have = set(edges)
        universe = [(a, b) for i, a in enumerate(uids) for b in uids[i + 1:] if (a, b) not in have]
        for e in rng.sample(universe, min(n, len(universe))):
            out[frozenset(e)] = {"synthetic"}
        return out, 0, min(n, len(universe))
    return out, 0, 0


def component_positions(comps: list[dict], sample: dict, labels_inv: dict) -> list[tuple[str, list[int]]]:
    out = []
    for r in comps:
        f = labels_inv.get(r["file"], r["file"])
        if f in sample["texts"]:
            out.append((f, effective_positions(sample, f, int(r["start_line"]), int(r["end_line"]))))
    return out


def evaluate(result: packer.PackResult, comp_pos: list[tuple[str, list[int]]], mandatory: dict, cand: dict) -> dict:
    pass
    if not result.target_fits_budget:
        return {"retained": 0, "retained_direct": 0, "retained_closure": 0}
    direct = defaultdict(list)
    for u in result.selected:
        direct[cand[u].file].extend(cand[u].ranges)
    ret = rd = rc = 0
    for f, pos in comp_pos:
        if covered(pos, result.files.get(f, [])):
            ret += 1
            if covered(pos, mandatory.get(f, []) + direct.get(f, [])):
                rd += 1
            else:
                rc += 1
    return {"retained": ret, "retained_direct": rd, "retained_closure": rc}


def source_map_ok(result: packer.PackResult, texts, target, labels) -> bool:
    pass
    if not result.target_fits_budget:
        return True
    text, segments = packer.serialise_with_map({f: (texts[f], r) for f, r in result.files.items()},
                                               next(iter(target)), labels)
    if text != result.text:
        return False
    for seg in segments:
        a, b = seg["src"]
        oa, ob = seg["out"]
        if text[oa:ob] != texts[seg["file"]][a:b].decode("utf-8", "replace"):
            return False
    return True


def run_evidence(run: Run, manifest_run: Path, extract_run: Path, build_run: Path) -> dict[str, Any]:
    from raven import encoder, p5

    manifest_run = _from_run(manifest_run, "p7-manifest")
    msum = json.loads((manifest_run / "manifest_summary.json").read_text())
    if _digest(manifest_run, tuple(msum["output_files"])) != msum["output_files"]:
        raise LineageError(f"{manifest_run.name} outputs changed after the run")
    extract_run = _from_run(extract_run, "extract-units")
    build_run = _from_run(build_run, "build-contexts")
    if msum["inputs"]["build_run"] != build_run.name or msum["inputs"]["extract_run"] != extract_run.name:
        raise LineageError("manifest run does not descend from the given P5 runs")
    cfg = run.config["p7"]["s3"]
    params = S.MessageParams(**cfg["params"])
    budgets = [int(b) for b in cfg["budgets"]]
    perturb_budget = int(cfg["perturbation_budget"])
    rates = [float(x) for x in cfg["perturbation_rates"]]
    seeds = [int(x) for x in cfg["perturbation_seeds"]]
    cases = [c for c in inv.read_rows(manifest_run / "evidence_cases.csv") if c["eligible"] == "true"]
    case_of = {(c["sample_id"], c["level"]): c for c in cases}
    want = {c["sample_id"] for c in cases}
    
    comps = defaultdict(list)
    for r in inv.read_rows(manifest_run / "evidence_components.csv"):
        if r["provenance"] != "mandatory" and r["selectability"] != "mandatory":
            comps[(r["sample_id"], r["level"])].append(r)
    eidx = edges_index(build_run)
    tokenizer = p5.load_tokenizer(run.config)
    memo: dict[str, int] = {}

    def count(text: str) -> int:  
        n = memo.get(text)
        if n is None:
            n = memo[text] = p5.count_tokens(tokenizer, text)
        return n

    enc = encoder.EncoderCache(device=cfg.get("encoder_device", "cpu"))
    cells, diag, timing = [], [], defaultdict(float)
    diag_path = run.path / "message_diagnostics.jsonl.gz"
    with gzip.open(diag_path, "wt", encoding="utf-8") as dfh:
        for s in iter_samples(run.config, extract_run, build_run, run.logger):
            sid = s["sample_id"]
            if sid not in want:
                continue
            src = "jsvul" if sid.startswith("jsvul:") else "sard_php"
            mandatory = s["levels"]["L0"]
            labels_inv = {v: k for k, v in (s["labels"] or {}).items()}
            tf = s["target_file"]
            t_text = b"".join(s["texts"][tf][a:b] for a, b in s["target"][tf]).decode("utf-8", "replace")
            for lv in S3_LEVELS[src]:
                case = case_of.get((sid, lv))
                if case is None:
                    continue
                opt, _ = packer.optional_candidates(s["texts"], mandatory, s["pools"][lv])
                opt = sorted(opt, key=lambda c: c.uid)
                comp_pos = component_positions(comps[(sid, lv)], s, labels_inv)
                memo.clear()
                uids = [c.uid for c in opt]
                cand = {c.uid: c for c in opt}
                t0 = time.time()
                unit_texts = [b"".join(s["texts"][c.file][a:b] for a, b in c.ranges).decode("utf-8", "replace")
                              for c in opt]
                h_all, clipped = enc.embed([t_text, *unit_texts])
                timing["encode_s"] += time.time() - t0
                ht, h = h_all[0], h_all[1:]
                v = (h @ ht).clamp_min(0.0) + params.relevance_floor if len(opt) else torch.zeros(0, dtype=S.DTYPE)
                pairs = unit_graph(s, uids, eidx)
                arrays = _sha(json.dumps({"uids": uids, "h": h.round(decimals=10).tolist(), "v": v.tolist(),
                                          "edges": sorted(sorted(p) for p in pairs)}))
                conditions = [("detected", "", 0.0, 0, pairs, 0, 0)]
                for kind in ("delete", "add"):
                    for rate in rates:
                        if rate == 0:
                            continue
                        for seed in seeds:
                            pp, nd, na = perturb(pairs, uids, kind, rate, seed, f"{sid}|{lv}")
                            conditions.append(("controlled", kind, rate, seed, pp, nd, na))
                for cond, kind, rate, seed, pp, nd, na in conditions:
                    gate = gate_matrix(uids, pp)
                    view = S.View(uids, h, v, gate, [cand[u].order for u in uids])
                    t1 = time.time()
                    scores, f = S.static_scores(view, params, seed=int(run.config["seed"]), sample_id=sid)
                    timing["score_s"] += time.time() - t1
                    if cond == "detected":
                        for row in S.diagnostics(view, params, scores, f):
                            dfh.write(json.dumps({"sample_id": sid, "level": lv, **row}) + "\n")
                    pol_budgets = budgets if cond == "detected" else [perturb_budget]
                    policies = S.POLICIES if cond == "detected" else GATED_POLICIES
                    for budget in pol_budgets:
                        for pol in policies:
                            t2 = time.time()
                            if pol in S.STATIC_POLICIES:
                                sc = scores[pol].tolist()
                                scored = [packer.Candidate(u, cand[u].file, cand[u].ranges, cand[u].closure, sc[i],
                                                           cand[u].order) for i, u in enumerate(uids)]
                                pack_fn = packer.for_version(run.config["p7"].get("packer_version", "legacy-v1"))
                                res = pack_fn(s["texts"], tf, mandatory, scored, budget, count, labels=s["labels"])
                            else:
                                vv = v.tolist()
                                scored = [packer.Candidate(u, cand[u].file, cand[u].ranges, cand[u].closure, vv[i],
                                                           cand[u].order) for i, u in enumerate(uids)]
                                res = packer.pack_sequential(s["texts"], tf, mandatory, scored, budget, count,
                                                             S.proposer(pol, view, params, f.sim), labels=s["labels"])
                            dt = time.time() - t2
                            timing[f"pack_s_{pol}"] += dt
                            ev = evaluate(res, comp_pos, mandatory, cand)
                            n_opt = int(case["decisive_optional"])
                            cells.append({
                                "sample_id": sid, "case_id": case["case_id"], "source": src, "family": case["family"],
                                "level": lv, "budget": budget, "policy": pol, "condition": cond, "kind": kind,
                                "rate": rate, "seed": seed, "edges": len(pp), "edges_deleted": nd, "edges_added": na,
                                "arrays_sha256": arrays, "optional_units": len(uids),
                                "tokens": res.tokens if res.target_fits_budget else "", "strategy": res.strategy,
                                "selected": len(res.selected), "decisive_optional": n_opt,
                                "decisive_in_pool": int(case["decisive_in_pool"]), **ev,
                                "all_retained": str(n_opt > 0 and ev["retained"] == n_opt).lower(),
                                "joint_fits": case.get(f"joint_fits_{budget}", ""),
                                "opportunity": case.get(f"opportunity_{budget}", ""),
                                "selected_uids": json.dumps(res.selected), "pack_sha256": _sha(res.text) if res.text else "",
                                "source_map_ok": str(source_map_ok(res, s["texts"], s["target"], s["labels"])).lower(),
                                "pack_s": round(dt, 4)})
                            if res.target_fits_budget and res.tokens > budget:
                                raise AssertionError(f"{sid} {pol} exceeds budget")
                diag.append({"sample_id": sid, "level": lv, "optional_units": len(uids), "edges": len(pairs),
                             "clipped_units": sum(clipped[1:]), "target_clipped": clipped[0]})
            run.logger.info("p7 s3 %s", sid)
    inv.write_rows(run.path / "s3_cells.csv", CELL_FIELDS_S3, cells)
    inv.write_rows(run.path / "s3_encoding.csv", ("sample_id", "level", "optional_units", "edges", "clipped_units",
                                                  "target_clipped"), diag)
    analysis = summarise_s3(cells, int(cfg.get("bootstrap", 2000)), int(run.config["seed"]), perturb_budget)
    inv.write_rows(run.path / "s3_summary.csv", tuple(analysis["rows"][0]) if analysis["rows"] else ("policy",),
                   analysis["rows"])
    inv.write_rows(run.path / "s3_paired.csv", tuple(analysis["paired"][0]) if analysis["paired"] else ("policy",),
                   analysis["paired"])
    inv.write_rows(run.path / "s3_graph_sensitivity.csv",
                   tuple(analysis["graph"][0]) if analysis["graph"] else ("policy",), analysis["graph"])
    result = {"manifest_run": manifest_run.name, "frozen_case_list_sha256": msum["frozen_case_list_sha256"],
              "params": params.as_dict(), "budgets": budgets, "perturbation": {"budget": perturb_budget, "rates": rates,
                                                                               "seeds": seeds},
              "encoder": enc.info(), "cells": len(cells),
              "budget_violations": 0, "source_map_failures": sum(c["source_map_ok"] != "true" for c in cells),
              "timing_s": {k: round(v, 2) for k, v in sorted(timing.items())}}
    result["output_files"] = _digest(run.path, ("s3_cells.csv", "s3_encoding.csv", "s3_summary.csv", "s3_paired.csv",
                                                "s3_graph_sensitivity.csv", "message_diagnostics.jsonl.gz"))
    _json(run.path / "s3_summary.json", result)
    return result


def _boot_diff(pairs_by_family: dict[str, list[float]], n_boot: int, seed: int) -> tuple[float, float, float]:
    pass
    fams = sorted(pairs_by_family)
    if not fams:
        return float("nan"), float("nan"), float("nan")
    means = {f: sum(v) / len(v) for f, v in pairs_by_family.items()}
    est = sum(means.values()) / len(fams)
    if len(fams) < 2:
        return est, float("nan"), float("nan")
    rng = random.Random(seed)
    boots = sorted(sum(means[rng.choice(fams)] for _ in fams) / len(fams) for _ in range(n_boot))
    return est, boots[int(0.025 * n_boot)], boots[min(n_boot - 1, int(0.975 * n_boot))]


def summarise_s3(cells: list[dict], n_boot: int, seed: int, perturb_budget: int = 2048) -> dict:
    det = [c for c in cells if c["condition"] == "detected"]
    rows, paired = [], []
    groups = defaultdict(list)
    for c in det:
        groups[(c["source"], c["level"], c["budget"], c["policy"])].append(c)
    for (src, lv, b, pol), cs in sorted(groups.items()):
        withopt = [c for c in cs if int(c["decisive_optional"]) > 0]
        inpool = [c for c in withopt if int(c["decisive_in_pool"]) > 0]
        sens = [c for c in withopt if c["joint_fits"] == "true" and c["opportunity"] == "true"]
        comp_total = sum(int(c["decisive_optional"]) for c in withopt)
        comp_pool = sum(int(c["decisive_in_pool"]) for c in withopt)
        fits = [c for c in cs if c["tokens"] != ""]
        rows.append({
            "source": src, "level": lv, "budget": b, "policy": pol, "cases": len(cs), "families": len({c["family"] for c in cs}),
            "cases_with_optional": len(withopt), "families_with_optional": len({c["family"] for c in withopt}),
            "components": comp_total, "components_in_pool": comp_pool,
            "components_retained": sum(int(c["retained"]) for c in withopt),
            "retained_direct": sum(int(c["retained_direct"]) for c in withopt),
            "retained_closure": sum(int(c["retained_closure"]) for c in withopt),
            "retention_all": _ratio(sum(int(c["retained"]) for c in withopt), comp_total),
            "retention_given_pool": _ratio(sum(int(c["retained"]) for c in inpool), comp_pool),
            "all_components_retained": _ratio(sum(c["all_retained"] == "true" for c in withopt), len(withopt)),
            "selection_sensitive_cases": len(sens),
            "selection_sensitive_all_retained": _ratio(sum(c["all_retained"] == "true" for c in sens), len(sens)),
            "infeasible_cells": len(cs) - len(fits),
            "mean_tokens": _ratio(sum(int(c["tokens"]) for c in fits), len(fits)),
            "mean_selected": _ratio(sum(int(c["selected"]) for c in fits), len(fits)),
            "mean_pack_s": _ratio(sum(float(c["pack_s"]) for c in cs), len(cs)),
        })
    
    ref = {(c["sample_id"], c["level"], c["budget"]): c for c in det if c["policy"] == "appare"}
    for (src, lv, b, pol), cs in sorted(groups.items()):
        if pol == "appare":
            continue
        fam_diffs, jac = defaultdict(list), []
        for c in cs:
            r = ref.get((c["sample_id"], c["level"], c["budget"]))
            if r is None or int(c["decisive_optional"]) == 0:
                continue
            fam_diffs[c["family"]].append(float(r["all_retained"] == "true") - float(c["all_retained"] == "true"))
            a, bb = set(json.loads(r["selected_uids"])), set(json.loads(c["selected_uids"]))
            jac.append(len(a & bb) / len(a | bb) if a | bb else 1.0)
        est, lo, hi = _boot_diff(fam_diffs, n_boot, seed)
        paired.append({"source": src, "level": lv, "budget": b, "policy": pol, "cases": sum(map(len, fam_diffs.values())),
                       "families": len(fam_diffs), "appare_minus_policy_all_retained": _r(est), "ci_low": _r(lo),
                       "ci_high": _r(hi), "mean_selected_jaccard_vs_appare": _ratio(sum(jac), len(jac))})
    graph = []
    gg = defaultdict(list)
    for c in cells:
        if c["condition"] == "controlled" or (c["condition"] == "detected" and c["policy"] in GATED_POLICIES
                                              and int(c["budget"]) == perturb_budget):
            gg[(c["source"], c["level"], c["budget"], c["policy"], c["kind"] or "none", c["rate"])].append(c)
    for (src, lv, b, pol, kind, rate), cs in sorted(gg.items(), key=lambda kv: tuple(map(str, kv[0]))):
        withopt = [c for c in cs if int(c["decisive_optional"]) > 0]
        graph.append({"source": src, "level": lv, "budget": b, "policy": pol, "kind": kind, "rate": rate,
                      "cells": len(cs), "edges_deleted": sum(int(c["edges_deleted"]) for c in cs),
                      "edges_added": sum(int(c["edges_added"]) for c in cs),
                      "all_components_retained": _ratio(sum(c["all_retained"] == "true" for c in withopt), len(withopt)),
                      "retention_all": _ratio(sum(int(c["retained"]) for c in withopt),
                                              sum(int(c["decisive_optional"]) for c in withopt))})
    return {"rows": rows, "paired": paired, "graph": graph}


def _ratio(a, b):
    return round(a / b, 4) if b else ""


def _r(x):
    return "" if math.isnan(x) else round(x, 4)


__all__ = ["find_run", "perturb", "run_evidence", "run_manifest", "split_families", "unit_graph"]
