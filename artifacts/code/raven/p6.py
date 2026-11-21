"""P6: exact budget packing, source provenance, coverage and select-then-predict isolation.

Inputs are the canonical P5 runs (extraction, contexts) and the P5C-corrected evidence table.
For every built sample the L0-L3 level sets are rebuilt with the P5 rules and checked against
the SHA-256 that P5 recorded for each serialised level, so P6 packs exactly the pool P5 profiled.

Cells are (sample, level, budget, method). Methods in P6 are controls only: ``zero_mask``
(target only) and ``random`` (seeded random scores). No detector, selector or label is used to
build a pack; labels are joined afterwards for coverage and the pack-level conflict check.
"""

from __future__ import annotations

import gzip
import hashlib
import json
import random
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any

from raven import inventory as inv
from raven import packer
from raven.p2 import LineageError, _data_root, _digest, _from_run, _json
from raven.runlog import Run

LEVELS = ("L1", "L2", "L3")
CELL_FIELDS = ("sample_id", "source", "split", "role", "label", "pair_id", "family", "level", "budget", "budget_name",
               "method", "target_fits_budget", "full_tokens", "full_fits_detector", "cohort_budgeted",
               "cohort_full_comparison", "long_input_stratum", "mandatory_tokens", "tokens", "unused_budget",
               "strategy", "pool_units", "direct_units", "closure_added_units", "rejected_did_not_fit",
               "rejected_estimated", "rejected_inside_mandatory", "replaced_by_best_single", "retokenized",
               "pack_sha256", "verified_tokens", "within_budget", "source_map_ok")
POOL_FIELDS = ("sample_id", "level", "index", "uid", "file", "first_line", "last_line", "closure_lines",
               "estimate_tokens")


def _sha(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


_STARTS: dict[int, tuple[bytes, list[int]]] = {}


def _line_starts(text: bytes) -> list[int]:
    hit = _STARTS.get(id(text))
    if hit is None or hit[0] is not text:
        import re

        hit = (text, [0] + [m.end() for m in re.finditer(rb"\n", text)])
        _STARTS[id(text)] = hit
    return hit[1]


def _lines(fu_text: bytes, ranges) -> str:
    import bisect

    starts = _line_starts(fu_text)
    out = []
    for a, b in ranges:
        la = bisect.bisect_right(starts, a)
        lb = bisect.bisect_right(starts, max(a, b - 1))
        out.append(f"{la}-{lb}")
    return ";".join(out)


def find_run(near: Path, name: str) -> Path:
    pass

    from raven.config import REPO_ROOT

    for cand in (near / name, *sorted((REPO_ROOT / "artifacts/results/pilot").glob(f"*/runs/{name}")),
                 REPO_ROOT / "artifacts/runs" / name):
        if (cand / "run.json").exists():
            return cand
    raise FileNotFoundError(f"run {name} not found")


def _uid(path: str, unit) -> str:
    return f"{path}#{unit.start}:{unit.kind}"



def iter_samples(config: dict[str, Any], extract_run: Path, build_run: Path, logger=None, only=None):
    pass



    from raven import analysis, context, p5

    cfg = config["p5"]
    build = {r["sample_id"]: r for r in inv.read_rows(build_run / "contexts.csv") if r["L0"]}
    ext = json.loads((extract_run / "extract_summary.json").read_text())
    p4_summary_run = find_run(extract_run.parent, ext["p4_summary_run"])
    summary, runs = p5._verify_p4(p4_summary_run)
    inventory_run = find_run(p4_summary_run.parent, summary["inputs"]["inventory_run"])
    targets = inv.read_rows(extract_run / "targets.csv")
    data_root = _data_root()
    max_bytes = cfg["extractor"]["max_eligible_file_bytes"]
    min_share_wrap = cfg["extractor"]["module_wrapper_min_line_share"]

    def check(sample_id: str, texts, levels: dict[str, dict], target_file: str, labels=None):
        row = build[sample_id]
        for name, ranges in levels.items():
            text = packer.serialise({p: (texts[p], r) for p, r in ranges.items()}, target_file, labels)
            if _sha(text) != row[f"{name}_sha256"]:
                raise LineageError(f"{sample_id}: rebuilt {name} differs from P5 contexts.csv")

    def cands(fus, pairs, target_file, umap=None):
        out, seen = [], set()
        file_rank = {target_file: 0}
        for p in sorted(fus):
            file_rank.setdefault(p, len(file_rank))
        for path, k in pairs:
            if (path, k) in seen:
                continue
            seen.add((path, k))
            u = fus[path].units[k]
            out.append(packer.Candidate(_uid(path, u), path, tuple(u.ranges), tuple(u.closure), 0.0,
                                        (file_rank[path], u.start)))
            if umap is not None:
                umap[out[-1].uid] = (path, k)
        return out

    
    js_targets = defaultdict(list)
    for t in targets:
        if t["source"] == "jsvul" and f"jsvul:{t['record_id']}" in build and (
                only is None or f"jsvul:{t['record_id']}" in only):
            js_targets[t["snapshot"]].append(t)
    cache: dict[tuple[str, str], Any] = {}
    last_project = None
    for snapshot in sorted(js_targets):
        project, revision = snapshot.split("@")
        if project != last_project:
            cache.clear()
            last_project = project
        rows = js_targets[snapshot]
        tarball = data_root / "snapshots" / "jsvul" / project.replace("/", "__") / f"{revision}.tar.gz"
        all_targets = {t["file"] for t in targets if t["source"] == "jsvul" and t["snapshot"] == snapshot}
        raw, mains = p5._snapshot_files(tarball, all_targets, max_bytes)
        fus = {}
        for path, data in raw.items():
            key = (hashlib.sha256(data).hexdigest(), context.grammar_for(path))
            if key not in cache:
                cache[key] = context.extract(data, key[1], min_share_wrap)
            if cache[key].status == "parsed":
                fus[path] = cache[key]
        files = set(fus)
        importers = defaultdict(set)
        for path, fu in fus.items():
            for spec in analysis.import_specs(fu.text):
                dst, _ = analysis.resolve_module(spec, path, files, mains)
                if dst:
                    importers[dst].add(path)
        usable_all = [t for t in targets if t["source"] == "jsvul" and t["snapshot"] == snapshot
                      and t["target_status"] in ("coincides", "nested")]
        target_files = {t["file"] for t in usable_all}
        needed = set(target_files)
        for tf in target_files:
            needed |= importers[tf]
            for spec in analysis.import_specs(fus[tf].text):
                dst, _ = analysis.resolve_module(spec, tf, files, mains)
                if dst:
                    needed.add(dst)
        analysers = {p: analysis.JsAnalyser(p, fus[p]) for p in sorted(needed)}
        for an in analysers.values():
            an.analyse()
        analysis.link(analysers, files, mains)
        texts = {p: fu.text for p, fu in fus.items()}
        all_units = {p: [r for k in range(len(fu.units)) for r in p5._with_closure(fu, k)] for p, fu in fus.items()}
        for t in rows:
            fu = fus[t["file"]]
            k = p5._unit_index(fu, t["unit_id"])
            target = p5._parse_ranges(t["target_ranges"])
            tclos = p5._parse_ranges(t["closure_ranges"])
            l0 = {t["file"]: target + tclos}
            l1 = {t["file"]: l0[t["file"]] + all_units[t["file"]]}
            l2 = {p: list(r) for p, r in l1.items()}
            callee, caller, imported = set(), set(), set()
            for e in analysers[t["file"]].g.edges:
                inside = any(a <= e.span[0] < b for a, b in target)
                if inside and e.status == "resolved" and e.dst_unit >= 0 and e.dst_file != t["file"]:
                    (callee if e.type == "call" else imported).add((e.dst_file, e.dst_unit))
            for an in analysers.values():
                if an.g.path == t["file"]:
                    continue
                for e in an.g.edges:
                    if e.type == "call" and e.status == "resolved" and e.dst_file == t["file"] and e.dst_unit == k:
                        caller.add((an.g.path, e.src_unit))
            hop = sorted(callee | caller | imported)
            for path, unit in hop:
                l2.setdefault(path, []).extend(p5._with_closure(fus[path], unit))
            l3 = {p: list(l2.get(p, [])) + all_units[p] for p in fus}
            sid = f"jsvul:{t['record_id']}"
            check(sid, texts, {"L0": l0, "L1": l1, "L2": l2, "L3": l3}, t["file"])
            own = [(t["file"], j) for j in range(len(fu.units))]
            umap: dict[str, tuple[str, int]] = {}
            pools = {"L1": cands(fus, own, t["file"], umap)}
            pools["L2"] = cands(fus, own + hop, t["file"], umap)
            pools["L3"] = cands(fus, own + hop + [(p, j) for p in sorted(fus) for j in range(len(fus[p].units))],
                                t["file"], umap)
            yield {"sample_id": sid, "row": build[sid], "texts": {p: texts[p] for p in l3}, "labels": None,
                   "fu": fu,
                   "target_file": t["file"], "target": {t["file"]: target}, "target_closure": {t["file"]: tclos},
                   "levels": {"L0": l0, "L1": l1, "L2": l2, "L3": l3}, "pools": pools,
                   "unit_index": umap, "snapshot": snapshot}
        if logger:
            logger.info("p6 samples %s: %d", snapshot, len(rows))

    
    if only is not None and not any(x.startswith("sard_php:") for x in only):
        return
    php_meta = {r["record_id"]: r for r in inv.read_rows(runs["overlap"] / "php_cases.csv.gz")}
    sard = {r["record_id"]: r for r in inv.read_rows(inventory_run / "inventory_sard_php.csv.gz")}
    php_t = {t["record_id"]: t for t in targets if t["source"] == "sard_php"}
    php_root = data_root / "snapshots" / "sard_php"
    pool_fu, pool_path = {}, {}
    for case_dir in sorted(p for p in php_root.iterdir() if p.is_dir() and p.name in sard):
        case = case_dir.name
        data, _ = context.blank_sard_markers((case_dir / sard[case]["src_file"]).read_bytes())
        fu = context.extract(data, "php", min_share_wrap)
        if fu.status == "parsed":
            pool_fu[case] = fu
            pool_path[case] = f"{case}/{sard[case]['src_file']}"
    pseudonym = {pool_path[c]: f"sard/{hashlib.sha256(c.encode()).hexdigest()[:12]}.php" for c in pool_path}
    pairs = [r for r in inv.read_rows(runs["sard_php"] / "php_twins.csv") if r["status"] == "aligned_not_reproduced"]
    for row in pairs:
        pool, _ = p5.php_pool(row["pair_id"], php_meta, set(pool_fu), config["seed"])
        for case in row["pair_id"].split("+"):
            sid = f"sard_php:{case}"
            if sid not in build or (only is not None and sid not in only):
                continue
            t = php_t[case]
            fus = {pool_path[c]: pool_fu[c] for c in [case, *pool]}
            path = pool_path[case]
            texts = {p: f.text for p, f in fus.items()}
            all_units = {p: [r for k in range(len(f.units)) for r in p5._with_closure(f, k)] for p, f in fus.items()}
            target = p5._parse_ranges(t["target_ranges"])
            tclos = p5._parse_ranges(t["closure_ranges"])
            l0 = {path: target + tclos}
            l1 = {path: l0[path] + all_units[path]}
            l3 = {p: (l1[p] if p == path else []) + all_units[p] for p in fus}
            check(sid, texts, {"L0": l0, "L1": l1, "L2": dict(l1), "L3": l3}, path, pseudonym)
            own = [(path, j) for j in range(len(fus[path].units))]
            umap = {}
            pools = {"L1": cands(fus, own, path, umap)}
            pools["L2"] = list(pools["L1"])
            pools["L3"] = cands(fus, own + [(p, j) for p in sorted(fus) for j in range(len(fus[p].units))], path, umap)
            yield {"sample_id": sid, "row": build[sid], "texts": texts, "labels": pseudonym, "target_file": path,
                   "fu": fus[path],
                   "target": {path: target}, "target_closure": {path: tclos},
                   "levels": {"L0": l0, "L1": l1, "L2": dict(l1), "L3": l3}, "pools": pools,
                   "unit_index": umap, "snapshot": ""}



def method_scores(method: str, seed: int, sample_id: str, pool: list[packer.Candidate]) -> list[packer.Candidate]:
    pass

    from dataclasses import replace

    if method == "zero_mask":
        return []
    if method == "uniform":
        return [replace(c, score=1.0) for c in pool]
    if method == "random":
        out = []
        for c in pool:
            h = hashlib.sha256(f"{seed}:{sample_id}:{c.uid}".encode()).digest()
            out.append(replace(c, score=(int.from_bytes(h[:8], "big") + 1) / 2**64))
        return out
    raise ValueError(f"unknown P6 method {method!r}")


def token_offsets(tokenizer, text: str) -> list[tuple[int, int]]:
    enc = tokenizer(text, add_special_tokens=False, return_offsets_mapping=True)
    return [tuple(o) for o in enc["offset_mapping"]]


def char_to_token_span(offsets: list[tuple[int, int]], a: int, b: int) -> tuple[int, int]:
    pass
    import bisect

    ends = [o[1] for o in offsets]
    i = bisect.bisect_right(ends, a)
    j = i
    while j < len(offsets) and offsets[j][0] < b:
        j += 1
    return i, j


def _roles(runs: dict[str, Path]) -> tuple[dict[str, dict], dict[str, dict]]:
    groups = {r["group_id"]: r for r in inv.read_rows(runs["overlap"] / "pilot_groups.csv")}
    nodes = {r["node"]: r for r in inv.read_rows(runs["overlap"] / "split_assignment.csv.gz")}
    php = {r["record_id"]: r for r in inv.read_rows(runs["overlap"] / "php_cases.csv.gz")}
    out = {}
    for node, r in nodes.items():
        out[node] = {"family": r["group_id"], "role": groups.get(r["group_id"], {}).get("role", r.get("role", ""))}
    for rid, r in php.items():
        out[f"sard_php:{rid}"] = {"family": r["group_id"], "role": groups.get(r["group_id"], {}).get("role", r["role"])}
    return out, groups


def _roles_for(extract_run: Path) -> dict[str, dict]:
    pass
    from raven import p5

    ext = json.loads((extract_run / "extract_summary.json").read_text())
    _, runs = p5._verify_p4(find_run(extract_run.parent, ext["p4_summary_run"]))
    return _roles(runs)[0]


def run_pack(run: Run, extract_run: Path, build_run: Path, p5c_run: Path) -> dict[str, Any]:
    from raven import p5

    cfg = run.config["p6"]
    extract_run = _from_run(extract_run, "extract-units")
    build_run = _from_run(build_run, "build-contexts")
    p5c_run = _from_run(p5c_run, "p5c-correction")
    csum = json.loads((build_run / "contexts_summary.json").read_text())
    if _digest(build_run, tuple(csum["output_files"])) != csum["output_files"]:
        raise LineageError(f"{build_run.name} outputs changed after the run")
    psum = json.loads((p5c_run / "correction_summary.json").read_text())
    if _digest(p5c_run, tuple(psum["output_files"])) != psum["output_files"]:
        raise LineageError(f"{p5c_run.name} outputs changed after the run")
    if psum["build_run"] != build_run.name or psum["extract_run"] != extract_run.name:
        raise LineageError("P5C run does not descend from the given extraction/contexts runs")
    approved = cfg["approved_evidence_selectability_sha256"]
    if psum["output_files"]["evidence_selectability.csv"] != approved:
        raise LineageError("P5C evidence table hash differs from the approved hash in p6.yaml")
    ext = json.loads((extract_run / "extract_summary.json").read_text())
    _, runs = p5._verify_p4(find_run(extract_run.parent, ext["p4_summary_run"]))
    roles, _ = _roles(runs)
    if roles_bad := sorted({roles.get(s, {}).get("role") for s in
                            (r["sample_id"] for r in inv.read_rows(build_run / "contexts.csv") if r["L0"])}
                           - {"pilot_dev"}):
        raise LineageError(f"P6 packs pilot_dev samples only; found roles {roles_bad}")

    tokenizer = p5.load_tokenizer(run.config)
    count = lambda text: p5.count_tokens(tokenizer, text)
    bstar = csum["bstar"]
    budgets = list(run.config["budgets"])
    limit = int(cfg["detector_context_limit"])
    reserved = int(cfg.get("reserved_tokens", 0))
    prompt = cfg.get("prompt_prefix", "")
    slack = int(cfg["estimate_slack_tokens"])
    methods = cfg["methods"]
    seed = run.config["seed"]
    rng = random.Random(seed)
    audit_rate = float(cfg["estimate_audit_rate"])

    cells, pool_rows, est_audit = [], [], Counter()
    manifest_path = run.path / "pack_manifest.jsonl.gz"
    review_candidates = []
    conflicts_key = defaultdict(set)
    with gzip.open(manifest_path, "wt", encoding="utf-8") as man:
        for n_done, s in enumerate(iter_samples(run.config, extract_run, build_run, run.logger)):
            if cfg.get("limit_samples") and n_done >= int(cfg["limit_samples"]):
                break
            row, sid = s["row"], s["sample_id"]
            texts, labels, tf = s["texts"], s["labels"], s["target_file"]
            mandatory = {tf: s["levels"]["L0"][tf]}
            role = roles.get(sid, {})
            src_budgets = budgets + ([bstar[row["source"]]] if bstar.get(row["source"]) not in (None, *budgets) else [])
            est_cache: dict[str, int] = {}
            for level in LEVELS:
                full_tokens = int(row[level])
                full_fits = full_tokens + reserved + len(tokenizer(prompt, add_special_tokens=False)["input_ids"]) <= limit
                pool = s["pools"][level]
                need = [c for c in pool if c.uid not in est_cache]
                for j in range(0, len(need), 256):
                    batch = need[j:j + 256]
                    enc = tokenizer([b"".join(texts[c.file][a:b] for a, b in packer._merge(c.span_set))
                                     .decode("utf-8", "replace") for c in batch], add_special_tokens=False)
                    for c, ids in zip(batch, enc["input_ids"]):
                        est_cache[c.uid] = len(ids)
                for i, c in enumerate(pool):
                    fu_text = texts[c.file]
                    pool_rows.append({"sample_id": sid, "level": level, "index": i, "uid": c.uid,
                                      "file": labels.get(c.file, c.file) if labels else c.file,
                                      "first_line": _lines(fu_text, [c.ranges[0]]).split("-")[0],
                                      "last_line": _lines(fu_text, [c.ranges[-1]]).split("-")[-1],
                                      "closure_lines": _lines(fu_text, c.closure), "estimate_tokens": est_cache[c.uid]})
                index = {c.uid: i for i, c in enumerate(pool)}
                for b in src_budgets:
                    bname = "bstar" if b == bstar.get(row["source"]) and b not in budgets else str(b)
                    eff = b - reserved
                    for method in methods:
                        scored = method_scores(method, seed, sid, pool)
                        res = packer.pack(texts, tf, mandatory, scored, eff, count, labels=labels, prompt=prompt,
                                          estimates=est_cache, slack=slack)
                        by_uid = {c.uid: c for c in scored}
                        pieces = packer.provenance(texts, tf, res, s["target"], s["target_closure"], by_uid,
                                                   labels, prompt) if res.target_fits_budget else []
                        ok = all(res.text[p["out"][0]:p["out"][1]] ==
                                 texts[p["file"]][p["src"][0]:p["src"][1]].decode("utf-8", "replace") for p in pieces)
                        verified = count(res.text) if res.target_fits_budget else res.mandatory_tokens
                        
                        if res.target_fits_budget and res.estimate_skips and rng.random() < audit_rate:
                            skipped = [u for u, why in res.rejected.items() if why == "estimated_over_budget"]
                            u = rng.choice(skipped)
                            trial = {f: list(r) for f, r in res.files.items()}
                            c = by_uid[u]
                            trial[c.file] = packer._merge(trial.get(c.file, []) + c.span_set)
                            n = count(prompt + packer.serialise({f: (texts[f], r) for f, r in trial.items()}, tf, labels))
                            est_audit["audited"] += 1
                            est_audit["would_have_fit"] += n <= eff
                        closure_added = {u for u in res.selected if by_uid[u].closure}
                        rej = Counter(res.rejected.values())
                        cell = {
                            "sample_id": sid, "source": row["source"], "split": row["split"],
                            "role": role.get("role", ""), "label": row["label"], "pair_id": row.get("pair_id", ""),
                            "family": role.get("family", ""), "level": level, "budget": b, "budget_name": bname,
                            "method": method, "target_fits_budget": str(res.target_fits_budget).lower(),
                            "full_tokens": full_tokens, "full_fits_detector": str(full_fits).lower(),
                            "cohort_budgeted": str(res.target_fits_budget).lower(),
                            "cohort_full_comparison": str(res.target_fits_budget and full_fits).lower(),
                            "long_input_stratum": str(res.target_fits_budget and not full_fits).lower(),
                            "mandatory_tokens": res.mandatory_tokens, "tokens": res.tokens if res.target_fits_budget else "",
                            "unused_budget": res.unused_budget if res.target_fits_budget else "",
                            "strategy": res.strategy, "pool_units": len(pool), "direct_units": len(res.selected),
                            "closure_added_units": len(closure_added), "rejected_did_not_fit": rej["did_not_fit"],
                            "rejected_estimated": rej["estimated_over_budget"],
                            "rejected_inside_mandatory": rej["inside_mandatory"],
                            "replaced_by_best_single": rej["replaced_by_best_single"], "retokenized": res.retokenized,
                            "pack_sha256": _sha(res.text) if res.target_fits_budget else "",
                            "verified_tokens": verified + reserved if res.target_fits_budget else "",
                            "within_budget": str((not res.target_fits_budget) or verified + reserved <= b).lower(),
                            "source_map_ok": str(ok).lower()}
                        cells.append(cell)
                        if res.target_fits_budget:
                            conflicts_key[(row["source"], level, bname, method, cell["pack_sha256"])].add(
                                (sid, row["label"]))
                        offsets = token_offsets(tokenizer, res.text) if pieces else []
                        man.write(json.dumps({
                            "sample_id": sid, "level": level, "budget": b, "method": method,
                            "target_fits_budget": res.target_fits_budget, "full_fits_detector": full_fits,
                            "tokens": res.tokens, "mandatory_tokens": res.mandatory_tokens, "strategy": res.strategy,
                            "prompt_sha256": _sha(prompt), "pack_sha256": cell["pack_sha256"],
                            "selected": [{"index": index[u], "uid": u, "rank": r, "score": by_uid[u].score,
                                          "closure_added": bool(by_uid[u].closure)} for r, u in enumerate(res.selected)],
                            "rejected": {why: sorted(index[u] for u, w in res.rejected.items() if w == why)
                                         for why in sorted(set(res.rejected.values()))},
                            "best_single": res.best_single_uid,
                            "pieces": [{**p, "file": labels.get(p["file"], p["file"]) if labels else p["file"],
                                        "lines": _lines(texts[p["file"]], [tuple(p["src"])]),
                                        "tokens": list(char_to_token_span(offsets, *p["out"]))} for p in pieces],
                        }, sort_keys=True) + "\n")
                        if res.target_fits_budget and method == "random" and res.selected:
                            review_candidates.append((sid, level, b, method))
            run.logger.info("p6 packed %s", sid)

    inv.write_rows(run.path / "pack_cells.csv", CELL_FIELDS, cells)
    inv.write_rows(run.path / "pool_units.csv.gz", POOL_FIELDS, pool_rows)

    
    cov = []
    keyed = defaultdict(list)
    for c in cells:
        if c["method"] == methods[0]:
            keyed[(c["source"], c["level"], c["budget_name"])].append(c)
    frontier = defaultdict(lambda: True)
    for c in cells:
        if c["method"] == methods[0] and c["budget_name"] != "bstar":
            frontier[(c["sample_id"], c["level"])] &= c["target_fits_budget"] == "true"
    for (source, level, bname), rows in sorted(keyed.items()):
        n = len(rows)
        tf = sum(r["target_fits_budget"] == "true" for r in rows)
        ff = sum(r["full_fits_detector"] == "true" for r in rows)
        both = sum(r["cohort_full_comparison"] == "true" for r in rows)
        cov.append({"source": source, "level": level, "budget": bname, "samples": n,
                    "target_fits_budget": tf, "share_target_fits": round(tf / n, 4),
                    "full_fits_detector": ff, "cohort_budgeted": tf, "cohort_full_comparison": both,
                    "long_input_stratum": tf - both,
                    "primary_frontier_samples": sum(frontier[(r["sample_id"], level)] for r in rows)})
    inv.write_rows(run.path / "coverage.csv", tuple(cov[0]) if cov else ("source",), cov)

    
    conflicts = []
    for (source, level, bname, method, h), members in sorted(conflicts_key.items()):
        if len({lab for _, lab in members}) > 1:
            gid = f"{source}:{level}:{bname}:{method}:{h[:12]}"
            conflicts += [{"source": source, "level": level, "budget": bname, "method": method, "conflict_group": gid,
                           "sample_id": sid, "label": lab, "pack_sha256": h} for sid, lab in sorted(members)]
    inv.write_rows(run.path / "pack_label_conflicts.csv",
                   ("source", "level", "budget", "method", "conflict_group", "sample_id", "label", "pack_sha256"),
                   conflicts)

    
    by_stratum = defaultdict(list)
    for key in review_candidates:
        by_stratum[(key[0].split(":")[0], key[1])].append(key)
    picks = []
    n_review = int(cfg["source_map_review_packs"])
    strata = sorted(by_stratum)
    for st in strata:
        rng.shuffle(by_stratum[st])
    i = 0
    while len(picks) < n_review and any(len(by_stratum[st]) > i for st in strata):
        for st in strata:
            if len(by_stratum[st]) > i and len(picks) < n_review:
                picks.append(by_stratum[st][i])
        i += 1
    pick_set = set(picks)
    sheet = []
    with gzip.open(manifest_path, "rt", encoding="utf-8") as man:
        for line in man:
            m = json.loads(line)
            if (m["sample_id"], m["level"], m["budget"], m["method"]) not in pick_set:
                continue
            for j, p in enumerate(m["pieces"]):
                sheet.append({"pack": f"{m['sample_id']}|{m['level']}|{m['budget']}|{m['method']}", "piece": j,
                              "file": p["file"], "lines": p["lines"], "origin": p["origin"],
                              "out_chars": f"{p['out'][0]}-{p['out'][1]}", "tokens": f"{p['tokens'][0]}-{p['tokens'][1]}",
                              "verdict": "", "reviewer": "", "date": ""})
    inv.write_rows(run.path / "source_map_review.csv",
                   ("pack", "piece", "file", "lines", "origin", "out_chars", "tokens", "verdict", "reviewer", "date"),
                   sheet)

    feasible = [c for c in cells if c["target_fits_budget"] == "true"]
    result = {
        "extract_run": extract_run.name, "build_run": build_run.name, "p5c_run": p5c_run.name,
        "evidence_selectability_sha256": approved, "tokenizer_revision": run.config["tokenizer_revision"],
        "detector_context_limit": limit, "reserved_tokens": reserved, "prompt_sha256": _sha(prompt),
        "methods": methods, "budgets": budgets, "bstar": bstar,
        "samples": len({c["sample_id"] for c in cells}), "cells": len(cells),
        "feasible_cells": len(feasible),
        "feasible_within_budget": sum(c["within_budget"] == "true" for c in feasible),
        "over_budget_cells": [f"{c['sample_id']}|{c['level']}|{c['budget']}|{c['method']}"
                              for c in feasible if c["within_budget"] != "true"],
        "source_map_ok_cells": sum(c["source_map_ok"] == "true" for c in feasible),
        "level_rebuild": "every rebuilt L0-L3 serialisation matched the P5 SHA-256",
        "four_combinations": dict(Counter(f"target_fits={c['target_fits_budget']}/full_fits={c['full_fits_detector']}"
                                          for c in cells)),
        "strategy": dict(Counter(c["strategy"] for c in cells)),
        "estimate_skip_audit": dict(est_audit),
        "pack_label_conflicts": len({c["conflict_group"] for c in conflicts}),
        "source_map_review_packs": len(picks),
    }
    result["output_files"] = _digest(run.path, ("pack_cells.csv", "pool_units.csv.gz", "pack_manifest.jsonl.gz",
                                                "coverage.csv", "pack_label_conflicts.csv", "source_map_review.csv"))
    _json(run.path / "pack_summary.json", result)
    run.logger.info("p6 pack: %s", json.dumps({k: result[k] for k in ("cells", "feasible_cells",
                                                                       "feasible_within_budget",
                                                                       "source_map_ok_cells", "estimate_skip_audit")}))
    if result["over_budget_cells"] or result["source_map_ok_cells"] != len(feasible):
        raise AssertionError("P6 pack: a feasible cell exceeds its budget or fails source mapping")
    if est_audit["would_have_fit"]:
        raise AssertionError("P6 pack: an estimate skip would have fitted (increase estimate_slack_tokens)")
    return result
