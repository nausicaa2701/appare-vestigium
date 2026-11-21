"""P5 commands. Unit rules are in ``docs/unit-spec.md`` (frozen before this code).

This module currently holds the necessity-review case selection, which must be committed
before review starts (plan §P5 AC 6). It reads only ``pilot_dev`` records, never detector or
selector outputs, and selects without looking at any model result.
"""

from __future__ import annotations

import hashlib
import json
import os
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any

from raven import inventory as inv
from raven.p2 import LineageError, _data_root, _digest, _from_run, _json
from raven.runlog import Run

QWEN_REPO = "Qwen/Qwen2.5-Coder-1.5B"
REVIEW_SETS = ("calibration", "validation")
LENGTH_STRATA = ("short", "medium", "long")


def load_tokenizer(config: dict[str, Any]):
    pass
    from transformers import AutoTokenizer

    tokenizer = AutoTokenizer.from_pretrained(QWEN_REPO, revision=config["tokenizer_revision"], local_files_only=True,
                                              cache_dir=os.environ.get("RAVEN_MODEL_CACHE"))
    if len(tokenizer) < 1000 or not tokenizer("function raven_probe() { return 42; }", add_special_tokens=False)["input_ids"]:
        raise RuntimeError("Qwen tokenizer cache is incomplete; set RAVEN_MODEL_CACHE to the pinned complete cache")
    return tokenizer


def count_tokens(tokenizer, text: str) -> int:
    return len(tokenizer(text, add_special_tokens=False)["input_ids"])


def _rank(seed: int, *parts: str) -> str:
    return hashlib.sha256(":".join((str(seed), *parts)).encode()).hexdigest()


def length_strata(lengths: dict[str, int]) -> dict[str, str]:
    pass
    order = sorted(lengths, key=lambda c: (lengths[c], c))
    n = len(order)
    return {c: LENGTH_STRATA[min(2, (3 * i) // n)] for i, c in enumerate(order)} if n else {}


def select_cases(cases: list[dict[str, Any]], cap: int, seed: int) -> list[dict[str, Any]]:
    pass






    by_stratum: dict[tuple[str, str], list[dict[str, Any]]] = defaultdict(list)
    for case in cases:
        by_stratum[(case["weakness"], case["length_stratum"])].append(case)
    for members in by_stratum.values():
        members.sort(key=lambda c: (_rank(seed, "family", c["family"]), _rank(seed, "case", c["case_id"])))
    strata = sorted(by_stratum, key=lambda s: _rank(seed, "stratum", *s))
    picked: list[dict[str, Any]] = []
    while len(picked) < cap and any(by_stratum[s] for s in strata):
        for stratum in strata:
            if len(picked) >= cap:
                break
            if by_stratum[stratum]:
                case = by_stratum[stratum].pop(0)
                picked.append(case)
    
    half = cap // 2
    members: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for case in picked:
        members[case["family"]].append(case)
    counts = {name: 0 for name in REVIEW_SETS}
    out = []
    for family in sorted(members, key=lambda f: _rank(seed, "family", f)):
        group = members[family]
        target = next((s for s in REVIEW_SETS if counts[s] + len(group) <= half), None)
        for case in group:
            out.append({**case, "review_set": target or "not_assigned"})
        if target:
            counts[target] += len(group)
    return out


def _verify_p4(summary_run: Path) -> tuple[dict[str, Any], dict[str, Path]]:
    pass
    summary_run = _from_run(summary_run, "p4-summary")
    summary = json.loads((summary_run / "p4_summary.json").read_text())
    if _digest(summary_run, tuple(summary["output_files"])) != summary["output_files"]:
        raise LineageError(f"{summary_run.name} outputs changed after the run")
    root = summary_run.parent
    runs = {
        "overlap": _from_run(root / summary["inputs"]["overlap_run"], "overlap"),
        "jsvul": _from_run(root / summary["inputs"]["runs"]["jsvul"]["run"], "jsvul-align"),
        "sard_php": _from_run(root / summary["inputs"]["runs"]["sard_php"]["run"], "php-twins"),
    }
    for source in ("jsvul", "sard_php"):
        recorded = summary["inputs"]["runs"][source]["output_files"]
        if _digest(runs[source], tuple(recorded)) != recorded:
            raise LineageError(f"{runs[source].name} outputs changed after the P4 summary")
    recorded = summary["inputs"]["overlap_output_files"]
    if _digest(runs["overlap"], tuple(recorded)) != recorded:
        raise LineageError(f"{runs['overlap'].name} outputs changed after the P4 summary")
    return summary, runs


def review_case_id(source: str, pair_id: str) -> str:
    pass
    return f"rc-{source}-{hashlib.sha256(pair_id.encode()).hexdigest()[:12]}"


def _twin_order(seed: int, case_id: str, records: list[str]) -> list[str]:
    pass
    return sorted(records, key=lambda r: _rank(seed, "twin", case_id, r))


def jsvul_cases(runs: dict[str, Path], roles: dict[str, str], groups: dict[str, str], tokenizer, seed: int) -> tuple[list[dict], list[dict]]:
    align = {r["record_id"]: r for r in inv.read_rows(runs["jsvul"] / "jsvul_alignment.csv")}
    cases, key = [], []
    for pair in inv.read_rows(runs["jsvul"] / "jsvul_pairs.csv"):
        if pair["status"] != "aligned_not_reproduced":
            continue
        records = pair["pair_id"].split("+")
        if any(roles.get(f"jsvul:{r}") != "pilot_dev" for r in records):
            raise PermissionError(f"review cases must be pilot_dev; {pair['pair_id']} is not")
        rows = [align[r] for r in records]
        lengths = []
        for row in rows:
            path = _data_root() / "files" / "jsvul" / row["project"].replace("/", "__") / row["revision"] / row["file"]
            lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
            lengths.append(count_tokens(tokenizer, "\n".join(lines[int(row["start_line"]) - 1:int(row["end_line"])])))
        case_id = review_case_id("jsvul", pair["pair_id"])
        twins = _twin_order(seed, case_id, records)
        cases.append({
            "case_id": case_id, "source": "jsvul", "family": groups[f"jsvul:{records[0]}"],
            "weakness": (pair["cwe"] or "unknown").split(";")[0], "project": pair["project"],
            "target_tokens": max(lengths),
            "twin_a": twins[0], "twin_b": twins[1],
            "twin_a_span": f"{align[twins[0]]['file']}:{align[twins[0]]['start_line']}-{align[twins[0]]['end_line']}",
            "twin_b_span": f"{align[twins[1]]['file']}:{align[twins[1]]['start_line']}-{align[twins[1]]['end_line']}",
            "twin_a_sha256": align[twins[0]]["file_sha256"], "twin_b_sha256": align[twins[1]]["file_sha256"],
        })
        key.append({"case_id": case_id, "pair_id": pair["pair_id"],
                    "twin_a_label": align[twins[0]]["label"], "twin_b_label": align[twins[1]]["label"]})
    return cases, key


def php_cases(runs: dict[str, Path], inventory_run: Path, tokenizer, seed: int) -> tuple[list[dict], list[dict]]:
    php_roles = {r["record_id"]: r for r in inv.read_rows(runs["overlap"] / "php_cases.csv.gz")}
    sard = {r["record_id"]: r for r in inv.read_rows(inventory_run / "inventory_sard_php.csv.gz")}
    root = _data_root() / "snapshots" / "sard_php"
    cases, key = [], []
    for row in inv.read_rows(runs["sard_php"] / "php_twins.csv"):
        if row["status"] != "aligned_not_reproduced":
            continue
        bad, good = row["pair_id"].split("+")
        if any(php_roles[c]["role"] != "pilot_dev" for c in (bad, good)):
            raise PermissionError(f"review cases must be pilot_dev; {row['pair_id']} is not")
        texts = {c: (root / c / sard[c]["src_file"]).read_bytes() for c in (bad, good)}
        case_id = review_case_id("sard_php", row["pair_id"])
        twins = _twin_order(seed, case_id, [bad, good])
        cases.append({
            "case_id": case_id, "source": "sard_php", "family": php_roles[bad]["group_id"],
            "weakness": row["cwe"], "project": "sard-103",
            "target_tokens": max(count_tokens(tokenizer, t.decode("utf-8", "replace")) for t in texts.values()),
            "twin_a": twins[0], "twin_b": twins[1],
            "twin_a_span": f"{sard[twins[0]]['src_file']}:sink {row['sink_line']!r}",
            "twin_b_span": f"{sard[twins[1]]['src_file']}:sink {row['sink_line']!r}",
            "twin_a_sha256": hashlib.sha256(texts[twins[0]]).hexdigest(),
            "twin_b_sha256": hashlib.sha256(texts[twins[1]]).hexdigest(),
        })
        key.append({"case_id": case_id, "pair_id": row["pair_id"], "twin_a_label": "1" if twins[0] == bad else "0",
                    "twin_b_label": "1" if twins[1] == bad else "0"})
    return cases, key


CASE_FIELDS = ("case_id", "source", "review_set", "family", "weakness", "length_stratum", "target_tokens",
               "project", "twin_a", "twin_b", "twin_a_span", "twin_b_span", "twin_a_sha256", "twin_b_sha256")


def run_review_cases(run: Run, p4_summary_run: Path) -> dict[str, Any]:
    cfg = run.config["p5"]["review"]
    seed = run.config["seed"]
    summary, runs = _verify_p4(p4_summary_run)
    inventory_run = p4_summary_run.parent / summary["inputs"]["inventory_run"]
    split = list(inv.read_rows(runs["overlap"] / "split_assignment.csv.gz"))
    roles = {r["node"]: r["role"] for r in split}
    groups = {r["node"]: r["group_id"] for r in split}
    tokenizer = load_tokenizer(run.config)
    rows, keys, report = [], [], {}
    for source, (cases, key), cap in (
        ("jsvul", jsvul_cases(runs, roles, groups, tokenizer, seed), cfg["cap_jsvul_targets"]),
        ("sard_php", php_cases(runs, inventory_run, tokenizer, seed), cfg["cap_php_pairs"]),
    ):
        
        
        too_long = [c["case_id"] for c in cases if c["target_tokens"] > max(run.config["budgets"])]
        cases = [c for c in cases if c["case_id"] not in too_long]
        strata = length_strata({c["case_id"]: c["target_tokens"] for c in cases})
        for case in cases:
            case["length_stratum"] = strata[case["case_id"]]
        chosen = select_cases(cases, cap, seed)
        rows += chosen
        chosen_ids = {c["case_id"] for c in chosen}
        keys += [k for k in key if k["case_id"] in chosen_ids]
        sets = Counter(c["review_set"] for c in chosen)
        report[source] = {
            "excluded_target_over_max_budget": too_long,
            "eligible_cases": len(cases), "eligible_families": len({c["family"] for c in cases}),
            "cap": cap, "selected": len(chosen), "by_set": dict(sets),
            "families_by_set": {s: len({c["family"] for c in chosen if c["review_set"] == s}) for s in sets},
            "by_weakness": dict(Counter(c["weakness"] for c in chosen)),
            "by_length_stratum": dict(Counter(c["length_stratum"] for c in chosen)),
            "shortage": {s: cap // 2 - sets.get(s, 0) for s in REVIEW_SETS if sets.get(s, 0) < cap // 2},
        }
    cal = {c["family"] for c in rows if c["review_set"] == "calibration"}
    val = {c["family"] for c in rows if c["review_set"] == "validation"}
    if cal & val:
        raise AssertionError(f"calibration and validation share families: {sorted(cal & val)[:3]}")
    inv.write_rows(run.path / "review_cases.csv", CASE_FIELDS, rows)
    
    inv.write_rows(run.path / "review_label_key.csv", ("case_id", "pair_id", "twin_a_label", "twin_b_label"), keys)
    result = {
        "p4_summary_run": p4_summary_run.name, "seed": seed, "rubric": run.config["p5"]["review"]["rubric"],
        "selection": "strata (weakness x target-length tercile) round-robin in hash order; families whole; "
                     "calibration/validation each up to cap/2, family-disjoint",
        "eligibility": "pilot_dev; P4 aligned_not_reproduced; max twin target tokens <= max(budgets)",
        "length_measure": "max over twins of Qwen tokens of the aligned target (JsVul) or the case file (PHP)",
        "sources": report,
        "inputs": {"p4_summary_output_files": summary["output_files"], "jsvul_run": runs["jsvul"].name,
                   "php_run": runs["sard_php"].name, "overlap_run": runs["overlap"].name},
    }
    result["output_files"] = _digest(run.path, ("review_cases.csv", "review_label_key.csv"))
    _json(run.path / "review_cases_summary.json", result)
    run.logger.info("review cases: %s", json.dumps(report, sort_keys=True))
    return result




EXCLUDED_DIRS = frozenset({"node_modules", "vendor", "bower_components", "dist", "build", "coverage", "test",
                           "tests", "__tests__", "spec", "fixtures", "examples"})
EXCLUDED_SUFFIXES = (".min.js", ".bundle.js", ".d.ts", ".d.mts", ".d.cts", ".map")
UNIT_FIELDS = ("unit_id", "source", "snapshot", "file", "kind", "name", "parent_class", "ranges", "first",
               "last", "closure", "file_sha256")
STATUS_FIELDS = ("source", "snapshot", "file", "scope", "grammar", "status", "bytes", "units", "file_sha256")
FAILURE_FIELDS = ("source", "snapshot", "file", "scope", "grammar", "status", "first_error", "error_nodes",
                  "error_byte_share", "exception")
TARGET_FIELDS = ("record_id", "source", "snapshot", "file", "grammar", "parse_status", "target_status",
                 "unit_id", "unit_kind", "target_lines", "target_ranges", "remainder_ranges", "closure_ranges",
                 "reason", "file_sha256")


def eligibility(path: str, size: int, family: str, max_bytes: int) -> str:
    pass
    from raven import context

    grammar = context.grammar_for(path)
    lower = path.lower()
    if lower.endswith(EXCLUDED_SUFFIXES):
        return "excluded_suffix"
    if grammar is None:
        return "not_code"
    if context.FAMILY[grammar] != family:
        return "other_language"
    if any(part in EXCLUDED_DIRS for part in path.split("/")[:-1]):
        return "excluded_dir"
    if size > max_bytes:
        return "too_large"
    return ""


def _ranges(ranges) -> str:
    return ";".join(f"{a}-{b}" for a, b in ranges)


def _unit_rows(source: str, snapshot: str, path: str, fu, sha: str) -> list[dict]:
    rows = []
    for unit in fu.units:
        first, last = fu.position(unit.start), fu.position(unit.end - 1)
        rows.append({
            "unit_id": f"{source}:{snapshot}/{path}:{unit.kind}:{unit.start}", "source": source,
            "snapshot": snapshot, "file": path, "kind": unit.kind, "name": unit.name,
            "parent_class": unit.parent_class, "ranges": _ranges(unit.ranges),
            "first": f"{first[0]}:{first[1]}", "last": f"{last[0]}:{last[1]}",
            "closure": _ranges(unit.closure), "file_sha256": sha,
        })
    return rows


class _Extracted:
    pass

    def __init__(self, min_share: float):
        self.min_share = min_share
        self.cache: dict[tuple[str, str], Any] = {}
        self.status: list[dict] = []
        self.failures: list[dict] = []
        self.units: list[dict] = []
        self.notes: Counter = Counter()
        self.markers: Counter = Counter()

    def add(self, source: str, snapshot: str, path: str, scope: str, data: bytes, with_units: bool = True):
        from raven import context

        grammar = context.grammar_for(path)
        sha = hashlib.sha256(data).hexdigest()  
        blanked = 0
        if source == "sard_php":
            data, blanked = context.blank_sard_markers(data)
            self.markers[scope] += blanked
            self.markers[f"{scope}_files_with_markers"] += bool(blanked)
        key = (sha, grammar)
        if key not in self.cache:
            self.cache[key] = context.extract(data, grammar, self.min_share)
            self.notes.update({k: v for k, v in self.cache[key].notes.items() if v})
        fu = self.cache[key]
        self.status.append({"source": source, "snapshot": snapshot, "file": path, "scope": scope,
                            "grammar": grammar, "status": fu.status, "bytes": len(data),
                            "units": len(fu.units), "file_sha256": sha})
        if fu.status != "parsed":
            self.failures.append({"source": source, "snapshot": snapshot, "file": path, "scope": scope,
                                  "grammar": grammar, "status": fu.status, **{k: fu.error.get(k, "") for k in
                                  ("first_error", "error_nodes", "error_byte_share", "exception")}})
        elif with_units:
            self.units += _unit_rows(source, snapshot, path, fu, sha)
        return fu, sha


def _target_row(record_id: str, source: str, snapshot: str, path: str, fu, sha: str, lines: str, tm) -> dict:
    row = {"record_id": record_id, "source": source, "snapshot": snapshot, "file": path, "grammar": fu.grammar,
           "parse_status": fu.status, "target_lines": lines, "file_sha256": sha}
    if tm is None:
        return {**row, "target_status": "extract_failed", "reason": fu.status}
    unit = tm.unit
    return {**row, "target_status": tm.status, "reason": tm.reason,
            "unit_id": f"{source}:{snapshot}/{path}:{unit.kind}:{unit.start}" if unit else "",
            "unit_kind": unit.kind if unit else "", "target_ranges": _ranges(tm.target),
            "remainder_ranges": _ranges(tm.remainder), "closure_ranges": _ranges(tm.closure)}


def run_extract_units(run: Run, p4_summary_run: Path) -> dict[str, Any]:
    import tarfile

    from raven import context

    cfg = run.config["p5"]["extractor"]
    summary, runs = _verify_p4(p4_summary_run)
    inventory_run = p4_summary_run.parent / summary["inputs"]["inventory_run"]
    roles = {r["node"]: r["role"] for r in inv.read_rows(runs["overlap"] / "split_assignment.csv.gz")}
    ex = _Extracted(cfg["module_wrapper_min_line_share"])
    targets: list[dict] = []
    data_root = _data_root()

    
    aligned = [r for r in inv.read_rows(runs["jsvul"] / "jsvul_alignment.csv")
               if r["status"] in ("unique_exact", "unique_near")]
    if any(roles.get(f"jsvul:{r['record_id']}") != "pilot_dev" for r in aligned):
        raise PermissionError("P5 builds pilot_dev JsVul records only")
    snapshots: dict[tuple[str, str], set[str]] = defaultdict(set)
    target_bytes: dict[tuple[str, str, str], bytes] = {}
    for row in aligned:
        snapshot = f"{row['project']}@{row['revision']}"
        path = data_root / "files" / "jsvul" / row["project"].replace("/", "__") / row["revision"] / row["file"]
        data = path.read_bytes()
        if hashlib.sha256(data).hexdigest() != row["file_sha256"]:
            raise LineageError(f"{path} does not match the P4 alignment hash")
        target_bytes[(row["project"], row["revision"], row["file"])] = data
        snapshots[(row["project"], row["revision"])].add(row["file"])
        fu, sha = ex.add("jsvul", snapshot, row["file"], "target", data, with_units=False)
        tm = context.map_target(fu, int(row["start_line"]), int(row["end_line"])) if fu.status == "parsed" else None
        targets.append(_target_row(row["record_id"], "jsvul", snapshot, row["file"], fu, sha,
                                   f"{row['start_line']}-{row['end_line']}", tm))

    
    exclusions: Counter = Counter()
    tarball_mismatch = []
    for (project, revision), files in sorted(snapshots.items()):
        snapshot = f"{project}@{revision}"
        tarball = data_root / "snapshots" / "jsvul" / project.replace("/", "__") / f"{revision}.tar.gz"
        seen = set()
        with tarfile.open(tarball, "r:gz") as tar:
            for member in tar:
                if not member.isfile() or "/" not in member.name:
                    continue
                path = member.name.split("/", 1)[1]
                reason = "" if path in files else eligibility(path, member.size, "js", cfg["max_eligible_file_bytes"])
                if reason:
                    exclusions[reason] += 1
                    continue
                handle = tar.extractfile(member)
                data = handle.read() if handle else b""
                if path in files:
                    seen.add(path)
                    if data != target_bytes[(project, revision, path)]:
                        tarball_mismatch.append(f"{snapshot}/{path}")
                ex.add("jsvul", snapshot, path, "snapshot", data)
        for path in sorted(files - seen):
            tarball_mismatch.append(f"{snapshot}/{path} (absent from tarball)")

    
    sard = {r["record_id"]: r for r in inv.read_rows(inventory_run / "inventory_sard_php.csv.gz")}
    php_root = data_root / "snapshots" / "sard_php"
    pairs = [r for r in inv.read_rows(runs["sard_php"] / "php_twins.csv") if r["status"] == "aligned_not_reproduced"]
    one_sided = Counter()
    for row in pairs:
        
        
        texts = []
        for case in row["pair_id"].split("+"):
            raw = (php_root / case / sard[case]["src_file"]).read_bytes()
            texts.append(Counter(context.php_comments(context.blank_sard_markers(raw)[0])))
        for comment in (texts[0] - texts[1]) + (texts[1] - texts[0]):
            one_sided[comment.decode("utf-8", "replace")[:80]] += 1
        for case in row["pair_id"].split("+"):
            path = sard[case]["src_file"]
            data = (php_root / case / path).read_bytes()
            fu, sha = ex.add("sard_php", case, path, "target", data, with_units=False)
            tm, lines = None, ""
            if fu.status == "parsed":
                hits = context.anchor_line(fu, row["sink_line"])
                lines = ",".join(map(str, hits))
                
                tm = context.map_anchor(fu, hits[-1]) if hits else context.TargetMap(
                    "target_misaligned", None, [], [], [], "sink line not found")
            targets.append(_target_row(case, "sard_php", case, path, fu, sha, lines, tm))
    
    for case_dir in sorted(p for p in php_root.iterdir() if p.is_dir()):
        case = case_dir.name
        if case not in sard:
            exclusions["sard_not_in_inventory"] += 1
            continue
        path = sard[case]["src_file"]
        ex.add("sard_php", case, path, "snapshot", (case_dir / path).read_bytes())

    
    rates = {}
    for source in ("jsvul", "sard_php"):
        for scope in ("target", "snapshot"):
            rows = [r for r in ex.status if r["source"] == source and r["scope"] == scope]
            parsed = sum(r["status"] == "parsed" for r in rows)
            rate = parsed / len(rows) if rows else 0.0
            rates[f"{source}/{scope}"] = {"files": len(rows), "parsed": parsed, "rate": round(rate, 4),
                                          "pass": rate >= cfg["min_parse_rate"],
                                          "by_status": dict(Counter(r["status"] for r in rows))}
    inv.write_rows(run.path / "units.csv.gz", UNIT_FIELDS, ex.units)
    inv.write_rows(run.path / "parse_status.csv.gz", STATUS_FIELDS, ex.status)
    inv.write_rows(run.path / "parse_failures.csv", FAILURE_FIELDS, ex.failures)
    inv.write_rows(run.path / "targets.csv", TARGET_FIELDS, targets)
    result = {
        "p4_summary_run": p4_summary_run.name, "unit_spec": run.config["p5"]["unit_spec"],
        "min_parse_rate": cfg["min_parse_rate"], "parse_rates": rates,
        "parse_ac_pass": all(v["pass"] for v in rates.values()),
        "targets": {s: dict(Counter(t["target_status"] for t in targets if t["source"] == s))
                    for s in ("jsvul", "sard_php")},
        "target_unit_kinds": {s: dict(Counter(t.get("unit_kind", "") for t in targets if t["source"] == s))
                              for s in ("jsvul", "sard_php")},
        "units": {s: dict(Counter(u["kind"] for u in ex.units if u["source"] == s)) for s in ("jsvul", "sard_php")},
        "snapshots": {"jsvul": len(snapshots), "sard_php": sum(1 for r in ex.status
                                                               if r["source"] == "sard_php" and r["scope"] == "snapshot")},
        "exclusions": dict(exclusions), "tarball_target_mismatch": tarball_mismatch,
        "extractor_notes": dict(ex.notes), "sard_markers_blanked": dict(ex.markers),
        "sard_one_sided_comments_after_blanking": dict(one_sided), "distinct_files_extracted": len(ex.cache),
        "grammars": cfg["grammars"],
        "inputs": {"p4_summary_output_files": summary["output_files"], "jsvul_run": runs["jsvul"].name,
                   "php_run": runs["sard_php"].name, "overlap_run": runs["overlap"].name,
                   "inventory_run": inventory_run.name},
    }
    result["output_files"] = _digest(run.path, ("units.csv.gz", "parse_status.csv.gz", "parse_failures.csv",
                                                "targets.csv"))
    _json(run.path / "extract_summary.json", result)
    run.logger.info("extract: parse=%s targets=%s", json.dumps(rates, sort_keys=True), json.dumps(result["targets"]))
    return result




LEVELS = ("L0", "L1", "L2", "L3")
CONTEXT_FIELDS = ("sample_id", "source", "record_id", "pair_id", "label", "split", "snapshot", "file",
                  "target_status", "L0", "L1", "L2", "L3", "L0_sha256", "L1_sha256", "L2_sha256", "L3_sha256",
                  "L2_callee_units", "L2_caller_units", "L2_import_use_units", "L2_files", "L3_files", "note")
EDGE_FIELDS = ("edge_id", "source", "snapshot", "file", "src_unit", "src_lines", "type", "status", "reason",
               "confidence", "dst_file", "dst_unit", "dst_lines", "text", "src_code", "dst_code")
CONFLICT_FIELDS = ("source", "record_id", "label", "conflict_group", "L0_sha256", "L3_sha256", "status", "rule")
SANITIZER_FIELDS = ("pair_id", "twin", "label", "changed_lines", "selectability", "class", "srr_eligible_pair",
                    "pool_cases", "pool_split", "L0", "L0_plus_sanitizer", "L0_sanitizer_pool",
                    *(f"forced_{b}" for b in ("512", "1024", "2048", "4096", "8192", "bstar")))
AUDIT_FIELDS = ("edge_id", "stratum", "type", "status", "reason", "confidence", "src", "ref", "src_code", "dst",
                "dst_code", "verdict", "reviewer", "date", "note")


def _parse_ranges(value: str) -> list[tuple[int, int]]:
    return [tuple(int(x) for x in part.split("-")) for part in value.split(";") if part] if value else []


def _sha(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def _unit_index(fu, unit_id: str) -> int:
    kind, start = unit_id.rsplit(":", 2)[1:]
    for k, unit in enumerate(fu.units):
        if unit.kind == kind and unit.start == int(start):
            return k
    raise LineageError(f"unit {unit_id} not found on re-extraction")


def _with_closure(fu, k: int) -> list[tuple[int, int]]:
    return list(fu.units[k].ranges) + list(fu.units[k].closure)


def _snapshot_files(tarball: Path, targets: set[str], max_bytes: int) -> tuple[dict[str, bytes], dict[str, str]]:
    pass
    import tarfile

    files, mains = {}, {}
    with tarfile.open(tarball, "r:gz") as tar:
        for member in tar:
            if not member.isfile() or "/" not in member.name:
                continue
            path = member.name.split("/", 1)[1]
            if path.endswith("package.json") and member.size < 1 << 20:
                handle = tar.extractfile(member)
                try:
                    main = json.loads(handle.read()).get("main") if handle else None
                except (ValueError, UnicodeDecodeError, AttributeError):
                    main = None
                if isinstance(main, str):
                    mains[path[: -len("package.json")].rstrip("/") or "."] = main
                continue
            if path in targets or not eligibility(path, member.size, "js", max_bytes):
                handle = tar.extractfile(member)
                files[path] = handle.read() if handle else b""
    return files, mains


class _Counter:
    def __init__(self, tokenizer):
        self.tokenizer = tokenizer

    def __call__(self, files, target_file, labels=None) -> tuple[int, str]:
        from raven import packer

        text = packer.serialise(files, target_file, labels)
        return count_tokens(self.tokenizer, text), text


def _levels(count, texts: dict[str, bytes], levels: list[dict[str, list]], target_file: str, labels=None):
    pass
    out, previous = {}, -1
    for name, ranges in zip(LEVELS, levels, strict=True):
        tokens, text = count({p: (texts[p], r) for p, r in ranges.items()}, target_file, labels)
        if tokens < previous:
            raise AssertionError(f"L*1 monotonicity violated at {name}: {tokens} < {previous}")
        previous = tokens
        out[name], out[f"{name}_sha256"], out[f"_{name}_text"] = tokens, _sha(text), text
    return out


def _edge_row(source: str, snapshot: str, fus: dict, e, idx: int) -> dict:
    fu = fus[e.file]
    a = fu.position(e.span[0])[0] if e.span != (0, 0) else ""
    b = fu.position(max(e.span[1] - 1, e.span[0]))[0] if e.span != (0, 0) else ""
    dst_lines = ""
    dst_code = ""
    if e.dst_file in fus and e.dst_unit >= 0:
        unit = fus[e.dst_file].units[e.dst_unit]
        dst_lines = f"{fus[e.dst_file].position(unit.start)[0]}-{fus[e.dst_file].position(unit.end - 1)[0]}"
        core = unit.core[0] if unit.core else unit.start
        dst_code = _line(fus[e.dst_file], fus[e.dst_file].position(core)[0])  
    src_code = _line(fu, a) if a else ""
    return {"edge_id": f"{source}:{snapshot}:{idx}", "source": source, "snapshot": snapshot, "file": e.file,
            "src_unit": e.src_unit, "src_lines": f"{a}-{b}", "type": e.type, "status": e.status,
            "reason": e.reason, "confidence": e.confidence, "dst_file": e.dst_file, "dst_unit": e.dst_unit,
            "dst_lines": dst_lines, "text": e.text, "src_code": src_code, "dst_code": dst_code}


def _line(fu, n: int) -> str:
    start = fu.line_starts[n - 1]
    end = fu.line_starts[n] - 1 if n < len(fu.line_starts) else len(fu.text)
    return fu.text[start:end].decode("utf-8", "replace").strip()[:200]


def length_profile(rows: list[dict], budgets: list[int], fraction: float, min_share: float) -> tuple[list[dict], dict]:
    pass
    import statistics

    bstar = {}
    for source in sorted({r["source"] for r in rows}):
        l2 = [int(r["L2"]) for r in rows if r["source"] == source and r["split"] in ("train", "val") and r["L2"]]
        bstar[source] = round(fraction * statistics.median(l2)) if l2 else None
    table = []
    for source in sorted({r["source"] for r in rows}):
        sub = [r for r in rows if r["source"] == source and r["L0"]]
        for level in LEVELS:
            vals = sorted(int(r[level]) for r in sub)
            if not vals:
                continue
            row = {"source": source, "level": level, "n": len(vals), "median": statistics.median(vals),
                   "p90": vals[min(len(vals) - 1, int(0.9 * len(vals)))], "max": vals[-1],
                   "share_gt_1k": round(sum(v > 1000 for v in vals) / len(vals), 4), "bstar": bstar[source]}
            for b in [*budgets, bstar[source]]:
                name = "bstar" if b == bstar[source] and b not in budgets else str(b)
                if b is None:
                    continue
                row[f"share_over_{name}"] = round(sum(v > b for v in vals) / len(vals), 4)
                l0 = [int(r["L0"]) for r in sub]
                row[f"share_opportunity_{name}"] = round(
                    sum(int(r["L0"]) <= b < int(r[level]) for r in sub) / len(vals), 4)
                row[f"share_L0_fits_{name}"] = round(sum(v <= b for v in l0) / len(l0), 4)
            share = row[f"share_over_{min(budgets)}"]
            row["selection_opportunity"] = "sufficient" if share >= min_share else "insufficient"
            row["decision_rule"] = f"share_over_{min(budgets)}={share} vs >= {min_share}"
            table.append(row)
    return table, bstar


def php_pool(pair_id: str, meta: dict[str, dict], available: set[str], seed: int) -> tuple[list[str], str]:
    pass

    twins = pair_id.split("+")
    splits = {meta[c]["split"] for c in twins}
    if len(splits) != 1:
        raise AssertionError(f"S1: twins of {pair_id} are in different splits {splits}")
    split = splits.pop()
    family = {meta[c]["group_id"] for c in twins}
    pool = [c for c in available if c not in twins and meta[c]["split"] == split and meta[c]["group_id"] not in family]
    pool.sort(key=lambda c: _rank(seed, "pool", pair_id, c))
    if any(meta[c]["split"] != split for c in pool):
        raise AssertionError(f"S1: pool of {pair_id} leaves the split")
    return pool, split


def run_contexts(run: Run, extract_run: Path, review_run: Path) -> dict[str, Any]:
    import difflib

    from raven import analysis, context

    cfg, budgets = run.config["p5"], run.config["budgets"]
    extract_run = _from_run(extract_run, "extract-units")
    review_run = _from_run(review_run, "review-cases")
    ext = json.loads((extract_run / "extract_summary.json").read_text())
    if _digest(extract_run, tuple(ext["output_files"])) != ext["output_files"]:
        raise LineageError(f"{extract_run.name} outputs changed after the run")
    p4_summary_run = extract_run.parent / ext["p4_summary_run"]
    summary, runs = _verify_p4(p4_summary_run)
    inventory_run = p4_summary_run.parent / summary["inputs"]["inventory_run"]
    split_rows = inv.read_rows(runs["overlap"] / "split_assignment.csv.gz")
    js_split = {r["node"]: r["split"] for r in split_rows}
    php_meta = {r["record_id"]: r for r in inv.read_rows(runs["overlap"] / "php_cases.csv.gz")}
    labels_js = {r["record_id"]: r for r in inv.read_rows(runs["jsvul"] / "jsvul_alignment.csv")}
    targets = inv.read_rows(extract_run / "targets.csv")
    tokenizer = load_tokenizer(run.config)
    count = _Counter(tokenizer)
    internal, php_version = analysis.php_internal_functions()
    data_root = _data_root()
    max_bytes = cfg["extractor"]["max_eligible_file_bytes"]
    min_share_wrap = cfg["extractor"]["module_wrapper_min_line_share"]
    review = inv.read_rows(review_run / "review_cases.csv")
    reviewed = {f"{c['source']}:{c[t]}" for c in review for t in ("twin_a", "twin_b")}
    contexts, edge_rows, texts_l2 = [], [], {}
    graph_stats: Counter = Counter()

    
    js_targets = defaultdict(list)
    for t in targets:
        if t["source"] == "jsvul":
            js_targets[t["snapshot"]].append(t)
    cache: dict[tuple[str, str], Any] = {}
    last_project = None
    for snapshot in sorted(js_targets):
        project, revision = snapshot.split("@")
        if project != last_project:
            cache.clear()
            last_project = project
        rows = js_targets[snapshot]
        usable = [t for t in rows if t["target_status"] in ("coincides", "nested")]
        for t in rows:
            if t not in usable:
                contexts.append({"sample_id": f"jsvul:{t['record_id']}", "source": "jsvul", "record_id": t["record_id"],
                                 "label": labels_js[t["record_id"]]["label"], "split": js_split[f"jsvul:{t['record_id']}"],
                                 "snapshot": snapshot, "file": t["file"], "target_status": t["target_status"],
                                 "note": "not built: " + (t["reason"] or t["target_status"])[:200]})
        if not usable:
            continue
        tarball = data_root / "snapshots" / "jsvul" / project.replace("/", "__") / f"{revision}.tar.gz"
        raw, mains = _snapshot_files(tarball, {t["file"] for t in rows}, max_bytes)
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
        target_files = {t["file"] for t in usable}
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
        all_units = {p: [r for k in range(len(fu.units)) for r in _with_closure(fu, k)] for p, fu in fus.items()}
        for edge in (e for tf in sorted(target_files) for e in analysers[tf].g.edges):
            edge_rows.append(_edge_row("jsvul", snapshot, fus, edge, len(edge_rows)))
            graph_stats[(edge.type, edge.status, edge.reason)] += 1
        for t in usable:
            fu = fus[t["file"]]
            k = _unit_index(fu, t["unit_id"])
            target = _parse_ranges(t["target_ranges"])
            l0 = {t["file"]: target + _parse_ranges(t["closure_ranges"])}
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
            for path, unit in callee | caller | imported:
                l2.setdefault(path, []).extend(_with_closure(fus[path], unit))
            l3 = {p: list(l2.get(p, [])) + all_units[p] for p in fus}
            lv = _levels(count, texts, [l0, l1, l2, l3], t["file"])
            sample = f"jsvul:{t['record_id']}"
            if sample in reviewed:
                texts_l2[sample] = (l2, {p: texts[p] for p in l2}, None, t, t["file"])
            contexts.append({
                "sample_id": sample, "source": "jsvul", "record_id": t["record_id"],
                "label": labels_js[t["record_id"]]["label"], "split": js_split[f"jsvul:{t['record_id']}"],
                "snapshot": snapshot, "file": t["file"], "target_status": t["target_status"],
                **{k2: v for k2, v in lv.items() if not k2.startswith("_")},
                "L2_callee_units": len(callee), "L2_caller_units": len(caller), "L2_import_use_units": len(imported),
                "L2_files": len(l2), "L3_files": len(l3)})
        run.logger.info("contexts %s: %d files, %d analysed, %d samples", snapshot, len(fus), len(analysers), len(usable))

    
    php_root = data_root / "snapshots" / "sard_php"
    sard = {r["record_id"]: r for r in inv.read_rows(inventory_run / "inventory_sard_php.csv.gz")}
    php_t = {t["record_id"]: t for t in targets if t["source"] == "sard_php"}
    pool_fu, pool_path = {}, {}
    for case_dir in sorted(p for p in php_root.iterdir() if p.is_dir() and p.name in sard):
        case = case_dir.name
        data, _ = context.blank_sard_markers((case_dir / sard[case]["src_file"]).read_bytes())
        fu = context.extract(data, "php", min_share_wrap)
        if fu.status == "parsed":
            pool_fu[case] = fu
            pool_path[case] = f"{case}/{sard[case]['src_file']}"
    pseudonym = {pool_path[c]: f"sard/{hashlib.sha256(c.encode()).hexdigest()[:12]}.php" for c in pool_path}
    pools, sanitizer_rows = {}, []
    pairs = [r for r in inv.read_rows(runs["sard_php"] / "php_twins.csv") if r["status"] == "aligned_not_reproduced"]
    php_cache = {}
    for row in pairs:
        bad, good = row["pair_id"].split("+")
        pool, split = php_pool(row["pair_id"], php_meta, set(pool_fu), run.config["seed"])
        pools[row["pair_id"]] = pool
        twin_texts = {}
        for case in (bad, good):
            fu = pool_fu[case]
            t = php_t[case]
            an = analysis.PhpAnalyser(pool_path[case], fu, internal)
            an.analyse(set(pool_path.values()))
            fus = {pool_path[c]: pool_fu[c] for c in [case, *pool]}
            for edge in an.g.edges:
                edge_rows.append(_edge_row("sard_php", case, fus, edge, len(edge_rows)))
                graph_stats[(edge.type, edge.status, edge.reason)] += 1
            path = pool_path[case]
            texts = {p: f.text for p, f in fus.items()}
            all_units = {p: [r for k in range(len(f.units)) for r in _with_closure(f, k)] for p, f in fus.items()}
            l0 = {path: _parse_ranges(t["target_ranges"]) + _parse_ranges(t["closure_ranges"])}
            l1 = {path: l0[path] + all_units[path]}
            l3 = {p: (l1[p] if p == path else []) + all_units[p] for p in fus}
            lv = _levels(count, texts, [l0, l1, dict(l1), l3], path, pseudonym)
            sample = f"sard_php:{case}"
            if sample in reviewed:
                texts_l2[sample] = (l1, {p: texts[p] for p in l1}, pseudonym, t, path)
            twin_texts[case] = (fu, t, path, texts, all_units, l0)
            contexts.append({
                "sample_id": sample, "source": "sard_php", "record_id": case, "pair_id": row["pair_id"],
                "label": "1" if case == bad else "0", "split": split, "snapshot": case, "file": path,
                "target_status": t["target_status"], **{k2: v for k2, v in lv.items() if not k2.startswith("_")},
                "L2_files": 1, "L3_files": len(l3), "note": "SARD: L2 = L1 (no package snapshot); L3 adds same-split pool"})
            php_cache[case] = an
        
        lines = {c: twin_texts[c][0].text.split(b"\n") for c in (bad, good)}
        sm = difflib.SequenceMatcher(None, lines[bad], lines[good], autojunk=False)
        changed = {bad: set(), good: set()}
        for tag, i1, i2, j1, j2 in sm.get_opcodes():
            if tag != "equal":
                changed[bad].update(i for i in range(i1, i2) if lines[bad][i].strip())
                changed[good].update(j for j in range(j1, j2) if lines[good][j].strip())
        classes = {}
        for case in (bad, good):
            fu, t, path, texts, all_units, l0 = twin_texts[case]
            ranges = [context.line_range(fu, i + 1, i + 1) for i in sorted(changed[case])]
            tm = context.TargetMap(t["target_status"], None, _parse_ranges(t["target_ranges"]), [],
                                   _parse_ranges(t["closure_ranges"]))
            sel = context.selectability(fu, ranges, tm)
            classes[case] = (sel, context.sanitizer_class(sel), ranges)
        eligible = classes[good][1] in ("a_selectable", "b_closure_only")
        for case in (bad, good):
            fu, t, path, texts, all_units, l0 = twin_texts[case]
            sel, cls, ranges = classes[case]
            san_units = {k for k, u in enumerate(fu.units) for a, b in ranges if any(x < b and a < y for x, y in u.ranges)}
            with_san = {path: l0[path] + [r for k in san_units for r in _with_closure(fu, k)]}
            fus_pool = {pool_path[c]: pool_fu[c] for c in pool}
            with_pool = dict(with_san)
            for p, f in fus_pool.items():
                with_pool[p] = [r for k in range(len(f.units)) for r in _with_closure(f, k)]
            all_texts = {**texts, **{p: f.text for p, f in fus_pool.items()}}
            n0 = count({path: (all_texts[path], l0[path])}, path, pseudonym)[0]
            ns = count({p: (all_texts[p], r) for p, r in with_san.items()}, path, pseudonym)[0]
            npool = count({p: (all_texts[p], r) for p, r in with_pool.items()}, path, pseudonym)[0]
            sanitizer_rows.append({
                "pair_id": row["pair_id"], "twin": case, "label": "1" if case == bad else "0",
                "changed_lines": ",".join(str(i + 1) for i in sorted(changed[case])), "selectability": sel,
                "class": cls, "srr_eligible_pair": eligible, "pool_cases": len(pool), "pool_split": split,
                "L0": n0, "L0_plus_sanitizer": ns, "L0_sanitizer_pool": npool})
    
    inv.write_rows(run.path / "contexts.csv", CONTEXT_FIELDS, contexts)
    inv.write_rows(run.path / "edges.csv.gz", EDGE_FIELDS, edge_rows)
    rows = inv.read_rows(run.path / "contexts.csv")  
    table, bstar = length_profile(rows, budgets, cfg["bstar_fraction_of_median_l2"], cfg["min_share_over_smallest_budget"])
    fields = list(dict.fromkeys(k for r in table for k in r))
    inv.write_rows(run.path / "length_profile.csv", tuple(fields), table)
    for r in sanitizer_rows:
        for b in [*budgets, bstar.get("sard_php")]:
            name = "bstar" if b == bstar.get("sard_php") and b not in budgets else str(b)
            if b is not None:
                r[f"forced_{name}"] = int(r["L0"]) <= b < int(r["L0_sanitizer_pool"])
                r[f"feasible_{name}"] = int(r["L0_plus_sanitizer"]) <= b
    san_fields = SANITIZER_FIELDS + tuple(k for k in (sanitizer_rows[0] if sanitizer_rows else {}) if k.startswith("feasible_"))
    inv.write_rows(run.path / "sanitizer_origin.csv", san_fields, sanitizer_rows)
    inv.write_rows(run.path / "php_pools.csv", ("pair_id", "rank", "case", "split", "group_id"),
                   [{"pair_id": p, "rank": i, "case": c, "split": php_meta[c]["split"], "group_id": php_meta[c]["group_id"]}
                    for p, pool in pools.items() for i, c in enumerate(pool)])

    
    rule = cfg["contexts"]["label_conflicts"]["rule"]
    groups = defaultdict(list)
    for r in rows:
        if r["L0_sha256"]:
            groups[(r["source"], r["L0_sha256"], r["L3_sha256"])].append(r)
    conflicts = []
    for (source, h0, h3), members in sorted(groups.items()):
        if len({m["label"] for m in members}) > 1:
            gid = f"{source}:{h0[:12]}:{h3[:12]}"
            conflicts += [{"source": source, "record_id": m["record_id"], "label": m["label"], "conflict_group": gid,
                           "L0_sha256": h0, "L3_sha256": h3, "status": "excluded", "rule": rule} for m in members]
    inv.write_rows(run.path / "label_conflicts.csv", CONFLICT_FIELDS, conflicts)
    if any(c["status"] not in ("excluded", "adjudicated") for c in conflicts):
        raise AssertionError("primary cohort has an unresolved label conflict")
    per_level_dups = {}
    for level in LEVELS:
        g2 = defaultdict(set)
        for r in rows:
            if r[f"{level}_sha256"]:
                g2[(r["source"], r[f"{level}_sha256"])].add(r["label"])
        per_level_dups[level] = {s: sum(1 for (src, _), labs in g2.items() if src == s and len(labs) > 1)
                                 for s in ("jsvul", "sard_php")}

    
    strata = defaultdict(list)
    for r in edge_rows:
        stratum = f"{r['type']}/{r['status']}/{r['reason'] or r['confidence']}"
        strata[stratum].append(r)
    for key in strata:
        strata[key].sort(key=lambda r: _rank(run.config["seed"], "audit", r["edge_id"]))
    sample, i = [], 0
    while len(sample) < cfg["graph_audit_sample"] and any(len(v) > i for v in strata.values()):
        for key in sorted(strata, key=lambda s: _rank(run.config["seed"], "stratum", s)):
            if len(strata[key]) > i and len(sample) < cfg["graph_audit_sample"]:
                sample.append((key, strata[key][i]))
        i += 1
    audit = []
    for key, r in sample:
        audit.append({"edge_id": r["edge_id"], "stratum": key, "type": r["type"], "status": r["status"],
                      "reason": r["reason"], "confidence": r["confidence"],
                      "src": f"{r['snapshot']}/{r['file']}:{r['src_lines']}", "ref": r["text"],
                      "dst": f"{r['dst_file']}:{r['dst_lines']}" if r["dst_file"] else "",
                      "src_code": r["src_code"], "dst_code": r["dst_code"]})
    inv.write_rows(run.path / "graph_audit.csv", AUDIT_FIELDS, audit)

    
    packet_rows = _review_packets(run.path / "review_packet", review, texts_l2)

    calls = [r for r in edge_rows if r["type"] == "call"]
    non_builtin = [r for r in calls if r["reason"] != "builtin"]
    graph = {
        source: {
            "calls": sum(r["source"] == source for r in calls),
            "builtin_calls": sum(r["source"] == source and r["reason"] == "builtin" for r in calls),
            "unresolved_rate_excl_builtin": round(
                sum(r["source"] == source and r["status"] == "unresolved" for r in non_builtin)
                / max(1, sum(r["source"] == source for r in non_builtin)), 4),
            "unresolved_by_reason": dict(Counter(r["reason"] for r in non_builtin
                                                 if r["source"] == source and r["status"] == "unresolved")),
            "edges_by_type_status": dict(Counter(f"{r['type']}/{r['status']}" for r in edge_rows if r["source"] == source)),
        } for source in ("jsvul", "sard_php")}
    built = [r for r in rows if r["L0"]]
    result = {
        "extract_run": extract_run.name, "review_run": review_run.name, "p4_summary_run": p4_summary_run.name,
        "serialisation": cfg["serialisation"], "tokenizer_revision": run.config["tokenizer_revision"],
        "php_version_for_internal_functions": php_version, "bstar": bstar,
        "samples": {s: {"built": sum(r["source"] == s for r in built),
                        "not_built": sum(r["source"] == s and not r["L0"] for r in rows)} for s in ("jsvul", "sard_php")},
        "monotonicity_assert": "passed for every built sample",
        "graph": graph,
        "label_conflicts": {"rule": rule, "conflicts": len(conflicts),
                            "identical_with_different_labels_by_level": per_level_dups},
        "sanitizer": {
            "pairs": len(pairs),
            "class_by_twin": dict(Counter(f"{'bad' if r['label'] == '1' else 'good'}:{r['class']}" for r in sanitizer_rows)),
            "srr_eligible_pairs": len({r["pair_id"] for r in sanitizer_rows if r["srr_eligible_pair"]}),
            "forced_twins_by_budget": {k[len("forced_"):]: sum(bool(r.get(k)) for r in sanitizer_rows)
                                       for k in (sanitizer_rows[0] if sanitizer_rows else {}) if k.startswith("forced_")},
            "feasible_twins_by_budget": {k[len("feasible_"):]: sum(bool(r.get(k)) for r in sanitizer_rows)
                                         for k in (sanitizer_rows[0] if sanitizer_rows else {}) if k.startswith("feasible_")},
        },
        "graph_audit_sample": len(audit), "review_packets": packet_rows,
        "inputs": {"extract_output_files": ext["output_files"], "review_cases_sha256":
                   hashlib.sha256((review_run / "review_cases.csv").read_bytes()).hexdigest()},
    }
    result["output_files"] = _digest(run.path, ("contexts.csv", "edges.csv.gz", "length_profile.csv",
                                                "sanitizer_origin.csv", "php_pools.csv", "label_conflicts.csv",
                                                "graph_audit.csv", "necessity_review_template.csv"))
    _json(run.path / "contexts_summary.json", result)
    run.logger.info("contexts: %s", json.dumps({k: result[k] for k in ("samples", "bstar", "label_conflicts")}))
    return result


def _review_packets(out: Path, review: list[dict], texts_l2: dict) -> int:
    pass
    from raven import packer

    out.mkdir(parents=True, exist_ok=True)
    template = []
    for case in review:
        for twin in ("twin_a", "twin_b"):
            record = case[twin]
            sample = f"{case['source']}:{record}"
            if sample not in texts_l2:
                template.append({"case_id": case["case_id"], "twin_id": twin, "input_hash": "",
                                 "missing_information": "context not built"})
                continue
            l2, texts, pseudonym, t, tpath = texts_l2[sample]
            target_line = f"# mandatory target: {_label(tpath, pseudonym)} lines {_target_lines(texts[tpath], t)}"
            lines = [f"# case {case['case_id']} {twin}", target_line, ""]
            for path in [tpath, *sorted(p for p in l2 if p != tpath)]:
                name = _label(path, pseudonym)
                lines.append(f"// file: {name} sha256={hashlib.sha256(texts[path]).hexdigest()}")
                prev = None
                for n, text in packer.numbered(texts[path], l2[path]):
                    if prev is not None and n != prev + 1:
                        lines.append("// ...")
                    lines.append(f"{n:6d}  {text}")
                    prev = n
                lines.append("")
            body = "\n".join(lines) + "\n"
            (out / f"{case['case_id']}_{twin}.txt").write_text(body, encoding="utf-8")
            template.append({"case_id": case["case_id"], "twin_id": twin, "input_hash": _sha(body)})
    fields = ("case_id", "twin_id", "input_hash", "evidence_scope", "interprocedural_dependency", "evidence_spans",
              "dependency_explanation", "missing_information", "category", "reviewer", "date")
    inv.write_rows(out.parent / "necessity_review_template.csv", fields, template)
    return len(template)


def _label(path: str, pseudonym: dict | None) -> str:
    return (pseudonym or {}).get(path, path)


def _target_lines(text: bytes, t: dict) -> str:
    spans = _parse_ranges(t["target_ranges"])
    if not spans:
        return ""
    first = text.count(b"\n", 0, spans[0][0]) + 1
    last = text.count(b"\n", 0, max(spans[-1][1] - 1, spans[0][0])) + 1
    return f"{first}-{last}"



REVIEW_SCOPES = ("target_local", "same_file_outside_target", "cross_file", "uncertain")
SPAN_ROLES = ("target", "source", "sink", "validation", "precondition", "dependency", "other")
SELECTABILITY_FIELDS = ("case_id", "twin_id", "source", "review_set", "record_id", "span_index", "file_id",
                        "start_line", "end_line", "role", "in_target_file", "selectability_raw", "selectability")
REVIEW_FIELDS = ("case_id", "twin_id", "source", "review_set", "record_id", "input_hash", "evidence_scope",
                 "interprocedural_dependency", "evidence_spans", "dependency_explanation", "missing_information",
                 "category", "reviewer", "date", "evidence_class", "valid")


def parse_packet(body: str) -> dict[str, dict]:
    pass
    import re

    files, cur = {}, None
    for line in body.split("\n"):
        m = re.match(r"// file: (\S+) sha256=([0-9a-f]{64})$", line)
        if m:
            cur = m.group(1)
            files[cur] = {"sha": m.group(2), "lines": {}}
            continue
        m = re.match(r"\s*(\d+)  (.*)$", line)
        if m and cur is not None:
            files[cur]["lines"][int(m.group(1))] = m.group(2)
    return files


def validate_review_row(row: dict, expected_hash: str, packet: dict[str, dict]) -> tuple[list[dict], list[str]]:
    pass

    import re

    problems = []
    if row["input_hash"] != expected_hash:
        problems.append("input_hash mismatch")
    if row["evidence_scope"] not in REVIEW_SCOPES:
        problems.append(f"evidence_scope {row['evidence_scope']!r}")
    if row["interprocedural_dependency"] not in ("true", "false", "null"):
        problems.append(f"interprocedural_dependency {row['interprocedural_dependency']!r}")
    try:
        spans = json.loads(row["evidence_spans"] or "[]")
        missing = json.loads(row["missing_information"] or "[]")
    except ValueError as exc:
        return [], problems + [f"json: {exc}"]
    if not isinstance(spans, list) or not isinstance(missing, list):
        return [], problems + ["evidence_spans/missing_information must be arrays"]
    if not spans and row["evidence_scope"] != "uncertain":
        problems.append("certain judgment without evidence spans")
    def norm(text: str) -> str:
        return re.sub(r"\s+", " ", text).strip()

    for i, s in enumerate(spans):
        keys = {"file_id", "source_sha256", "start_line", "end_line", "quote", "role"}
        if not isinstance(s, dict) or set(s) != keys:
            problems.append(f"span {i}: fields")
            continue
        f = packet.get(s["file_id"])
        if f is None:
            problems.append(f"span {i}: file not in packet")
        elif s["source_sha256"] != f["sha"]:
            problems.append(f"span {i}: sha mismatch")
        elif s["role"] not in SPAN_ROLES:
            problems.append(f"span {i}: role {s['role']!r}")
        elif not (isinstance(s["start_line"], int) and isinstance(s["end_line"], int)
                  and s["start_line"] <= s["end_line"]
                  and all(n in f["lines"] for n in range(s["start_line"], s["end_line"] + 1))):
            problems.append(f"span {i}: lines outside packet")
        elif norm(s["quote"]) not in norm(" ".join(f["lines"][n] for n in range(s["start_line"], s["end_line"] + 1))):
            problems.append(f"span {i}: quote not in span")
    return spans, problems


def evidence_class(classes: list[str]) -> str:
    pass
    found = {c for value in classes for c in value.split("+") if c not in ("empty", "comment_only")}
    if not found:
        return "no_evidence"
    if "not_in_pool" in found:
        return "outside_pool"
    if "selectable" in found:
        return "needs_selection"
    if "closure_only" in found:
        return "closure_only"
    return "mandatory_only"


def run_necessity(run: Run, extract_run: Path, build_run: Path, review_file: Path, reviewer: str, date: str) -> dict[str, Any]:
    from raven import context

    cfg = run.config["p5"]
    extract_run = _from_run(extract_run, "extract-units")
    build_run = _from_run(build_run, "build-contexts")
    summary = json.loads((build_run / "contexts_summary.json").read_text())
    if _digest(build_run, tuple(summary["output_files"])) != summary["output_files"]:
        raise LineageError(f"{build_run.name} outputs changed after the run")
    if summary["extract_run"] != extract_run.name:
        raise LineageError(f"{build_run.name} was not built from {extract_run.name}")
    template = {(r["case_id"], r["twin_id"]): r for r in inv.read_rows(build_run / "necessity_review_template.csv")}
    review_bytes = review_file.read_bytes()
    review_sha = hashlib.sha256(review_bytes).hexdigest()
    (run.path / "necessity_review_input.csv").write_bytes(review_bytes)
    rows = inv.read_rows(review_file)
    review_run = _from_run(build_run.parent / summary["review_run"], "review-cases")
    cases = {c["case_id"]: c for c in inv.read_rows(review_run / "review_cases.csv")}
    targets = {(t["source"], t["record_id"]): t for t in inv.read_rows(extract_run / "targets.csv")}
    data_root = _data_root()
    min_share_wrap = cfg["extractor"]["module_wrapper_min_line_share"]
    max_bytes = cfg["extractor"]["max_eligible_file_bytes"]

    keys = [(r["case_id"], r["twin_id"]) for r in rows]
    if len(set(keys)) != len(keys):
        raise ValueError("duplicate (case_id, twin_id) rows in the review file")
    missing = sorted(set(template) - set(keys))
    extra = sorted(set(keys) - set(template))
    out_rows, sel_rows, problems = [], [], []
    snapshot_cache: dict[str, dict[str, bytes]] = {}
    fu_cache: dict[str, Any] = {}

    def file_units(data: bytes, path: str):
        key = hashlib.sha256(data).hexdigest()
        if key not in fu_cache:
            fu_cache[key] = context.extract(data, context.grammar_for(path), min_share_wrap)
        return fu_cache[key]

    for row in rows:
        k = (row["case_id"], row["twin_id"])
        if k not in template:
            continue
        case = cases[row["case_id"]]
        source, record = case["source"], case[row["twin_id"]]
        packet = parse_packet((build_run / "review_packet" / f"{k[0]}_{k[1]}.txt").read_text(encoding="utf-8"))
        spans, errs = validate_review_row(row, template[k]["input_hash"], packet)
        problems.extend({"case_id": k[0], "twin_id": k[1], "problem": e} for e in errs)
        t = targets[(source, record)]
        if source == "jsvul":
            snap = t["snapshot"]
            if snap not in snapshot_cache:
                project, revision = snap.split("@")
                tarball = data_root / "snapshots" / "jsvul" / project.replace("/", "__") / f"{revision}.tar.gz"
                snapshot_cache.clear()
                snapshot_cache[snap] = _snapshot_files(tarball, {t["file"]}, max_bytes)[0]
            raw = snapshot_cache[snap]
            target_id = t["file"]
            resolve = lambda fid, r=raw: r.get(fid)
        else:
            data, _ = context.blank_sard_markers((data_root / "snapshots" / "sard_php" / record / t["file"]).read_bytes())
            target_id = f"sard/{hashlib.sha256(record.encode()).hexdigest()[:12]}.php"
            resolve = lambda fid, d=data, tid=target_id: d if fid == tid else None
        classes = []
        bad_spans = {int(e.split()[1].rstrip(":")) for e in errs if e.startswith("span ")}
        for i, s in enumerate(spans):
            raw_cls = ""
            if i in bad_spans:
                cls = "invalid_span"
            else:
                data = resolve(s["file_id"])
                if data is None or hashlib.sha256(data).hexdigest() != s["source_sha256"]:
                    raise LineageError(f"{k}: span file {s['file_id']} does not match the snapshot")
                fu = file_units(data, s["file_id"] if source == "jsvul" else t["file"])
                tm = None
                if s["file_id"] == target_id:
                    tm = context.TargetMap(t["target_status"], None, _parse_ranges(t["target_ranges"]), [],
                                           _parse_ranges(t["closure_ranges"]))
                span = [context.line_range(fu, s["start_line"], s["end_line"])]
                raw_cls = context.selectability(fu, span, tm)
                code = context.subtract(span, context.comment_ranges(fu))
                cls = context.selectability(fu, code, tm) if code else "comment_only"
                classes.append(cls)
            sel_rows.append({"case_id": k[0], "twin_id": k[1], "source": source, "review_set": case["review_set"],
                             "record_id": record, "span_index": i, "file_id": s.get("file_id", ""),
                             "start_line": s.get("start_line", ""), "end_line": s.get("end_line", ""),
                             "role": s.get("role", ""), "in_target_file": str(s.get("file_id") == target_id).lower(),
                             "selectability_raw": raw_cls, "selectability": cls})
        out_rows.append({**{f: row.get(f, "") for f in REVIEW_FIELDS if f in row}, "source": source,
                         "review_set": case["review_set"], "record_id": record,
                         "reviewer": row["reviewer"] or reviewer, "date": row["date"] or date,
                         "evidence_class": evidence_class(classes) if row["evidence_scope"] != "uncertain" else "uncertain",
                         "valid": str(not errs).lower()})
    inv.write_rows(run.path / "necessity_review.csv", REVIEW_FIELDS, out_rows)
    inv.write_rows(run.path / "evidence_selectability.csv", SELECTABILITY_FIELDS, sel_rows)
    inv.write_rows(run.path / "review_validation.csv", ("case_id", "twin_id", "problem"), problems)

    def tab(rows_, *fields):
        out = defaultdict(Counter)
        for r in rows_:
            out[r["source"]][" / ".join(r[f] for f in fields)] += 1
        return {s: dict(sorted(c.items())) for s, c in sorted(out.items())}

    span_total = len(sel_rows)
    span_invalid = sum(r["selectability"] == "invalid_span" for r in sel_rows)
    result = {
        "build_run": build_run.name, "extract_run": extract_run.name,
        "review_file": str(review_file), "review_sha256": review_sha,
        "reviewer_filled": sum(not r["reviewer"] for r in rows), "reviewer": reviewer, "date": date,
        "rows": len(rows), "missing_rows": [list(m) for m in missing], "extra_rows": [list(e) for e in extra],
        "invalid_rows": len({(p["case_id"], p["twin_id"]) for p in problems}),
        "spans": span_total, "invalid_spans": span_invalid,
        "invalid_span_rate": round(span_invalid / span_total, 4) if span_total else None,
        "evidence_scope": tab(out_rows, "evidence_scope"),
        "interprocedural": tab(out_rows, "interprocedural_dependency"),
        "scope_by_interprocedural": tab(out_rows, "evidence_scope", "interprocedural_dependency"),
        "scope_by_review_set": tab(out_rows, "review_set", "evidence_scope"),
        "evidence_class": tab(out_rows, "evidence_class"),
        "span_selectability": tab(sel_rows, "selectability"),
        "span_selectability_with_comments": tab(sel_rows, "selectability_raw"),
        "share_evidence_in_pool": {
            s: round(sum(r["evidence_class"] in ("mandatory_only", "closure_only", "needs_selection")
                         for r in out_rows if r["source"] == s)
                     / max(1, sum(r["evidence_class"] != "uncertain" for r in out_rows if r["source"] == s)), 4)
            for s in sorted({r["source"] for r in out_rows})},
        "judge": "blocked: API credit and spend cap not confirmed (judge.yaml execution_enabled=false)",
    }
    result["output_files"] = _digest(run.path, ("necessity_review.csv", "evidence_selectability.csv",
                                                "review_validation.csv", "necessity_review_input.csv"))
    _json(run.path / "necessity_summary.json", result)
    run.logger.info("necessity: %s", json.dumps({k: result[k] for k in ("rows", "spans", "invalid_spans",
                                                                         "share_evidence_in_pool")}))
    if missing or extra:
        raise ValueError(f"review rows do not match the template: missing {missing[:3]}, extra {extra[:3]}")
    return result

