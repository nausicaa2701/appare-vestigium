"""P5C: dated, lineage-linked correction of the P5 evidence spans and the graph-support boundary.

The original human review, necessity run, adjudication worksheet and final-label run are never
edited. A correction worksheet lists every re-reviewed twin (pair mates included); this command
applies the adjudicated final labels plus the corrections to the initial review, re-runs the P5
span validator and selectability (``p5.run_necessity``) into a new run, and writes:

- ``correction_log.csv``: prior and corrected scope/spans per re-reviewed twin, with hashes that
  link back to the necessity run, the adjudication run and the review packet;
- ``scope_reconciliation.csv``: per twin, whether the final scope agrees with where its cited
  spans lie, and why outside-target evidence is or is not selectable;
- ``selectability_diff.csv``: evidence class before and after the correction, per twin;
- ``graph_coverage.csv``: per reviewed twin, resolved/unresolved graph edges in the target and
  heuristic flags for the three unsupported resolution mechanisms (``export *``, ``.js``->``.ts``,
  build aliases), so absent edges are never read as independence.
"""

from __future__ import annotations

import csv
import gzip
import hashlib
import io
import json
import re
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any

from raven import inventory as inv
from raven.p2 import LineageError, _digest, _from_run, _json
from raven.runlog import Run

ACTIONS = ("add_spans", "replace_spans", "reclassify", "unchanged")
WORKSHEET_FIELDS = ("case_id", "twin_id", "action", "corrected_scope", "corrected_interprocedural",
                    "corrected_spans", "rationale", "reviewer", "date")
OUTSIDE_SCOPES = ("same_file_outside_target", "cross_file")
LOG_FIELDS = ("case_id", "twin_id", "source", "action", "input_hash", "prior_scope", "prior_interprocedural",
              "prior_spans", "corrected_scope", "corrected_interprocedural", "corrected_spans", "rationale",
              "reviewer", "date", "necessity_run", "necessity_selectability_sha256", "adjudication_run",
              "final_labels_sha256", "worksheet_sha256")
RECON_FIELDS = ("case_id", "twin_id", "source", "review_set", "final_scope", "target", "spans", "outside_spans",
                "outside_span_classes", "evidence_class", "consistent", "explanation")
DIFF_FIELDS = ("case_id", "twin_id", "source", "scope_before", "scope_after", "class_before", "class_after",
               "changed")
COVERAGE_FIELDS = ("case_id", "twin_id", "source", "snapshot", "file", "target_lines", "calls", "builtin_calls",
                   "resolved_calls", "unresolved_calls", "unresolved_rate", "unresolved_by_reason", "imports",
                   "resolved_imports", "unresolved_imports", "js_to_ts_candidates", "reexport_candidates",
                   "alias_candidates")
DATE = re.compile(r"^\d{4}-\d{2}-\d{2}$")
TARGET_HEADER = re.compile(r"^# mandatory target: (\S+) lines (\d+)-(\d+)$", re.MULTILINE)


def _sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _verified(run_dir: Path, command: str, summary_name: str) -> dict[str, Any]:
    run_dir = _from_run(run_dir, command)
    summary = json.loads((run_dir / summary_name).read_text())
    if _digest(run_dir, tuple(summary["output_files"])) != summary["output_files"]:
        raise LineageError(f"{run_dir.name} outputs changed after the run")
    return summary


def packet_target(packet_text: str) -> tuple[str, int, int]:
    pass
    m = TARGET_HEADER.search(packet_text)
    if not m:
        raise ValueError("review packet has no '# mandatory target' header")
    return m.group(1), int(m.group(2)), int(m.group(3))


def outside_target(span: dict, target: tuple[str, int, int]) -> bool:
    pass
    file, first, last = target
    return span["file_id"] != file or span["start_line"] < first or span["end_line"] > last


def check_worksheet(rows: list[dict], final: dict[tuple, dict]) -> list[dict]:
    pass
    problems = []

    def bad(r, field, msg):
        problems.append({"case_id": r.get("case_id", ""), "twin_id": r.get("twin_id", ""), "field": field,
                         "problem": msg})

    keys = [(r.get("case_id", ""), r.get("twin_id", "")) for r in rows]
    for k, n in Counter(keys).items():
        if n > 1:
            problems.append({"case_id": k[0], "twin_id": k[1], "field": "", "problem": "duplicate row"})
    cases = defaultdict(set)
    for r in rows:
        k = (r.get("case_id", ""), r.get("twin_id", ""))
        missing = [f for f in WORKSHEET_FIELDS if f not in r]
        if missing:
            bad(r, ",".join(missing), "missing columns")
            continue
        if k not in final:
            bad(r, "case_id", "not in final labels")
            continue
        cases[k[0]].add(k[1])
        f = final[k]
        if r["action"] not in ACTIONS:
            bad(r, "action", f"{r['action']!r} not in {ACTIONS}")
        if r["corrected_scope"] not in ("target_local", "same_file_outside_target", "cross_file", "uncertain"):
            bad(r, "corrected_scope", repr(r["corrected_scope"]))
        if r["corrected_interprocedural"] not in ("true", "false", "null"):
            bad(r, "corrected_interprocedural", repr(r["corrected_interprocedural"]))
        if not r["rationale"].strip():
            bad(r, "rationale", "empty")
        if not r["reviewer"].strip():
            bad(r, "reviewer", "empty")
        if not DATE.match(r["date"]):
            bad(r, "date", "not an ISO date")
        try:
            spans = json.loads(r["corrected_spans"] or "[]")
        except ValueError:
            spans = None
        if not isinstance(spans, list):
            bad(r, "corrected_spans", "not a JSON array")
            continue
        same_label = (r["corrected_scope"], r["corrected_interprocedural"]) == (f["final_scope"],
                                                                                f["final_interprocedural"])
        if r["action"] == "unchanged" and (spans or not same_label):
            bad(r, "action", "'unchanged' must keep the final labels and add no spans")
        if r["action"] in ("add_spans", "replace_spans") and not spans:
            bad(r, "corrected_spans", f"'{r['action']}' needs spans")
        if r["action"] in ("add_spans", "replace_spans") and r["corrected_scope"] != f["final_scope"]:
            bad(r, "action", "a scope change must use 'reclassify'")
        if r["action"] == "reclassify" and same_label:
            bad(r, "action", "'reclassify' must change the scope or the interprocedural label")
    for case, twins in sorted(cases.items()):
        mates = {t for (c, t) in final if c == case}
        if twins != mates:
            problems.append({"case_id": case, "twin_id": ",".join(sorted(mates - twins)), "field": "",
                             "problem": "pair mate not re-reviewed (list every twin of a corrected case)"})
    return problems


def corrected_review(initial: list[dict], final: dict[tuple, dict], corrections: dict[tuple, dict]) -> list[dict]:
    pass
    out = []
    for row in initial:
        k = (row["case_id"], row["twin_id"])
        r = dict(row)
        f = final[k]
        r["evidence_scope"], r["interprocedural_dependency"] = f["final_scope"], f["final_interprocedural"]
        c = corrections.get(k)
        if c and c["action"] != "unchanged":
            spans = json.loads(c["corrected_spans"] or "[]")
            if c["action"] == "add_spans":
                spans = json.loads(row["evidence_spans"] or "[]") + spans
            elif c["action"] == "reclassify" and not spans:
                spans = json.loads(row["evidence_spans"] or "[]")
            r["evidence_spans"] = json.dumps(spans, ensure_ascii=False)
            r["evidence_scope"], r["interprocedural_dependency"] = c["corrected_scope"], c["corrected_interprocedural"]
            r["dependency_explanation"] = c["rationale"]
            r["reviewer"], r["date"] = c["reviewer"], c["date"]
        r["category"] = r["evidence_scope"]
        out.append(r)
    return out


GAP_EXPLANATION = {
    "selectable": "outside-target evidence is inside a candidate unit (selectable)",
    "closure_only": "outside-target evidence appears only through another unit's closure",
    "mandatory": "outside the target lines but inside the target's closure, so it is mandatory",
    "not_in_pool": "outside-target evidence is not in the candidate pool",
    "comment_only": "outside-target span covers only comments",
    "invalid_span": "outside-target span failed validation",
}


def reconcile(review: list[dict], spans: list[dict], targets: dict[tuple, tuple]) -> list[dict]:
    pass

    by_twin = defaultdict(list)
    for s in spans:
        by_twin[(s["case_id"], s["twin_id"])].append(s)
    out = []
    for r in review:
        k = (r["case_id"], r["twin_id"])
        tgt = targets[k]
        rows = sorted(by_twin.get(k, []), key=lambda s: int(s["span_index"]))
        outside = [s for s in rows if outside_target({"file_id": s["file_id"], "start_line": int(s["start_line"]),
                                                      "end_line": int(s["end_line"])}, tgt)]
        classes = sorted({c for s in outside for c in s["selectability"].split("+")})
        scope = r["evidence_scope"]
        if scope == "uncertain":
            consistent, why = True, "uncertain: no span-location requirement"
        elif scope in OUTSIDE_SCOPES:
            consistent = bool(outside)
            why = ("; ".join(GAP_EXPLANATION.get(c, c) for c in classes) if outside
                   else "final scope is outside the target but no cited span lies outside it")
        else:
            consistent = not outside
            why = ("all cited spans inside the target" if not outside
                   else "final scope is target_local but a cited span lies outside the target")
        out.append({"case_id": k[0], "twin_id": k[1], "source": r["source"], "review_set": r["review_set"],
                    "final_scope": scope, "target": f"{tgt[0]}:{tgt[1]}-{tgt[2]}", "spans": len(rows),
                    "outside_spans": len(outside), "outside_span_classes": "+".join(classes),
                    "evidence_class": r["evidence_class"], "consistent": str(consistent).lower(),
                    "explanation": why})
    return out


JS_SPEC = re.compile(r"\.(m|c)?js$")


def graph_coverage(edges_gz: Path, twins: list[dict]) -> list[dict]:
    pass

    want = {(t["snapshot"], t["file"]) for t in twins}
    by_file = defaultdict(list)
    with gzip.open(edges_gz, "rt", encoding="utf-8", newline="") as fh:
        for e in csv.DictReader(fh):
            if (e["snapshot"], e["file"]) in want:
                by_file[(e["snapshot"], e["file"])].append(e)
    out = []
    for t in twins:
        edges = by_file.get((t["snapshot"], t["file"]), [])
        first, last = t["first"], t["last"]

        def in_target(e, first=first, last=last):
            try:
                a = int(e["src_lines"].split("-")[0])
            except ValueError:
                return False
            return first <= a <= last

        calls = [e for e in edges if e["type"] == "call" and in_target(e)]
        builtin = [e for e in calls if e["reason"] == "builtin"]
        unresolved = [e for e in calls if e["status"] == "unresolved" and e["reason"] != "builtin"]
        resolved = [e for e in calls if e["status"] == "resolved"]
        imports = [e for e in edges if e["type"] == "import"]
        un_imp = [e for e in imports if e["status"] == "unresolved"]
        js_ts = [e for e in un_imp if e["reason"] == "not_found" and e["text"].startswith(".")
                 and JS_SPEC.search(e["text"])]
        reexport = [e for e in edges if e["status"] == "unresolved" and e["reason"] == "not_found"
                    and e["dst_file"] and e["type"] != "import"]
        alias = [e for e in un_imp if e["reason"] == "external_module"
                 and (e["text"].startswith(("@/", "~/", "~", "#")) or
                      (not e["text"].startswith("@") and "/" in e["text"] and
                       e["text"].split("/")[0] in t["top_dirs"]))]
        denom = len(calls) - len(builtin)
        out.append({"case_id": t["case_id"], "twin_id": t["twin_id"], "source": t["source"],
                    "snapshot": t["snapshot"], "file": t["file"], "target_lines": f"{first}-{last}",
                    "calls": len(calls), "builtin_calls": len(builtin), "resolved_calls": len(resolved),
                    "unresolved_calls": len(unresolved),
                    "unresolved_rate": round(len(unresolved) / denom, 4) if denom else "",
                    "unresolved_by_reason": json.dumps(dict(sorted(Counter(e["reason"] for e in unresolved).items()))),
                    "imports": len(imports), "resolved_imports": len(imports) - len(un_imp),
                    "unresolved_imports": len(un_imp), "js_to_ts_candidates": len(js_ts),
                    "reexport_candidates": len(reexport), "alias_candidates": len(alias)})
    return out


def run_correction(run: Run, necessity_run: Path, adjudication_run: Path, worksheet: Path) -> dict[str, Any]:
    from raven import p5

    nsum = _verified(necessity_run, "necessity-review", "necessity_summary.json")
    asum = _verified(adjudication_run, "judge-adjudication", "adjudication_summary.json")
    agreement_run = adjudication_run.parent / asum["agreement_run"]
    gsum = _verified(agreement_run, "judge-agreement", "agreement_summary.json")
    if gsum["necessity_run"] != necessity_run.name:
        raise LineageError(f"{adjudication_run.name} does not descend from {necessity_run.name}")
    build_run = necessity_run.parent / nsum["build_run"]
    extract_run = necessity_run.parent / nsum["extract_run"]

    final = {(r["case_id"], r["twin_id"]): r for r in inv.read_rows(adjudication_run / "final_labels.csv")}
    initial = inv.read_rows(necessity_run / "necessity_review_input.csv")
    if {(r["case_id"], r["twin_id"]) for r in initial} != set(final):
        raise LineageError("final labels and the initial review cover different twins")

    data = worksheet.read_bytes()
    ws_sha = hashlib.sha256(data).hexdigest()
    (run.path / "correction_input.csv").write_bytes(data)
    rows = list(csv.DictReader(io.StringIO(data.decode("utf-8-sig"), newline="")))
    problems = check_worksheet(rows, final)
    inv.write_rows(run.path / "correction_validation.csv", ("case_id", "twin_id", "field", "problem"), problems)
    if problems:
        raise LineageError(f"{len(problems)} correction worksheet problems; see correction_validation.csv")
    corrections = {(r["case_id"], r["twin_id"]): r for r in rows}

    corrected = corrected_review(initial, final, corrections)
    fields = list(initial[0].keys())
    buf = io.StringIO(newline="")
    w = csv.DictWriter(buf, fieldnames=fields, lineterminator="\n")
    w.writeheader()
    w.writerows({f: r.get(f, "") for f in fields} for r in corrected)
    corrected_path = run.path / "necessity_review_corrected.csv"
    corrected_path.write_text(buf.getvalue(), encoding="utf-8")

    
    nres = p5.run_necessity(run, extract_run, build_run, corrected_path, nsum["reviewer"], nsum["date"])
    nres["judge"] = f"final labels from {adjudication_run.name}; judge not called in P5C"
    nres["p5c_note"] = "necessity_review_input.csv is the P5C-corrected review, not the initial human file"
    _json(run.path / "necessity_summary.json", nres)

    review = inv.read_rows(run.path / "necessity_review.csv")
    spans = inv.read_rows(run.path / "evidence_selectability.csv")
    packets = build_run / "review_packet"
    targets = {(r["case_id"], r["twin_id"]): packet_target(
        (packets / f"{r['case_id']}_{r['twin_id']}.txt").read_text(encoding="utf-8")) for r in review}
    recon = reconcile(review, spans, targets)
    inv.write_rows(run.path / "scope_reconciliation.csv", RECON_FIELDS, recon)

    before = {(r["case_id"], r["twin_id"]): r for r in inv.read_rows(necessity_run / "necessity_review.csv")}
    diff = [{"case_id": r["case_id"], "twin_id": r["twin_id"], "source": r["source"],
             "scope_before": before[(r["case_id"], r["twin_id"])]["evidence_scope"], "scope_after": r["evidence_scope"],
             "class_before": before[(r["case_id"], r["twin_id"])]["evidence_class"], "class_after": r["evidence_class"],
             "changed": str(before[(r["case_id"], r["twin_id"])]["evidence_class"] != r["evidence_class"]
                            or before[(r["case_id"], r["twin_id"])]["evidence_scope"] != r["evidence_scope"]).lower()}
            for r in review]
    inv.write_rows(run.path / "selectability_diff.csv", DIFF_FIELDS, diff)

    init_by = {(r["case_id"], r["twin_id"]): r for r in initial}
    sel_sha = nsum["output_files"]["evidence_selectability.csv"]
    fl_sha = asum["output_files"]["final_labels.csv"]
    template = {(r["case_id"], r["twin_id"]): r for r in inv.read_rows(build_run / "necessity_review_template.csv")}
    log = []
    for k, c in sorted(corrections.items()):
        corr = next(r for r in corrected if (r["case_id"], r["twin_id"]) == k)
        log.append({"case_id": k[0], "twin_id": k[1], "source": final[k]["source"], "action": c["action"],
                    "input_hash": template[k]["input_hash"], "prior_scope": final[k]["final_scope"],
                    "prior_interprocedural": final[k]["final_interprocedural"],
                    "prior_spans": init_by[k]["evidence_spans"], "corrected_scope": corr["evidence_scope"],
                    "corrected_interprocedural": corr["interprocedural_dependency"],
                    "corrected_spans": corr["evidence_spans"], "rationale": c["rationale"],
                    "reviewer": c["reviewer"], "date": c["date"], "necessity_run": necessity_run.name,
                    "necessity_selectability_sha256": sel_sha, "adjudication_run": adjudication_run.name,
                    "final_labels_sha256": fl_sha, "worksheet_sha256": ws_sha})
    inv.write_rows(run.path / "correction_log.csv", LOG_FIELDS, log)

    
    cases = {c["case_id"]: c for c in inv.read_rows(build_run.parent / json.loads(
        (build_run / "contexts_summary.json").read_text())["review_run"] / "review_cases.csv")}
    tmap = {(t["source"], t["record_id"]): t for t in inv.read_rows(extract_run / "targets.csv")}
    edge_files = defaultdict(set)
    with gzip.open(build_run / "edges.csv.gz", "rt", encoding="utf-8", newline="") as fh:
        for e in csv.DictReader(fh):
            edge_files[e["snapshot"]].add(e["file"].split("/")[0])
    twins = []
    for r in review:
        case = cases[r["case_id"]]
        t = tmap[(case["source"], case[r["twin_id"]])]
        _, first, last = targets[(r["case_id"], r["twin_id"])]
        
        efile = f"{t['snapshot']}/{t['file']}" if case["source"] == "sard_php" else t["file"]
        twins.append({"case_id": r["case_id"], "twin_id": r["twin_id"], "source": case["source"],
                      "snapshot": t["snapshot"], "file": efile, "first": first, "last": last,
                      "top_dirs": edge_files.get(t["snapshot"], set())})
    coverage = graph_coverage(build_run / "edges.csv.gz", twins)
    inv.write_rows(run.path / "graph_coverage.csv", COVERAGE_FIELDS, coverage)

    outside_labels = [r for r in recon if r["final_scope"] in OUTSIDE_SCOPES]
    by_src = defaultdict(Counter)
    for r in recon:
        by_src[r["source"]]["twins"] += 1
        by_src[r["source"]]["outside_scope"] += r["final_scope"] in OUTSIDE_SCOPES
        by_src[r["source"]]["outside_span"] += int(r["outside_spans"]) > 0 and r["final_scope"] != "uncertain"
        by_src[r["source"]]["needs_selection"] += r["evidence_class"] == "needs_selection"
        by_src[r["source"]]["inconsistent"] += r["consistent"] != "true"
    result = {
        "date": rows[0]["date"] if rows else "", "necessity_run": necessity_run.name,
        "adjudication_run": adjudication_run.name, "agreement_run": agreement_run.name,
        "build_run": build_run.name, "extract_run": extract_run.name,
        "necessity_selectability_sha256": sel_sha, "final_labels_sha256": fl_sha,
        "worksheet": str(worksheet), "worksheet_sha256": ws_sha,
        "reviewers": sorted({r["reviewer"] for r in rows}), "corrections": dict(Counter(r["action"] for r in rows)),
        "re_reviewed_twins": len(rows),
        "outside_scope_labels": len(outside_labels),
        "outside_scope_without_outside_span": [f"{r['case_id']}/{r['twin_id']}" for r in outside_labels
                                               if r["consistent"] != "true"],
        "inconsistent": [f"{r['case_id']}/{r['twin_id']}" for r in recon if r["consistent"] != "true"],
        "reconciliation_by_source": {s: dict(c) for s, c in sorted(by_src.items())},
        "evidence_class": nres["evidence_class"], "evidence_scope": nres["evidence_scope"],
        "invalid_spans": nres["invalid_spans"], "changed_twins": sum(d["changed"] == "true" for d in diff),
        "graph_coverage_note": ("candidates are heuristic flags for unsupported mechanisms (export *, .js->.ts, "
                                "build aliases); a flag is not a confirmed missed edge and zero is not proof of "
                                "completeness"),
    }
    result["output_files"] = _digest(run.path, ("correction_input.csv", "correction_validation.csv",
                                                "necessity_review_corrected.csv", "necessity_review.csv",
                                                "evidence_selectability.csv", "review_validation.csv",
                                                "scope_reconciliation.csv", "selectability_diff.csv",
                                                "correction_log.csv", "graph_coverage.csv"))
    _json(run.path / "correction_summary.json", result)
    run.logger.info("p5c: %s", json.dumps({k: result[k] for k in ("re_reviewed_twins", "corrections",
                                                                   "inconsistent", "invalid_spans")}))
    if result["inconsistent"] or nres["invalid_spans"]:
        raise LineageError(f"P5C correction leaves inconsistencies: {result['inconsistent']}, "
                           f"invalid spans {nres['invalid_spans']}")
    return result
