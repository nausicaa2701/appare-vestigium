"""P6 manual source-map review: complete packets and a separate R1 review file.

``raven source-map-packets`` renders, for the 24 packs listed in the canonical pack run's
``source_map_review.csv`` plus supplementary packs chosen deterministically so that every
provenance origin is covered (``target_closure``, ``closure_added``, cross-file), one Markdown
packet per pack with the **complete** pack text of every piece next to the **complete** numbered
source lines. Each pack is rebuilt and must match the canonical SHA-256. It also writes
``source_map_review_template.csv``: one row per piece, with the pack id, pack SHA-256, pack run
and the SHA-256 of the original worksheet.

R1 fills a **copy** of the template outside the run directory (run outputs are hash-locked).
``raven source-map-review-check`` validates that copy: same rows and pinned columns as the
template, every check column answered, reviewer and date present, the original worksheet and the
pack run outputs unchanged, and reports mismatches. Sign-off requires zero open mismatches.
"""

from __future__ import annotations

import gzip
import hashlib
import json
import re
from pathlib import Path
from typing import Any

from raven import inventory as inv
from raven import packer
from raven.p2 import LineageError, _digest, _from_run, _json
from raven.runlog import Run

CHECKS = ("file_ok", "lines_ok", "content_ok", "origin_ok")
TEMPLATE_FIELDS = ("pack_id", "pack_sha256", "selection", "packet", "piece", "file", "lines", "origin",
                   "out_chars", "tokens", *CHECKS, "verdict", "note", "reviewer", "date", "pack_run",
                   "worksheet_sha256")
PINNED = ("pack_id", "pack_sha256", "selection", "packet", "piece", "file", "lines", "origin", "out_chars",
          "tokens", "pack_run", "worksheet_sha256")
DATE = re.compile(r"^\d{4}-\d{2}-\d{2}$")


def pack_id(key: tuple) -> str:
    return "|".join(map(str, key))


def _fence(text: str) -> str:
    longest = max((len(m.group(0)) for m in re.finditer(r"`+", text)), default=0)
    return "`" * max(3, longest + 1)


def render_packet(key: tuple, manifest: dict, text: str, texts: dict[str, bytes], labels: dict[str, str],
                  pack_run: str, worksheet_sha: str, selection: str) -> str:
    pass
    from raven import p6

    by_label = {labels.get(f, f): f for f in texts}
    out = [f"# Source-map check: {pack_id(key)}", "",
           f"- pack run: `{pack_run}`", f"- pack_sha256: `{manifest['pack_sha256']}`",
           f"- original worksheet sha256: `{worksheet_sha}`", f"- selection: {selection}",
           (f"- tokens {manifest['tokens']}, mandatory {manifest['mandatory_tokens']}, pieces {len(manifest['pieces'])}, "
           f"files {len({p['file'] for p in manifest['pieces']})}"), "",
           ("For each piece answer in the review CSV: right file? right lines? pack text equal to the source "
           "lines? right origin (target / target_closure / direct / closure_added / gap_whitespace)?"), ""]
    for j, piece in enumerate(manifest["pieces"]):
        f = by_label[piece["file"]]
        data = texts[f]
        starts = p6._line_starts(data)
        a, b = piece["src"]
        la, lb = (int(x) for x in piece["lines"].split("-"))
        src = "\n".join(f"{n:>6}  {data[starts[n - 1]:(starts[n] - 1 if n < len(starts) else len(data))].decode('utf-8', 'replace')}"
                        for n in range(la, lb + 1))
        chunk = text[piece["out"][0]:piece["out"][1]]
        fp, fs = _fence(chunk), _fence(src)
        out += [f"## piece {j}: {piece['origin']} — {piece['file']} lines {piece['lines']}",
                (f"bytes {a}-{b}; pack chars {piece['out'][0]}-{piece['out'][1]}; tokens "
                f"{piece['tokens'][0]}-{piece['tokens'][1]}"), "",
                "pack text (complete):", fp, chunk, fp, "source lines (complete):", fs, src, fs, ""]
    return "\n".join(out)


def supplementary(manifests: list[dict], chosen: set[tuple], seed: int, max_budget: int) -> list[tuple[tuple, str]]:
    pass

    wants = [
        ("target_closure+direct", lambda o, nfiles: "target_closure" in o and "direct" in o and "closure_added" not in o),
        ("target_closure+closure_added+cross_file",
         lambda o, nfiles: "target_closure" in o and "closure_added" in o and nfiles > 1),
        ("closure_added", lambda o, nfiles: "closure_added" in o and "target_closure" not in o),
    ]
    picked: list[tuple[tuple, str]] = []
    used_samples = {k[0] for k in chosen}
    for name, ok in wants:
        cands = []
        for m in manifests:
            key = (m["sample_id"], m["level"], m["budget"], m["method"])
            origins = {p["origin"] for p in m["pieces"]}
            if (key in chosen or m["budget"] > max_budget or m["sample_id"] in used_samples
                    or not ok(origins, len({p["file"] for p in m["pieces"]}))):
                continue
            cands.append((hashlib.sha256(f"{seed}:{name}:{pack_id(key)}".encode()).hexdigest(), key))
        if cands:
            key = min(cands)[1]
            picked.append((key, f"supplementary: {name}"))
            used_samples.add(key[0])
            chosen = chosen | {key}
    return picked


def run_packets(run: Run, extract_run: Path, build_run: Path, pack_run: Path) -> dict[str, Any]:
    from raven import p5, p6

    cfg = run.config["p6"]
    extract_run = _from_run(extract_run, "extract-units")
    build_run = _from_run(build_run, "build-contexts")
    pack_run = _from_run(pack_run, "pack-cells")
    psum = json.loads((pack_run / "pack_summary.json").read_text())
    if _digest(pack_run, tuple(psum["output_files"])) != psum["output_files"]:
        raise LineageError(f"{pack_run.name} outputs changed after the run")
    if psum["build_run"] != build_run.name or psum["extract_run"] != extract_run.name:
        raise LineageError("pack run does not descend from the given extraction/contexts runs")
    worksheet = pack_run / "source_map_review.csv"
    ws_sha = psum["output_files"]["source_map_review.csv"]
    original = sorted({tuple(r["pack"].split("|")) for r in inv.read_rows(worksheet)})
    original = [(s, lv, int(b), m) for s, lv, b, m in original]
    manifests = []
    with gzip.open(pack_run / "pack_manifest.jsonl.gz", "rt", encoding="utf-8") as fh:
        for line in fh:
            m = json.loads(line)
            if m["target_fits_budget"]:
                manifests.append(m)
    extra = supplementary(manifests, set(original), run.config["seed"], int(cfg["review_supplement_max_budget"]))
    selection = {k: "original worksheet" for k in original} | dict(extra)
    by_key = {(m["sample_id"], m["level"], m["budget"], m["method"]): m for m in manifests}
    missing = [k for k in selection if k not in by_key]
    if missing:
        raise LineageError(f"selected packs missing from the manifest: {missing[:3]}")

    tok = p5.load_tokenizer(run.config)
    count = lambda t: p5.count_tokens(tok, t)
    pdir = run.path / "packets"
    pdir.mkdir()
    rows, written = [], {}
    need = {k[0] for k in selection}
    for s in p6.iter_samples(run.config, extract_run, build_run, run.logger):
        if s["sample_id"] not in need:
            continue
        for key in sorted(k for k in selection if k[0] == s["sample_id"]):
            pool = p6.method_scores(key[3], run.config["seed"], key[0], s["pools"][key[1]])
            est = {c.uid: count(b"".join(s["texts"][c.file][a:b] for a, b in packer._merge(c.span_set))
                                .decode("utf-8", "replace")) for c in pool}
            tf = s["target_file"]
            res = packer.pack(s["texts"], tf, {tf: s["levels"]["L0"][tf]}, pool, key[2], count, labels=s["labels"],
                              prompt=cfg["prompt_prefix"], estimates=est, slack=int(cfg["estimate_slack_tokens"]))
            m = by_key[key]
            if p6._sha(res.text) != m["pack_sha256"]:
                raise LineageError(f"rebuilt pack differs from the canonical pack run for {key}")
            name = f"{hashlib.sha256(pack_id(key).encode()).hexdigest()[:12]}.md"
            (pdir / name).write_text(render_packet(key, m, res.text, s["texts"], s["labels"] or {}, pack_run.name,
                                                   ws_sha, selection[key]), encoding="utf-8")
            written[key] = name
            for j, p in enumerate(m["pieces"]):
                rows.append({"pack_id": pack_id(key), "pack_sha256": m["pack_sha256"], "selection": selection[key],
                             "packet": f"packets/{name}", "piece": j, "file": p["file"], "lines": p["lines"],
                             "origin": p["origin"], "out_chars": f"{p['out'][0]}-{p['out'][1]}",
                             "tokens": f"{p['tokens'][0]}-{p['tokens'][1]}", **dict.fromkeys(CHECKS, ""),
                             "verdict": "", "note": "", "reviewer": "", "date": "", "pack_run": pack_run.name,
                             "worksheet_sha256": ws_sha})
    if set(written) != set(selection):
        raise LineageError(f"packets not written for {sorted(set(selection) - set(written))[:3]}")
    rows.sort(key=lambda r: (r["selection"] != "original worksheet", r["pack_id"], int(r["piece"])))
    inv.write_rows(run.path / "source_map_review_template.csv", TEMPLATE_FIELDS, rows)
    origins = {}
    for r in rows:
        origins[r["origin"]] = origins.get(r["origin"], 0) + 1
    result = {
        "pack_run": pack_run.name, "worksheet": "source_map_review.csv", "worksheet_sha256": ws_sha,
        "packs": len(selection), "original_packs": len(original), "supplementary": [pack_id(k) for k, _ in extra],
        "pieces": len(rows), "pieces_by_origin": origins,
        "cross_file_packs": sum(len({p["file"] for p in by_key[k]["pieces"]}) > 1 for k in selection),
        "truncation": "none: complete pack text and source lines per piece",
    }
    result["output_files"] = _digest(run.path, ("source_map_review_template.csv",))
    result["packets"] = {pack_id(k): v for k, v in sorted(written.items())}
    _json(run.path / "packets_summary.json", result)
    return result


def check_review(template_rows: list[dict], review_rows: list[dict]) -> tuple[list[dict], dict[str, int]]:
    pass
    problems = []
    key = lambda r: (r.get("pack_id", ""), str(r.get("piece", "")))
    tmpl = {key(r): r for r in template_rows}
    rev = {}
    for r in review_rows:
        if key(r) in rev:
            problems.append({"pack_id": r.get("pack_id", ""), "piece": r.get("piece", ""), "problem": "duplicate row"})
        rev[key(r)] = r
    for k in sorted(set(tmpl) - set(rev)):
        problems.append({"pack_id": k[0], "piece": k[1], "problem": "row missing from review"})
    for k in sorted(set(rev) - set(tmpl)):
        problems.append({"pack_id": k[0], "piece": k[1], "problem": "row not in template"})
    counts = {"ok": 0, "mismatch": 0, "blank": 0}
    for k in sorted(set(tmpl) & set(rev)):
        t, r = tmpl[k], rev[k]
        for f in PINNED:
            if str(r.get(f, "")) != str(t[f]):
                problems.append({"pack_id": k[0], "piece": k[1], "problem": f"pinned column {f} changed"})
        answers = [r.get(c, "").strip().lower() for c in CHECKS]
        verdict = r.get("verdict", "").strip().lower()
        if not verdict:
            counts["blank"] += 1
            problems.append({"pack_id": k[0], "piece": k[1], "problem": "verdict blank"})
            continue
        if any(a not in ("yes", "no") for a in answers):
            problems.append({"pack_id": k[0], "piece": k[1], "problem": "check columns must be yes/no"})
        if verdict not in ("ok", "mismatch"):
            problems.append({"pack_id": k[0], "piece": k[1], "problem": "verdict must be ok/mismatch"})
        elif verdict == "ok" and any(a == "no" for a in answers):
            problems.append({"pack_id": k[0], "piece": k[1], "problem": "verdict ok but a check is 'no'"})
        elif verdict == "mismatch" and not r.get("note", "").strip():
            problems.append({"pack_id": k[0], "piece": k[1], "problem": "mismatch without a note"})
        counts[verdict] = counts.get(verdict, 0) + 1
        if not r.get("reviewer", "").strip():
            problems.append({"pack_id": k[0], "piece": k[1], "problem": "reviewer blank"})
        if not DATE.match(r.get("date", "").strip()):
            problems.append({"pack_id": k[0], "piece": k[1], "problem": "date not ISO"})
    return problems, counts


def run_review_check(run: Run, packets_run: Path, review: Path) -> dict[str, Any]:
    packets_run = _from_run(packets_run, "source-map-packets")
    s = json.loads((packets_run / "packets_summary.json").read_text())
    if _digest(packets_run, tuple(s["output_files"])) != s["output_files"]:
        raise LineageError(f"{packets_run.name} outputs changed after the run")
    from raven.p6 import find_run

    pack_run = find_run(packets_run.parent, s["pack_run"])
    psum = json.loads((pack_run / "pack_summary.json").read_text())
    pack_ok = _digest(pack_run, tuple(psum["output_files"])) == psum["output_files"]
    ws_ok = psum["output_files"]["source_map_review.csv"] == s["worksheet_sha256"] and hashlib.sha256(
        (pack_run / "source_map_review.csv").read_bytes()).hexdigest() == s["worksheet_sha256"]
    data = review.read_bytes()
    (run.path / "review_input.csv").write_bytes(data)
    problems, counts = check_review(inv.read_rows(packets_run / "source_map_review_template.csv"),
                                    inv.read_rows(run.path / "review_input.csv"))
    if not pack_ok:
        problems.append({"pack_id": "", "piece": "", "problem": "pack run outputs changed"})
    if not ws_ok:
        problems.append({"pack_id": "", "piece": "", "problem": "original worksheet hash changed"})
    inv.write_rows(run.path / "review_problems.csv", ("pack_id", "piece", "problem"), problems)
    rows = inv.read_rows(run.path / "review_input.csv")
    result = {
        "packets_run": packets_run.name, "pack_run": pack_run.name, "review": str(review),
        "review_sha256": hashlib.sha256(data).hexdigest(), "worksheet_sha256": s["worksheet_sha256"],
        "worksheet_unchanged": ws_ok, "pack_run_unchanged": pack_ok, "verdicts": counts,
        "packs_reviewed": len({r["pack_id"] for r in rows if r.get("verdict")}),
        "reviewers": sorted({r["reviewer"] for r in rows if r.get("reviewer")}),
        "mismatches": [f"{r['pack_id']}#{r['piece']}" for r in rows if r.get("verdict", "").lower() == "mismatch"],
        "problems": len(problems),
        "sign_off_ready": not problems and counts.get("mismatch", 0) == 0,
    }
    result["output_files"] = _digest(run.path, ("review_input.csv", "review_problems.csv"))
    _json(run.path / "review_check_summary.json", result)
    return result
