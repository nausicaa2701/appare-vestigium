"""P6C leakage probes (proposal §9.8) and the label-conflict rerun.

Per source, three channels of the cleaned detector input are probed with family-grouped
cross-validation: the serialised **path** header, **comments** inside the L1 input, and a
**bag-of-words** over the code with comments removed (L0 and L1; shortcut reference, X2).
Each probe is compared with a prevalence-aware, family-restricted label-permutation baseline
(twins swap labels within a family; pure families swap labels with same-size families), and its
out-of-fold MCC gets a family-bootstrap interval. A channel whose features are empty or carry
no shared vocabulary (e.g. pseudonymised SARD paths) is recorded as **removal**, not as a
passed test. Failing to beat the baseline is not evidence that no leakage exists.

Labels are used only as probe targets here, never to build a pack.
"""

from __future__ import annotations

import hashlib
import json
import re
from collections import defaultdict
from pathlib import Path
from typing import Any

from raven import context, packer
from raven import inventory as inv
from raven.p2 import LineageError, _digest, _from_run, _json
from raven.runlog import Run

TOKEN = r"(?u)\b[A-Za-z_][A-Za-z0-9_]*\b"
ARTIFACT_PATTERNS = {
    "cve_id": r"CVE-\d{4}-\d{4,}",
    "ghsa_id": r"GHSA-[0-9a-z]{4}-",
    "vuln_word": r"(?i)\bvuln\w*",
    "security_word": r"(?i)\bsecurity\b",
    "xss_word": r"(?i)\bxss\b",
    "sanitiz_word": r"(?i)\bsaniti[sz]\w*",
    "unsafe_word": r"(?i)\bunsafe\b",
    "safe_word": r"(?i)\bsafe\b",
    "fix_word": r"(?i)\bfix(es|ed)?\b",
}
PROBE_FIELDS = ("source", "channel", "samples", "families", "positives", "status", "nonempty_samples",
                "vocabulary", "mcc", "mcc_ci_low", "mcc_ci_high", "balanced_accuracy", "perm_mean", "perm_q95",
                "p_value", "above_baseline", "permutations", "bootstrap", "folds", "seed")


def split_path(path: str) -> str:
    parts = re.split(r"[/\\._\-]+", path)
    out = []
    for p in parts:
        out += re.findall(r"[A-Z]?[a-z]+|[A-Z]+(?![a-z])|\d+", p) or [p]
    return " ".join(w.lower() for w in out if w)


def channel_texts(sample: dict) -> dict[str, str]:
    pass
    texts, tf, fu = sample["texts"], sample["target_file"], sample["fu"]
    labels = sample["labels"] or {}
    comments = context.comment_ranges(fu)
    l1 = packer._merge(sample["levels"]["L1"][tf])
    l0 = packer._merge(sample["levels"]["L0"][tf])
    in_l1 = [(max(a, x), min(b, y)) for a, b in comments for x, y in l1 if a < y and x < b]
    comment_text = "\n".join(texts[tf][a:b].decode("utf-8", "replace") for a, b in in_l1)

    def code(ranges):
        kept = packer._subtract(ranges, comments)
        return "\n".join(texts[tf][a:b].decode("utf-8", "replace") for a, b in kept)

    return {"path": split_path(labels.get(tf, tf)), "comment": comment_text, "bow_L0": code(l0), "bow_L1": code(l1),
            "_l1_full": packer.serialise({tf: (texts[tf], l1)}, tf, sample["labels"])}


def restricted_permutation(y, groups: list[str], rng):
    pass


    import numpy as np

    y = np.asarray(y)
    out = y.copy()
    fam = defaultdict(list)
    for i, g in enumerate(groups):
        fam[g].append(i)
    pure = defaultdict(list)
    for g, idx in fam.items():
        labels = y[idx]
        if len(set(labels.tolist())) > 1:
            out[idx] = rng.permutation(labels)
        else:
            pure[len(idx)].append(g)
    for gs in pure.values():
        labs = [int(y[fam[g][0]]) for g in gs]
        for g, lab in zip(gs, rng.permutation(labs)):
            out[fam[g]] = lab
    return out


def _mcc(y, p) -> float:
    from sklearn.metrics import matthews_corrcoef

    return float(matthews_corrcoef(y, p)) if len(set(y)) > 1 else 0.0


def probe(docs: list[str], y: list[int], groups: list[str], *, seed: int, folds: int, permutations: int,
          bootstrap: int) -> dict[str, Any]:
    pass
    import numpy as np
    from sklearn.feature_extraction.text import CountVectorizer
    from sklearn.linear_model import LogisticRegression
    from sklearn.metrics import balanced_accuracy_score
    from sklearn.model_selection import StratifiedGroupKFold

    y = np.asarray(y)
    nonempty = sum(bool(re.search(TOKEN, d)) for d in docs)
    try:
        vocab = len(CountVectorizer(token_pattern=TOKEN, binary=True).fit(docs).vocabulary_)
    except ValueError:
        vocab = 0
    out = {"samples": len(y), "families": len(set(groups)), "positives": int(y.sum()), "nonempty_samples": nonempty,
           "vocabulary": vocab, "permutations": permutations, "bootstrap": bootstrap, "folds": folds, "seed": seed}
    n_groups = len(set(groups))
    k = min(folds, n_groups, int(min(y.sum(), len(y) - y.sum())))
    if vocab == 0 or nonempty < max(4, 0.1 * len(y)):
        return {**out, "status": "removal_or_empty_channel"}
    if k < 2:
        return {**out, "status": "too_few_groups"}

    def oof(labels):
        pred = np.zeros(len(labels), dtype=int)
        cv = StratifiedGroupKFold(n_splits=k, shuffle=True, random_state=seed)
        for tr, te in cv.split(docs, labels, groups):
            if len(set(labels[tr])) < 2:
                pred[te] = round(labels[tr].mean())
                continue
            vec = CountVectorizer(token_pattern=TOKEN, binary=True)
            xtr = vec.fit_transform([docs[i] for i in tr])
            if xtr.shape[1] == 0:
                pred[te] = round(labels[tr].mean())
                continue
            clf = LogisticRegression(C=1.0, solver="liblinear", class_weight="balanced", random_state=seed)
            clf.fit(xtr, labels[tr])
            pred[te] = clf.predict(vec.transform([docs[i] for i in te]))
        return pred

    pred = oof(y)
    obs = _mcc(y, pred)
    rng = np.random.default_rng(seed)
    perm = []
    for _ in range(permutations):
        yp = restricted_permutation(y, groups, rng)
        perm.append(_mcc(yp, oof(yp)))
    perm = np.asarray(perm)
    fam = defaultdict(list)
    for i, g in enumerate(groups):
        fam[g].append(i)
    keys = sorted(fam)
    boots = []
    for _ in range(bootstrap):
        idx = [i for g in rng.choice(keys, size=len(keys), replace=True) for i in fam[g]]
        boots.append(_mcc(y[idx], pred[idx]))
    q95 = float(np.quantile(perm, 0.95))
    p = float((1 + (perm >= obs).sum()) / (1 + permutations))
    return {**out, "status": "probed", "mcc": round(obs, 4), "mcc_ci_low": round(float(np.quantile(boots, 0.025)), 4),
            "mcc_ci_high": round(float(np.quantile(boots, 0.975)), 4),
            "balanced_accuracy": round(float(balanced_accuracy_score(y, pred)), 4),
            "perm_mean": round(float(perm.mean()), 4), "perm_q95": round(q95, 4), "p_value": round(p, 4)}


def top_features(docs: list[str], y: list[int], n: int = 15, seed: int = 0) -> list[dict]:
    pass
    import numpy as np
    from sklearn.feature_extraction.text import CountVectorizer
    from sklearn.linear_model import LogisticRegression

    vec = CountVectorizer(token_pattern=TOKEN, binary=True)
    x = vec.fit_transform(docs)
    clf = LogisticRegression(C=1.0, solver="liblinear", class_weight="balanced", random_state=seed).fit(x, y)
    names = np.asarray(vec.get_feature_names_out())
    coef = clf.coef_[0]
    order = np.argsort(-np.abs(coef))[:n]
    yv = np.asarray(y)
    return [{"feature": str(names[i]), "coef": round(float(coef[i]), 4),
             "docs_pos": int(x[yv == 1][:, i].sum()), "docs_neg": int(x[yv == 0][:, i].sum())} for i in order]


def review_packet(sample: dict, cell_key: tuple, manifest: dict, text: str) -> str:
    pass

    from raven import p6

    sid, level, budget, method = cell_key
    labels = sample["labels"] or {}
    by_label = {labels.get(f, f): f for f in sample["texts"]}
    out = [f"# Source-map check: {sid} | {level} | B={budget} | {method}", "",
           f"pack_sha256 `{manifest['pack_sha256']}`, tokens {manifest['tokens']}, pieces {len(manifest['pieces'])}.",
           "For each piece: does the pack text equal the source lines shown, and is the origin label right?", ""]
    for j, piece in enumerate(manifest["pieces"]):
        f = by_label[piece["file"]]
        data = sample["texts"][f]
        starts = p6._line_starts(data)
        a, b = piece["src"]
        la, lb = (int(x) for x in piece["lines"].split("-"))
        src_lines = [f"{n:>6}  {data[starts[n - 1]:(starts[n] - 1 if n < len(starts) else len(data))].decode('utf-8', 'replace')}"
                     for n in range(la, lb + 1)]
        chunk = text[piece["out"][0]:piece["out"][1]]
        out += [(f"## piece {j}: {piece['origin']} — {piece['file']} lines {piece['lines']} (bytes {a}-{b}, "
                f"chars {piece['out'][0]}-{piece['out'][1]}, tokens {piece['tokens'][0]}-{piece['tokens'][1]})"), "",
                "pack text:", "```", chunk[:1500] + ("…" if len(chunk) > 1500 else ""), "```",
                "source lines:", "```", "\n".join(src_lines[:40]) + ("\n…" if len(src_lines) > 40 else ""), "```", ""]
    return "\n".join(out)


def run_leakage(run: Run, extract_run: Path, build_run: Path, pack_run: Path) -> dict[str, Any]:
    from raven import p5, p6

    cfg = run.config["p6"]["leakage"]
    seed = run.config["seed"]
    extract_run = _from_run(extract_run, "extract-units")
    build_run = _from_run(build_run, "build-contexts")
    pack_run = _from_run(pack_run, "pack-cells")
    psum = json.loads((pack_run / "pack_summary.json").read_text())
    if _digest(pack_run, tuple(psum["output_files"])) != psum["output_files"]:
        raise LineageError(f"{pack_run.name} outputs changed after the run")
    if psum["build_run"] != build_run.name or psum["extract_run"] != extract_run.name:
        raise LineageError("pack run does not descend from the given extraction/contexts runs")
    ext = json.loads((extract_run / "extract_summary.json").read_text())
    _, runs = p5._verify_p4(p6.find_run(extract_run.parent, ext["p4_summary_run"]))
    roles, _ = p6._roles(runs)

    
    import gzip

    picks = sorted({tuple(x["pack"].split("|")) for x in inv.read_rows(pack_run / "source_map_review.csv")})
    picks = [(sid, lv, int(b), m) for sid, lv, b, m in picks]
    pick_samples = {p[0] for p in picks}
    manifests = {}
    with gzip.open(pack_run / "pack_manifest.jsonl.gz", "rt", encoding="utf-8") as fh:
        for line in fh:
            m = json.loads(line)
            key = (m["sample_id"], m["level"], m["budget"], m["method"])
            if key in picks:
                manifests[key] = m
    pdir = run.path / "source_map_review_packets"
    pdir.mkdir(exist_ok=True)
    from raven import p5 as _p5

    tok = _p5.load_tokenizer(run.config)
    count = lambda t: _p5.count_tokens(tok, t)
    p6cfg = run.config["p6"]
    written = 0
    rows, scan, sha_groups = [], [], defaultdict(list)
    for s in p6.iter_samples(run.config, extract_run, build_run, run.logger):
        r = s["row"]
        if s["sample_id"] in pick_samples:
            for key in [k for k in picks if k[0] == s["sample_id"]]:
                pool = p6.method_scores(key[3], seed, key[0], s["pools"][key[1]])
                est = {c.uid: count(b"".join(s["texts"][c.file][a:b] for a, b in packer._merge(c.span_set))
                                    .decode("utf-8", "replace")) for c in pool}
                tf = s["target_file"]
                res = packer.pack(s["texts"], tf, {tf: s["levels"]["L0"][tf]}, pool, key[2], count,
                                  labels=s["labels"], prompt=p6cfg["prompt_prefix"], estimates=est,
                                  slack=int(p6cfg["estimate_slack_tokens"]))
                if p6._sha(res.text) != manifests[key]["pack_sha256"]:
                    raise LineageError(f"rebuilt pack differs from the pack run for {key}")
                name = hashlib.sha256("|".join(map(str, key)).encode()).hexdigest()[:12]
                (pdir / f"{name}.md").write_text(review_packet(s, key, manifests[key], res.text), encoding="utf-8")
                written += 1
        ch = channel_texts(s)
        full = ch.pop("_l1_full")
        rows.append({"sample_id": s["sample_id"], "source": r["source"], "label": int(r["label"]),
                     "family": roles[s["sample_id"]]["family"], **ch})
        hits = {k: int(bool(re.search(p, full))) for k, p in ARTIFACT_PATTERNS.items()}
        scan.append({"sample_id": s["sample_id"], "source": r["source"], "label": r["label"], **hits})
        
        l0 = packer.serialise({p: (s["texts"][p], rg) for p, rg in s["levels"]["L0"].items()}, s["target_file"],
                              s["labels"])
        l3 = packer.serialise({p: (s["texts"][p], rg) for p, rg in s["levels"]["L3"].items()}, s["target_file"],
                              s["labels"])
        h0, h3 = (hashlib.sha256(t.encode()).hexdigest() for t in (l0, l3))
        if h0 != r["L0_sha256"] or h3 != r["L3_sha256"]:
            raise LineageError(f"{s['sample_id']}: rebuilt L0/L3 differ from P5")
        sha_groups[(r["source"], h0, h3)].append((s["sample_id"], r["label"]))

    probes, inspection = [], []
    for source in sorted({r["source"] for r in rows}):
        sub = [r for r in rows if r["source"] == source]
        y = [r["label"] for r in sub]
        g = [r["family"] for r in sub]
        for channel in ("path", "comment", "bow_L0", "bow_L1"):
            docs = [r[channel] for r in sub]
            res = probe(docs, y, g, seed=seed, folds=cfg["folds"], permutations=cfg["permutations"],
                        bootstrap=cfg["bootstrap"])
            if source == "sard_php" and channel == "path":
                res["status"] = "removal_pseudonymised"  
            above = res.get("status") == "probed" and res["mcc"] > res["perm_q95"] and res["p_value"] <= cfg["alpha"]
            res["above_baseline"] = str(above).lower()
            probes.append({"source": source, "channel": channel, **res})
            if above:
                for f in top_features(docs, y, seed=seed):
                    inspection.append({"source": source, "channel": channel, **f})
            run.logger.info("leakage %s/%s: %s", source, channel,
                            json.dumps({k: res.get(k) for k in ("status", "mcc", "perm_q95", "p_value")}))
    inv.write_rows(run.path / "leakage_probes.csv", PROBE_FIELDS, probes)
    inv.write_rows(run.path / "leakage_top_features.csv",
                   ("source", "channel", "feature", "coef", "docs_pos", "docs_neg"), inspection)
    inv.write_rows(run.path / "artifact_scan.csv", ("sample_id", "source", "label", *ARTIFACT_PATTERNS), scan)
    scan_summary = {}
    for source in sorted({r["source"] for r in scan}):
        sub = [r for r in scan if r["source"] == source]
        scan_summary[source] = {k: {"label1": sum(r[k] for r in sub if r["label"] == "1"),
                                    "label0": sum(r[k] for r in sub if r["label"] == "0")} for k in ARTIFACT_PATTERNS}
    conflicts = []
    for (source, h0, h3), members in sorted(sha_groups.items()):
        if len({lab for _, lab in members}) > 1:
            conflicts += [{"source": source, "sample_id": sid, "label": lab, "L0_sha256": h0, "L3_sha256": h3,
                           "status": "excluded", "rule": "exclude_from_primary"} for sid, lab in members]
    inv.write_rows(run.path / "label_conflicts_rerun.csv",
                   ("source", "sample_id", "label", "L0_sha256", "L3_sha256", "status", "rule"), conflicts)
    result = {
        "extract_run": extract_run.name, "build_run": build_run.name, "pack_run": pack_run.name, "seed": seed,
        "settings": cfg, "samples": len(rows),
        "probes": {f"{p['source']}/{p['channel']}": {k: p.get(k) for k in ("status", "mcc", "mcc_ci_low",
                                                                         "mcc_ci_high", "perm_q95", "p_value",
                                                                         "above_baseline")} for p in probes},
        "above_baseline": [f"{p['source']}/{p['channel']}" for p in probes if p["above_baseline"] == "true"],
        "artifact_scan": scan_summary,
        "label_conflicts_rerun": len(conflicts),
        "pack_label_conflict_groups": psum.get("pack_label_conflicts"),
        "source_map_review_packets": written,
        "note": "not finding significance is not evidence of no leakage; removal channels are not passed tests",
    }
    result["output_files"] = _digest(run.path, ("leakage_probes.csv", "leakage_top_features.csv", "artifact_scan.csv",
                                                "label_conflicts_rerun.csv"))
    _json(run.path / "leakage_summary.json", result)
    return result
