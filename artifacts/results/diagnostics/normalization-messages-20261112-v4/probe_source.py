"""Synthetic mechanism probe for Appare Vestigium. No detector or corpus scores are used.

The unit-cost experiment isolates score/selection behavior. A separate bridge runs static
scores through the existing P6 packer with the pinned, local Qwen tokenizer.
"""

from __future__ import annotations

import argparse
import csv
import gzip
import hashlib
import json
import platform
import subprocess
import time
from collections import defaultdict
from pathlib import Path

import numpy as np
import torch

from raven import packer

METHODS = (
    "relevance", "dependency_expansion", "mmr", "gated_mmr", "dn", "gated_dn",
    "dependency_mean", "gated_dn_with_support", "gated_subtraction",
)
STATIC = tuple(m for m in METHODS if m not in ("dependency_expansion", "mmr", "gated_mmr"))
SCENARIOS = (
    "linked_complements_with_duplicate_rivals", "missing_dependency",
    "false_protection_of_duplicate_rivals", "singleton_rivals", "weak_companion",
    "observational_twin", "dependency_hub", "all_similar_unlinked",
    "dominant_duplicate_rivals",
)
TOKENIZER_REVISION = "df3ce67c0e24480f20468b6ef2894622d69eb73b"


def scene(name: str, seed: int, size: int = 16) -> dict:
    
    base_name = "weak_companion" if name == "observational_twin" else name
    names = [x for x in SCENARIOS if x != "observational_twin"]
    shared_noise = (*SCENARIOS[:3], "dominant_duplicate_rivals")
    noise_name = SCENARIOS[0] if base_name in shared_noise else base_name
    rng = np.random.default_rng(np.random.SeedSequence([seed, names.index(noise_name)]))
    h = np.eye(size)
    h[1] = h[0] + 0.03 * h[1]
    h[3] = h[2] + 0.03 * h[3]
    v = rng.uniform(0.08, 0.25, size)
    v[:4] = [1.0, 0.62, 0.90, 0.88]
    g = np.zeros((size, size), dtype=bool)
    g[0, 1] = g[1, 0] = True
    required = [0, 1]
    if base_name == "dominant_duplicate_rivals":
        v[:4] = [0.65, 0.60, 0.99, 0.98]
    if base_name == "missing_dependency":
        g[:] = False
    if base_name == "false_protection_of_duplicate_rivals":
        g[2, 3] = g[3, 2] = True
    if base_name in ("singleton_rivals", "weak_companion"):
        h[3] = np.eye(size)[3]
    if base_name == "singleton_rivals":
        v[:4] = [1.0, 0.62, 0.80, 0.78]
    if base_name == "weak_companion":
        v[:4] = [1.0, 0.15, 0.55, 0.50]
        v[4] = 0.32
    if name == "observational_twin":
        required = [0, 4]
    if base_name == "dependency_hub":
        v[:5] = [0.90, 0.40, 0.80, 0.78, 0.55]
        for j in range(4):
            g[4, j] = g[j, 4] = True
    if base_name == "all_similar_unlinked":
        h[:] = np.eye(size)[0]
        g[:] = False
    v = np.maximum(0.01, v + rng.normal(0, 0.015, size))
    h += rng.normal(0, 0.005, h.shape)
    
    perm = rng.permutation(size)
    required = [int(np.flatnonzero(perm == i)[0]) for i in required]
    v, h, g = v[perm], h[perm], g[np.ix_(perm, perm)]
    return {"scenario": name, "seed": seed, "v": v, "h": h, "g": g, "required": required}


def fields(h: np.ndarray, g: np.ndarray, neighbors: int = 8) -> tuple[np.ndarray, np.ndarray]:
    h = h / np.linalg.norm(h, axis=1, keepdims=True)
    similarity = np.maximum(0, h @ h.T)
    np.fill_diagonal(similarity, 0)
    
    mask = np.zeros_like(g)
    for i, row in enumerate(similarity):
        ids = np.flatnonzero(np.arange(len(row)) != i)
        order = ids[np.lexsort((ids, -row[ids]))]
        mask[i, order[:neighbors]] = True
    return similarity, np.square(similarity) * mask


def static_scores(v: np.ndarray, g: np.ndarray, weights: np.ndarray,
                  sigma: float = 1.0, support: float = 0.5) -> dict[str, np.ndarray]:
    gated = weights * (~g)
    degree = g.sum(axis=1)
    mean = np.divide(g @ v, degree, out=np.zeros_like(v), where=degree > 0)
    return {
        "relevance": v.copy(),
        "dn": v / (sigma + weights @ v),
        "gated_dn": v / (sigma + gated @ v),
        "dependency_mean": v + support * mean,
        "gated_dn_with_support": (v + support * mean) / (sigma + gated @ v),
        "gated_subtraction": np.maximum(0, v - gated @ v),
    }


def select(method: str, budget: int, v: np.ndarray, g: np.ndarray,
           similarity: np.ndarray, scores: dict[str, np.ndarray]) -> list[int]:
    ids = np.arange(len(v))
    if method in scores:
        return np.lexsort((ids, -scores[method]))[:budget].tolist()
    remaining = set(ids.tolist())
    chosen = []
    while remaining and len(chosen) < budget:
        if method == "dependency_expansion" and chosen:
            linked = [i for i in remaining if g[i, chosen].any()]
            candidates = linked or list(remaining)
            nxt = min(candidates, key=lambda i: (-v[i], i))
        else:
            candidates = sorted(remaining)
            penalties = {}
            for i in candidates:
                penalties[i] = max(
                    (similarity[i, j] * (not g[i, j] if method == "gated_mmr" else 1)
                     for j in chosen), default=0.0)
            
            nxt = min(candidates, key=lambda i: (
                -(v[i] if not chosen else 0.5 * v[i] - 0.5 * penalties[i]), i))
        chosen.append(nxt)
        remaining.remove(nxt)
    return chosen


def invariants() -> dict:
    s = scene(SCENARIOS[0], 0)
    v, h, g = s["v"], s["h"], s["g"]
    _, w = fields(h, g, neighbors=len(v) - 1)
    scores = static_scores(v, g, w)
    assert np.all(scores["gated_dn"] >= scores["dn"])
    zero_support = static_scores(v, g, w, support=0.0)
    np.testing.assert_array_equal(zero_support["gated_dn_with_support"], scores["gated_dn"])
    perm = np.random.default_rng(42).permutation(len(v))
    _, wp = fields(h[perm], g[np.ix_(perm, perm)], neighbors=len(v) - 1)
    permuted = static_scores(v[perm], g[np.ix_(perm, perm)], wp)
    for name in STATIC:
        np.testing.assert_allclose(scores[name][perm], permuted[name], rtol=1e-12, atol=1e-12)
    
    uniform = np.ones((len(v), len(v))) - np.eye(len(v))
    np.testing.assert_array_equal(np.argsort(v), np.argsort(v / (1 + uniform @ v)))
    
    vt = torch.tensor([1.0, 0.6, 0.9], dtype=torch.float64, requires_grad=True)
    wt = torch.tensor([[0, 0, .4], [0, 0, .2], [.4, .2, 0]], dtype=torch.float64)
    sig = torch.tensor(1.0, dtype=torch.float64, requires_grad=True)
    jac = torch.autograd.functional.jacobian(lambda x: x / (sig + wt @ x), vt)
    assert jac[0, 0] > 0 and jac[0, 1] == 0 and jac[0, 2] < 0
    out = vt / (sig + wt @ vt)
    out.sum().backward()
    assert torch.isfinite(vt.grad).all() and sig.grad.isfinite() and sig.grad != 0
    
    a, b = scene("weak_companion", 3), scene("observational_twin", 3)
    for key in ("v", "h", "g"):
        np.testing.assert_array_equal(a[key], b[key])
    assert a["required"] != b["required"]
    clean, missing = scene(SCENARIOS[0], 3), scene("missing_dependency", 3)
    for key in ("v", "h"):
        np.testing.assert_array_equal(clean[key], missing[key])
    return {"score_permutation_equivariance": True, "uniform_pool_rank_degeneracy": True,
            "fixed_kernel_jacobian": jac.detach().tolist(), "finite_nonzero_gradients": True,
            "observational_twin_inputs_identical": True, "graph_counterfactual_inputs_matched": True,
            "gate_monotonicity_fixed_kernel": True, "zero_support_matches_primary": True}


def write_csv(path: Path, rows: list[dict]) -> None:
    with path.open("w", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(fh, fieldnames=list(rows[0]))
        writer.writeheader()
        writer.writerows(rows)


def packing_bridge(out_dir: Path) -> dict:
    from raven import p5

    tok = p5.load_tokenizer({"tokenizer_revision": TOKENIZER_REVISION})
    count = lambda text: len(tok(text, add_special_tokens=False)["input_ids"])
    target = b"function target(x) { return x; }\n"
    chunks = [f"function u{i:03d}(x) {{ return x + 1; }}\n".encode() for i in range(16)]
    text = target + b"".join(chunks)
    ranges = []
    start = len(target)
    for chunk in chunks:
        ranges.append((start, start + len(chunk)))
        start += len(chunk)
    texts = {"probe.js": text}
    mandatory = {"probe.js": [(0, len(target))]}
    rows = []
    for scenario in SCENARIOS:
        s = scene(scenario, 0)
        _, w = fields(s["h"], s["g"])
        scores = static_scores(s["v"], s["g"], w)
        for budget in (64, 96):
            for method in STATIC:
                candidates = [packer.Candidate(str(i), "probe.js", (span,), (), float(scores[method][i]),
                                               (0, span[0])) for i, span in enumerate(ranges)]
                estimates = {str(i): count(text[a:b].decode()) for i, (a, b) in enumerate(ranges)}
                result = packer.pack(texts, "probe.js", mandatory, candidates, budget, count,
                                     estimates=estimates)
                assert result.target_fits_budget and count(result.text) <= budget
                assert target.decode().strip() in result.text
                selected = [int(i) for i in result.selected]
                rows.append({"scenario": scenario, "method": method, "budget": budget,
                             "tokens": count(result.text), "selected_ids": json.dumps(selected),
                             "component_retention": len(set(selected) & set(s["required"])) / 2,
                             "all_components": int(set(s["required"]) <= set(selected)),
                             "pack_sha256": hashlib.sha256(result.text.encode()).hexdigest()})
    write_csv(out_dir / "packing_bridge.csv", rows)
    return {"cells": len(rows), "all_within_budget": True, "mandatory_target_retained": True,
            "tokenizer_revision": TOKENIZER_REVISION,
            "note": "Synthetic code text; static policies only; Qwen tokens and the existing P6 packer."}


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output-dir", required=True, type=Path)
    parser.add_argument("--seeds", default=32, type=int)
    parser.add_argument("--skip-packing-bridge", action="store_true")
    args = parser.parse_args()
    if args.seeds < 1:
        parser.error("--seeds must be positive")
    out_dir = args.output_dir
    out_dir.mkdir(parents=True, exist_ok=False)
    (out_dir / "probe_source.py").write_bytes(Path(__file__).read_bytes())
    (out_dir / "packer_source.py").write_bytes(Path(packer.__file__).read_bytes())
    started = time.monotonic()
    protocol = {"seeds": list(range(args.seeds)), "scenarios": SCENARIOS, "methods": METHODS,
                "unit_budgets": [1, 2, 3, 16], "pool_size": 16, "similarity_neighbors": 8,
                "sigma": 1.0, "beta": 1.0, "gamma": 2.0, "support_alpha": 0.5, "mmr_lambda": 0.5,
                "drive_noise_sd": 0.015, "embedding_noise_sd": 0.005,
                "source_order": "per-scene random permutation, shared by observable counterfactuals",
                "truth_access": "required IDs are used for evaluation only",
                "scope": "Synthetic mechanism diagnostics; no vulnerability detector or real dataset."}
    protocol["extension_note"] = (
        "dominant_duplicate_rivals was added after inspection of the v3 aggregate table to test "
        "global suppression when raw relevance seeds favor repeated distractors. It is an "
        "exploratory counterexample, not an independent preregistered result.")
    (out_dir / "protocol.json").write_text(json.dumps(protocol, indent=2) + "\n")
    checks = invariants()
    rows = []
    with gzip.open(out_dir / "inputs.jsonl.gz", "wt", encoding="utf-8") as inputs:
        for name in SCENARIOS:
            for seed in range(args.seeds):
                s = scene(name, seed)
                inputs.write(json.dumps({k: v.tolist() if isinstance(v, np.ndarray) else v
                                         for k, v in s.items()}) + "\n")
                similarity, w = fields(s["h"], s["g"])
                scores = static_scores(s["v"], s["g"], w)
                for budget in protocol["unit_budgets"]:
                    for method in METHODS:
                        chosen = select(method, budget, s["v"], s["g"], similarity, scores)
                        assert len(chosen) == budget and len(set(chosen)) == budget
                        truth = set(s["required"])
                        rows.append({"scenario": name, "seed": seed, "unit_budget": budget,
                                     "method": method, "selected_ids": json.dumps(chosen),
                                     "component_retention": len(set(chosen) & truth) / len(truth),
                                     "all_components": int(truth <= set(chosen)),
                                     "relevance_sum": float(s["v"][chosen].sum())})
    write_csv(out_dir / "unit_cost_results.csv", rows)
    grouped = defaultdict(list)
    for row in rows:
        grouped[(row["scenario"], row["unit_budget"], row["method"])].append(row)
    aggregate = [{"scenario": key[0], "unit_budget": key[1], "method": key[2], "scenes": len(items),
                  "mean_component_retention": float(np.mean([r["component_retention"] for r in items])),
                  "all_components_rate": float(np.mean([r["all_components"] for r in items]))}
                 for key, items in sorted(grouped.items())]
    write_csv(out_dir / "unit_cost_summary.csv", aggregate)
    
    sensitivity = []
    for name in SCENARIOS:
        s = scene(name, 0)
        similarity, w = fields(s["h"], s["g"])
        for sigma in (0.25, 1.0, 4.0):
            for alpha in (0.0, 0.5, 1.0):
                sc = static_scores(s["v"], s["g"], w, sigma=sigma, support=alpha)
                for method in ("gated_dn", "gated_dn_with_support"):
                    chosen = select(method, 2, s["v"], s["g"], similarity, sc)
                    sensitivity.append({"scenario": name, "sigma": sigma, "alpha": alpha,
                                        "method": method, "selected_ids": json.dumps(chosen),
                                        "all_components": int(set(s["required"]) <= set(chosen))})
    write_csv(out_dir / "sensitivity.csv", sensitivity)
    bridge = {"status": "skipped_by_flag"}
    if not args.skip_packing_bridge:
        bridge = packing_bridge(out_dir)
    summary = {"protocol": protocol, "invariants": checks, "unit_cost_cells": len(rows),
               "packing_bridge": bridge, "wall_seconds": time.monotonic() - started,
               "environment": {"python": platform.python_version(), "numpy": np.__version__,
                               "torch": torch.__version__,
                               "git_head": subprocess.check_output(["git", "rev-parse", "HEAD"], text=True).strip()},
               "source_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
               "packer_source_sha256": hashlib.sha256(Path(packer.__file__).read_bytes()).hexdigest()}
    summary["output_files"] = {p.name: hashlib.sha256(p.read_bytes()).hexdigest()
                               for p in out_dir.iterdir() if p.is_file()}
    (out_dir / "summary.json").write_text(json.dumps(summary, indent=2) + "\n")
    print(json.dumps({k: summary[k] for k in ("unit_cost_cells", "packing_bridge", "wall_seconds")}))


if __name__ == "__main__":
    main()
