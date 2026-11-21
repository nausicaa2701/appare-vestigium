"""S1/S2 acceptance: one-step message layer, matched controls, sequential packer, v4 regression."""

import csv
import gzip
import json
import random

import pytest
import torch

from raven import packer
from raven import selectors as S
from raven.config import REPO_ROOT

P = S.MessageParams()
V4 = REPO_ROOT / "artifacts/results/diagnostics/normalization-messages-20261112-v4"


def view(h, v, edges=(), order=None):
    n = len(v)
    uids = [f"u{i:02d}" for i in range(n)]
    g = torch.zeros((n, n), dtype=torch.bool)
    for i, j in edges:
        g[i, j] = g[j, i] = True
    return S.View(uids, torch.tensor(h, dtype=S.DTYPE), torch.tensor(v, dtype=S.DTYPE), g, order or [])


def rand_view(n, d=6, seed=0, p_edge=0.2):
    rng = random.Random(seed)
    h = [[rng.gauss(0, 1) for _ in range(d)] for _ in range(n)]
    v = [rng.uniform(0, 1) for _ in range(n)]
    edges = [(i, j) for i in range(n) for j in range(i + 1, n) if rng.random() < p_edge]
    return view(h, v, edges)



@pytest.mark.parametrize("n,seed", [(0, 0), (1, 0), (2, 1), (5, 2), (12, 3), (20, 4)])
def test_tensor_scores_match_scalar_reference(n, seed):
    vw = rand_view(n, seed=seed) if n else S.View([], torch.zeros((0, 4), dtype=S.DTYPE), torch.zeros(0, dtype=S.DTYPE),
                                                    torch.zeros((0, 0), dtype=torch.bool))
    scores, _ = S.static_scores(vw, P)
    ref = S.reference_scores(vw.uids, vw.h.tolist(), vw.v.tolist(), vw.gate.tolist(), P)
    for name, vals in ref.items():
        assert scores[name].tolist() == pytest.approx(vals, rel=1e-12, abs=1e-12), name


def test_zero_drive_zero_similarity_and_complete_linkage():
    
    vw = view([[1, 0], [1, 0.1], [0, 1]], [0.0, 0.0, 0.0])
    sc, _ = S.static_scores(vw, P)
    assert all(torch.isfinite(t).all() for t in sc.values())
    assert sc["appare"].tolist() == [0.0, 0.0, 0.0]
    
    vw = view([[1, 0, 0], [0, 1, 0], [0, 0, 1]], [0.3, 0.2, 0.1])
    sc, f = S.static_scores(vw, P)
    assert f.m_ungated.tolist() == [0.0, 0.0, 0.0]
    assert sc["appare"].tolist() == pytest.approx([0.3, 0.2, 0.1])
    
    vw = view([[1, 0], [1, 0.05], [1, 0.1]], [0.5, 0.4, 0.3], edges=[(0, 1), (0, 2), (1, 2)])
    _, f = S.static_scores(vw, P)
    assert f.m_gated.tolist() == [0.0, 0.0, 0.0] and float(f.m_ungated.min()) > 0


def test_no_self_message_gated_message_zero_positive_denominator():
    vw = rand_view(10, seed=7, p_edge=0.3)
    _, f = S.static_scores(vw, P)
    assert not bool(f.mask.diagonal().any()) and float(f.w.diagonal().abs().max()) == 0.0
    k = f.w * (~vw.gate).to(S.DTYPE)
    assert float(k[vw.gate].abs().sum()) == 0.0
    assert float((P.sigma + f.m_gated).min()) > 0


def test_permutation_equivariance_and_deterministic_selection():
    vw = rand_view(15, seed=11)
    sc, _ = S.static_scores(vw, P)
    perm = list(range(15))
    random.Random(3).shuffle(perm)
    
    new_uids = [None] * 15
    for new_pos, old in enumerate(perm):
        new_uids[new_pos] = vw.uids[old]
    order = sorted(range(15), key=lambda k: new_uids[k])
    idx = [perm[k] for k in order]
    pv = S.View([vw.uids[i] for i in idx], vw.h[idx], vw.v[idx], vw.gate[idx][:, idx])
    psc, _ = S.static_scores(pv, P)
    for name in sc:
        if name == "random":
            continue
        assert psc[name].tolist() == pytest.approx(sc[name][idx].tolist(), rel=1e-12)
    for pol in S.POLICIES:
        if pol.startswith("truncation"):
            continue
        assert S.select_unit_cost(pol, vw, P, 4) == S.select_unit_cost(pol, pv, P, 4)


def test_ties_follow_canonical_uid():
    vw = view([[1, 0, 0], [0, 1, 0], [0, 0, 1]], [0.5, 0.5, 0.5])
    for pol in ("relevance", "appare", "dn_ungated", "gated_subtraction", "mmr", "dependency_expansion"):
        assert S.select_unit_cost(pol, vw, P, 3) == ["u00", "u01", "u02"]


def test_knn_ties_by_uid_and_k_clamped():
    vw = view([[1, 0], [1, 0], [1, 0], [1, 0]], [0.1, 0.2, 0.3, 0.4])
    m = S.knn_mask(S.similarity(vw.h), vw.uids, k=2)
    assert m[0].tolist() == [False, True, True, False]
    assert m[3].tolist() == [True, True, False, False]
    assert int(S.knn_mask(S.similarity(vw.h), vw.uids, k=8).sum()) == 4 * 3


def test_uniform_all_other_suppression_preserves_relevance_order():
    
    v = [0.9, 0.1, 0.5, 0.3, 0.7]
    vw = view([[1.0, 0.0]] * 5, v)
    sc, _ = S.static_scores(vw, P)
    assert S.rank(sc["appare"], vw.uids) == S.rank(sc["relevance"], vw.uids)


def test_support_weight_zero_recovers_primary():
    vw = rand_view(9, seed=5, p_edge=0.4)
    sc, _ = S.static_scores(vw, S.MessageParams(alpha=0.0))
    assert sc["dn_support"].tolist() == sc["appare"].tolist()


def test_fixed_kernel_derivative_signs():
    vw = view([[1, 0], [0.99, 0.1], [0.9, 0.4]], [1.0, 0.6, 0.9], edges=[(0, 1)])
    f = S.fields(vw, P)

    def out(v):
        return S.divisive(v, S.messages(v, f.w, vw.gate), P.sigma)
    jac = torch.autograd.functional.jacobian(out, vw.v.clone())
    assert jac[0, 0] > 0  
    assert jac[0, 1] == 0  
    assert jac[0, 2] < 0  


def test_gradients_reach_relevance_sigma_gamma_and_upstream_weights():
    torch.manual_seed(0)
    n, d = 8, 5
    h0 = torch.randn(n, d, dtype=S.DTYPE)
    enc = torch.nn.Linear(d, d, dtype=S.DTYPE)  
    head = torch.nn.Linear(4 * d, 1, dtype=S.DTYPE)  
    s_raw = torch.tensor(0.3, dtype=S.DTYPE, requires_grad=True)
    c_raw = torch.tensor(0.2, dtype=S.DTYPE, requires_grad=True)
    ht = torch.randn(d, dtype=S.DTYPE)
    gate = torch.zeros((n, n), dtype=torch.bool)
    gate[0, 1] = gate[1, 0] = True
    uids = [f"u{i}" for i in range(n)]
    mask = S.knn_mask(S.similarity(enc(h0)), uids, 4)  

    def loss_fn():
        h = enc(h0)
        t = ht.expand(n, d)
        v = torch.nn.functional.softplus(head(torch.cat([t, h, (t - h).abs(), t * h], 1))).squeeze(1)
        w = S.kernel(S.similarity(h), mask, S.gamma_from_raw(c_raw))
        r = S.divisive(v, S.messages(v, w, gate), S.sigma_from_raw(s_raw))
        return (r * torch.arange(1, n + 1, dtype=S.DTYPE)).sum()

    loss = loss_fn()
    loss.backward()
    for name, g in [("sigma", s_raw.grad), ("gamma", c_raw.grad), ("enc", enc.weight.grad), ("head", head.weight.grad)]:
        assert g is not None and torch.isfinite(g).all() and float(g.abs().sum()) > 0, name
    
    for tensor, index in [(s_raw, ()), (enc.weight, (1, 2))]:
        with torch.no_grad():
            orig = tensor[index].item() if index else tensor.item()
            eps = 1e-6
            (tensor.__setitem__(index, orig + eps) if index else tensor.fill_(orig + eps))
            up = loss_fn().item()
            (tensor.__setitem__(index, orig - eps) if index else tensor.fill_(orig - eps))
            dn = loss_fn().item()
            (tensor.__setitem__(index, orig) if index else tensor.fill_(orig))
        analytic = (tensor.grad[index] if index else tensor.grad).item()
        assert analytic == pytest.approx((up - dn) / (2 * eps), rel=1e-5, abs=1e-8)



def scene():
    
    h = [[1, 0, 0, 0], [0, 1, 0, 0], [0, 0, 1, 0], [0, 0, 1, 0.03], [0, 0, 0, 1]]
    v = [0.65, 0.60, 0.99, 0.98, 0.1]
    return view(h, v, edges=[(0, 1)])


def test_fixture_policy_behaviour():
    vw = scene()
    assert S.select_unit_cost("relevance", vw, P, 2) == ["u02", "u03"]
    assert set(S.select_unit_cost("appare", vw, P, 2)) == {"u00", "u01"}
    assert set(S.select_unit_cost("gated_subtraction", vw, P, 2)) == {"u00", "u01"}
    assert S.select_unit_cost("dn_ungated", vw, P, 2)[0] in ("u00", "u01")
    
    assert S.select_unit_cost("dependency_expansion", vw, P, 2) == ["u02", "u03"]
    
    assert S.select_unit_cost("mmr", vw, P, 2) == ["u02", "u00"]


def test_gated_mmr_removes_redundancy_between_linked_units():
    h = [[1, 0], [1, 0.01], [0, 1]]
    vw = view(h, [0.9, 0.8, 0.5], edges=[(0, 1)])
    assert S.select_unit_cost("mmr", vw, P, 2) == ["u00", "u02"]
    assert S.select_unit_cost("gated_mmr", vw, P, 2) == ["u00", "u01"]


def test_expansion_prefers_linked_and_reseeds():
    vw = view([[1, 0], [0, 1], [1, 1], [0.5, 1]], [0.9, 0.1, 0.8, 0.7], edges=[(0, 1)])
    assert S.select_unit_cost("dependency_expansion", vw, P, 4) == ["u00", "u01", "u02", "u03"]


def test_subtraction_clips_and_dependency_mean_empty_is_zero():
    vw = view([[1, 0], [1, 0.01], [0, 1]], [0.2, 0.9, 0.3])
    sc, f = S.static_scores(vw, P)
    assert sc["gated_subtraction"][0].item() == 0.0  
    assert f.support.tolist() == [0.0, 0.0, 0.0]
    assert sc["dependency_mean"].tolist() == sc["relevance"].tolist()


def test_truncation_head_and_tail_follow_source_order():
    vw = view([[1, 0]] * 3, [0.1, 0.9, 0.5], order=[(0, 30), (0, 10), (1, 0)])
    assert S.select_unit_cost("truncation_head", vw, P, 3) == ["u01", "u00", "u02"]
    assert S.select_unit_cost("truncation_tail", vw, P, 3) == ["u02", "u00", "u01"]


def test_view_rejects_bad_inputs():
    with pytest.raises(ValueError):
        S.View(["b", "a"], torch.zeros(2, 2), torch.zeros(2), torch.zeros(2, 2, dtype=torch.bool))
    g = torch.zeros(2, 2, dtype=torch.bool)
    g[0, 1] = True
    with pytest.raises(ValueError):
        S.View(["a", "b"], torch.zeros(2, 2), torch.zeros(2), g)
    with pytest.raises(ValueError):
        S.View(["a", "b"], torch.zeros(2, 2), torch.tensor([-1.0, 0.0]), torch.zeros(2, 2, dtype=torch.bool))



def _toy_pack_inputs():
    target = b"function target(x) { return helper(x); }\n"
    chunks = [f"function u{i:02d}(x) {{ return x + {i}; }}\n".encode() for i in range(6)]
    text = target + b"".join(chunks)
    cands, start = [], len(target)
    for i, ch in enumerate(chunks):
        cands.append(packer.Candidate(f"u{i:02d}", "t.js", ((start, start + len(ch)),), (), 0.0, (0, start)))
        start += len(ch)
    
    cands.append(packer.Candidate("u_in", "t.js", ((0, 10),), (), 0.0, (0, 0)))
    return {"t.js": text}, {"t.js": [(0, len(target))]}, cands


def count_words(text: str) -> int:
    return len(text.split())


@pytest.mark.parametrize("policy", S.POLICIES)
@pytest.mark.parametrize("budget", [5, 20, 40, 400])
def test_every_policy_keeps_target_and_budget(policy, budget):
    texts, mandatory, cands = _toy_pack_inputs()
    opt, rej = packer.optional_candidates(texts, mandatory, cands)
    assert rej == {"u_in": "inside_mandatory"}
    n = len(opt)
    vw = view([[1.0, i / n] for i in range(n)], [0.1 * (i + 1) for i in range(n)], edges=[(0, 1)],
              order=[c.order for c in opt])
    by = {c.uid: c for c in opt}
    if policy in S.STATIC_POLICIES:
        sc, _ = S.static_scores(vw, P, seed=1, sample_id="s")
        scored = [packer.Candidate(c.uid, c.file, c.ranges, c.closure, float(sc[policy][i]), c.order)
                  for i, c in enumerate(opt)]
        res = packer.pack(texts, "t.js", mandatory, scored, budget, count_words)
    else:
        vv = dict(zip(vw.uids, vw.v.tolist(), strict=True))
        scored = [packer.Candidate(u, by[u].file, by[u].ranges, by[u].closure, vv[u], by[u].order) for u in vw.uids]
        res = packer.pack_sequential(texts, "t.js", mandatory, scored, budget, count_words, S.proposer(policy, vw, P))
    t0 = count_words(packer.serialise({"t.js": (texts["t.js"], mandatory["t.js"])}, "t.js"))
    if t0 > budget:
        assert not res.target_fits_budget
        return
    assert res.target_fits_budget and res.tokens <= budget
    assert "function target" in res.text
    assert count_words(res.text) == res.tokens
    if budget == 400:  
        assert sorted(res.selected) == sorted(by)


def test_sequential_packer_charges_overlap_once():
    text = b"function t() {}\nfunction a() { return 1; }\n"
    texts = {"f.js": text}
    mandatory = {"f.js": [(0, 16)]}
    a = packer.Candidate("a", "f.js", ((16, len(text)),), (), 1.0, (0, 16))
    b = packer.Candidate("b", "f.js", ((16, len(text)),), (), 0.5, (0, 17))  
    res = packer.pack_sequential(texts, "f.js", mandatory, [a, b], 100, count_words,
                                 lambda sel, rem: min(rem))
    assert res.selected == ["a", "b"]
    assert res.tokens == count_words(packer.serialise({"f.js": (text, [(0, len(text))])}, "f.js"))



PROBE_TO_POLICY = {"relevance": "relevance", "dependency_expansion": "dependency_expansion", "mmr": "mmr",
                   "gated_mmr": "gated_mmr", "dn": "dn_ungated", "gated_dn": "appare",
                   "dependency_mean": "dependency_mean", "gated_dn_with_support": "dn_support",
                   "gated_subtraction": "gated_subtraction"}


def test_v4_unit_cost_regression():
    with gzip.open(V4 / "inputs.jsonl.gz", "rt") as fh:
        scenes = {(s["scenario"], s["seed"]): s for s in map(json.loads, fh)}
    rows = list(csv.DictReader((V4 / "unit_cost_results.csv").open()))
    assert len(rows) == 10368
    views = {}
    mismatches = []
    for r in rows:
        key = (r["scenario"], int(r["seed"]))
        if key not in views:
            s = scenes[key]
            n = len(s["v"])
            views[key] = S.View([f"{i:02d}" for i in range(n)], torch.tensor(s["h"], dtype=S.DTYPE),
                                torch.tensor(s["v"], dtype=S.DTYPE), torch.tensor(s["g"], dtype=torch.bool))
        got = [int(u) for u in S.select_unit_cost(PROBE_TO_POLICY[r["method"]], views[key], P, int(r["unit_budget"]))]
        if got != json.loads(r["selected_ids"]):
            mismatches.append((r["scenario"], r["seed"], r["method"], r["unit_budget"]))
    assert not mismatches, mismatches[:5]
