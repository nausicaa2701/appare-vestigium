"""S0 split rule and S3 perturbation/graph helpers."""

import math

from raven import p7


def test_split_families_hash_rule_and_disjoint_folds():
    fams = [f"g{i:03d}" for i in range(59)]
    out = p7.split_families(fams)
    order = sorted(fams, key=p7.inner_hash)
    assert [g for g in order if out[g]["inner_role"] == "calibration"] == order[:math.ceil(0.2 * 59)]
    for f in range(3):
        roles = {g: out[g][f"fold{f}_role"] for g in fams}
        assess = {g for g, r in roles.items() if r == "assessment"}
        assert assess == {g for g in fams if out[g]["outer_fold"] == f}
        rest = [g for g in order if g not in assess]
        assert [g for g in rest if roles[g] == "calibration"] == rest[:math.ceil(0.2 * len(rest))]
    assert p7.split_families(list(reversed(fams))) == out  


def test_inner_hash_matches_the_recorded_rule():
    import hashlib
    assert p7.inner_hash("gabc") == hashlib.sha256(b"pilot-inner-split-v1|42|gabc").hexdigest()


def test_perturb_counts_and_paired_determinism():
    uids = [f"u{i}" for i in range(8)]
    pairs = {frozenset((f"u{i}", f"u{i + 1}")): {"call"} for i in range(6)}
    d, nd, na = p7.perturb(pairs, uids, "delete", 0.5, 1, "s|L1")
    assert (nd, na, len(d)) == (3, 0, 3) and set(d) <= set(pairs)
    a, nd, na = p7.perturb(pairs, uids, "add", 0.25, 1, "s|L1")
    assert (nd, na, len(a)) == (0, 2, 8) and set(pairs) <= set(a)
    assert p7.perturb(pairs, uids, "add", 0.25, 1, "s|L1")[0] == a
    assert p7.perturb(pairs, uids, "delete", 0.1, 0, "s|L1")[1] == 1  
    assert p7.perturb({}, uids, "add", 0.5, 0, "x")[2] == 0


def test_unit_graph_symmetric_and_restricted_to_pool():
    sample = {"snapshot": "p@r", "unit_index": {"a": ("f.js", 0), "b": ("f.js", 1), "c": ("g.js", 0)}}
    eidx = {("p@r", "f.js", 0): [("f.js", 1, "call", "high"), ("x.js", 3, "call", "high")],
            ("p@r", "g.js", 0): [("f.js", 1, "import", "high"), ("g.js", 0, "def_use", "low")]}
    pairs = p7.unit_graph(sample, ["a", "b", "c"], eidx)
    assert pairs == {frozenset(("a", "b")): {"call"}, frozenset(("b", "c")): {"import"}}
    g = p7.gate_matrix(["a", "b", "c"], pairs)
    assert bool((g == g.T).all()) and not bool(g.diagonal().any())


def test_covered_requires_all_non_whitespace_bytes():
    text = b"a = 1;\n  b = 2;\n"
    a, b = p7.line_span(text, 2, 2)
    pos = p7.nonws(text, a, b)
    assert p7.covered(pos, [(a + 2, b)]) and not p7.covered(pos, [(a + 3, b)])
