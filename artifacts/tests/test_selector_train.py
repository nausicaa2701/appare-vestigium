"""S4 acceptance on toy problems: exact gradient, STOP/cost masking, isolation, resume."""

import copy
import math

import pytest
import torch

from raven import selector_train as T
from raven import selectors as S


def problem(seed=0, n=4, d=3):
    g = torch.Generator().manual_seed(seed)
    ht = torch.randn(d, generator=g, dtype=S.DTYPE)
    h = torch.randn(n, d, generator=g, dtype=S.DTYPE)
    gate = torch.zeros((n, n), dtype=torch.bool)
    gate[0, 1] = gate[1, 0] = True
    mask = S.knn_mask(S.similarity(h), [f"u{i}" for i in range(n)], 2)
    return ht, h, gate, mask


def loss_of(actions):  
    return 1.0 - 0.3 * (0 in actions) - 0.4 * (1 in actions) + 0.1 * len(actions)


def test_enumeration_sums_to_one_and_respects_budget():
    torch.manual_seed(0)
    net = T.PolicyNet(3, hidden=8)
    ht, h, gate, mask = problem()
    env = T.ToyEnv([3, 1, 2, 2], budget=4)
    r = net.responses(ht, h, gate, mask)
    trajs = T.enumerate_trajectories(r, env, net.stop, 1.0)
    assert float(sum(lp.exp() for _, lp in trajs)) == pytest.approx(1.0, abs=1e-12)
    for seq, _ in trajs:
        assert sum(env.costs[i] for i in seq) <= env.budget and len(set(seq)) == len(seq)


def test_score_function_estimator_matches_exact_expected_gradient():
    torch.manual_seed(0)
    net = T.PolicyNet(3, hidden=8)
    ht, h, gate, mask = problem()
    env = T.ToyEnv([3, 1, 2, 2], budget=4)
    
    r = net.responses(ht, h, gate, mask)
    exact = sum(lp.exp() * loss_of(seq) for seq, lp in T.enumerate_trajectories(r, env, net.stop, 0.7))
    net.zero_grad()
    exact.backward()
    g_exact = torch.cat([p.grad.flatten() for p in net.parameters()]).clone()
    
    net.zero_grad()
    r = net.responses(ht, h, gate, mask)
    est = sum(lp.exp().detach() * (loss_of(seq) - 0.37) * lp for seq, lp in T.enumerate_trajectories(r, env, net.stop, 0.7))
    est.backward()
    g_est = torch.cat([p.grad.flatten() for p in net.parameters()])
    assert torch.allclose(g_est, g_exact, rtol=1e-9, atol=1e-12)
    assert float(g_exact.abs().sum()) > 0
    
    gen = torch.Generator().manual_seed(1)
    net.zero_grad()
    r = net.responses(ht, h, gate, mask)
    n = 40000
    tot = torch.zeros((), dtype=S.DTYPE)
    for _ in range(n):
        tr = T.sample(r, env, net.stop, 0.7, gen)
        tot = tot + T.surrogate(tr, loss_of(tr.actions), 0.9) / n
    tot.backward()
    g_mc = torch.cat([p.grad.flatten() for p in net.parameters()])
    assert float((g_mc - g_exact).norm() / g_exact.norm()) < 0.1


def test_sample_masks_infeasible_and_logs_stop():
    torch.manual_seed(0)
    net = T.PolicyNet(3, hidden=8)
    ht, h, gate, mask = problem()
    env = T.ToyEnv([5, 1, 9, 2], budget=3)  
    gen = torch.Generator().manual_seed(0)
    r = net.responses(ht, h, gate, mask)
    for _ in range(200):
        tr = T.sample(r, env, net.stop, 1.0, gen)
        assert set(tr.actions) <= {1, 3}
        assert all(set(m) <= {1, 3} for m in tr.masks)
        assert len(tr.step_logps) == len(tr.actions) + int(tr.stopped)


def test_gradients_reach_head_sigma_gamma_stop():
    torch.manual_seed(0)
    net = T.PolicyNet(3, hidden=8)
    ht, h, gate, mask = problem()
    env = T.ToyEnv([1, 1, 1, 1], budget=2)
    r = net.responses(ht, h, gate, mask)
    exact = sum(lp.exp() * loss_of(seq) for seq, lp in T.enumerate_trajectories(r, env, net.stop, 1.0))
    exact.backward()
    for name, p in net.named_parameters():
        assert p.grad is not None and torch.isfinite(p.grad).all() and float(p.grad.abs().sum()) > 0, name


def test_train_step_isolated_from_detector_and_detector_unchanged():
    torch.manual_seed(0)
    net = T.PolicyNet(3, hidden=8)
    detector = torch.nn.Linear(3, 2, dtype=S.DTYPE)
    before = T.params_hash(detector)
    opt = torch.optim.Adam(net.parameters(), lr=1e-2)
    T.assert_isolated(opt, detector)
    with pytest.raises(AssertionError):
        T.assert_isolated(torch.optim.Adam([*net.parameters(), *detector.parameters()]), detector)
    ht, h, gate, mask = problem()
    item = {"ht": ht, "h": h, "gate": gate, "mask": mask, "env": T.ToyEnv([1, 1, 1, 1], 2), "label": 1,
            "p_full": torch.tensor([0.2, 0.8], dtype=S.DTYPE)}

    def detector_probs(it, actions):
        x = torch.zeros(3, dtype=S.DTYPE)
        for a in actions:
            x[a % 3] += 1
        return torch.softmax(detector(x), dim=0)

    base = T.LaggedBaseline()
    gen = torch.Generator().manual_seed(0)
    for _ in range(5):
        out = T.train_step(net, opt, base, [item], detector_probs, 1.0, 0.5, gen)
        assert all(math.isfinite(v) for v in out["grad_norms"].values()) and out["detector_calls"] == 1
    assert T.params_hash(detector) == before
    assert base.n == 5


def test_resume_restores_policy_optimizer_baseline_and_rng():
    ht, h, gate, mask = problem()
    item = {"ht": ht, "h": h, "gate": gate, "mask": mask, "env": T.ToyEnv([1, 2, 1, 1], 3), "label": 0,
            "p_full": torch.tensor([0.6, 0.4], dtype=S.DTYPE)}
    det = torch.nn.Linear(3, 2, dtype=S.DTYPE)

    def probs(it, actions):
        x = torch.zeros(3, dtype=S.DTYPE)
        for a in actions:
            x[a % 3] += 1
        return torch.softmax(det(x), dim=0)

    def run(steps, state=None):
        torch.manual_seed(0)
        net = T.PolicyNet(3, hidden=8)
        opt = torch.optim.Adam(net.parameters(), lr=1e-2)
        base, gen = T.LaggedBaseline(), torch.Generator().manual_seed(3)
        if state:
            net.load_state_dict(state["net"])
            opt.load_state_dict(state["opt"])
            base.load_state_dict(state["base"])
            gen.set_state(state["gen"])
        for _ in range(steps):
            T.train_step(net, opt, base, [item], probs, 1.0, 0.5, gen)
        return {"net": copy.deepcopy(net.state_dict()), "opt": copy.deepcopy(opt.state_dict()),
                "base": base.state_dict(), "gen": gen.get_state()}

    full = run(6)
    half = run(3)
    rest = run(3, half)
    for k in full["net"]:
        assert torch.equal(full["net"][k], rest["net"][k]), k
    assert full["base"] == rest["base"]


def test_distill_loss_is_zero_when_pack_matches_teacher_and_label_term_off():
    p = torch.tensor([0.3, 0.7], dtype=S.DTYPE)
    assert T.distill_loss(p, p, 1, 0.0) == pytest.approx(0.0, abs=1e-12)
    assert T.distill_loss(p, p, 1, 1.0) == pytest.approx(-torch.log(torch.tensor(0.7)).item(), rel=1e-6)
