"""S4: selector learning with a frozen detector (plan §8).

The policy ranks optional units with the S1 message layer, using a target-conditioned scalar head
``v_i = softplus(head([h_t, h_i, |h_t-h_i|, h_t*h_i])) + floor`` and the update
``r_i = v_i / (sigma + M_i)``. A trajectory is sampled step by step. Each step chooses among the
currently feasible extensions and STOP, with

    logit_i = (log r_i - log cost_i) / temperature,     logit_STOP = stop_logit / temperature,

where ``cost_i`` is the exact incremental token cost given by the environment. The loss is

    L(tau) = KL(detach(p_full) || p_pack(tau)) + lambda_y * CE(p_pack(tau), y) + lambda_E * evidence(tau),

computed with a forward pass of the frozen detector. It is detached, and the policy is trained
with ``(L(tau) - b) * log p_theta(tau)``. The baseline ``b`` is a lagged EMA of earlier training
losses and is independent of the current actions. Neighbour membership, graph extraction and
packing are discrete within a pass. Inference uses deterministic response-per-cost packing
(``packer.pack``).
"""

from __future__ import annotations

import hashlib
import math
from collections.abc import Callable, Sequence
from dataclasses import dataclass, field

import torch

from raven import selectors as S


class PolicyNet(torch.nn.Module):
    pass

    def __init__(self, dim: int, hidden: int = 64, floor: float = 1e-6, sigma: float = 1.0, gamma: float = 2.0,
                 stop_logit: float = 0.0):
        super().__init__()
        self.mlp = torch.nn.Sequential(torch.nn.Linear(4 * dim, hidden, dtype=S.DTYPE), torch.nn.Tanh(),
                                       torch.nn.Linear(hidden, 1, dtype=S.DTYPE))
        self.floor = floor
        
        self.s_raw = torch.nn.Parameter(torch.tensor(math.log(math.expm1(sigma)), dtype=S.DTYPE))
        self.c_raw = torch.nn.Parameter(torch.tensor(math.log(math.expm1(gamma - 1.0)), dtype=S.DTYPE))
        self.stop = torch.nn.Parameter(torch.tensor(stop_logit, dtype=S.DTYPE))

    def relevance(self, ht: torch.Tensor, h: torch.Tensor) -> torch.Tensor:
        t = ht.to(S.DTYPE).expand_as(h)
        h = h.to(S.DTYPE)
        x = torch.cat([t, h, (t - h).abs(), t * h], dim=1)
        return torch.nn.functional.softplus(self.mlp(x)).squeeze(1) + self.floor

    def responses(self, ht: torch.Tensor, h: torch.Tensor, gate: torch.Tensor, mask: torch.Tensor) -> torch.Tensor:
        v = self.relevance(ht, h)
        w = S.kernel(S.similarity(h), mask, S.gamma_from_raw(self.c_raw))
        return S.divisive(v, S.messages(v, w, gate), S.sigma_from_raw(self.s_raw))


class Env:
    pass


    def feasible(self, state: tuple) -> dict[int, int]:  # pragma: no cover - interface
        raise NotImplementedError

    def step(self, state: tuple, action: int) -> tuple:
        return tuple(sorted((*state, action)))


@dataclass
class ToyEnv(Env):
    pass

    costs: Sequence[int]
    budget: int

    def feasible(self, state):
        used = sum(self.costs[i] for i in state)
        return {i: c for i, c in enumerate(self.costs) if i not in state and used + c <= self.budget}


@dataclass
class Trajectory:
    actions: list[int] = field(default_factory=list)  
    logp: torch.Tensor | None = None
    step_logps: list[float] = field(default_factory=list)
    masks: list[list[int]] = field(default_factory=list)
    stopped: bool = False


def step_distribution(r: torch.Tensor, feasible: dict[int, int], stop_logit: torch.Tensor, temperature: float,
                      stop_mode: str = "legacy_density"):
    if temperature <= 0 or not math.isfinite(temperature):
        raise ValueError("temperature must be finite and positive")
    acts = sorted(feasible)
    logits = [(torch.log(r[i]) - math.log(max(1, feasible[i]))) / temperature for i in acts]
    if stop_mode == "bernoulli":
        candidate_lp = torch.log_softmax(torch.stack(logits), dim=0)
        z = stop_logit / temperature
        return acts, torch.cat([torch.nn.functional.logsigmoid(-z) + candidate_lp,
                                torch.nn.functional.logsigmoid(z).reshape(1)])
    if stop_mode != "legacy_density":
        raise ValueError(f"unknown STOP mode: {stop_mode}")
    logits.append(stop_logit / temperature)
    return acts, torch.log_softmax(torch.stack(logits), dim=0)


def sample(r: torch.Tensor, env: Env, stop_logit: torch.Tensor, temperature: float, gen: torch.Generator,
           action_cap: int = 64, stop_mode: str = "legacy_density") -> Trajectory:
    tr = Trajectory()
    state: tuple = ()
    total = torch.zeros((), dtype=S.DTYPE)
    for _ in range(action_cap):
        feas = env.feasible(state)
        if not feas:
            break
        acts, logp = step_distribution(r, feas, stop_logit, temperature, stop_mode)
        k = int(torch.multinomial(logp.detach().exp(), 1, generator=gen))
        total = total + logp[k]
        tr.step_logps.append(float(logp[k].detach()))
        tr.masks.append(acts)
        if k == len(acts):
            tr.stopped = True
            break
        tr.actions.append(acts[k])
        state = env.step(state, acts[k])
    tr.logp = total
    return tr


def enumerate_trajectories(r: torch.Tensor, env: Env, stop_logit: torch.Tensor, temperature: float,
                           action_cap: int = 64, stop_mode: str = "legacy_density") -> list[tuple[list[int], torch.Tensor]]:
    pass
    out = []

    def rec(state, seq, lp, depth):
        feas = env.feasible(state)
        if not feas or depth == action_cap:
            out.append((seq, lp))
            return
        acts, logp = step_distribution(r, feas, stop_logit, temperature, stop_mode)
        out.append((seq, lp + logp[-1]))  
        for k, a in enumerate(acts):
            rec(env.step(state, a), [*seq, a], lp + logp[k], depth + 1)

    rec((), [], torch.zeros((), dtype=S.DTYPE), 0)
    return out


class LaggedBaseline:
    pass

    def __init__(self, decay: float = 0.9):
        self.decay, self.value, self.n = decay, 0.0, 0

    def update(self, loss: float) -> None:
        self.value = loss if self.n == 0 else self.decay * self.value + (1 - self.decay) * loss
        self.n += 1

    def state_dict(self) -> dict:
        return {"decay": self.decay, "value": self.value, "n": self.n}

    def load_state_dict(self, d: dict) -> None:
        self.decay, self.value, self.n = d["decay"], d["value"], d["n"]


def distill_loss(p_full: torch.Tensor, p_pack: torch.Tensor, label: int, lambda_y: float,
                 evidence: float = 0.0, lambda_e: float = 0.0) -> float:
    pass
    p, q = p_full.detach().double().clamp_min(1e-12), p_pack.detach().double().clamp_min(1e-12)
    kl = float((p * (p.log() - q.log())).sum())
    ce = float(-q[label].log())
    return kl + lambda_y * ce + lambda_e * evidence


def surrogate(tr: Trajectory, loss: float, baseline: float) -> torch.Tensor:
    pass
    return (loss - baseline) * tr.logp


def params_hash(module: torch.nn.Module) -> str:
    h = hashlib.sha256()
    for name, p in sorted(module.state_dict().items()):
        h.update(name.encode())
        h.update(p.detach().to(torch.float32).cpu().contiguous().numpy().tobytes())
    return h.hexdigest()


def assert_isolated(optimizer: torch.optim.Optimizer, detector: torch.nn.Module) -> None:
    det_ids = {id(p) for p in detector.parameters()}
    for g in optimizer.param_groups:
        for p in g["params"]:
            if id(p) in det_ids:
                raise AssertionError("selector optimizer contains a detector parameter")


def train_step(net: PolicyNet, opt: torch.optim.Optimizer, baseline: LaggedBaseline, batch: list[dict],
               detector_probs: Callable[[dict, list[int]], torch.Tensor], temperature: float, lambda_y: float,
               gen: torch.Generator, *, action_cap: int = 64, stop_mode: str = "legacy_density") -> dict:
    pass


    opt.zero_grad(set_to_none=True)
    if not batch:
        raise ValueError("selector batch must be nonempty")
    total = torch.zeros((), dtype=S.DTYPE)
    losses, calls, lengths, empty = [], 0, [], 0
    b = baseline.value
    for it in batch:
        r = net.responses(it["ht"], it["h"], it["gate"], it["mask"])
        tr = sample(r, it["env"], net.stop, temperature, gen, action_cap, stop_mode)
        lengths.append(len(tr.actions))
        empty += int(not tr.masks)
        with torch.no_grad():
            q = detector_probs(it, tr.actions)
        calls += 1
        loss = distill_loss(it["p_full"], q, it["label"], lambda_y)
        if not math.isfinite(loss):
            raise FloatingPointError("nonfinite selector loss before optimizer update")
        losses.append(loss)
        total = total + surrogate(tr, loss, b) / len(batch)
    if total.requires_grad:
        total.backward()
    grads = {n: (float(p.grad.norm()) if p.grad is not None else 0.0) for n, p in net.named_parameters()}
    if not all(math.isfinite(g) for g in grads.values()):
        opt.zero_grad(set_to_none=True)
        raise FloatingPointError("nonfinite selector gradient before optimizer update")
    if total.requires_grad:
        opt.step()
    for loss in losses:
        baseline.update(loss)
    return {"loss_mean": sum(losses) / len(losses), "baseline_before": b, "grad_norms": grads,
            "detector_calls": calls, "empty_action_records": empty, "action_lengths": lengths,
            "optimizer_updated": total.requires_grad}
