"""Evidence selectors for P7 (plan ``docs/p7-selector-implementation-and-experiments-2026-11-12.md``).

S1, the one-step message layer of Appare Vestigium, over the optional units of one target:

    w_ij = beta * max(0, cos(h_i, h_j)) ** gamma          j in N_k(i), j != i
    K_ij = w_ij * (1 - g_ij)                               g = symmetric direct-dependency mask
    M_i  = sum_j K_ij * v_j                                messages from the initial relevance
    r_i  = v_i / (sigma + M_i)                             simultaneous divisive update

S2, the matched controls. Every policy for one target shares ``h``, ``v``, the graph, the kNN
membership, the tokenizer, the closure and the exact packer:

* static scorers: ``relevance``, ``dn_ungated``, ``appare`` (primary), ``gated_subtraction``,
  ``dependency_mean``, ``dn_support`` and ``random``. They are packed with ``packer.pack``,
  i.e. score per incremental cost plus the best-single alternative.
* sequential policies: ``dependency_expansion``, ``mmr``, ``gated_mmr``, ``truncation_head`` and
  ``truncation_tail``. They propose the next unit from the current feasible set and
  ``packer.pack_sequential`` checks the serialised extension.

Numerics are float64 torch, so autograd reaches ``v``, ``sigma``, ``gamma`` and, upstream, the
scorer and encoder weights. Neighbour membership and the dependency mask are fixed (discrete)
within a pass. Ties are broken by the canonical unit id (``uid``). Labels, evidence
annotations, patches and roles are never arguments of any function here.
"""

from __future__ import annotations

import hashlib
import math
from collections.abc import Callable, Sequence
from dataclasses import dataclass, field

import torch

DTYPE = torch.float64

STATIC_POLICIES = ("relevance", "dn_ungated", "appare", "gated_subtraction", "dependency_mean", "dn_support", "random")
SEQUENTIAL_POLICIES = ("dependency_expansion", "mmr", "gated_mmr", "truncation_head", "truncation_tail")
POLICIES = STATIC_POLICIES + SEQUENTIAL_POLICIES

REQUIRED_CONTROLS = ("relevance", "dependency_expansion", "gated_mmr", "dn_ungated", "appare", "gated_subtraction",
                     "dependency_mean", "dn_support")


@dataclass(frozen=True)
class MessageParams:
    pass

    sigma: float = 1.0
    gamma: float = 2.0
    beta: float = 1.0
    k: int = 8
    eta: float = 1.0
    alpha: float = 0.5
    mmr_lambda: float = 0.5
    relevance_floor: float = 1e-6
    sigma_epsilon: float = 1e-6

    def as_dict(self) -> dict:
        return {f: getattr(self, f) for f in self.__dataclass_fields__}


def sigma_from_raw(s: torch.Tensor, epsilon: float = 1e-6) -> torch.Tensor:
    pass
    return torch.nn.functional.softplus(s) + epsilon


def gamma_from_raw(c: torch.Tensor) -> torch.Tensor:
    pass
    return 1.0 + torch.nn.functional.softplus(c)



def normalise(h: torch.Tensor) -> torch.Tensor:
    return h / h.norm(dim=-1, keepdim=True).clamp_min(1e-12)


def similarity(h: torch.Tensor) -> torch.Tensor:
    pass
    hn = normalise(h.to(DTYPE))
    s = (hn @ hn.T).clamp_min(0.0)
    return s * (1.0 - torch.eye(len(hn), dtype=DTYPE))


def knn_mask(sim: torch.Tensor, uids: Sequence[str], k: int) -> torch.Tensor:
    pass

    n = len(uids)
    mask = torch.zeros((n, n), dtype=torch.bool)
    keff = min(k, max(0, n - 1))
    if keff == 0:
        return mask
    s = sim.detach()
    for i in range(n):
        order = sorted((j for j in range(n) if j != i), key=lambda j: (-float(s[i, j]), uids[j]))
        mask[i, order[:keff]] = True
    return mask


def kernel(sim: torch.Tensor, mask: torch.Tensor, gamma, beta=1.0) -> torch.Tensor:
    pass
    gamma = torch.as_tensor(gamma, dtype=DTYPE)
    w = beta * torch.where(sim > 0, sim.clamp_min(1e-300) ** gamma, torch.zeros_like(sim))
    return w * mask.to(DTYPE)


def messages(v: torch.Tensor, w: torch.Tensor, gate: torch.Tensor | None) -> torch.Tensor:
    pass
    k = w if gate is None else w * (~gate).to(DTYPE)
    return k @ v.to(DTYPE)


def divisive(v: torch.Tensor, m: torch.Tensor, sigma) -> torch.Tensor:
    return v / (torch.as_tensor(sigma, dtype=DTYPE) + m)


def subtraction(v: torch.Tensor, m: torch.Tensor, eta) -> torch.Tensor:
    pass
    return (v - torch.as_tensor(eta, dtype=DTYPE) * m).clamp_min(0.0)


def dependency_mean(v: torch.Tensor, gate: torch.Tensor) -> torch.Tensor:
    pass
    g = gate.to(DTYPE)
    deg = g.sum(dim=1)
    return torch.where(deg > 0, (g @ v) / deg.clamp_min(1.0), torch.zeros_like(v))


@dataclass
class View:
    pass

    uids: list[str]
    h: torch.Tensor  
    v: torch.Tensor  
    gate: torch.Tensor  
    order: list[tuple] = field(default_factory=list)  

    def __post_init__(self):
        if list(self.uids) != sorted(self.uids):
            raise ValueError("View.uids must be in canonical (sorted) order")
        if self.gate.shape != (len(self.uids), len(self.uids)):
            raise ValueError("gate shape mismatch")
        if bool((self.gate != self.gate.T).any()) or bool(self.gate.diagonal().any()):
            raise ValueError("gate must be symmetric with an empty diagonal")
        if self.v.numel() and float(self.v.min()) < 0:
            raise ValueError("relevance must be non-negative")


@dataclass
class Fields:
    sim: torch.Tensor
    mask: torch.Tensor
    w: torch.Tensor
    m_gated: torch.Tensor
    m_ungated: torch.Tensor
    support: torch.Tensor


def fields(view: View, p: MessageParams, sigma=None, gamma=None) -> Fields:
    sim = similarity(view.h)
    mask = knn_mask(sim, view.uids, p.k)
    w = kernel(sim, mask, p.gamma if gamma is None else gamma, p.beta)
    return Fields(sim, mask, w, messages(view.v, w, view.gate), messages(view.v, w, None),
                  dependency_mean(view.v, view.gate))


def random_scores(seed: int, sample_id: str, uids: Sequence[str]) -> torch.Tensor:
    out = []
    for u in uids:
        h = hashlib.sha256(f"{seed}:{sample_id}:{u}".encode()).digest()
        out.append((int.from_bytes(h[:8], "big") + 1) / 2**64)
    return torch.tensor(out, dtype=DTYPE)


def static_scores(view: View, p: MessageParams, *, seed: int = 0, sample_id: str = "", sigma=None,
                  gamma=None) -> tuple[dict[str, torch.Tensor], Fields]:
    pass
    f = fields(view, p, sigma, gamma)
    s = p.sigma if sigma is None else sigma
    v = view.v.to(DTYPE)
    out = {
        "relevance": v,
        "dn_ungated": divisive(v, f.m_ungated, s),
        "appare": divisive(v, f.m_gated, s),
        "gated_subtraction": subtraction(v, f.m_gated, p.eta),
        "dependency_mean": v + p.alpha * f.support,
        "dn_support": divisive(v + p.alpha * f.support, f.m_gated, s),
        "random": random_scores(seed, sample_id, view.uids),
    }
    return out, f


def rank(scores: torch.Tensor, uids: Sequence[str]) -> list[str]:
    pass
    vals = scores.detach().tolist()
    return [uids[i] for i in sorted(range(len(uids)), key=lambda i: (-vals[i], uids[i]))]



Proposer = Callable[[list[str], set[str]], str]


def proposer(policy: str, view: View, p: MessageParams, sim: torch.Tensor | None = None) -> Proposer:
    pass

    idx = {u: i for i, u in enumerate(view.uids)}
    v = view.v.detach().tolist()
    if sim is None:
        sim = similarity(view.h)
    s = sim.detach().tolist()  
    nbrs = [{j for j, x in enumerate(row) if x} for row in view.gate.tolist()]

    if policy == "dependency_expansion":
        
        
        
        def nxt(selected, remaining):
            chosen = {idx[u] for u in selected}
            linked = [u for u in remaining if nbrs[idx[u]] & chosen]
            pool = linked or list(remaining)
            return min(pool, key=lambda u: (-v[idx[u]], u))
        return nxt

    if policy in ("mmr", "gated_mmr"):
        
        
        
        lam = p.mmr_lambda

        def nxt(selected, remaining):
            chosen = [idx[u] for u in selected]
            if not chosen:
                return min(remaining, key=lambda u: (-v[idx[u]], u))

            def score(u):
                i = idx[u]
                row, linked = s[i], nbrs[i]
                pen = max((row[j] * (0.0 if policy == "gated_mmr" and j in linked else 1.0) for j in chosen),
                          default=0.0)
                return lam * v[i] - (1 - lam) * pen
            return min(remaining, key=lambda u: (-score(u), u))
        return nxt

    if policy in ("truncation_head", "truncation_tail"):
        order = {u: view.order[i] if view.order else (i,) for i, u in enumerate(view.uids)}
        sign = 1 if policy == "truncation_head" else -1

        def nxt(selected, remaining):
            return min(remaining, key=lambda u: (tuple(sign * x if isinstance(x, (int, float)) else x
                                                       for x in order[u]), u))
        return nxt

    raise ValueError(f"unknown sequential policy {policy!r}")


def select_unit_cost(policy: str, view: View, p: MessageParams, budget: int, *, seed: int = 0,
                     sample_id: str = "") -> list[str]:
    pass
    if policy in STATIC_POLICIES:
        scores, _ = static_scores(view, p, seed=seed, sample_id=sample_id)
        return rank(scores[policy], view.uids)[:budget]
    nxt = proposer(policy, view, p)
    selected, remaining = [], set(view.uids)
    while remaining and len(selected) < budget:
        u = nxt(selected, remaining)
        selected.append(u)
        remaining.discard(u)
    return selected


def diagnostics(view: View, p: MessageParams, scores: dict[str, torch.Tensor], f: Fields) -> list[dict]:
    pass
    ranks = {name: {u: k for k, u in enumerate(rank(sc, view.uids))} for name, sc in scores.items()}
    rows = []
    for i, u in enumerate(view.uids):
        nbr = [j for j in range(len(view.uids)) if bool(f.mask[i, j])]
        rows.append({
            "uid": u, "v": float(view.v[i]),
            "neighbors": [view.uids[j] for j in nbr],
            "weights": [round(float(f.w[i, j]), 12) for j in nbr],
            "gated": [bool(view.gate[i, j]) for j in nbr],
            "dependency_degree": int(view.gate[i].sum()),
            "M_gated": float(f.m_gated[i]), "M_ungated": float(f.m_ungated[i]), "support": float(f.support[i]),
            **{f"score_{n}": float(sc[i]) for n, sc in scores.items()},
            **{f"rank_{n}": ranks[n][u] for n in scores},
        })
    return rows



def reference_scores(uids, h, v, gate, p: MessageParams) -> dict[str, list[float]]:
    pass
    n = len(uids)

    def cos(a, b):
        na = math.sqrt(sum(x * x for x in a)) or 1e-12
        nb = math.sqrt(sum(x * x for x in b)) or 1e-12
        return max(0.0, sum(x * y for x, y in zip(a, b, strict=True)) / (na * nb))

    sim = [[0.0 if i == j else cos(h[i], h[j]) for j in range(n)] for i in range(n)]
    keff = min(p.k, max(0, n - 1))
    nb = [sorted((j for j in range(n) if j != i), key=lambda j: (-sim[i][j], uids[j]))[:keff] for i in range(n)]
    w = [[(p.beta * sim[i][j] ** p.gamma if (j in nb[i] and sim[i][j] > 0) else 0.0) for j in range(n)] for i in range(n)]
    mg = [sum(w[i][j] * (0 if gate[i][j] else 1) * v[j] for j in range(n)) for i in range(n)]
    mu = [sum(w[i][j] * v[j] for j in range(n)) for i in range(n)]
    sup = []
    for i in range(n):
        linked = [v[j] for j in range(n) if gate[i][j]]
        sup.append(sum(linked) / len(linked) if linked else 0.0)
    return {
        "relevance": list(v),
        "dn_ungated": [v[i] / (p.sigma + mu[i]) for i in range(n)],
        "appare": [v[i] / (p.sigma + mg[i]) for i in range(n)],
        "gated_subtraction": [max(0.0, v[i] - p.eta * mg[i]) for i in range(n)],
        "dependency_mean": [v[i] + p.alpha * sup[i] for i in range(n)],
        "dn_support": [(v[i] + p.alpha * sup[i]) / (p.sigma + mg[i]) for i in range(n)],
    }
