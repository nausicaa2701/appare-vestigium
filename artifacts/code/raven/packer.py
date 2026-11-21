"""Serialisation ``raven-pack-v1`` (docs/unit-spec.md §7).

Units are grouped by file; the target file comes first, then other files in path order;
within a file, spans are merged and kept in source order. Each file starts with
``// file: <path>``; non-adjacent spans are separated by a line ``// ...``. Spans whose gap
is whitespace only are adjacent (the gap is kept verbatim). Text inside spans is not changed
(SARD label markers are already blanked before parsing, unit-spec S0).
"""

from __future__ import annotations

from collections.abc import Iterable

Range = tuple[int, int]
GAP = "// ..."


def merge_adjacent(text: bytes, ranges: Iterable[Range]) -> list[Range]:
    pass
    out: list[list[int]] = []
    for start, end in sorted(ranges):
        if start >= end:
            continue
        if out and (start <= out[-1][1] or not text[out[-1][1]:start].strip()):
            out[-1][1] = max(out[-1][1], end)
        else:
            out.append([start, end])
    return [(a, b) for a, b in out]


def serialise(files: dict[str, tuple[bytes, Iterable[Range]]], target_file: str, labels: dict[str, str] | None = None) -> str:
    pass

    labels = labels or {}
    order = [target_file] + sorted(p for p in files if p != target_file)
    blocks = []
    for path in order:
        if path not in files:
            continue
        text, ranges = files[path]
        spans = merge_adjacent(text, ranges)
        if not spans:
            continue
        body = f"\n{GAP}\n".join(text[a:b].decode("utf-8") for a, b in spans)
        blocks.append(f"// file: {labels.get(path, path)}\n{body}")
    return "\n".join(blocks) + "\n" if blocks else ""


def numbered(text: bytes, ranges: Iterable[Range]) -> list[tuple[int, str]]:
    pass
    lines = text.split(b"\n")
    starts = [0]
    for line in lines[:-1]:
        starts.append(starts[-1] + len(line) + 1)
    import bisect

    keep: set[int] = set()
    for a, b in merge_adjacent(text, ranges):
        first = bisect.bisect_right(starts, a) - 1
        last = bisect.bisect_right(starts, b - 1) - 1
        keep.update(range(first, last + 1))
    return [(i + 1, lines[i].decode("utf-8")) for i in sorted(keep)]



def serialise_with_map(files: dict[str, tuple[bytes, Iterable[Range]]], target_file: str,
                       labels: dict[str, str] | None = None) -> tuple[str, list[dict]]:
    pass

    labels = labels or {}
    order = [target_file] + sorted(p for p in files if p != target_file)
    parts: list[str] = []
    segments: list[dict] = []
    pos = 0
    first_block = True
    for path in order:
        if path not in files:
            continue
        text, ranges = files[path]
        spans = merge_adjacent(text, ranges)
        if not spans:
            continue
        header = ("" if first_block else "\n") + f"// file: {labels.get(path, path)}\n"
        first_block = False
        parts.append(header)
        pos += len(header)
        for i, (a, b) in enumerate(spans):
            if i:
                sep = f"\n{GAP}\n"
                parts.append(sep)
                pos += len(sep)
            chunk = text[a:b].decode("utf-8")
            segments.append({"file": path, "src": (a, b), "out": (pos, pos + len(chunk))})
            parts.append(chunk)
            pos += len(chunk)
    if not parts:
        return "", []
    parts.append("\n")
    return "".join(parts), segments



import itertools
from dataclasses import dataclass, field


def _merge(ranges: Iterable[Range]) -> list[Range]:
    out: list[list[int]] = []
    for a, b in sorted((a, b) for a, b in ranges):
        if a >= b:
            continue
        if out and a <= out[-1][1]:
            out[-1][1] = max(out[-1][1], b)
        else:
            out.append([a, b])
    return [(a, b) for a, b in out]


def _subtract(ranges: Iterable[Range], holes: Iterable[Range]) -> list[Range]:
    out = []
    holes = _merge(holes)
    for a, b in _merge(ranges):
        cur = a
        for x, y in holes:
            if y <= cur or x >= b:
                continue
            if x > cur:
                out.append((cur, x))
            cur = max(cur, y)
        if cur < b:
            out.append((cur, b))
    return out


@dataclass(frozen=True)
class Candidate:
    pass


    uid: str
    file: str
    ranges: tuple[Range, ...]
    closure: tuple[Range, ...] = ()
    score: float = 0.0
    order: tuple = ()

    @property
    def span_set(self) -> list[Range]:
        return list(self.ranges) + list(self.closure)


@dataclass
class PackResult:
    budget: int
    target_fits_budget: bool
    mandatory_tokens: int
    tokens: int
    text: str
    strategy: str  
    selected: list[str] = field(default_factory=list)  
    files: dict[str, list[Range]] = field(default_factory=dict)
    rejected: dict[str, str] = field(default_factory=dict)  
    greedy_score: float = 0.0
    best_single_uid: str = ""
    best_single_score: float = 0.0
    retokenized: int = 0
    estimate_skips: int = 0

    @property
    def unused_budget(self) -> int:
        return self.budget - self.tokens if self.target_fits_budget else 0


def rank_candidates(candidates: Iterable[Candidate], estimates: dict[str, int]) -> list[Candidate]:
    pass
    return sorted(candidates, key=lambda c: (-(c.score / max(1, estimates.get(c.uid, 1))), -c.score, c.order, c.uid))


def pack(texts: dict[str, bytes], target_file: str, mandatory: dict[str, list[Range]],
         candidates: Iterable[Candidate], budget: int, count, *, labels: dict[str, str] | None = None,
         prompt: str = "", estimates: dict[str, int] | None = None, slack: int = 32) -> PackResult:
    pass








    estimates = dict(estimates or {})
    base = {f: _merge(r) for f, r in mandatory.items()}

    def render(files: dict[str, list[Range]]) -> tuple[int, str]:
        text = prompt + serialise({f: (texts[f], r) for f, r in files.items()}, target_file, labels)
        return count(text), text

    t0, text0 = render(base)
    if t0 > budget:
        return PackResult(budget, False, t0, t0, "", "infeasible")
    cands = list(candidates)
    rejected: dict[str, str] = {}
    useful = []
    for c in cands:
        new = _subtract(c.span_set, base.get(c.file, []))
        if not any(texts[c.file][a:b].strip() for a, b in new):
            rejected[c.uid] = "inside_mandatory"
        else:
            useful.append(c)
    ranked = rank_candidates(useful, estimates)
    files = {f: list(r) for f, r in base.items()}
    tokens, text, selected, retok, skips = t0, text0, [], 1, 0
    for c in ranked:
        residual = budget - tokens
        if c.uid in estimates and estimates[c.uid] > residual + slack:
            rejected[c.uid] = "estimated_over_budget"
            skips += 1
            continue
        trial = {f: list(r) for f, r in files.items()}
        trial[c.file] = _merge(trial.get(c.file, []) + c.span_set)
        n, t = render(trial)
        retok += 1
        if n <= budget:
            files, tokens, text = trial, n, t
            selected.append(c.uid)
        else:
            rejected[c.uid] = "did_not_fit"
    by_uid = {c.uid: c for c in useful}
    greedy_score = sum(by_uid[u].score for u in selected)
    
    best_uid, best_score, best = "", 0.0, None
    for c in sorted(useful, key=lambda c: (-c.score, c.order, c.uid)):
        if c.score <= greedy_score:
            break
        if c.uid in estimates and estimates[c.uid] > budget - t0 + slack:
            continue
        trial = {f: list(r) for f, r in base.items()}
        trial[c.file] = _merge(trial.get(c.file, []) + c.span_set)
        n, t = render(trial)
        retok += 1
        if n <= budget:
            best_uid, best_score, best = c.uid, c.score, (trial, n, t)
            break
    if best is not None and best_score > greedy_score:
        for u in selected:
            rejected[u] = "replaced_by_best_single"
        rejected.pop(best_uid, None)
        files, tokens, text = best
        return PackResult(budget, True, t0, tokens, text, "best_single", [best_uid], files, rejected,
                          greedy_score, best_uid, best_score, retok, skips)
    return PackResult(budget, True, t0, tokens, text, "greedy" if selected else "target_only", selected, files,
                      rejected, greedy_score, best_uid, best_score, retok, skips)


def optional_candidates(texts: dict[str, bytes], mandatory: dict[str, list[Range]],
                        candidates: Iterable[Candidate]) -> tuple[list[Candidate], dict[str, str]]:
    pass

    base = {f: _merge(r) for f, r in mandatory.items()}
    useful, rejected = [], {}
    for c in candidates:
        new = _subtract(c.span_set, base.get(c.file, []))
        if not any(texts[c.file][a:b].strip() for a, b in new):
            rejected[c.uid] = "inside_mandatory"
        else:
            useful.append(c)
    return useful, rejected


def pack_density_v2(texts: dict[str, bytes], target_file: str, mandatory: dict[str, list[Range]],
                    candidates: Iterable[Candidate], budget: int, count, *, labels=None, prompt: str = "",
                    estimates=None, slack: int = 32, serializer=None) -> PackResult:
    pass





    base = {f: _merge(r) for f, r in mandatory.items()}
    retok = 0

    def render(files):
        nonlocal retok
        retok += 1
        text = prompt + (serializer or serialise)({f: (texts[f], spans) for f, spans in files.items()}, target_file, labels)
        return count(text), text

    t0, text0 = render(base)
    if t0 > budget:
        return PackResult(budget, False, t0, t0, "", "infeasible")
    useful, rejected = optional_candidates(texts, mandatory, candidates)
    remaining = {c.uid: c for c in useful}
    files, tokens, text, selected = dict(base), t0, text0, []
    best = None
    while remaining:
        feasible = []
        for uid, c in sorted(remaining.items()):
            trial = {f: list(spans) for f, spans in files.items()}
            trial[c.file] = _merge(trial.get(c.file, []) + c.span_set)
            n, rendered = render(trial)
            if n <= budget:
                feasible.append((-(c.score / max(1, n - tokens)), -c.score, uid, trial, n, rendered))
                if not selected and (best is None or (-c.score, uid) < best[:2]):
                    best = (-c.score, uid, trial, n, rendered)
        if not feasible:
            break
        _, _, uid, files, tokens, text = min(feasible, key=lambda row: row[:3])
        selected.append(uid)
        del remaining[uid]
    for uid in remaining:
        rejected[uid] = "did_not_fit"
    scores = {c.uid: c.score for c in useful}
    greedy_score = sum(scores[u] for u in selected)
    best_uid, best_score = (best[1], -best[0]) if best else ("", 0.0)
    if best and best_score > greedy_score:
        rejected.update({u: "replaced_by_best_single" for u in selected})
        rejected.pop(best_uid, None)
        _, _, files, tokens, text = best
        return PackResult(budget, True, t0, tokens, text, "best_single", [best_uid], files, rejected,
                          greedy_score, best_uid, best_score, retok)
    return PackResult(budget, True, t0, tokens, text, "greedy" if selected else "target_only", selected,
                      files, rejected, greedy_score, best_uid, best_score, retok)


def for_version(version: str):
    pass
    if version == "density-v2":
        return pack_density_v2
    if version == "legacy-v1":
        return pack
    raise ValueError(f"unknown packer version: {version}")


def pack_sequential(texts: dict[str, bytes], target_file: str, mandatory: dict[str, list[Range]],
                    candidates: Iterable[Candidate], budget: int, count, propose, *,
                    labels: dict[str, str] | None = None, prompt: str = "", serializer=None) -> PackResult:
    pass







    base = {f: _merge(r) for f, r in mandatory.items()}

    def render(files: dict[str, list[Range]]) -> tuple[int, str]:
        text = prompt + (serializer or serialise)({f: (texts[f], r) for f, r in files.items()}, target_file, labels)
        return count(text), text

    t0, text0 = render(base)
    if t0 > budget:
        return PackResult(budget, False, t0, t0, "", "infeasible")
    useful, rejected = optional_candidates(texts, mandatory, candidates)
    by_uid = {c.uid: c for c in useful}
    remaining = set(by_uid)
    files = {f: list(r) for f, r in base.items()}
    tokens, text, selected, retok = t0, text0, [], 1
    while remaining:
        uid = propose(list(selected), set(remaining))
        if uid not in remaining:
            raise ValueError(f"proposer returned {uid!r}, not a remaining candidate")
        remaining.discard(uid)
        c = by_uid[uid]
        trial = {f: list(r) for f, r in files.items()}
        trial[c.file] = _merge(trial.get(c.file, []) + c.span_set)
        n, t = render(trial)
        retok += 1
        if n <= budget:
            files, tokens, text = trial, n, t
            selected.append(uid)
        else:
            rejected[uid] = "did_not_fit"
    greedy_score = sum(by_uid[u].score for u in selected)
    best_uid, best_score, best = "", 0.0, None
    for c in sorted(useful, key=lambda c: (-c.score, c.order, c.uid)):
        if c.score <= greedy_score:
            break
        trial = {f: list(r) for f, r in base.items()}
        trial[c.file] = _merge(trial.get(c.file, []) + c.span_set)
        n, t = render(trial)
        retok += 1
        if n <= budget:
            best_uid, best_score, best = c.uid, c.score, (trial, n, t)
            break
    if best is not None and best_score > greedy_score:
        for u in selected:
            rejected[u] = "replaced_by_best_single"
        rejected.pop(best_uid, None)
        files, tokens, text = best
        return PackResult(budget, True, t0, tokens, text, "best_single", [best_uid], files, rejected,
                          greedy_score, best_uid, best_score, retok, 0)
    return PackResult(budget, True, t0, tokens, text, "greedy" if selected else "target_only", selected, files,
                      rejected, greedy_score, best_uid, best_score, retok, 0)


ORIGIN_ORDER = ("target", "target_closure", "direct", "closure_added")


def provenance(texts: dict[str, bytes], target_file: str, result: PackResult, target: dict[str, list[Range]],
               target_closure: dict[str, list[Range]], candidates: dict[str, Candidate],
               labels: dict[str, str] | None = None, prompt: str = "") -> list[dict]:
    pass


    if not result.target_fits_budget:
        return []
    origins: dict[str, dict[str, list[Range]]] = {o: {} for o in ORIGIN_ORDER}
    for f, r in target.items():
        origins["target"][f] = _merge(r)
    for f, r in target_closure.items():
        origins["target_closure"][f] = _merge(r)
    for uid in result.selected:
        c = candidates[uid]
        origins["direct"].setdefault(c.file, []).extend(c.ranges)
        origins["closure_added"].setdefault(c.file, []).extend(c.closure)
    text, segments = serialise_with_map({f: (texts[f], r) for f, r in result.files.items()}, target_file, labels)
    if prompt + text != result.text:
        raise AssertionError("provenance: re-serialisation differs from the packed text")
    off = len(prompt)
    pieces = []
    for seg in segments:
        f, (a, b), (oa, _) = seg["file"], seg["src"], seg["out"]
        data = texts[f]
        cuts = {a, b}
        for o in ORIGIN_ORDER:
            for x, y in origins[o].get(f, []):
                if a < x < b:
                    cuts.add(x)
                if a < y < b:
                    cuts.add(y)
        bounds = sorted(cuts)
        runs: list[list] = []
        for x, y in itertools.pairwise(bounds):
            lab = "gap_whitespace"
            for o in ORIGIN_ORDER:
                if any(p <= x < q for p, q in origins[o].get(f, [])):
                    lab = o
                    break
            if runs and runs[-1][2] == lab:
                runs[-1][1] = y
            else:
                runs.append([x, y, lab])
        for x, y, lab in runs:
            ca = oa + len(data[a:x].decode("utf-8", "replace"))
            cb = oa + len(data[a:y].decode("utf-8", "replace"))
            pieces.append({"file": f, "src": [x, y], "out": [off + ca, off + cb], "origin": lab})
    return pieces
