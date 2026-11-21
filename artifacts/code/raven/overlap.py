"""Cross-source equivalence groups, purge, splits and pilot-group roles (P3).

Order follows proposal §9.3: equivalence groups are built over every record first,
complete groups are then assigned to splits, and only then are roles assigned.

Code equivalence uses tree-sitter leaf tokens with identifiers, strings, numbers and
declaration keywords abstracted and comments/punctuation dropped, so ESLint-curated
JsVul bodies and raw package code compare on structure. Exact matches use the hash of
that token sequence; near duplicates use MinHash/LSH on token shingles, verified by the
exact Jaccard similarity.
"""

from __future__ import annotations

import hashlib
import zlib
from collections import defaultdict
from collections.abc import Iterable
from dataclasses import dataclass, field
from datetime import date
from typing import Any

import numpy as np



FUNCTION_NODES = {
    "function_declaration", "function_expression", "generator_function",
    "generator_function_declaration", "arrow_function", "method_definition",
}
_ABSTRACT = {
    "identifier": "ID", "property_identifier": "ID", "shorthand_property_identifier": "ID",
    "shorthand_property_identifier_pattern": "ID", "private_property_identifier": "ID",
    "type_identifier": "ID", "statement_identifier": "ID", "this": "ID",
    "string": "STR", "template_string": "STR", "string_fragment": "STR",
    "number": "NUM", "regex": "RE",
}
_DECL = {"var", "let", "const"}
_DROP = {";", ",", "(", ")", "comment", "html_comment"}

_SKIP_SUBTREE = {
    "type_annotation", "type_arguments", "type_parameters", "accessibility_modifier",
    "override_modifier", "optional_type", "asserts_annotation",
}

_KEEP_FIRST_CHILD = {"as_expression", "satisfies_expression", "non_null_expression"}


def _parsers() -> dict[str, Any]:
    import tree_sitter_javascript as tsjs
    import tree_sitter_typescript as tsts
    from tree_sitter import Language, Parser

    return {
        "js": Parser(Language(tsjs.language())),
        "ts": Parser(Language(tsts.language_typescript())),
        "tsx": Parser(Language(tsts.language_tsx())),
    }


_PARSERS: dict[str, Any] | None = None


def parser_for(extension: str) -> Any:
    global _PARSERS
    if _PARSERS is None:
        _PARSERS = _parsers()
    return _PARSERS["tsx" if extension == "tsx" else "ts" if extension in {"ts", "mts", "cts"} else "js"]


def node_tokens(node: Any) -> list[str]:
    out: list[str] = []
    stack = [node]
    while stack:
        current = stack.pop()
        kind = current.type
        if kind in _DROP or kind in _SKIP_SUBTREE:
            continue
        if kind in _KEEP_FIRST_CHILD and current.child_count:
            stack.append(current.children[0])
            continue
        if kind in _ABSTRACT:
            out.append(_ABSTRACT[kind])
            continue
        if current.child_count == 0:
            out.append("DECL" if kind in _DECL else kind)
            continue
        stack.extend(reversed(current.children))
    return out


def code_tokens(source: bytes, extension: str) -> list[str]:
    return node_tokens(parser_for(extension).parse(source).root_node)


def snippet_tokens(source: bytes, extension: str) -> tuple[list[str], str]:
    pass






    parser = parser_for(extension)
    tree = parser.parse(source)
    if not tree.root_node.has_error:
        return node_tokens(tree.root_node), "plain"
    wrapped = b"class __RavenWrap__ {\n" + source + b"\n}"
    wrapped_tree = parser.parse(wrapped)
    if not wrapped_tree.root_node.has_error:
        methods = list(functions_in(wrapped, extension, 1))
        if len(methods) >= 1:
            
            first = min(methods, key=lambda m: (m[0], -m[1]))
            return first[2], "class_wrapped"
    return node_tokens(tree.root_node), "plain_with_errors"


def functions_in(source: bytes, extension: str, min_tokens: int) -> Iterable[tuple[int, int, list[str]]]:
    pass
    tree = parser_for(extension).parse(source)
    stack = [tree.root_node]
    while stack:
        node = stack.pop()
        if node.type in FUNCTION_NODES:
            tokens = node_tokens(node)
            if len(tokens) >= min_tokens:
                yield node.start_point[0] + 1, node.end_point[0] + 1, tokens
        stack.extend(node.children)


def token_hash(tokens: list[str]) -> str:
    return hashlib.sha256(" ".join(tokens).encode()).hexdigest()


def shingles(tokens: list[str], k: int) -> np.ndarray:
    grams = {" ".join(tokens[i:i + k]) for i in range(max(1, len(tokens) - k + 1))}
    return np.fromiter((zlib.crc32(g.encode()) for g in grams), dtype=np.uint64, count=len(grams))


@dataclass
class MinHasher:
    permutations: int
    bands: int
    seed: int
    _a: np.ndarray = field(init=False, repr=False)
    _b: np.ndarray = field(init=False, repr=False)

    PRIME = np.uint64((1 << 61) - 1)

    def __post_init__(self) -> None:
        if self.permutations % self.bands:
            raise ValueError("permutations must be a multiple of bands")
        rng = np.random.default_rng(self.seed)
        self._a = rng.integers(1, (1 << 31) - 1, self.permutations, dtype=np.uint64)
        self._b = rng.integers(0, (1 << 31) - 1, self.permutations, dtype=np.uint64)

    def signature(self, shingle_hashes: np.ndarray) -> np.ndarray:
        values = (np.outer(shingle_hashes, self._a) + self._b) % self.PRIME
        return values.min(axis=0)

    def band_keys(self, signature: np.ndarray) -> list[bytes]:
        rows = self.permutations // self.bands
        return [bytes([i]) + signature[i * rows:(i + 1) * rows].tobytes() for i in range(self.bands)]


def jaccard(a: np.ndarray, b: np.ndarray) -> float:
    if not len(a) and not len(b):
        return 1.0
    inter = len(np.intersect1d(a, b, assume_unique=True))
    return inter / (len(a) + len(b) - inter)


class NearDuplicateIndex:
    pass

    def __init__(self, hasher: MinHasher, threshold: float) -> None:
        self.hasher = hasher
        self.threshold = threshold
        self.buckets: dict[bytes, list[str]] = defaultdict(list)
        self.sets: dict[str, np.ndarray] = {}

    def add(self, item: str, shingle_hashes: np.ndarray) -> None:
        self.sets[item] = np.unique(shingle_hashes)
        for key in self.hasher.band_keys(self.hasher.signature(shingle_hashes)):
            self.buckets[key].append(item)

    def query(self, shingle_hashes: np.ndarray, exclude: str = "") -> list[tuple[str, float]]:
        candidates: set[str] = set()
        for key in self.hasher.band_keys(self.hasher.signature(shingle_hashes)):
            candidates.update(self.buckets.get(key, ()))
        candidates.discard(exclude)
        own = np.unique(shingle_hashes)
        found = []
        for item in sorted(candidates):
            score = jaccard(own, self.sets[item])
            if score >= self.threshold:
                found.append((item, round(score, 4)))
        return found





class UnionFind:
    def __init__(self) -> None:
        self.parent: dict[str, str] = {}

    def add(self, item: str) -> None:
        self.parent.setdefault(item, item)

    def find(self, item: str) -> str:
        self.add(item)
        root = item
        while self.parent[root] != root:
            root = self.parent[root]
        while self.parent[item] != root:
            self.parent[item], item = root, self.parent[item]
        return root

    def union(self, a: str, b: str) -> None:
        ra, rb = self.find(a), self.find(b)
        if ra != rb:
            if rb < ra:
                ra, rb = rb, ra
            self.parent[rb] = ra

    def groups(self) -> dict[str, list[str]]:
        out: dict[str, list[str]] = defaultdict(list)
        for item in self.parent:
            out[self.find(item)].append(item)
        return {root: sorted(members) for root, members in out.items()}


def build_groups(record_keys: dict[str, set[str]], edges: Iterable[tuple[str, str]]) -> dict[str, str]:
    pass
    uf = UnionFind()
    owner: dict[str, str] = {}
    for node, keys in record_keys.items():
        uf.add(node)
        for key in keys:
            if key in owner:
                uf.union(node, owner[key])
            else:
                owner[key] = node
    for a, b in edges:
        uf.union(a, b)
    mapping = {}
    for members in uf.groups().values():
        gid = "g" + hashlib.sha256(members[0].encode()).hexdigest()[:16]
        for member in members:
            mapping[member] = gid
    return mapping





def temporal_cutoffs(dates: list[str], fractions: dict[str, float]) -> list[str]:
    pass
    ordered = sorted(d for d in dates if d)
    cutoffs, acc = [], 0.0
    for name in list(fractions)[:-1]:
        acc += fractions[name]
        cutoffs.append(ordered[min(len(ordered) - 1, int(acc * len(ordered)))])
    return cutoffs


def strict_temporal_split(
    groups: dict[str, list[dict[str, Any]]], fractions: dict[str, float]
) -> tuple[dict[str, str], list[str]]:
    pass






    names = list(fractions)
    cutoffs = temporal_cutoffs([r.get("publish_date", "") for rows in groups.values() for r in rows], fractions)

    def window(day: str) -> int:
        return sum(day >= c for c in cutoffs)

    assignment = {}
    for gid, rows in groups.items():
        windows = {window(r["publish_date"]) for r in rows if r.get("publish_date")}
        assignment[gid] = names[windows.pop()] if len(windows) == 1 else "quarantine"
    return assignment, cutoffs


def hash_fraction(seed: int, namespace: str, item: str) -> float:
    digest = hashlib.sha256(f"{seed}\0{namespace}\0{item}".encode()).digest()
    return int.from_bytes(digest[:8], "big") / 2**64


def compositional_split(
    combos: Iterable[tuple[str, str]], seed: int, held_out_fraction: float, val_fraction: float
) -> dict[tuple[str, str], str]:
    pass
    out = {}
    for combo in sorted(set(combos)):
        u = hash_fraction(seed, "sard_php_combo", f"{combo[0]}|{combo[1]}")
        if u < held_out_fraction:
            out[combo] = "test"
        elif u < held_out_fraction + val_fraction:
            out[combo] = "val"
        else:
            out[combo] = "train"
    return out


def parse_date(value: str) -> date | None:
    try:
        return date.fromisoformat(value) if value else None
    except ValueError:
        return None
