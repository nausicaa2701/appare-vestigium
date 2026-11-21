"""Unit extraction for P5 (docs/unit-spec.md §1-§4, §6).

Tree-sitter supplies syntax and byte spans only. Every rule implemented here is named by
its spec ID (U*, N*, C*) so the tests in ``artifacts/tests/test_p5.py`` can refer to it.
Closure (C1/C2) is syntactic and never uses labels, patches or the analysis graph.
"""

from __future__ import annotations

import bisect
import itertools
import re
from collections.abc import Iterable
from dataclasses import dataclass, field
from functools import cache

Range = tuple[int, int]

GRAMMAR_BY_EXT = {
    ".js": "javascript", ".mjs": "javascript", ".cjs": "javascript", ".jsx": "javascript",
    ".ts": "typescript", ".mts": "typescript", ".cts": "typescript", ".tsx": "tsx",
    ".php": "php",
}
FAMILY = {"javascript": "js", "typescript": "js", "tsx": "js", "php": "php"}
DECLARATION_SUFFIXES = (".d.ts", ".d.mts", ".d.cts")

JS_FUNC_EXPR = {"function_expression", "function", "arrow_function", "generator_function"}
JS_FUNC_DECL = {"function_declaration", "generator_function_declaration"}
JS_CLASS_DECL = {"class_declaration", "abstract_class_declaration"}
PHP_FUNC_EXPR = {"anonymous_function", "anonymous_function_creation_expression", "arrow_function"}
PHP_CLASS_DECL = {"class_declaration", "trait_declaration", "interface_declaration", "enum_declaration"}
PHP_INCLUDE = {"require_expression", "require_once_expression", "include_expression", "include_once_expression"}
CONTROL = {
    "js": {"if_statement", "for_statement", "for_in_statement", "while_statement", "do_statement",
           "try_statement"},
    "php": {"if_statement", "for_statement", "foreach_statement", "while_statement", "do_statement",
            "try_statement", "namespace_definition"},
}
BLOCKS = {"statement_block", "compound_statement"}
CLAUSES = {"else_clause", "catch_clause", "finally_clause", "if_statement", "else_if_clause"}
PHP_SKIP = {"php_tag", "text_interpolation", "text", "php_end_tag"}


def grammar_for(path: str) -> str | None:
    pass
    lower = path.lower()
    if lower.endswith(DECLARATION_SUFFIXES):
        return None
    dot = lower.rfind(".")
    return GRAMMAR_BY_EXT.get(lower[dot:]) if dot >= 0 else None


@cache
def _parser(grammar: str):
    import tree_sitter as ts

    if grammar == "javascript":
        import tree_sitter_javascript as mod
        lang = mod.language()
    elif grammar in ("typescript", "tsx"):
        import tree_sitter_typescript as mod
        lang = mod.language_typescript() if grammar == "typescript" else mod.language_tsx()
    elif grammar == "php":
        import tree_sitter_php as mod
        lang = mod.language_php()
    else:
        raise ValueError(f"no grammar {grammar!r}")
    return ts.Parser(ts.Language(lang))


@dataclass
class Unit:
    kind: str
    ranges: list[Range]
    name: str = ""
    parent_class: str = ""
    closure: list[Range] = field(default_factory=list)
    core: Range | None = None  

    @property
    def start(self) -> int:
        return self.ranges[0][0]

    @property
    def end(self) -> int:
        return self.ranges[-1][1]


@dataclass
class FileUnits:
    status: str  
    grammar: str
    text: bytes
    units: list[Unit] = field(default_factory=list)
    error: dict = field(default_factory=dict)
    notes: dict = field(default_factory=dict)
    _line_starts: list[int] | None = None

    @property
    def line_starts(self) -> list[int]:
        if self._line_starts is None:
            starts = [0]
            starts += [i + 1 for i, b in enumerate(self.text) if b == 10]
            self._line_starts = starts
        return self._line_starts

    def position(self, byte: int) -> tuple[int, int]:
        pass
        line = bisect.bisect_right(self.line_starts, byte) - 1
        return line + 1, byte - self.line_starts[line] + 1


def subtract(ranges: Iterable[Range], holes: Iterable[Range]) -> list[Range]:
    pass
    holes = sorted(holes)
    out = []
    for start, end in ranges:
        cur = start
        for h0, h1 in holes:
            if h1 <= cur or h0 >= end:
                continue
            if h0 > cur:
                out.append((cur, h0))
            cur = max(cur, h1)
        if cur < end:
            out.append((cur, end))
    return out


def merge(ranges: Iterable[Range]) -> list[Range]:
    out: list[list[int]] = []
    for start, end in sorted(ranges):
        if out and start <= out[-1][1]:
            out[-1][1] = max(out[-1][1], end)
        else:
            out.append([start, end])
    return [(a, b) for a, b in out]


def _strip(node):
    while node is not None and node.type == "parenthesized_expression" and node.named_child_count == 1:
        node = node.named_child(0)
    return node


def _parse_errors(root, text: bytes) -> dict:
    pass
    first, count, spans = None, 0, []
    stack = [root]
    while stack:
        node = stack.pop()
        if node.is_error or node.is_missing:
            count += 1
            if first is None or node.start_byte < first.start_byte:
                first = node
            if node.is_error:
                spans.append((node.start_byte, node.end_byte))
        if node.has_error:
            stack.extend(reversed(node.children))
    error_bytes = sum(b - a for a, b in merge(spans))
    position = ""
    if first is not None:
        line_start = text.rfind(b"\n", 0, first.start_byte) + 1
        position = f"{text.count(b'\n', 0, first.start_byte) + 1}:{first.start_byte - line_start + 1}"
    return {"first_error": position, "error_nodes": count,
            "error_byte_share": round(error_bytes / len(text), 6) if text else 0.0}


class _Extractor:
    def __init__(self, text: bytes, grammar: str, module_wrapper_min_line_share: float):
        self.text = text
        self.grammar = grammar
        self.family = FAMILY[grammar]
        self.min_share = module_wrapper_min_line_share
        self.units: list[Unit] = []
        self.notes = {"module_wrapper": 0, "control_descent": 0}
        self.line_starts = [0] + [i + 1 for i, b in enumerate(text) if b == 10]

    
    def src(self, node) -> str:
        return self.text[node.start_byte:node.end_byte].decode("utf-8", "replace")

    def is_func_expr(self, node) -> bool:
        node = _strip(node)
        return node is not None and node.type in (JS_FUNC_EXPR if self.family == "js" else PHP_FUNC_EXPR)

    def is_class_expr(self, node) -> bool:
        node = _strip(node)
        return node is not None and node.type == "class"

    def is_object(self, node) -> bool:
        node = _strip(node)
        return node is not None and node.type == "object"

    def row(self, byte: int) -> int:
        pass

        return bisect.bisect_right(self.line_starts, byte) - 1

    def _lead(self, siblings: list, i: int) -> int:
        pass
        node = siblings[i]
        start, row = node.start_byte, self.row(node.start_byte)
        j = i - 1
        while j >= 0 and siblings[j].type == "comment" and self.row(siblings[j].end_byte - 1) == row - 1:
            prev = siblings[j - 1] if j > 0 else None
            if prev is not None and prev.type != "comment" and \
                    self.row(prev.end_byte - 1) == self.row(siblings[j].start_byte):
                break  
            start, row = siblings[j].start_byte, self.row(siblings[j].start_byte)
            j -= 1
        return start

    def emit(self, unit: Unit) -> Unit:
        unit.ranges = [r for r in unit.ranges if self.text[r[0]:r[1]].strip()]
        if unit.ranges:
            self.units.append(unit)
        return unit

    
    def bound_value(self, stmt):
        pass
        t = stmt.type
        if self.family == "php":
            if t == "function_definition":
                return "function", self.src(stmt.child_by_field_name("name")), stmt
            if t in PHP_CLASS_DECL:
                name = stmt.child_by_field_name("name")
                return "class", self.src(name) if name else "", stmt
            if t == "expression_statement" and stmt.named_child_count:
                expr = _strip(stmt.named_child(0))
                if expr.type == "assignment_expression" and self.is_func_expr(expr.child_by_field_name("right")):
                    return "function", self.src(expr.child_by_field_name("left")), _strip(expr.child_by_field_name("right"))
            return None, "", None
        if t == "export_statement":
            inner = stmt.child_by_field_name("declaration") or stmt.child_by_field_name("value")
            if inner is None:
                return None, "", None
            if inner.type in JS_FUNC_DECL | JS_CLASS_DECL | {"lexical_declaration", "variable_declaration"}:
                return self.bound_value(inner)
            inner = _strip(inner)
            if self.is_func_expr(inner):
                return "function", "default", inner
            if self.is_class_expr(inner):
                name = inner.child_by_field_name("name")
                return "class", self.src(name) if name else "default", inner
            if self.is_object(inner):
                return "object", "default", inner
            return None, "", None
        if t in JS_FUNC_DECL:
            return "function", self.src(stmt.child_by_field_name("name")), stmt
        if t in JS_CLASS_DECL:
            name = stmt.child_by_field_name("name")
            return "class", self.src(name) if name else "", stmt
        if t in ("lexical_declaration", "variable_declaration"):
            decls = [c for c in stmt.named_children if c.type == "variable_declarator"]
            pairs = [(self.src(d.child_by_field_name("name")), _strip(d.child_by_field_name("value"))) for d in decls]
            if len(pairs) == 1 and pairs[0][1] is not None:
                name, value = pairs[0]
                if self.is_func_expr(value):
                    return "function", name, value
                if self.is_class_expr(value):
                    return "class", name, value
                if self.is_object(value):
                    return "object", name, value
            funcs = [(n, v) for n, v in pairs if v is not None and self.is_func_expr(v)]
            if funcs:
                return "function", ",".join(n for n, _ in funcs), funcs[0][1]
            return None, "", None
        if t == "expression_statement" and stmt.named_child_count:
            expr = _strip(stmt.named_child(0))
            if expr.type == "assignment_expression":
                right = _strip(expr.child_by_field_name("right"))
                name = self.src(expr.child_by_field_name("left"))
                if self.is_func_expr(right):
                    return "function", name, right
                if self.is_class_expr(right):
                    return "class", name, right
                if self.is_object(right):
                    return "object", name, right
        return None, "", None

    def is_import(self, stmt) -> bool:
        pass
        t = stmt.type
        if self.family == "php":
            if t == "namespace_use_declaration":
                return True
            return t == "expression_statement" and stmt.named_child_count > 0 and \
                _strip(stmt.named_child(0)).type in PHP_INCLUDE
        if t == "import_statement":
            return True
        if t in ("lexical_declaration", "variable_declaration"):
            decls = [c for c in stmt.named_children if c.type == "variable_declarator"]
            return bool(decls) and all(self._is_require(d.child_by_field_name("value")) for d in decls)
        if t == "expression_statement" and stmt.named_child_count:
            return self._is_require(stmt.named_child(0))
        return False

    def _is_require(self, node) -> bool:
        node = _strip(node)
        if node is not None and node.type == "await_expression" and node.named_child_count:
            node = _strip(node.named_child(0))
        if node is None or node.type != "call_expression":
            return False
        callee = node.child_by_field_name("function")
        return callee is not None and (callee.type == "import" or (callee.type == "identifier" and self.src(callee) == "require"))

    def has_function(self, node) -> bool:
        pass
        for block in self.blocks(node):
            for stmt in block.named_children:
                if self.bound_value(stmt)[0] in ("function", "class"):
                    return True
                if stmt.type in CONTROL[self.family] and self.has_function(stmt):
                    return True
        return False

    def blocks(self, node) -> list:
        pass
        out, stack = [], list(reversed(node.named_children))
        while stack:
            child = stack.pop()
            if child.type in BLOCKS:
                out.append(child)
            elif child.type in CLAUSES:
                stack.extend(reversed(child.named_children))
        return out

    
    def statements(self, nodes: list, ctrl: list[Range]) -> None:
        pass
        nodes = [n for n in nodes if not (self.family == "php" and n.type in PHP_SKIP)]
        i = 0
        while i < len(nodes):
            node = nodes[i]
            if node.type == "comment":
                i += 1
                continue
            lead = self._lead(nodes, i)
            if self.is_import(node):
                j, last = i, i
                while j + 1 < len(nodes) and (nodes[j + 1].type == "comment" or self.is_import(nodes[j + 1])):
                    j += 1
                    if nodes[j].type != "comment":
                        last = j
                self.emit(Unit("imports", [(lead, nodes[last].end_byte)], closure=list(ctrl),
                               core=(node.start_byte, nodes[last].end_byte)))
                i = last + 1
                continue
            self.statement(node, lead, ctrl)
            i += 1

    def statement(self, node, lead: int, ctrl: list[Range]) -> None:
        kind, name, value = self.bound_value(node)
        if kind == "function":
            self.emit(Unit("function", [(lead, node.end_byte)], name=name, core=(value.start_byte, value.end_byte)))
        elif kind == "class":
            self.klass(node, lead, value, name)
        elif kind == "object" and self.object_split(node, lead, value, name, ctrl):
            pass
        elif node.type in CONTROL[self.family] and (node.type == "namespace_definition" or self.has_function(node)):
            self.control(node, lead, ctrl)
        else:
            self.emit(Unit("top_level", [(lead, node.end_byte)], closure=list(ctrl),
                           core=(node.start_byte, node.end_byte)))

    def klass(self, outer, lead: int, cls, name: str) -> None:
        pass
        body = cls.child_by_field_name("body")
        if body is None:
            self.emit(Unit("class_shell", [(lead, outer.end_byte)], name=name, core=(cls.start_byte, cls.end_byte)))
            return
        header = [(outer.start_byte, body.start_byte + 1), (body.end_byte - 1, body.end_byte)]
        members = list(body.named_children)
        holes = []
        for i, member in enumerate(members):
            fn = None
            if member.type in ("method_definition", "method_declaration"):
                fn = member
            elif member.type in ("field_definition", "public_field_definition"):
                value = member.child_by_field_name("value")
                if value is not None and self.is_func_expr(value):
                    fn = member
            if fn is None:
                continue
            mname = member.child_by_field_name("name") or member.child_by_field_name("property")
            unit = self.emit(Unit("method", [(self._lead(members, i), member.end_byte)],
                                  name=self.src(mname) if mname else "", parent_class=name,
                                  closure=list(header), core=(member.start_byte, member.end_byte)))
            holes += unit.ranges
        self.emit(Unit("class_shell", subtract([(lead, outer.end_byte)], holes), name=name,
                       core=(cls.start_byte, cls.end_byte)))

    def object_split(self, stmt, lead: int, obj, name: str, ctrl: list[Range]) -> bool:
        pass
        props = list(obj.named_children)
        holes = []
        for i, prop in enumerate(props):
            if prop.type == "method_definition":
                key = prop.child_by_field_name("name")
            elif prop.type == "pair" and self.is_func_expr(prop.child_by_field_name("value")):
                key = prop.child_by_field_name("key")
            else:
                continue
            unit = self.emit(Unit("function", [(self._lead(props, i), prop.end_byte)],
                                  name=f"{name}.{self.src(key)}" if key else name,
                                  core=(prop.start_byte, prop.end_byte)))
            holes += unit.ranges
        if not holes:
            return False
        self.emit(Unit("top_level", subtract([(lead, stmt.end_byte)], holes), name=name, closure=list(ctrl),
                       core=(stmt.start_byte, stmt.end_byte)))
        return True

    def control(self, node, lead: int, ctrl: list[Range]) -> None:
        pass

        self.notes["control_descent"] += 1
        blocks = self.blocks(node)
        before = len(self.units)
        for k, block in enumerate(blocks):
            header = [(node.start_byte, blocks[0].start_byte + 1)]
            if k and block.parent is not None and block.parent.start_byte > node.start_byte:
                header.append((block.parent.start_byte, block.start_byte + 1))
            header.append((block.end_byte - 1, block.end_byte))
            self.statements(list(block.children[1:-1]) if self.text[block.start_byte:block.start_byte + 1] == b"{"
                            else list(block.named_children), ctrl + header)
        inner = [r for u in self.units[before:] for r in u.ranges]
        self.emit(Unit("top_level", subtract([(lead, node.end_byte)], inner), closure=list(ctrl),
                       core=(node.start_byte, node.end_byte)))

    
    def module_wrapper(self, stmt):
        if self.family != "js" or stmt.type != "expression_statement" or not stmt.named_child_count:
            return None
        expr = _strip(stmt.named_child(0))
        if expr.type == "unary_expression" and expr.named_child_count:
            expr = _strip(expr.named_child(0))
        if expr.type != "call_expression":
            return None
        callee = _strip(expr.child_by_field_name("function"))
        candidates = []
        if callee is not None and self.is_func_expr(callee):
            candidates.append(callee)
        elif callee is not None and callee.type == "member_expression":
            obj = _strip(callee.child_by_field_name("object"))
            prop = callee.child_by_field_name("property")
            if obj is not None and self.is_func_expr(obj) and prop is not None and self.src(prop) in ("call", "apply"):
                candidates.append(obj)
        args = expr.child_by_field_name("arguments")
        if args is not None:
            candidates += [_strip(a) for a in args.named_children if self.is_func_expr(a)]
        candidates = [c for c in candidates if (b := c.child_by_field_name("body")) is not None and b.type in BLOCKS]
        if not candidates:
            return None
        fn = max(candidates, key=lambda c: c.end_byte - c.start_byte)
        nonblank = [line for line in self.text.split(b"\n") if line.strip()]
        inside = [line for line in self.text[fn.start_byte:fn.end_byte].split(b"\n") if line.strip()]
        if not nonblank or len(inside) / len(nonblank) < self.min_share:
            return None
        return fn

    def run(self, root) -> None:
        nodes = list(root.named_children)
        for i, node in enumerate(nodes):
            fn = self.module_wrapper(node)
            if fn is None:
                continue
            self.notes["module_wrapper"] = 1
            lead = self._lead(nodes, i)
            self.statements(nodes[:i], [])
            body = fn.child_by_field_name("body")
            self.statements(list(body.children[1:-1]), [])  
            self.emit(Unit("top_level", [(lead, body.start_byte + 1), (body.end_byte - 1, node.end_byte)],
                           name="module_wrapper", core=(node.start_byte, node.end_byte)))
            self.statements(nodes[i + 1:], [])
            return
        self.statements(nodes, [])


def check_disjoint(units: list[Unit], size: int) -> None:
    pass
    spans = sorted((a, b, k) for k, u in enumerate(units) for a, b in u.ranges)
    for (a0, b0, k0), (a1, b1, k1) in itertools.pairwise(spans):
        if a1 < b0:
            raise AssertionError(f"U8: units {units[k0].kind}/{units[k1].kind} overlap at bytes {a1}-{b0}")
    if spans and (spans[0][0] < 0 or max(b for _, b, _ in spans) > size):
        raise AssertionError("U8: unit outside the file")
    for u in units:
        if any(a >= b for a, b in u.ranges) or u.ranges != sorted(u.ranges):
            raise AssertionError(f"U8: malformed ranges in {u.kind} {u.name}")


def extract(text: bytes, grammar: str, module_wrapper_min_line_share: float = 0.80) -> FileUnits:
    pass
    try:
        text.decode("utf-8", errors="strict")
    except UnicodeDecodeError as exc:
        return FileUnits("read_error", grammar, text, error={"exception": str(exc)})
    tree = _parser(grammar).parse(text)
    root = tree.root_node
    if root.has_error:
        return FileUnits("parse_error", grammar, text, error=_parse_errors(root, text))
    ex = _Extractor(text, grammar, module_wrapper_min_line_share)
    ex.run(root)
    units = sorted(ex.units, key=lambda u: u.start)
    check_disjoint(units, len(text))
    return FileUnits("parsed", grammar, text, units=units, notes=ex.notes)




@dataclass
class TargetMap:
    status: str  
    unit: Unit | None
    target: list[Range]
    remainder: list[Range]
    closure: list[Range]
    reason: str = ""


SEPARATORS = b" \t\r\n,;"


def _overlap_text(fu: FileUnits, unit: Unit, t0: int, t1: int) -> bytes:
    return b"".join(fu.text[max(a, t0):min(b, t1)] for a, b in unit.ranges if a < t1 and t0 < b)


def line_range(fu: FileUnits, start_line: int, end_line: int) -> Range:
    pass
    starts = fu.line_starts
    a = starts[start_line - 1]
    b = starts[end_line] if end_line < len(starts) else len(fu.text)
    while a < b and fu.text[a:a + 1].isspace():
        a += 1
    while b > a and fu.text[b - 1:b].isspace():
        b -= 1
    return a, b


def map_target(fu: FileUnits, start_line: int, end_line: int) -> TargetMap:
    pass
    t0, t1 = line_range(fu, start_line, end_line)
    hit = [u for u in fu.units if any(a < t1 and t0 < b for a, b in u.ranges)]
    if len(hit) > 1:
        
        
        hit = [u for u in hit if _overlap_text(fu, u, t0, t1).strip(SEPARATORS)] or hit
    if not hit:
        return TargetMap("target_misaligned", None, [(t0, t1)], [], [], "no unit overlaps the target")
    if len(hit) > 1:
        names = ";".join(f"{u.kind}:{u.name}@{u.start}" for u in hit)
        return TargetMap("target_misaligned", None, [(t0, t1)], [], [], f"target crosses units {names}")
    unit = hit[0]
    core = unit.core or (unit.start, unit.end)
    if t0 <= core[0] and core[1] <= t1:
        return TargetMap("coincides", unit, list(unit.ranges), [], list(unit.closure))
    target = [(max(a, t0), min(b, t1)) for a, b in unit.ranges if a < t1 and t0 < b]
    return TargetMap("nested", unit, target, subtract(unit.ranges, [(t0, t1)]), list(unit.closure))


def anchor_line(fu: FileUnits, line_text: str) -> list[int]:
    pass


    from raven.pairs import _PHP_LINE_COMMENT

    want = line_text.strip()
    lines = fu.text.decode("utf-8").split("\n")
    return [i + 1 for i, line in enumerate(lines) if _PHP_LINE_COMMENT.sub("", line).strip() == want]


def map_anchor(fu: FileUnits, line: int) -> TargetMap:
    pass
    a, _ = line_range(fu, line, line)
    for unit in fu.units:
        if any(r0 <= a < r1 for r0, r1 in unit.ranges):
            return TargetMap("coincides", unit, list(unit.ranges), [], list(unit.closure))
    return TargetMap("target_misaligned", None, [(a, a)], [], [], "sink line is in no unit")




SARD_MARKERS = (
    re.compile(rb"//[ \t]*(?:flaw|no_sanitizing)\b[^\n]*"),
    re.compile(rb"/\*[\s/*]*(?:Safe|Unsafe) sample.*?\*/", re.DOTALL),
    re.compile(rb"<!--\s*(?:Safe|Unsafe) sample.*?-->", re.DOTALL),
)
SARD_RESIDUE = re.compile(rb"//[ \t]*(?:flaw|no_sanitizing)\b|(?:Safe|Unsafe) sample")


def blank_sard_markers(data: bytes) -> tuple[bytes, int]:
    pass

    out, count = bytearray(data), 0
    for pattern in SARD_MARKERS:
        for match in pattern.finditer(bytes(out)):
            count += 1
            for i in range(match.start(), match.end()):
                if out[i] != 10:
                    out[i] = 32
    if SARD_RESIDUE.search(bytes(out)):
        raise AssertionError("S0: a SARD label marker remains after blanking")
    return bytes(out), count


def php_comments(data: bytes) -> list[bytes]:
    pass
    tree = _parser("php").parse(data)
    out, stack = [], [tree.root_node]
    while stack:
        node = stack.pop()
        if node.type == "comment":
            out.append(data[node.start_byte:node.end_byte].strip())
        stack.extend(node.children)
    return out


def comment_ranges(fu: FileUnits) -> list[Range]:
    pass
    tree = _parser(fu.grammar).parse(fu.text)
    out, stack = [], [tree.root_node]
    while stack:
        node = stack.pop()
        if node.type == "comment":
            out.append((node.start_byte, node.end_byte))
        else:
            stack.extend(node.children)
    return merge(out)


def selectability(fu: FileUnits, ranges: list[Range], target: TargetMap | None) -> str:
    pass


    mandatory = merge((target.target if target else []) + (target.closure if target else []))
    units = merge(r for u in fu.units for r in u.ranges)
    closures = merge(r for u in fu.units for r in u.closure)
    found = set()
    for a, b in ranges:
        for i in range(a, b):
            if fu.text[i:i + 1].isspace():
                continue
            if any(x <= i < y for x, y in mandatory):
                found.add("mandatory")
            elif any(x <= i < y for x, y in units):
                found.add("selectable")
            elif any(x <= i < y for x, y in closures):
                found.add("closure_only")
            else:
                found.add("not_in_pool")
    order = ("mandatory", "closure_only", "selectable", "not_in_pool")
    return "+".join(c for c in order if c in found) or "empty"


def sanitizer_class(selectable: str) -> str:
    pass
    if "mandatory" in selectable:
        return "c_mandatory"
    if "closure_only" in selectable:
        return "b_closure_only"
    if "selectable" in selectable:
        return "a_selectable"
    if selectable == "empty":
        return "absent"  
    return "not_in_pool"
