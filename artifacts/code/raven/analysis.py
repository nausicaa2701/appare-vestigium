"""Approximate graph G1-G4 (docs/unit-spec.md §5).

Edges are unit-level: ``call`` (G2), ``def_use`` (G1), ``import`` (G3); callers (G4) are the
resolved calls into a unit. Every edge has a status (``resolved``/``unresolved``), a reason
for unresolved calls, a confidence (``high``/``low``) and the source byte span. An absent edge
is never evidence of independence. Tree-sitter supplies syntax only; this module is the
separate, approximate analysis layer and never claims sound semantics.
"""

from __future__ import annotations

import bisect
import json
import posixpath
import re
import subprocess
from dataclasses import dataclass, field

from raven import context

JS_FUNCS = context.JS_FUNC_EXPR | context.JS_FUNC_DECL | {"method_definition"}
PHP_FUNCS = context.PHP_FUNC_EXPR | {"function_definition", "method_declaration"}
JS_BUILTINS = frozenset(["Array", "ArrayBuffer", "Boolean", "BigInt", "DataView", "Date", "Error", "EvalError", "Function", "Infinity", "JSON", "Map", "Math", "NaN", "Number", "Object", "Promise", "Proxy", "RangeError", "ReferenceError", "Reflect", "RegExp", "Set", "String", "Symbol", "SyntaxError", "TypeError", "URIError", "URL", "URLSearchParams", "WeakMap", "WeakSet", "WeakRef", "Int8Array", "Uint8Array", "Uint8ClampedArray", "Int16Array", "Uint16Array", "Int32Array", "Uint32Array", "Float32Array", "Float64Array", "BigInt64Array", "BigUint64Array", "TextEncoder", "TextDecoder", "AbortController", "Blob", "FormData", "Headers", "Request", "Response", "Intl", "Atomics", "globalThis", "console", "process", "Buffer", "require", "module", "exports", "window", "document", "navigator", "location", "localStorage", "sessionStorage", "history", "fetch", "setTimeout", "clearTimeout", "setInterval", "clearInterval", "setImmediate", "clearImmediate", "queueMicrotask", "requestAnimationFrame", "cancelAnimationFrame", "parseInt", "parseFloat", "isNaN", "isFinite", "encodeURI", "encodeURIComponent", "decodeURI", "decodeURIComponent", "escape", "unescape", "eval", "alert", "confirm", "prompt", "atob", "btoa", "structuredClone", "XMLHttpRequest", "WebSocket", "Event", "CustomEvent", "Element", "HTMLElement", "Node", "MutationObserver", "crypto", "performance", "self", "global", "__dirname", "__filename", "undefined", "arguments"])
JS_EXTS = (".js", ".mjs", ".cjs", ".ts", ".tsx", ".jsx")
JS_FUNC_VALUES = frozenset({"function", "function_expression", "arrow_function", "generator_function",
                            "generator_function_expression"})
IMPORT_SPEC = re.compile(rb"""(?:require\s*\(\s*|import\s*\(\s*|\bfrom\s+|\bimport\s+)['"]([^'"\n]+)['"]""")


@dataclass
class Edge:
    file: str
    src_unit: int
    span: tuple[int, int]
    type: str  
    status: str  
    reason: str = ""
    confidence: str = "high"
    dst_file: str = ""
    dst_unit: int = -1
    text: str = ""


@dataclass
class FileGraph:
    path: str
    fu: context.FileUnits
    defs: dict[str, list[int]] = field(default_factory=dict)
    members: dict[tuple[str, str], int] = field(default_factory=dict)
    methods: dict[tuple[str, str], int] = field(default_factory=dict)
    imports: dict[str, tuple[str, str]] = field(default_factory=dict)  
    import_spans: dict[str, tuple[int, int]] = field(default_factory=dict)
    exports: dict[str, int] = field(default_factory=dict)
    edges: list[Edge] = field(default_factory=list)




PHP_LEGACY_INTERNAL = frozenset({
    "mysql_connect", "mysql_close", "mysql_select_db", "mysql_query", "mysql_fetch_array",
    "mysql_fetch_assoc", "mysql_fetch_row", "mysql_real_escape_string", "mysql_escape_string",
    "mysql_num_rows", "mysql_error", "mysql_result", "eval", "exit", "die", "empty", "isset", "unset",
})


def php_internal_functions() -> tuple[frozenset[str], str]:
    pass

    out = subprocess.run(["php", "-r", "echo json_encode([PHP_VERSION, get_defined_functions()['internal']]);"],
                         capture_output=True, text=True, check=True, timeout=60)
    version, names = json.loads(out.stdout)
    return frozenset(n.lower() for n in names) | PHP_LEGACY_INTERNAL, version


def import_specs(text: bytes) -> list[str]:
    pass
    return [m.group(1).decode("utf-8", "replace") for m in IMPORT_SPEC.finditer(text)]


def resolve_module(spec: str, from_path: str, files: set[str], mains: dict[str, str]) -> tuple[str, str]:
    pass
    if not spec.startswith("."):
        return "", "external_module"
    base = posixpath.normpath(posixpath.join(posixpath.dirname(from_path), spec))
    if base in files:
        return base, ""
    for ext in JS_EXTS:
        if base + ext in files:
            return base + ext, ""
    main = mains.get(base)
    if main:
        cand = posixpath.normpath(posixpath.join(base, main))
        for path in (cand, *(cand + e for e in JS_EXTS), *(f"{cand}/index{e}" for e in JS_EXTS)):
            if path in files:
                return path, ""
    for ext in JS_EXTS:
        if f"{base}/index{ext}" in files:
            return f"{base}/index{ext}", ""
    return "", "not_found"


def resolve_include(spec: str, from_path: str, files: set[str]) -> tuple[str, str]:
    base = posixpath.normpath(posixpath.join(posixpath.dirname(from_path), spec))
    return (base, "") if base in files else ("", "not_found")


class _Units:
    def __init__(self, fu: context.FileUnits):
        self.spans = sorted((a, b, k) for k, u in enumerate(fu.units) for a, b in u.ranges)
        self.starts = [s[0] for s in self.spans]

    def at(self, byte: int) -> int:
        i = bisect.bisect_right(self.starts, byte) - 1
        if i >= 0 and self.spans[i][0] <= byte < self.spans[i][1]:
            return self.spans[i][2]
        return -1


def _src(text: bytes, node) -> str:
    return text[node.start_byte:node.end_byte].decode("utf-8", "replace")


def _function_value(text: bytes, node) -> bool:
    pass
    node = context._strip(node)
    while node is not None and node.type == "assignment_expression":
        node = context._strip(node.child_by_field_name("right"))
    if node is not None and node.type == "call_expression":
        callee = context._strip(node.child_by_field_name("function"))
        if callee is not None and callee.type == "member_expression" and \
                _src(text, callee.child_by_field_name("property")) == "bind":
            node = context._strip(callee.child_by_field_name("object"))
    return node is not None and node.type in JS_FUNC_VALUES


def _pattern_names(text: bytes, node) -> list[tuple[str, str]]:
    pass
    if node is None:
        return []
    if node.type in ("identifier", "shorthand_property_identifier_pattern"):
        return [(_src(text, node), _src(text, node))]
    out = []
    for child in node.named_children:
        if child.type == "pair_pattern":
            key, value = child.child_by_field_name("key"), child.child_by_field_name("value")
            for local, _ in _pattern_names(text, value):
                out.append((local, _src(text, key) if key is not None else local))
        elif child.type in ("object_assignment_pattern", "assignment_pattern"):
            out += _pattern_names(text, child.child_by_field_name("left") or child.named_child(0))
        else:
            out += _pattern_names(text, child)
    return out


class JsAnalyser:
    pass

    def __init__(self, path: str, fu: context.FileUnits):
        self.g = FileGraph(path, fu)
        self.text = fu.text
        self.units = _Units(fu)
        self.tree = context._parser(fu.grammar).parse(fu.text)
        self.pending: list[tuple[Edge, str, str]] = []  
        self._collect()

    
    def transparent(self, node) -> bool:
        pass
        k = self.units.at(node.start_byte)
        if k < 0:
            return True
        return not any(a <= node.start_byte and node.end_byte <= b for a, b in self.g.fu.units[k].ranges)

    def _def(self, name: str, unit: int) -> None:
        if unit >= 0 and name:
            self.g.defs.setdefault(name, [])
            if unit not in self.g.defs[name]:
                self.g.defs[name].append(unit)

    def _collect(self) -> None:
        text, g = self.text, self.g
        for k, unit in enumerate(g.fu.units):
            if unit.kind == "function" and "." in unit.name:
                obj, _, member = unit.name.rpartition(".")
                g.members[(obj, member)] = k
                if obj in ("exports", "module.exports"):
                    g.exports[member] = k
            elif unit.kind == "function" and unit.name == "module.exports":
                g.exports["default"] = k
            elif unit.kind == "method":
                g.methods[(unit.parent_class, unit.name)] = k
        stack = [(self.tree.root_node, False)]
        while stack:
            node, inside = stack.pop()
            t = node.type
            unit = self.units.at(node.start_byte)
            if not inside:
                if t in ("function_declaration", "generator_function_declaration", "class_declaration",
                         "abstract_class_declaration"):
                    name = node.child_by_field_name("name")
                    if name is not None:
                        self._def(_src(text, name), unit)
                elif t == "variable_declarator":
                    value = context._strip(node.child_by_field_name("value"))
                    names = _pattern_names(text, node.child_by_field_name("name"))
                    spec = self._require_spec(value)
                    for local, imported in names:
                        self._def(local, unit)
                        if spec is not None:
                            member = imported if node.child_by_field_name("name").type != "identifier" else "*"
                            if value.type == "member_expression":
                                member = _src(text, value.child_by_field_name("property"))
                            g.imports[local] = (spec, member)
                            g.import_spans[local] = (node.start_byte, node.end_byte)
                elif t == "assignment_expression":
                    left = node.child_by_field_name("left")
                    if left is not None and left.type == "identifier":
                        self._def(_src(text, left), unit)
                    elif left is not None and _src(text, left) == "module.exports":
                        self._module_exports(context._strip(node.child_by_field_name("right")), unit)
                elif t == "import_statement":
                    self._import(node)
                elif t == "export_statement":
                    self._export(node, unit)
            if t in JS_FUNCS and not self.transparent(node):
                inside = True
            stack.extend((c, inside) for c in reversed(node.children))

    def _require_spec(self, value) -> str | None:
        if value is not None and value.type == "member_expression":
            value = context._strip(value.child_by_field_name("object"))
        if value is not None and value.type == "await_expression" and value.named_child_count:
            value = context._strip(value.named_child(0))
        if value is None or value.type != "call_expression":
            return None
        callee = value.child_by_field_name("function")
        args = value.child_by_field_name("arguments")
        if callee is None or args is None or not args.named_child_count:
            return None
        if not (callee.type == "import" or _src(self.text, callee) == "require"):
            return None
        first = args.named_child(0)
        return _src(self.text, first)[1:-1] if first.type == "string" else None

    def _import(self, node) -> None:
        source = node.child_by_field_name("source")
        if source is None:
            return
        spec = _src(self.text, source)[1:-1]
        unit = self.units.at(node.start_byte)
        before = set(self.g.imports)
        for clause in node.named_children:
            if clause.type != "import_clause":
                continue
            for part in clause.named_children:
                if part.type == "identifier":
                    self.g.imports[_src(self.text, part)] = (spec, "default")
                    self._def(_src(self.text, part), unit)
                elif part.type == "namespace_import":
                    for ident in part.named_children:
                        self.g.imports[_src(self.text, ident)] = (spec, "*")
                        self._def(_src(self.text, ident), unit)
                elif part.type == "named_imports":
                    for spec_node in part.named_children:
                        if spec_node.type != "import_specifier":
                            continue
                        name = spec_node.child_by_field_name("name")
                        alias = spec_node.child_by_field_name("alias") or name
                        self.g.imports[_src(self.text, alias)] = (spec, _src(self.text, name))
                        self._def(_src(self.text, alias), unit)
        for local in set(self.g.imports) - before:
            self.g.import_spans[local] = (node.start_byte, node.end_byte)

    def _export(self, node, unit: int) -> None:
        decl = node.child_by_field_name("declaration")
        value = node.child_by_field_name("value")
        text = self.text
        if decl is not None:
            if decl.type in ("lexical_declaration", "variable_declaration"):
                for d in decl.named_children:
                    if d.type == "variable_declarator":
                        for local, _ in _pattern_names(text, d.child_by_field_name("name")):
                            self.g.exports[local] = unit
            else:
                name = decl.child_by_field_name("name")
                if name is not None:
                    self.g.exports[_src(text, name)] = unit
        elif value is not None or any(c.type == "default" for c in node.children):
            value = context._strip(value)
            if value is not None and value.type == "identifier" and self.g.defs.get(_src(text, value)):
                self.g.exports["default"] = self.g.defs[_src(text, value)][0]
            else:
                self.g.exports["default"] = unit
        for clause in node.named_children:
            if clause.type == "export_clause":
                for spec in clause.named_children:
                    name = spec.child_by_field_name("name")
                    alias = spec.child_by_field_name("alias") or name
                    if name is not None:
                        self.pending_exports = getattr(self, "pending_exports", [])
                        self.pending_exports.append((_src(text, alias), _src(text, name)))

    def _module_exports(self, value, unit: int) -> None:
        text = self.text
        if value is None:
            return
        if value.type == "identifier":
            self.pending_exports = getattr(self, "pending_exports", [])
            self.pending_exports.append(("default", _src(text, value)))
        elif value.type == "object":
            for prop in value.named_children:
                if prop.type == "shorthand_property_identifier":
                    self.pending_exports = getattr(self, "pending_exports", [])
                    self.pending_exports.append((_src(text, prop), _src(text, prop)))
                elif prop.type == "pair":
                    key, val = prop.child_by_field_name("key"), context._strip(prop.child_by_field_name("value"))
                    if key is not None and val is not None and val.type == "identifier":
                        self.pending_exports = getattr(self, "pending_exports", [])
                        self.pending_exports.append((_src(text, key), _src(text, val)))
        elif unit >= 0:
            self.g.exports.setdefault("default", unit)

    def finish_exports(self) -> None:
        for exported, local in getattr(self, "pending_exports", []):
            if self.g.defs.get(local):
                self.g.exports.setdefault(exported, self.g.defs[local][0])

    
    def _scope(self, fn) -> tuple[set[str], set[str], set[str]]:
        pass

        params, local, funcs = set(), set(), set()
        p = fn.child_by_field_name("parameters") or fn.child_by_field_name("parameter")
        if p is not None:
            params.update(n for n, _ in _pattern_names(self.text, p))
            if p.type == "identifier":
                params.add(_src(self.text, p))
        stack = [fn.child_by_field_name("body")] if fn.child_by_field_name("body") is not None else []
        while stack:
            node = stack.pop()
            t = node.type
            if t == "variable_declarator":
                names = [n for n, _ in _pattern_names(self.text, node.child_by_field_name("name"))]
                local.update(names)
                if _function_value(self.text, node.child_by_field_name("value")) and len(names) == 1:
                    funcs.update(names)
            elif t in ("function_declaration", "generator_function_declaration", "class_declaration"):
                name = node.child_by_field_name("name")
                if name is not None:
                    local.add(_src(self.text, name))
                    if t != "class_declaration":
                        funcs.add(_src(self.text, name))
            elif t == "assignment_expression":  
                left = node.child_by_field_name("left")
                if left is not None and left.type == "identifier" and \
                        _function_value(self.text, node.child_by_field_name("right")):
                    funcs.add(_src(self.text, left))
            elif t == "formal_parameters":
                local.update(n for n, _ in _pattern_names(self.text, node))
            elif t == "catch_clause" and node.child_by_field_name("parameter") is not None:
                local.update(n for n, _ in _pattern_names(self.text, node.child_by_field_name("parameter")))
            stack.extend(node.named_children)
        return params, local, funcs

    def analyse(self) -> None:
        self.finish_exports()
        seen_uses: set[tuple[int, int, str]] = set()
        stack = [(self.tree.root_node, ())]
        while stack:
            node, scopes = stack.pop()
            t = node.type
            unit = self.units.at(node.start_byte)
            if t == "call_expression" and unit >= 0:
                self._call(node, unit, scopes)
            elif t in ("identifier", "shorthand_property_identifier") and unit >= 0:
                self._use(node, unit, scopes, seen_uses)
            elif t in ("import_statement",) or (t == "call_expression" and self._require_spec(node) is not None):
                pass
            if t in JS_FUNCS and not self.transparent(node):
                scopes = scopes + (self._scope(node),)
            stack.extend((c, scopes) for c in reversed(node.children))
        for local, (spec, _) in self.g.imports.items():
            k = self.g.defs.get(local, [-1])[0]
            span = self.g.import_spans.get(local, (0, 0))
            self.pending.append((Edge(self.g.path, k, span, "import", "unresolved", text=spec), spec, ""))

    def _bound(self, name: str, scopes) -> str:
        for params, local, funcs in reversed(scopes):
            if name in params:
                return "param"
            if name in local:
                return "func" if name in funcs else "local"
        return ""

    def _call(self, node, unit: int, scopes) -> None:
        text = self.text
        callee = context._strip(node.child_by_field_name("function"))
        span = (node.start_byte, node.end_byte)
        edge = Edge(self.g.path, unit, span, "call", "unresolved", text=_src(text, callee)[:120] if callee else "")
        if callee is None:
            edge.reason = "computed_callee"
        elif callee.type == "identifier":
            name = _src(text, callee)
            bound = self._bound(name, scopes)
            if bound == "param":
                edge.reason = "callback_parameter"
            elif bound == "func":  
                edge.status, edge.dst_file, edge.dst_unit = "resolved", self.g.path, unit
            elif bound == "local":  
                edge.reason = "not_found"
            elif name in self.g.imports:
                self.pending.append((edge, name, ""))
                return
            elif self.g.defs.get(name):
                
                k = self.g.defs[name]
                fn = [u for u in k if self.g.fu.units[u].kind == "function"]
                if fn:
                    edge.status, edge.dst_file, edge.dst_unit = "resolved", self.g.path, fn[-1]
                    edge.confidence = "high" if len(k) == 1 else "low"
                else:
                    edge.reason = "not_found"
            elif name in JS_BUILTINS:
                edge.reason = "builtin"
            else:
                edge.reason = "not_found"
        elif callee.type == "member_expression":
            obj = context._strip(callee.child_by_field_name("object"))
            prop = callee.child_by_field_name("property")
            member = _src(text, prop) if prop is not None else ""
            owner = self.g.fu.units[unit]
            if obj is not None and obj.type == "this" and owner.parent_class and \
                    (owner.parent_class, member) in self.g.methods:
                edge.status, edge.dst_file = "resolved", self.g.path
                edge.dst_unit = self.g.methods[(owner.parent_class, member)]
            elif obj is not None and obj.type == "identifier" and not self._bound(_src(text, obj), scopes):
                name = _src(text, obj)
                if name in self.g.imports and self.g.imports[name][1] == "*":
                    self.pending.append((edge, name, member))
                    return
                if (name, member) in self.g.members:
                    edge.status, edge.dst_file, edge.dst_unit = "resolved", self.g.path, self.g.members[(name, member)]
                elif name in JS_BUILTINS:
                    edge.reason = "builtin"
                else:
                    edge.reason = "dynamic_property"
            else:
                edge.reason = "dynamic_property"
        else:
            edge.reason = "computed_callee"
        self.g.edges.append(edge)

    def _use(self, node, unit: int, scopes, seen: set) -> None:
        parent = node.parent
        if parent is None:
            return
        if parent.type == "call_expression" and parent.child_by_field_name("function") == node:
            return
        if parent.type in ("variable_declarator", "function_declaration", "class_declaration",
                           "import_specifier", "import_clause", "namespace_import", "formal_parameters",
                           "generator_function_declaration", "method_definition", "labeled_statement",
                           "break_statement", "continue_statement", "export_specifier") \
                and parent.child_by_field_name("value") != node:
            return
        if parent.type == "assignment_expression" and parent.child_by_field_name("left") == node:
            return
        name = _src(self.text, node)
        if self._bound(name, scopes):
            return
        if name in self.g.imports:
            key = (unit, -2, name)
            if key not in seen:
                seen.add(key)
                self.pending.append((Edge(self.g.path, unit, (node.start_byte, node.end_byte), "def_use",
                                          "unresolved", text=name), name, ""))
            return
        defs = [k for k in self.g.defs.get(name, []) if k != unit]
        for k in defs:
            key = (unit, k, name)
            if key in seen:
                continue
            seen.add(key)
            self.g.edges.append(Edge(self.g.path, unit, (node.start_byte, node.end_byte), "def_use", "resolved",
                                     confidence="high" if len(self.g.defs[name]) == 1 else "low",
                                     dst_file=self.g.path, dst_unit=k, text=name))


def link(analysers: dict[str, JsAnalyser], files: set[str], mains: dict[str, str]) -> None:
    pass
    for an in analysers.values():
        for edge, local, member in an.pending:
            if edge.type == "import":
                spec = local
                path, reason = resolve_module(spec, an.g.path, files, mains)
                edge.status, edge.reason, edge.dst_file = ("resolved", "", path) if path else ("unresolved", reason, "")
                an.g.edges.append(edge)
                continue
            spec, imported = an.g.imports[local]
            path, reason = resolve_module(spec, an.g.path, files, mains)
            if path and edge.type == "def_use":
                
                
                
                target = None
                if path in analysers:
                    name = "default" if imported == "*" else imported
                    target = analysers[path].g.exports.get(name)
                    if target is None and imported == "*":
                        target = analysers[path].g.exports.get("*")
                if target is not None:
                    edge.status, edge.reason, edge.dst_file, edge.dst_unit = "resolved", "", path, target
                else:
                    decl = [k for k in an.g.defs.get(local, []) if k != edge.src_unit]
                    if decl:
                        edge.status, edge.reason, edge.dst_file, edge.dst_unit = "resolved", "", an.g.path, decl[0]
                    else:
                        edge.reason, edge.dst_file = "not_found", path
                an.g.edges.append(edge)
                continue
            if not path:
                edge.reason = reason
            elif path not in analysers:
                edge.reason = "not_found"  
                edge.dst_file = path
            else:
                name = member if imported == "*" and member else ("default" if imported == "*" else imported)
                target = analysers[path].g.exports.get(name)
                if target is None and imported == "*" and not member:
                    target = analysers[path].g.exports.get("*")
                if target is None:
                    edge.reason = "not_found"
                    edge.dst_file = path
                else:
                    edge.status, edge.reason, edge.dst_file, edge.dst_unit = "resolved", "", path, target
            an.g.edges.append(edge)
        an.pending = []


class PhpAnalyser:
    pass

    BRANCH = frozenset({"if_statement", "else_clause", "else_if_clause", "while_statement", "for_statement",
              "foreach_statement", "do_statement", "switch_statement", "try_statement",
              "conditional_expression"})

    def __init__(self, path: str, fu: context.FileUnits, internal: frozenset[str]):
        self.g = FileGraph(path, fu)
        self.text = fu.text
        self.units = _Units(fu)
        self.internal = internal
        self.tree = context._parser("php").parse(fu.text)
        for k, unit in enumerate(fu.units):
            if unit.kind == "function":
                self.g.defs.setdefault(unit.name.lower(), []).append(k)
            elif unit.kind == "method":
                self.g.methods[(unit.parent_class, unit.name.lower())] = k

    def analyse(self, files: set[str]) -> None:
        text = self.text
        assigns: dict[str, list[tuple[int, int, bool]]] = {}  
        uses: list[tuple[str, int, int, bool, tuple[int, int]]] = []
        stack = [(self.tree.root_node, False, False)]
        while stack:
            node, in_fn, branch = stack.pop()
            t = node.type
            unit = self.units.at(node.start_byte)
            if t == "function_call_expression" and unit >= 0:
                fn = node.child_by_field_name("function")
                edge = Edge(self.g.path, unit, (node.start_byte, node.end_byte), "call", "unresolved",
                            text=_src(text, fn)[:120] if fn is not None else "")
                name = _src(text, fn).lstrip("\\").lower() if fn is not None else ""
                if fn is None or fn.type not in ("name", "qualified_name"):
                    edge.reason = "computed_callee"
                elif self.g.defs.get(name):
                    edge.status, edge.dst_file, edge.dst_unit = "resolved", self.g.path, self.g.defs[name][0]
                elif name in self.internal:
                    edge.reason = "builtin"
                else:
                    edge.reason = "not_found"
                self.g.edges.append(edge)
            elif t in ("member_call_expression", "scoped_call_expression") and unit >= 0:
                obj = node.child_by_field_name("object") or node.child_by_field_name("scope")
                name = node.child_by_field_name("name")
                edge = Edge(self.g.path, unit, (node.start_byte, node.end_byte), "call", "unresolved",
                            text=_src(text, node)[:120])
                owner = self.g.fu.units[unit]
                key = (owner.parent_class, _src(text, name).lower() if name is not None else "")
                if obj is not None and _src(text, obj) in ("$this", "self", "static") and key in self.g.methods:
                    edge.status, edge.dst_file, edge.dst_unit = "resolved", self.g.path, self.g.methods[key]
                else:
                    edge.reason = "dynamic_property"
                self.g.edges.append(edge)
            elif t in context.PHP_INCLUDE and unit >= 0:
                arg = node.named_child(0) if node.named_child_count else None
                edge = Edge(self.g.path, unit, (node.start_byte, node.end_byte), "import", "unresolved",
                            text=_src(text, node)[:120])
                if arg is not None and arg.type == "string":
                    path, reason = resolve_include(_src(text, arg)[1:-1], self.g.path, files)
                    edge.status, edge.reason, edge.dst_file = ("resolved", "", path) if path else ("unresolved", reason, "")
                else:
                    edge.reason = "computed_callee"
                self.g.edges.append(edge)
            elif t == "assignment_expression" and not in_fn and unit >= 0:
                left = node.child_by_field_name("left")
                if left is not None and left.type == "variable_name":
                    assigns.setdefault(_src(text, left), []).append((node.start_byte, unit, branch))
            elif t == "variable_name" and not in_fn and unit >= 0:
                parent = node.parent
                if not (parent is not None and parent.type == "assignment_expression"
                        and parent.child_by_field_name("left") == node):
                    uses.append((_src(text, node), node.start_byte, unit, branch, (node.start_byte, node.end_byte)))
            if t in PHP_FUNCS:
                in_fn = True
            if t in self.BRANCH:
                branch = True
            stack.extend((c, in_fn, branch) for c in reversed(node.children))
        
        seen = set()
        for name, pos, unit, branch, span in uses:
            prior = [a for a in assigns.get(name, []) if a[0] < pos]
            if not prior:
                continue
            reach = []
            for a in reversed(prior):
                reach.append(a)
                if not a[2]:
                    break  
            low = branch or len(reach) > 1
            for _, k, _ in reach:
                if k == unit or (unit, k, name) in seen:
                    continue
                seen.add((unit, k, name))
                self.g.edges.append(Edge(self.g.path, unit, span, "def_use", "resolved",
                                         confidence="low" if low else "high", dst_file=self.g.path,
                                         dst_unit=k, text=name))
