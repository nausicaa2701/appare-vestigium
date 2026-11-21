"""Vulnerable/fixed target alignment, reproduction audit and label conflicts (P4).

Reproduction follows the exploit isolation policy in ``docs/pilot-decisions.md``: images
are built (network allowed, no credentials) separately from execution; PoCs run only in
disposable containers with no network, read-only root, dropped capabilities, non-root
user, resource limits and a host-enforced timeout.
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

import numpy as np

PAIR_STATUSES = (
    "validated", "aligned_not_reproduced", "exploit_incompatible", "build_failed",
    "residual_flaw", "no_correspondence", "invalid_twin",
)
JSON_MARKER = "@@RAVEN_JEST_JSON@@"

_ASSERTION = re.compile(r"expect\(.*\)\.|Expected[^\n]*:|Received[^\n]*:", re.DOTALL)
_TEST_LINE = re.compile(r"\.test\.js:(\d+):\d+")


def isolation_args(name: str, policy: dict[str, Any]) -> list[str]:
    pass
    return [
        "--rm", "--name", name, "--network", "none", "--cap-drop", "ALL",
        "--security-opt", "no-new-privileges", "--pids-limit", str(policy["pids_limit"]),
        "--cpus", str(policy["cpus"]), "--memory", policy["memory"], "--memory-swap", policy["memory"],
        "--read-only", "--tmpfs", f"/tmp:rw,size={policy['tmpfs_mib']}m,mode=1777", "--user", policy["user"],
    ]


def jest_command(workdir: str, force_exit: bool = True) -> list[str]:
    pass







    script = (
        "set -u; mkdir -p /tmp/w && cp /exploit/flag.html /tmp/flag.html 2>/dev/null; "
        f"for f in {workdir}/* {workdir}/.[!.]*; do [ -e \"$f\" ] || continue; "
        "case \"$f\" in */node_modules) ln -s \"$f\" /tmp/w/node_modules;; *) cp -R \"$f\" /tmp/w/;; esac; done; "
        "cd /tmp/w; "
        f"jest --runInBand {'--forceExit ' if force_exit else ''}"
        f"--config '{{\"rootDir\": \"{workdir}\", \"cacheDirectory\": \"/tmp/jest-cache\"}}' "
        "--json --outputFile /tmp/jest.json; code=$?; "
        f"echo {JSON_MARKER}; cat /tmp/jest.json 2>/dev/null; exit $code"
    )
    return ["sh", "-c", script]


def parse_jest(stdout: str) -> dict[str, Any] | None:
    if JSON_MARKER not in stdout:
        return None
    tail = stdout.split(JSON_MARKER, 1)[1].strip()
    try:
        return json.loads(tail)
    except json.JSONDecodeError:
        return None


def first_package_line(test_source: str, package: str) -> int:
    pass
    pattern = re.compile(rf"""(require\(\s*['"]{re.escape(package)}(/[^'"]*)?['"]\s*\)|from\s+['"]{re.escape(package)}(/[^'"]*)?['"])""")
    for number, line in enumerate(test_source.splitlines(), 1):
        if pattern.search(line):
            return number
    return 0


def classify_side(report: dict[str, Any] | None, timed_out: bool, test_source: str, package: str) -> dict[str, Any]:
    pass





    if timed_out:
        return {"outcome": "timeout", "failed_after_import": False, "duration_ms": "", "detail": "host timeout"}
    if report is None:
        return {"outcome": "error", "failed_after_import": False, "duration_ms": "", "detail": "no jest report"}
    tests = [a for suite in report.get("testResults", []) for a in suite.get("assertionResults", [])]
    duration = sum(t.get("duration") or 0 for t in tests) if tests else ""
    suite_errors = [s.get("message", "") for s in report.get("testResults", []) if s.get("status") == "failed" and not s.get("assertionResults")]
    if suite_errors or not tests:
        return {"outcome": "error", "failed_after_import": False, "duration_ms": duration,
                "detail": (suite_errors[0] if suite_errors else "no tests")[:500]}
    if all(t.get("status") == "passed" for t in tests):
        return {"outcome": "pass", "failed_after_import": False, "duration_ms": duration, "detail": ""}
    messages = "\n".join(m for t in tests for m in t.get("failureMessages", []))
    lines = [int(x) for x in _TEST_LINE.findall(messages)]
    import_line = first_package_line(test_source, package)
    failing_line = lines[0] if lines else 0
    is_assertion = bool(_ASSERTION.search(messages)) and not re.search(r"\b(TypeError|ReferenceError|SyntaxError|Cannot find module)\b", messages)
    after_import = is_assertion and import_line > 0 and failing_line > import_line
    return {
        "outcome": "assertion_fail" if is_assertion else "error",
        "failed_after_import": after_import, "failing_line": failing_line, "import_line": import_line,
        "duration_ms": duration, "detail": messages[:500],
    }


def classify_pair(vuln: dict[str, Any] | None, fixed: dict[str, Any] | None, built: tuple[bool, bool],
                  oracle: dict[str, Any] | None = None) -> tuple[str, str]:
    pass







    if not all(built):
        side = "vulnerable" if not built[0] else "fixed"
        return "build_failed", f"{side} image did not build"
    assert vuln is not None and fixed is not None
    if vuln["outcome"] == "pass":
        if fixed["outcome"] == "pass":
            return "residual_flaw", "PoC still succeeds on the fixed version"
        if fixed["outcome"] == "assertion_fail" and fixed["failed_after_import"]:
            if oracle and oracle.get("confirmed"):
                return "validated", ""
            reason = (oracle or {}).get("reason") or "no oracle evidence"
            return "aligned_not_reproduced", f"oracle_unconfirmed: {reason}"
        if fixed["outcome"] == "assertion_fail":
            return "exploit_incompatible", "fixed failed before the package was exercised"
        return "exploit_incompatible", f"fixed side {fixed['outcome']}: {fixed['detail'][:120]}"
    if vuln["outcome"] == "assertion_fail":
        return "aligned_not_reproduced", "PoC assertion failed on the vulnerable version"
    return "exploit_incompatible", f"vulnerable side {vuln['outcome']}: {vuln['detail'][:120]}"




_SAFE_NAME = re.compile(r"^[@A-Za-z0-9._/-]+$")
EVIDENCE_MARKERS = ("@@RAVEN_EV_POC@@", "@@RAVEN_EV_COV@@", "@@RAVEN_EV_BASE@@", "@@RAVEN_EV_HASH@@", "@@RAVEN_EV_END@@")


_REDUCE_JS = r"""
const fs = require('fs');
const [pkg, file] = process.argv.slice(2);
const needle = '/node_modules/' + pkg + '/';
let out = {};
try {
  const cov = JSON.parse(fs.readFileSync(file, 'utf8'));
  for (const [path, d] of Object.entries(cov)) {
    const i = path.lastIndexOf(needle);
    if (i < 0) continue;
    const rel = path.slice(i + needle.length);
    if (rel.startsWith('node_modules/') || rel.includes('/node_modules/')) continue;
    const fns = {};
    for (const [k, f] of Object.entries(d.fnMap || {})) {
      const loc = f.loc || f.decl;
      fns[f.decl.start.line + ':' + f.decl.start.column] = [f.name, (d.f || {})[k] || 0, loc.start.line,
        loc.end.line, loc.start.column, loc.end.column];
    }
    out[rel] = fns;
  }
} catch (e) { out = {'__error__': String(e)}; }
process.stdout.write(JSON.stringify(out));
"""


def package_specifier(test_source: str, package: str) -> str:
    pass
    pattern = re.compile(rf"""(?:require\(\s*|from\s+)['"]({re.escape(package)}(?:/[^'"]*)?)['"]""")
    match = pattern.search(test_source)
    return match.group(1) if match else package


def evidence_command(workdir: str, package: str, specifier: str) -> list[str]:
    pass





    import base64

    for value in (workdir, package, specifier):
        if not _SAFE_NAME.match(value):
            raise ValueError(f"unsafe name for evidence script: {value!r}")
    reduce_b64 = base64.b64encode(_REDUCE_JS.encode()).decode()
    poc_cfg = json.dumps({"rootDir": workdir, "cacheDirectory": "/tmp/jest-cache", "coveragePathIgnorePatterns": []})
    
    base_cfg = json.dumps({"rootDir": workdir, "roots": ["/tmp/w"], "cacheDirectory": "/tmp/jest-cache-b",
                           "coveragePathIgnorePatterns": []})
    cov = "--coverage --coverageProvider=v8 --coverageReporters=json"
    poc, cov_m, base, hash_m, end = EVIDENCE_MARKERS
    script = (
        "set -u; mkdir -p /tmp/w && cp /exploit/flag.html /tmp/flag.html 2>/dev/null; "
        f"for f in {workdir}/* {workdir}/.[!.]*; do [ -e \"$f\" ] || continue; "
        "case \"$f\" in */node_modules) ln -s \"$f\" /tmp/w/node_modules;; *) cp -R \"$f\" /tmp/w/;; esac; done; "
        "cd /tmp/w; "
        f"echo {reduce_b64} | base64 -d > /tmp/raven_reduce.js; "
        f"jest --runInBand --forceExit --config '{poc_cfg}' {cov} --coverageDirectory /tmp/cov-poc "
        "--json --outputFile /tmp/poc.json >/dev/null 2>&1; "
        f"printf '%s\\n' \"require('{specifier}'); test('raven import baseline', () => {{}});\" > /tmp/w/raven_import_baseline.test.js; "
        f"jest --runInBand --forceExit --config '{base_cfg}' {cov} --coverageDirectory /tmp/cov-base "
        "--runTestsByPath /tmp/w/raven_import_baseline.test.js >/dev/null 2>&1; "
        f"echo {poc}; cat /tmp/poc.json 2>/dev/null; echo; "
        f"echo {cov_m}; node /tmp/raven_reduce.js '{package}' /tmp/cov-poc/coverage-final.json; echo; "
        f"echo {base}; node /tmp/raven_reduce.js '{package}' /tmp/cov-base/coverage-final.json; echo; "
        f"echo {hash_m}; (cd '/tmp/w/node_modules/{package}' 2>/dev/null && "
        "find . -type f \\( -name '*.js' -o -name '*.cjs' -o -name '*.mjs' \\) -not -path './node_modules/*' "
        "-not -path './.git/*' | LC_ALL=C sort | xargs -d '\\n' -r sha256sum); "
        f"echo {end}"
    )
    return ["sh", "-c", script]


def parse_evidence(stdout: str) -> dict[str, Any] | None:
    pass
    if not all(m in stdout for m in EVIDENCE_MARKERS):
        return None
    poc, cov_m, base, hash_m, end = EVIDENCE_MARKERS
    body = stdout.split(poc, 1)[1]
    poc_text, body = body.split(cov_m, 1)
    cov_text, body = body.split(base, 1)
    base_text, body = body.split(hash_m, 1)
    hash_text = body.split(end, 1)[0]

    def load(text: str) -> Any:
        try:
            return json.loads(text.strip())
        except json.JSONDecodeError:
            return None

    hashes = {}
    for line in hash_text.strip().splitlines():
        digest, _, path = line.partition("  ")
        if path:
            hashes[path.removeprefix("./")] = digest
    return {"poc": load(poc_text), "coverage": load(cov_text) or {}, "baseline": load(base_text) or {}, "hashes": hashes}


def parse_sink(sink: str) -> tuple[str, int, int] | None:
    pass
    match = re.match(r"^(.+?):(\d+)(?::(\d+))?$", sink.strip())
    if not match:
        return None
    return match.group(1).removeprefix("./"), int(match.group(2)), int(match.group(3) or 0)


def oracle_evidence(vuln_ev: dict[str, Any] | None, fixed_ev: dict[str, Any] | None, vuln_outcome: str,
                    sink: str = "", adjudication: dict[str, str] | None = None) -> dict[str, Any]:
    pass










    out: dict[str, Any] = {"confirmed": False, "rule": "", "reason": "", "api_functions": [], "changed_files": 0,
                           "sink": sink, "sink_file": "", "sink_functions": [], "related_functions": [],
                           "adjudication": ""}
    if vuln_ev is None or fixed_ev is None:
        out["reason"] = "evidence run failed"
    else:
        cov, base = vuln_ev["coverage"], vuln_ev["baseline"]
        changed = {f for f in set(vuln_ev["hashes"]) | set(fixed_ev["hashes"])
                   if vuln_ev["hashes"].get(f) != fixed_ev["hashes"].get(f)}
        out["changed_files"] = len(changed)
        
        funcs = {}  
        for path, fns in cov.items():
            if path == "__error__":
                continue
            for key, entry in fns.items():
                line, col = (int(x) for x in key.split(":"))
                first = (entry[2], entry[4] if len(entry) >= 6 else 0) if len(entry) >= 4 else (line, col)
                last = (entry[3], entry[5] if len(entry) >= 6 else 1 << 30) if len(entry) >= 4 else (line, col)
                base_entry = base.get(path, {}).get(key)
                funcs.setdefault(path, []).append(
                    (first, last, entry[0] or "(anonymous)", entry[1], base_entry[1] if base_entry else 0))
        api = []  
        for path, items in funcs.items():
            for f in items:
                wrapper = len(items) > 1 and all(f[0] <= g[0] and g[1] <= f[1] for g in items)
                if f[3] > f[4] and not wrapper:
                    api.append((path, f[2], f[0], f[1]))
        label = [f"{p}:{a[0]}.{a[1]}-{b[0]}.{b[1]}:{n}" for p, n, a, b in sorted(api)]
        out["api_functions"] = label[:50]
        out["related_functions"] = [x for x, f in zip(label, sorted(api)) if f[0] in changed][:50]
        located = parse_sink(sink) if sink else None
        if located:
            
            exact = located[0] if located[0] in vuln_ev["hashes"] else None
            suffix = [f for f in vuln_ev["hashes"] if f.endswith("/" + located[0])]
            sink_file = exact or (suffix[0] if len(suffix) == 1 else None)
            out["sink_file"] = sink_file or ""
            located = (sink_file, located[1], located[2]) if sink_file else None
        if located and located[0] in funcs:
            
            
            point = (located[1], located[2])
            holders = [f for f in funcs[located[0]] if f[0] <= point <= f[1]]
            
            holders.sort(key=lambda f: (f[0], (-f[1][0], -f[1][1])), reverse=True)
            if holders:
                f = holders[0]
                out["sink_function"] = f"{located[0]}:{f[0][0]}.{f[0][1]}-{f[1][0]}.{f[1][1]}:{f[2]}"
                out["sink_function_calls"] = [f[3], f[4]]
                if f[3] > f[4]:
                    out["sink_functions"] = [out["sink_function"]]
        tests = [t for s in (vuln_ev["poc"] or {}).get("testResults", []) for t in s.get("assertionResults", [])]
        ev_outcome = "pass" if tests and all(t.get("status") == "passed" for t in tests) else "not_pass"
        
        
        sink_in_tree = bool(located) and located[0] in funcs
        if "__error__" in cov or not cov:
            out["reason"] = "no coverage for the package"
        elif not vuln_ev["hashes"] or not fixed_ev["hashes"]:
            out["reason"] = "package files not found"
        elif ev_outcome != ("pass" if vuln_outcome == "pass" else "not_pass"):
            out["reason"] = "coverage run did not reproduce the vulnerable outcome"
        elif not changed:
            out["reason"] = "no package file differs between vulnerable and fixed"
        elif not api:
            out["reason"] = "no package function executed beyond import"
        elif sink_in_tree:
            out["rule"] = "sink"
            if out["sink_functions"]:
                out["confirmed"] = True
            else:
                out["reason"] = "innermost function containing the sink line not executed beyond import"
        else:
            out["rule"] = "changed_file"
            if out["related_functions"]:
                out["confirmed"] = True
            else:
                out["reason"] = "no executed function in a file changed by the fix"
    if adjudication:
        out["adjudication"] = f"{adjudication['decision']} by {adjudication['reviewer']} on {adjudication['date']}"
        out["confirmed"] = adjudication["decision"] == "confirmed"
        out["rule"] = "adjudication"
        out["reason"] = "" if out["confirmed"] else f"adjudicated rejected: {adjudication['rationale'][:120]}"
    return out


ADJUDICATION_FIELDS = ("record_id", "decision", "reviewer", "date", "evidence", "rationale")


def load_adjudications(rows: list[dict[str, str]]) -> dict[str, dict[str, str]]:
    pass
    out = {}
    for row in rows:
        if row.get("decision") not in ("confirmed", "rejected"):
            raise ValueError(f"adjudication {row.get('record_id')}: decision must be confirmed/rejected")
        if not all(row.get(k, "").strip() for k in ("reviewer", "date", "evidence", "rationale")):
            raise ValueError(f"adjudication {row['record_id']}: reviewer, date, evidence and rationale are required")
        if row["record_id"] in out:
            raise ValueError(f"adjudication {row['record_id']} listed twice")
        out[row["record_id"]] = row
    return out


def redos_flags(status: str, vulnerable_ms: Any, fixed_ms: Any, cfg: dict[str, Any]) -> dict[str, Any]:
    pass
    try:
        v, f = float(vulnerable_ms), float(fixed_ms)
    except (TypeError, ValueError):
        return {"ratio": "", "flag": "no_timing"}
    ratio = round(v / max(f, 1.0), 1)
    flag = ""
    if status != "validated" and v < cfg["threshold_ms"] and ratio >= cfg["min_ratio"]:
        flag = "oracle_threshold_not_met"
    elif status == "validated" and v < cfg["near_threshold_ms"]:
        flag = "near_threshold"
    return {"ratio": ratio, "flag": flag}




ALIGN_STATUSES = ("unique_exact", "unique_near", "ambiguous", "unresolved", "file_missing")


def align_body(body_tokens: list[str], candidates: list[tuple[int, int, list[str]]], cfg: dict[str, Any]) -> dict[str, Any]:
    pass






    from raven import overlap as ov

    exact = [c for c in candidates if c[2] == body_tokens]
    if len(exact) == 1:
        return {"status": "unique_exact", "start_line": exact[0][0], "end_line": exact[0][1], "score": 1.0,
                "runner_up": 0.0, "best_start": exact[0][0], "best_end": exact[0][1]}
    if len(exact) > 1:
        return {"status": "ambiguous", "start_line": "", "end_line": "", "score": 1.0, "runner_up": 1.0,
                "best_start": exact[0][0], "best_end": exact[0][1], "note": f"{len(exact)} identical candidates"}
    target = np.unique(ov.shingles(body_tokens, cfg["shingle_k"]))
    scored = sorted(((ov.jaccard(target, np.unique(ov.shingles(c[2], cfg["shingle_k"]))), c) for c in candidates),
                    key=lambda x: (-x[0], x[1][0]))
    
    best_span = {"best_start": scored[0][1][0], "best_end": scored[0][1][1]} if scored else {"best_start": "", "best_end": ""}
    if not scored or scored[0][0] < cfg["near_jaccard"]:
        return {"status": "unresolved", "start_line": "", "end_line": "", "score": round(scored[0][0], 4) if scored else 0.0,
                "runner_up": round(scored[1][0], 4) if len(scored) > 1 else 0.0, **best_span}
    best, runner = scored[0][0], (scored[1][0] if len(scored) > 1 else 0.0)
    status = "unique_near" if best - runner >= cfg["margin"] else "ambiguous"
    return {"status": status, "start_line": scored[0][1][0] if status == "unique_near" else "",
            "end_line": scored[0][1][1] if status == "unique_near" else "", "score": round(best, 4),
            "runner_up": round(runner, 4), **best_span}


def jsvul_pair_status(vuln: dict[str, Any], fixed: dict[str, Any]) -> tuple[str, str]:
    pass
    ok = {"unique_exact", "unique_near"}
    if vuln["status"] in ok and fixed["status"] in ok:
        return "aligned_not_reproduced", ""
    return "no_correspondence", f"vulnerable {vuln['status']}, fixed {fixed['status']}"




_PHP_BLOCK_COMMENT = re.compile(r"/\*.*?\*/", re.DOTALL)
_PHP_LINE_COMMENT = re.compile(r"(^|\s)(//|#).*$")
_PHP_BLOCKS = re.compile(r"<\?php(.*?)(\?>|\Z)", re.DOTALL)
_PHP_SOURCE = re.compile(r"^\$tainted\s*=")


PHP_SINKS: dict[str, re.Pattern[str]] = {
    "CWE-78": re.compile(r"\b(system|exec|shell_exec|passthru|popen|proc_open|pcntl_exec)\s*\("),
    "CWE-79": re.compile(r"^(echo|print)\b|\bprintf\s*\("),
    "CWE-89": re.compile(r"\b(mysql_query|mysqli_query|pg_query|sqlite_query|mssql_query)\s*\(|->(query|prepare|exec)\s*\("),
    "CWE-90": re.compile(r"\bldap_(search|list|read)\s*\("),
    "CWE-91": re.compile(r"->xpath\s*\(|\bxpath_eval\s*\("),
    "CWE-95": re.compile(r"\b(eval|assert|create_function)\s*\("),
    "CWE-98": re.compile(r"\b(include|require|include_once|require_once)\b"),
    "CWE-601": re.compile(r"\b(header|http_redirect)\s*\("),
}
PHP_SINKS["CWE-862"] = PHP_SINKS["CWE-89"]  


def php_code_lines(source: str) -> list[str]:
    pass




    lines = []
    for block in _PHP_BLOCKS.findall(source):
        text = _PHP_BLOCK_COMMENT.sub("", block[0])
        for line in text.splitlines():
            stripped = _PHP_LINE_COMMENT.sub("", line).strip()
            if stripped:
                lines.append(stripped)
    return lines


def php_case_name(file_name: str) -> dict[str, str]:
    pass
    parts = Path(file_name).stem.split("__")
    if len(parts) != 4:
        return {}
    cwe = "CWE-" + parts[0].split("_")[1]
    return {"cwe": cwe, "input": parts[1], "sanitize": parts[2], "construction": parts[3]}


def php_twin_check(bad: str, good: str, cwe: str, names: tuple[str, str] = ("", "")) -> dict[str, Any]:
    pass







    import difflib

    out: dict[str, Any] = {"hunks": 0, "prefix_lines": 0, "suffix_lines": 0, "source_line": "", "sink_line": ""}
    if any(names):
        meta = [php_case_name(n) for n in names]
        if not all(meta):
            return {**out, "valid": False, "reason": "case_name_unparsed"}
        for key in ("cwe", "input", "construction"):
            if meta[0][key] != meta[1][key]:
                return {**out, "valid": False, "reason": f"metadata_{key}_differs"}
        if meta[0]["cwe"] != cwe:
            return {**out, "valid": False, "reason": "metadata_cwe_mismatch"}
        if meta[0]["sanitize"] == meta[1]["sanitize"]:
            return {**out, "valid": False, "reason": "metadata_same_sanitizer"}
    sink = PHP_SINKS.get(cwe)
    if sink is None:
        return {**out, "valid": False, "reason": "no_sink_pattern_for_cwe"}
    a, b = php_code_lines(bad), php_code_lines(good)
    blocks = [m for m in difflib.SequenceMatcher(None, a, b, autojunk=False).get_opcodes() if m[0] != "equal"]
    if not blocks:
        return {**out, "valid": False, "reason": "identical_code"}
    prefix, suffix = blocks[0][1], len(a) - blocks[-1][2]
    out.update(hunks=len(blocks), prefix_lines=prefix, suffix_lines=suffix,
               changed_bad_lines=blocks[-1][2] - blocks[0][1], changed_good_lines=blocks[-1][4] - blocks[0][3])
    source = next((i for i, line in enumerate(a) if _PHP_SOURCE.search(line)), None)
    if source is None:
        return {**out, "valid": False, "reason": "no_source_statement"}
    out["source_line"] = a[source]
    if source >= prefix:
        return {**out, "valid": False, "reason": "source_not_in_common_prefix"}
    sinks_a = [i for i, line in enumerate(a) if sink.search(line)]
    sinks_b = [i for i, line in enumerate(b) if sink.search(line)]
    if not sinks_a or not sinks_b:
        return {**out, "valid": False, "reason": "no_sink_statement"}
    out["sink_line"] = a[sinks_a[-1]]
    if a[sinks_a[-1]] != b[sinks_b[-1]]:
        return {**out, "valid": False, "reason": "sink_statement_differs"}
    if sinks_a[-1] < blocks[-1][2] or sinks_b[-1] < blocks[-1][4]:
        return {**out, "valid": False, "reason": "sink_not_in_common_suffix"}
    changed = [line for tag, i1, i2, j1, j2 in blocks for line in a[i1:i2] + b[j1:j2]]
    if any(sink.search(line) for line in changed):
        return {**out, "valid": False, "reason": "sink_call_in_changed_region"}
    return {**out, "valid": True, "reason": ""}





def availability_level(source: str, *, file_ok: bool, snapshot_ok: bool, aligned: bool, reproduced: bool) -> str:
    pass





    if reproduced and snapshot_ok:
        return "C3"
    if snapshot_ok and aligned:
        return "C2"
    if file_ok and aligned:
        return "C1"
    return "C0"
