"""P3 commands: identity acquisition, overlap/purge/splits/roles, and the split checker.

``acquire-identities`` (network): npm version documents and vulnerable-version tarballs for
every SecBench row, and GitHub rename lookups for every repository. Nothing is installed or
executed.

``overlap``: canonical keys + code equivalence → union-find groups over **all** records →
purge of every group touching SecBench → temporal JsVul split → PHP compositional split →
roles (``external``, ``pilot_dev``, ``confirmatory_reserved``).

``check-split``: re-derives the invariants from the written keys/edges, independently of
the group ids, and fails on any violation.
"""

from __future__ import annotations

import hashlib
import json
import re
import tarfile
import zipfile
from collections import Counter, defaultdict
from pathlib import Path, PurePosixPath
from typing import Any

from raven import identities as ids
from raven import inventory as inv
from raven import overlap as ov
from raven import provenance as prov
from raven.config import REPO_ROOT
from raven.p2 import (
    INVENTORY_FILES,
    SUBSET_FILES,
    LineageError,
    _data_root,
    _digest,
    _from_run,
    _input,
    _json,
    check_lineage,
)
from raven.runlog import Run

CODE_EXTENSIONS = {"js", "mjs", "cjs", "jsx", "ts", "tsx", "mts", "cts"}
ROLES = ("external", "pilot_dev", "confirmatory_reserved")


def _secbench_targets(row: dict[str, str], helpers: set[str]) -> dict[str, Any]:
    packages = [p for p in row["package"].split(";") if p]
    versions = row["vulnerable_version"].split(";") if row["vulnerable_version"] else []
    versions += [""] * (len(packages) - len(versions))
    targets, aux, rule = ids.target_dependencies(row["record_id"], packages, helpers)
    by_name = dict(zip(packages, versions))
    return {
        "targets": [(p, by_name[p]) for p in targets],
        "auxiliary": [(p, by_name[p]) for p in aux],
        "rule": rule if packages else "no_dependencies",
    }





def run_acquire(run: Run, inventory_run: Path) -> dict[str, Any]:
    inventory_run = _from_run(inventory_run, "inventory")
    cfg = run.config["p3"]
    helpers = {ids.canonical_package(h) for h in cfg["test_helper_packages"]}
    guard = prov.StorageGuard.from_config(_data_root(), run.config["p2"]["storage"])
    fetcher = prov.Fetcher(guard, run.logger.info)
    npm = prov.NpmRecovery(fetcher, _data_root(), run.config["p2"]["npm_tarball_max_mib"] * prov.MiB)
    npm.root = _data_root() / "snapshots" / "secbench"
    docs_root = _data_root() / "identities" / "npm"

    secbench = inv.read_rows(inventory_run / "inventory_secbench.csv.gz")
    jsvul = inv.read_rows(inventory_run / "inventory_jsvul.csv.gz")

    def version_doc(package: str, version: str) -> dict[str, Any]:
        pass
        tag = version if prov.is_exact_version(version) else "latest"
        url = f"https://registry.npmjs.org/{package.replace('/', '%2F')}/{tag}"
        dest = docs_root / package.replace("/", "__") / f"{tag}.json"
        fetch = fetcher.download(url, dest, 8 * prov.MiB)
        out = {"package": package, "requested": version, "tag": tag, "ok": fetch.ok,
               "error": fetch.error, "sha256": fetch.sha256, "repos": []}
        if fetch.ok:
            doc = json.loads(Path(fetch.path).read_text(encoding="utf-8"))
            repo = doc.get("repository")
            urls = [repo.get("url", "") if isinstance(repo, dict) else str(repo or "")]
            bugs = doc.get("bugs")
            urls += [doc.get("homepage") or "", bugs.get("url", "") if isinstance(bugs, dict) else ""]
            out["repos"] = sorted({r for r in map(ids.canonical_repo, urls) if r})
            out["resolved_version"] = doc.get("version", "")
        return out

    def one(row: dict[str, str]) -> dict[str, Any]:
        plan = _secbench_targets(row, helpers)
        docs = [version_doc(p, v) for p, v in plan["targets"]]
        tarballs = [npm.fetch_version(p, v) for p, v in plan["targets"] if prov.is_exact_version(v)]
        return {"record_id": row["record_id"], **plan, "docs": docs, "tarballs": tarballs}

    records = prov.run_parallel(one, secbench, run.config["p2"]["workers"])
    run.logger.info("secbench identities: %d rows", len(records))

    repos = {f"github.com/{r['project'].lower()}" for r in jsvul if r["project"]}
    for rec in records:
        for doc in rec["docs"]:
            repos.update(doc["repos"])
    for row in secbench:
        if row["fix_repo"]:
            repos.add(f"github.com/{row['fix_repo'].lower()}")
        repos.update(r for r in map(ids.canonical_repo, row["links"].split(";")) if r)
    github = sorted(r.removeprefix("github.com/") for r in repos if r.startswith("github.com/"))
    locations = dict(zip(github, prov.run_parallel(ids.github_location, github, run.config["p2"]["workers"])))
    run.logger.info("github lookups: %d repos", len(github))

    _json(run.path / "identities_secbench.json", records)
    _json(run.path / "github_locations.json",
          {repo: {"status": status, "renamed_to": target} for repo, (status, target) in locations.items()})
    _json(run.path / "fetch_log.json", fetcher.records)
    summary = {
        "inventory_run": inventory_run.name,
        "inventory_files": _digest(inventory_run, INVENTORY_FILES),
        "secbench_rows": len(records),
        "target_rules": dict(Counter(r["rule"] for r in records)),
        "docs_ok": sum(d["ok"] for r in records for d in r["docs"]),
        "docs_total": sum(len(r["docs"]) for r in records),
        "tarballs_ok": sum(t["ok"] for r in records for t in r["tarballs"]),
        "tarballs_total": sum(len(r["tarballs"]) for r in records),
        "rows_without_tarball": sum(not any(t["ok"] for t in r["tarballs"]) for r in records),
        "github_status": dict(Counter(str(s) for s, _ in locations.values())),
        "github_renamed": sum(bool(t) and not t.startswith("error") for _, t in locations.values()),
        "bytes_written": guard.written,
    }
    summary["output_files"] = _digest(run.path, ("identities_secbench.json", "github_locations.json"))
    _json(run.path / "acquire_summary.json", summary)
    return summary





def _check_identities(identities_run: Path, inventory_run: Path) -> dict[str, Any]:
    summary = json.loads((identities_run / "acquire_summary.json").read_text())
    if summary["inventory_run"] != inventory_run.name or summary["inventory_files"] != _digest(inventory_run, INVENTORY_FILES):
        raise LineageError(f"{identities_run.name} was not acquired from {inventory_run.name}")
    if _digest(identities_run, tuple(summary["output_files"])) != summary["output_files"]:
        raise LineageError(f"{identities_run.name} outputs changed after acquisition")
    return summary


def _repo_aliases(repo: str, locations: dict[str, dict[str, Any]]) -> set[str]:
    keys = {f"repo:{repo}"}
    if repo.startswith("github.com/"):
        renamed = locations.get(repo.removeprefix("github.com/"), {}).get("renamed_to", "")
        if renamed and not renamed.startswith("error"):
            keys.add(f"repo:github.com/{renamed.lower()}")
    return keys


def _jsvul_bodies(path: Path) -> dict[str, str]:
    bodies = {}
    with zipfile.ZipFile(path) as zf:
        for split in inv.JSVUL_SPLITS:
            for raw in zf.open(f"{split}.jsonl"):
                rec = json.loads(raw)
                bodies[rec["id"]] = rec.get("body") or ""
    return bodies


def _tarball_functions(
    path: Path, max_file_bytes: int, min_tokens: int
) -> tuple[list[tuple[str, int, int, list[str]]], dict[str, str]]:
    pass




    out, boundaries = [], {}
    with tarfile.open(path, "r:gz") as tar:
        for member in tar:
            if not member.isfile():
                continue
            parts = member.name.split("/")
            if parts[-1] == "package.json" and len(parts) > 2:
                handle = tar.extractfile(member)
                try:
                    name = str(json.loads(handle.read()).get("name") or "") if handle else ""
                except (ValueError, UnicodeDecodeError, AttributeError):
                    name = ""
                
                
                if name:
                    boundaries[member.name[: -len("package.json")]] = name
                continue
            ext = PurePosixPath(member.name).suffix.lstrip(".").lower()
            if ext not in CODE_EXTENSIONS or member.size > max_file_bytes:
                continue
            handle = tar.extractfile(member)
            if handle is None:
                continue
            for start, end, tokens in ov.functions_in(handle.read(), ext, min_tokens):
                out.append((member.name, start, end, tokens))
    return out, boundaries


def nested_boundary(member: str, boundaries: dict[str, str]) -> str:
    pass
    best = ""
    for directory in boundaries:
        if member.startswith(directory) and len(directory) > len(best):
            best = directory
    return boundaries.get(best, "")


def _alnum(text: str) -> str:
    return re.sub(r"[^a-z0-9]", "", text.lower())


def is_own_package_file(package: str, member: str) -> bool:
    pass
    base = _alnum(package.rsplit("/", 1)[-1])
    stem = _alnum(PurePosixPath(member).name.split(".", 1)[0])
    return len(base) >= 3 and base in stem


MATCH_PRIORITY = {"own": 0, "unresolved": 1, "bundled": 2}


def classify_match(package: str, member: str, boundary: str, n_packages: int, cfg: dict[str, Any]) -> tuple[str, str]:
    pass






    rel = member.split("/", 1)[1] if "/" in member else member
    if is_own_package_file(package, rel):
        return "own", "own_named_file"
    if boundary and ids.canonical_package(boundary) != ids.canonical_package(package):
        return "bundled", f"nested_package:{boundary}"
    if re.search(cfg["vendor_path_regex"], rel, re.IGNORECASE):
        return "bundled", "vendor_path"
    if re.search(cfg["build_output_regex"], rel, re.IGNORECASE):
        return "unresolved", "build_output_not_own_named"
    if n_packages > cfg["shared_package_limit"]:
        return "unresolved", f"shared_across_{n_packages}_packages"
    return "own", "package_source"


def aggregate_external_matches(matches: list[dict[str, Any]], cfg: dict[str, Any]) -> list[dict[str, Any]]:
    pass




    packages: dict[str, set[str]] = defaultdict(set)
    for m in matches:
        packages[m["b"]].add(m["package"])
    for m in matches:
        m["class"], m["reason"] = classify_match(m["package"], m["member"], m["boundary"], len(packages[m["b"]]), cfg)
    by_pair: dict[tuple[str, str], list[dict[str, Any]]] = defaultdict(list)
    for m in matches:
        by_pair[(m["a"], m["b"])].append(m)
    edges = []
    for (a, b), locs in sorted(by_pair.items()):
        best = min(MATCH_PRIORITY[m["class"]] for m in locs)
        chosen = [m for m in locs if MATCH_PRIORITY[m["class"]] == best]
        top = max(chosen, key=lambda m: (m["kind"] == "exact", m["jaccard"], m["loc"]))
        kind = "code" if chosen[0]["class"] == "own" else chosen[0]["class"]
        edges.append({
            "a": a, "b": b, "type": f"external_{kind}_{top['kind']}", "jaccard": top["jaccard"],
            "a_loc": top["loc"], "b_loc": "",
            "evidence": json.dumps({
                "locations": len(locs),
                "classes": dict(Counter(m["class"] for m in locs)),
                "reasons": dict(Counter(m["reason"] for m in locs)),
                "examples": [f"{m['class']}|{m['reason']}|{m['loc']}" for m in sorted(locs, key=lambda m: m["loc"])[:10]],
            }, sort_keys=True),
        })
    return edges


AUDIT_DECISIONS = ("target_in_own_code", "target_in_bundled_boundary", "unresolved")
AUDIT_FIELDS = ("instance", "decision", "boundary_package", "target_location", "evidence", "decided", "decided_by")


def load_bundled_audit(path: Path) -> dict[str, dict[str, str]]:
    pass
    rows = inv.read_rows(path)
    if rows and tuple(rows[0]) != AUDIT_FIELDS:
        raise ValueError(f"{path}: columns must be {AUDIT_FIELDS}")
    audit: dict[str, dict[str, str]] = {}
    for row in rows:
        if row["decision"] not in AUDIT_DECISIONS:
            raise ValueError(f"{row['instance']}: unknown decision {row['decision']!r}")
        if not row["evidence"].strip():
            raise ValueError(f"{row['instance']}: decision without evidence")
        if row["decision"] == "target_in_bundled_boundary" and not row["boundary_package"]:
            raise ValueError(f"{row['instance']}: boundary decision needs boundary_package")
        if row["instance"] in audit:
            raise ValueError(f"{row['instance']}: more than one decision")
        audit[row["instance"]] = row
    return audit


def apply_boundary_decisions(edges: list[dict[str, Any]], audit: dict[str, dict[str, str]]) -> int:
    pass
    changed = 0
    for e in edges:
        row = audit.get(e["a"])
        if row and row["decision"] == "target_in_bundled_boundary" and e["type"].startswith("external_bundled_"):
            reasons = json.loads(e["evidence"])["reasons"]
            if f"nested_package:{row['boundary_package']}" in reasons:
                e["type"] = e["type"].replace("external_bundled_", "external_code_")
                changed += 1
    return changed


def bundled_gate(
    edges: list[dict[str, Any]], group_of: dict[str, str], external_groups: set[str],
    audit: dict[str, dict[str, str]],
) -> tuple[dict[str, str], list[str]]:
    pass




    overrides: dict[str, set[str]] = defaultdict(set)
    missing: set[str] = set()
    for e in edges:
        if not e["type"].startswith("external_bundled_") or group_of[e["b"]] in external_groups:
            continue
        row = audit.get(e["a"])
        if row is None:
            missing.add(e["a"])
        elif row["decision"] == "unresolved":
            overrides[group_of[e["b"]]].add(e["a"])
    return ({g: "bundled_audit_unresolved:" + ";".join(sorted(i)) for g, i in overrides.items()},
            sorted(missing))


def _tarball_snippet(loc: str) -> str:
    pass
    head, member, span = loc.split(":", 2)
    package, version = head.rsplit("@", 1)
    start, end = (int(x) for x in span.split("-"))
    path = _data_root() / "snapshots" / "secbench" / package.replace("/", "__") / f"{version}.tgz"
    with tarfile.open(path, "r:gz") as tar:
        handle = tar.extractfile(member)
        lines = handle.read().decode("utf-8", errors="replace").splitlines() if handle else []
    return "\n".join(lines[start - 1:end])


def run_overlap(run: Run, inventory_run: Path, select_run: Path, identities_run: Path) -> dict[str, Any]:
    inventory_run = _from_run(inventory_run, "inventory")
    select_run = _from_run(select_run, "select-subsets")
    identities_run = _from_run(identities_run, "acquire-identities")
    selection = check_lineage(run.config, inventory_run, select_run)
    _check_identities(identities_run, inventory_run)
    cfg, seed = run.config["p3"], run.config["seed"]
    code_cfg = cfg["code"]

    jsvul = inv.read_rows(inventory_run / "inventory_jsvul.csv.gz")
    secbench = inv.read_rows(inventory_run / "inventory_secbench.csv.gz")
    identities = {r["record_id"]: r for r in json.loads((identities_run / "identities_secbench.json").read_text())}
    locations = json.loads((identities_run / "github_locations.json").read_text())

    
    keys: dict[str, set[str]] = {}
    for r in jsvul:
        node = f"jsvul:{r['record_id']}"
        k = _repo_aliases(f"github.com/{r['project'].lower()}", locations)
        k |= ids.advisory_keys(r["cve"], r["ghsa"], r["snyk"], r["other"])
        if ids.COMMIT.match(r["revision"]):
            k.add(f"commit:{r['revision']}")
        keys[node] = k
    no_repo_secbench = 0
    for r in secbench:
        node = f"secbench:{r['record_id']}"
        ident = identities[r["record_id"]]
        k = {f"npm:{ids.canonical_package(p)}" for p, _ in ident["targets"]}
        repos = {repo for doc in ident["docs"] for repo in doc["repos"]}
        if r["fix_repo"]:
            repos.add(f"github.com/{r['fix_repo'].lower()}")
        repos |= {x for x in map(ids.canonical_repo, r["links"].split(";")) if x}
        for repo in repos:
            k |= _repo_aliases(repo, locations)
        no_repo_secbench += not repos
        k |= ids.advisory_keys(r["advisory_id"], r["links"], r["fix_commit_url"])
        if ids.COMMIT.match(r["fix_commit"]):
            k.add(f"commit:{r['fix_commit']}")
        keys[node] = k
    run.logger.info("metadata keys: %d nodes", len(keys))

    
    path, _ = _input(run.config["p2"]["manifest"]["jsvul"], run)
    bodies = _jsvul_bodies(path)
    project = {f"jsvul:{r['record_id']}": r["project"].lower() for r in jsvul}
    ext = {f"jsvul:{r['record_id']}": r["extension"] for r in jsvul}
    hashes: dict[str, str] = {}
    shingle_sets: dict[str, Any] = {}
    short = 0
    tokenization: Counter = Counter()
    for r in jsvul:
        node = f"jsvul:{r['record_id']}"
        tokens, how = ov.snippet_tokens(bodies[r["record_id"]].encode(), ext[node])
        tokenization[how] += 1
        if len(tokens) < code_cfg["min_tokens"]:
            short += 1
            continue
        hashes[node] = ov.token_hash(tokens)
        shingle_sets[node] = ov.shingles(tokens, code_cfg["shingle_k"])
    projects_per_hash: dict[str, set[str]] = defaultdict(set)
    for node, h in hashes.items():
        projects_per_hash[h].add(project[node])
    generic = {h for h, ps in projects_per_hash.items() if len(ps) > code_cfg["generic_project_limit"]}
    by_hash: dict[str, list[str]] = defaultdict(list)
    for node, h in hashes.items():
        by_hash[h].append(node)
        if h not in generic:
            keys[node].add(f"code:{h}")
    run.logger.info("jsvul code: %d hashed, %d below %d tokens, %d generic hashes",
                    len(hashes), short, code_cfg["min_tokens"], len(generic))

    hasher = ov.MinHasher(code_cfg["minhash_permutations"], code_cfg["lsh_bands"], seed)
    index = ov.NearDuplicateIndex(hasher, code_cfg["near_duplicate_jaccard"])
    for node in sorted(shingle_sets):
        index.add(node, shingle_sets[node])

    edges: list[dict[str, Any]] = []
    for node in sorted(shingle_sets):
        if hashes[node] in generic:
            continue
        for other, score in index.query(shingle_sets[node], exclude=node):
            if other > node and project[other] != project[node] and hashes[other] not in generic:
                exact = hashes[other] == hashes[node]
                edges.append({"a": node, "b": other, "type": "jsvul_code_exact" if exact else "jsvul_code_near",
                              "jaccard": score, "a_loc": "", "b_loc": ""})
    run.logger.info("jsvul-jsvul code edges: %d", len(edges))

    secbench_code = {"with_tarball": 0, "functions": 0, "without_code": 0}
    matches: list[dict[str, Any]] = []
    for r in secbench:
        node = f"secbench:{r['record_id']}"
        tarballs = [t for t in identities[r["record_id"]]["tarballs"] if t["ok"]]
        if not tarballs:
            secbench_code["without_code"] += 1
            continue
        secbench_code["with_tarball"] += 1
        for t in tarballs:
            tar_path = _data_root() / "snapshots" / "secbench" / t["package"].replace("/", "__") / f"{t['version']}.tgz"
            functions, boundaries = _tarball_functions(tar_path, code_cfg["max_file_kib"] * 1024, code_cfg["min_tokens"])
            for member, start, end, tokens in functions:
                secbench_code["functions"] += 1
                base = {"a": node, "package": t["package"], "member": member,
                        "loc": f"{t['package']}@{t['version']}:{member}:{start}-{end}",
                        "boundary": nested_boundary(member, boundaries)}
                for other in by_hash.get(ov.token_hash(tokens), ()):  
                    matches.append({**base, "b": other, "kind": "exact", "jaccard": 1.0})
                for other, score in index.query(ov.shingles(tokens, code_cfg["shingle_k"])):
                    if hashes.get(other) != ov.token_hash(tokens):
                        matches.append({**base, "b": other, "kind": "near", "jaccard": score})
    edges += aggregate_external_matches(matches, code_cfg)
    audit_path = REPO_ROOT / cfg["bundled_target_audit"]
    audit = load_bundled_audit(audit_path)
    boundary_retyped = apply_boundary_decisions(edges, audit)
    inv.write_rows(run.path / "external_matches.csv.gz",
                   ("a", "b", "kind", "jaccard", "package", "member", "loc", "boundary", "class", "reason"),
                   ({k: m[k] for k in ("a", "b", "kind", "jaccard", "package", "member", "loc", "boundary", "class", "reason")}
                    for m in sorted(matches, key=lambda m: (m["a"], m["b"], m["loc"], m["kind"]))))
    run.logger.info("secbench code: %s; total edges %d", secbench_code, len(edges))

    
    pair_edges = [(f"jsvul:{r['record_id']}", f"jsvul:{r['paired_id']}") for r in jsvul if r["paired_id"]]
    merging = [(e["a"], e["b"]) for e in edges if not e["type"].startswith("external_bundled_")]
    group_of = ov.build_groups(keys, merging + pair_edges)
    members: dict[str, list[str]] = defaultdict(list)
    for node, gid in group_of.items():
        members[gid].append(node)
    external_groups = {gid for gid, ns in members.items() if any(n.startswith("secbench:") for n in ns)}

    
    external_nodes = {n for n in keys if n.startswith("secbench:")}
    key_owners: dict[str, set[str]] = defaultdict(set)
    for node in external_nodes:
        for k in keys[node]:
            key_owners[k].add(node)
    direct: dict[str, list[str]] = defaultdict(list)
    for node, k in keys.items():
        if node.startswith("jsvul:"):
            for key in sorted(k):
                if key_owners.get(key):
                    direct[node].append(key)
    for e in edges:
        if e["type"].startswith(("external_code_", "external_unresolved_")):
            direct[e["b"]].append(f"{e['type']}:{e['a']}")
    excluded = []
    for gid in sorted(external_groups):
        group_direct = sorted({d for n in members[gid] for d in direct.get(n, ())})
        for node in sorted(n for n in members[gid] if n.startswith("jsvul:")):
            reason = ";".join(direct[node]) if direct.get(node) else f"transitive_via_group:{';'.join(group_direct[:5])}"
            excluded.append({"node": node, "group_id": gid, "linking_keys": reason})

    
    rows_by_node = {f"jsvul:{r['record_id']}": r for r in jsvul}
    retained = {gid: [rows_by_node[n] for n in ns if n.startswith("jsvul:")]
                for gid, ns in members.items() if gid not in external_groups}
    retained = {gid: rows for gid, rows in retained.items() if rows}
    split_of, cutoffs = ov.strict_temporal_split(retained, cfg["jsvul_split_fractions"])
    split_reason = {
        gid: ("temporal_window" if split != "quarantine"
              else "undated" if not any(r["publish_date"] for r in retained[gid]) else "straddles_cutoff")
        for gid, split in split_of.items()
    }
    overrides, missing = bundled_gate(edges, group_of, external_groups, audit)
    if missing:
        raise RuntimeError(f"gate 5c: no bundled-target decision for {missing}")
    for gid, reason in overrides.items():
        split_of[gid], split_reason[gid] = "quarantine", reason

    
    p2_ids = set()
    for name in ("subset_jsvul.csv",):
        p2_ids |= {f"jsvul:{r['record_id']}" for r in inv.read_rows(select_run / name)}
    prior = json.loads((REPO_ROOT / run.config["p2"]["prior_probe_ids"]).read_text())["record_ids"]
    touched = p2_ids | {f"jsvul:{i}" for i in prior}
    role_of = {}
    for gid, ns in members.items():
        if gid in external_groups:
            role_of[gid] = "external"
        elif touched & set(ns):
            role_of[gid] = "pilot_dev"
        else:
            role_of[gid] = "confirmatory_reserved"

    assignment = []
    for node, gid in sorted(group_of.items()):
        source = node.split(":", 1)[0]
        split = "external" if gid in external_groups else split_of.get(gid, "")
        reason = "external" if gid in external_groups else split_reason.get(gid, "")
        assignment.append({"node": node, "source": source, "group_id": gid, "split": split,
                           "split_reason": reason, "role": role_of[gid]})

    
    php = _php_split(run, inventory_run, select_run, seed)

    
    inv.write_rows(run.path / "overlap_keys.csv.gz", ("node", "key"),
                   ({"node": node, "key": key} for node in sorted(keys) for key in sorted(keys[node])))
    for e in edges:
        e.setdefault("evidence", "")
    inv.write_rows(run.path / "code_edges.csv.gz", ("a", "b", "type", "jaccard", "a_loc", "b_loc", "evidence"), edges)
    inv.write_rows(run.path / "split_assignment.csv.gz",
                   ("node", "source", "group_id", "split", "split_reason", "role"), assignment)
    inv.write_rows(run.path / "excluded_jsvul.csv", ("node", "group_id", "linking_keys"), excluded)
    role_by_node = {row["node"]: row["role"] for row in assignment}
    bundled_audit = [
        {"secbench": e["a"], "jsvul": e["b"], "jsvul_role": role_by_node[e["b"]], "type": e["type"],
         "jaccard": e["jaccard"], "location": e["a_loc"], "evidence": e["evidence"]}
        for e in edges if e["type"].startswith("external_bundled_") and role_by_node[e["b"]] != "external"
    ]
    inv.write_rows(run.path / "bundled_audit.csv",
                   ("secbench", "jsvul", "jsvul_role", "type", "jaccard", "location", "evidence"), bundled_audit)
    pilot_groups = []
    for gid, ns in sorted(members.items()):
        sources = sorted({n.split(":", 1)[0] for n in ns})
        fams = {project[n] for n in ns if n in project}
        pilot_groups.append({
            "group_id": gid, "sources": ";".join(sources), "role": role_of[gid],
            "split": "external" if gid in external_groups else split_of.get(gid, ""),
            "split_reason": "external" if gid in external_groups else split_reason.get(gid, ""),
            "records": len(ns), "jsvul_records": sum(n.startswith("jsvul:") for n in ns),
            "jsvul_projects": len(fams),
        })
    pilot_groups += php["groups"]
    inv.write_rows(run.path / "pilot_groups.csv",
                   ("group_id", "sources", "role", "split", "split_reason", "records", "jsvul_records",
                    "jsvul_projects"), pilot_groups)
    inv.write_rows(run.path / "php_split.csv", php["pair_fields"], php["pairs"])
    inv.write_rows(run.path / "php_cases.csv.gz", ("record_id", "sanitize", "construction", "split", "role", "group_id"), php["cases"])

    
    def family(node: str, loc: str) -> str:
        return project[node] if node.startswith("jsvul:") else loc.split(":", 1)[0].rsplit("@", 1)[0]

    def code_of(node: str, loc: str) -> str:
        return bodies.get(node.removeprefix("jsvul:"), "") if node.startswith("jsvul:") else _tarball_snippet(loc)

    strata = {
        "merged_jsvul_jsvul": [e for e in edges if e["type"] == "jsvul_code_near"],
        "merged_external": [e for e in edges if e["type"] in ("external_code_near", "external_unresolved_near")],
        "bundled_to_retained": [e for e in edges if e["type"].startswith("external_bundled_")
                                and role_of[group_of[e["b"]]] != "external"],
    }
    review: dict[str, Any] = {}
    for name, pool in strata.items():
        by_pair: dict[str, dict[str, Any]] = {}
        for e in sorted(pool, key=lambda e: (e["a"], e["b"])):
            by_pair.setdefault(f"{family(e['a'], e['a_loc'])}|{family(e['b'], e['b_loc'])}", e)
        chosen = prov.select_subset(by_pair, seed, f"p3-review-{name}", min(cfg["near_duplicate_review"], len(by_pair)))
        review[name] = {
            "pool_edges": len(pool), "distinct_family_pairs": len(by_pair),
            "pairs": [{**by_pair[c["record_id"]], "family_pair": c["record_id"],
                       "a_code": code_of(by_pair[c["record_id"]]["a"], by_pair[c["record_id"]]["a_loc"]),
                       "b_code": code_of(by_pair[c["record_id"]]["b"], ""),
                       "verdict": "", "reviewer": "", "note": ""} for c in chosen],
        }
    _json(run.path / "near_duplicate_review_sample.json", review)

    summary = {
        "inventory_run": inventory_run.name, "select_run": select_run.name, "identities_run": identities_run.name,
        "inventory_files": _digest(inventory_run, INVENTORY_FILES),
        "subset_files": selection["subset_files"],
        "nodes": len(keys), "groups": len(members),
        "edges": dict(Counter(e["type"] for e in edges)),
        "jsvul": {
            "records": len(jsvul), "hashed": len(hashes), "below_min_tokens": short,
            "body_tokenization": dict(tokenization),
            "generic_hashes": len(generic),
            "records_with_generic_hash": sum(h in generic for h in hashes.values()),
            "excluded_records": len(excluded),
            "excluded_projects": len({project[x["node"]] for x in excluded}),
            "excluded_direct": sum(not x["linking_keys"].startswith("transitive") for x in excluded),
            "retained_records": sum(len(v) for v in retained.values()),
            "retained_groups": len(retained),
            "temporal_cutoffs": dict(zip(list(cfg["jsvul_split_fractions"])[1:], cutoffs)),
            "split_records": dict(Counter(split_of[g] for g, rows in retained.items() for _ in rows)),
            "quarantine_reasons": dict(Counter(
                split_reason[g].split(":", 1)[0] for g in retained if split_of[g] == "quarantine")),
            "split_groups": dict(Counter(split_of.values())),
            "role_records": dict(Counter(role_of[group_of[n]] for n in rows_by_node)),
            "role_groups": dict(Counter(role_of[g] for g, ns in members.items() if any(n.startswith("jsvul:") for n in ns))),
            "role_projects": {
                r: len({project[n] for n, g in group_of.items() if role_of[g] == r and n in project}) for r in ROLES
            },
            "p2_subset_records_by_role": dict(Counter(role_of[group_of[n]] for n in p2_ids)),
            "prior_probe_by_role": dict(Counter(role_of[group_of[f"jsvul:{i}"]] for i in prior)),
            "largest_groups": sorted((len(ns) for ns in members.values()), reverse=True)[:10],
        },
        "secbench": {
            "records": len(secbench), "code": secbench_code, "without_repo_key": no_repo_secbench,
            "groups": len(external_groups),
        },
        "php": php["summary"],
    }
    summary["bundled_audit"] = {
        "edges_to_retained": len(bundled_audit),
        "retained_records": len({b["jsvul"] for b in bundled_audit}),
        "reasons": dict(Counter(r for b in bundled_audit for r in json.loads(b["evidence"])["reasons"])),
    }
    summary["bundled_gate"] = {
        "audit_file": cfg["bundled_target_audit"],
        "audit_sha256": hashlib.sha256(audit_path.read_bytes()).hexdigest(),
        "decisions": {i: r["decision"] for i, r in sorted(audit.items())},
        "boundary_edges_retyped": boundary_retyped,
        "quarantined_groups": len(overrides),
        "quarantined_records": sum(len([n for n in members[g] if n.startswith("jsvul:")]) for g in overrides),
        "quarantined_by_instance": dict(Counter(i for r in overrides.values() for i in r.split(":", 1)[1].split(";"))),
    }
    summary["external_match_classes"] = dict(Counter(m["class"] for m in matches))
    summary["external_match_reasons"] = dict(Counter(m["reason"].split(":")[0] for m in matches))
    outputs = ("overlap_keys.csv.gz", "code_edges.csv.gz", "external_matches.csv.gz", "bundled_audit.csv",
               "split_assignment.csv.gz", "excluded_jsvul.csv",
               "pilot_groups.csv", "php_split.csv", "php_cases.csv.gz")
    summary["output_files"] = _digest(run.path, outputs)
    _json(run.path / "overlap_summary.json", summary)
    return summary


def _php_split(run: Run, inventory_run: Path, select_run: Path, seed: int) -> dict[str, Any]:
    pass





    cfg = run.config["p3"]["php"]
    cases = inv.read_rows(inventory_run / "inventory_sard_php.csv.gz")
    pairs = inv.read_rows(inventory_run / "sard_candidate_pairs.csv.gz")
    pilot_pairs = {r["record_id"] for r in inv.read_rows(select_run / "subset_sard_php.csv")}
    by_id = {c["record_id"]: c for c in cases}
    combos = {(c["sanitize"], c["construction"]) for c in cases if c["sanitize"] and c["construction"]}
    held = {k for k in combos if ov.hash_fraction(seed, "sard_php_combo", f"{k[0]}|{k[1]}") < cfg["held_out_fraction"]}
    val_share = cfg["val_fraction"] / (1 - cfg["held_out_fraction"])

    def free_split(item: str) -> str:
        return "val" if ov.hash_fraction(seed, "sard_php_val", item) < val_share else "train"

    def combo(rid: str) -> tuple[str, str]:
        return by_id[rid]["sanitize"], by_id[rid]["construction"]

    split_of: dict[str, str] = {}
    pair_rows, in_pair = [], {}
    for p in pairs:
        bad, good = p["bad_record_id"], p["good_record_id"]
        held_twins = [t for t in (bad, good) if combo(t) in held]
        split = "test" if held_twins else free_split(p["pair_id"])
        split_of[bad] = split_of[good] = split
        in_pair[bad] = in_pair[good] = p["pair_id"]
        pair_rows.append({
            "pair_id": p["pair_id"], "cwe": p["cwe"], "sanitizer": p["good_sanitize"],
            "bad_sanitizer": p["bad_sanitize"], "construction": p["construction"],
            "held_out_via": ";".join("good" if t == good else "bad" for t in held_twins),
            "split": split, "role": "pilot_dev" if p["pair_id"] in pilot_pairs else "confirmatory_reserved",
        })
    unparsed = 0
    for c in cases:
        rid = c["record_id"]
        if rid in split_of:
            continue
        if not (c["sanitize"] and c["construction"]):
            split_of[rid] = ""
            unparsed += 1
        else:
            split_of[rid] = "test" if combo(rid) in held else free_split(rid)

    
    distractors: set[str] = set()
    for split in ("train", "val", "test"):
        pool = [rid for rid, s in split_of.items() if s == split and rid not in in_pair]
        distractors |= {x["record_id"] for x in prov.select_subset(
            pool, seed, f"sard_php_distractors_{split}", min(cfg["pilot_distractors_per_split"], len(pool)))}

    pair_role = {r["pair_id"]: r["role"] for r in pair_rows}
    case_rows = []
    for c in cases:
        rid = c["record_id"]
        if rid in in_pair:
            gid, role = f"php_pair:{in_pair[rid]}", pair_role[in_pair[rid]]
        else:
            gid, role = f"php_case:{rid}", "pilot_dev" if rid in distractors else "confirmatory_reserved"
        case_rows.append({"record_id": rid, "sanitize": c["sanitize"], "construction": c["construction"],
                          "split": split_of[rid], "role": role, "group_id": gid})
    by_group: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for row in case_rows:
        by_group[row["group_id"]].append(row)
    groups = [{"group_id": gid, "sources": "sard_php", "role": rows[0]["role"],
               "split": rows[0]["split"] if len({r["split"] for r in rows}) == 1 else "conflict",
               "split_reason": "compositional",
               "records": len(rows), "jsvul_records": 0, "jsvul_projects": 0}
              for gid, rows in sorted(by_group.items())]
    return {
        "pairs": pair_rows, "cases": case_rows, "groups": groups,
        "pair_fields": ("pair_id", "cwe", "sanitizer", "bad_sanitizer", "construction", "held_out_via", "split", "role"),
        "summary": {
            "cases": len(cases), "unparsed_cases": unparsed, "combos": len(combos), "held_out_combos": len(held),
            "case_splits": dict(Counter(split_of.values())),
            "pairs": len(pair_rows), "pair_splits": dict(Counter(r["split"] for r in pair_rows)),
            "pilot_pairs_by_split": dict(Counter(r["split"] for r in pair_rows if r["role"] == "pilot_dev")),
            "pilot_distractors": len(distractors),
            "pilot_distractors_by_split": dict(Counter(split_of[d] for d in distractors)),
        },
    }





def check_split(run: Run, inventory_run: Path, select_run: Path, overlap_run: Path, php: bool) -> dict[str, Any]:
    pass
    inventory_run = _from_run(inventory_run, "inventory")
    select_run = _from_run(select_run, "select-subsets")
    overlap_run = _from_run(overlap_run, "overlap")
    check_lineage(run.config, inventory_run, select_run)
    summary = json.loads((overlap_run / "overlap_summary.json").read_text())
    if (summary["inventory_run"], summary["select_run"]) != (inventory_run.name, select_run.name):
        raise LineageError(f"{overlap_run.name} was not built from these inventory/select runs")
    if _digest(overlap_run, tuple(summary["output_files"])) != summary["output_files"]:
        raise LineageError(f"{overlap_run.name} outputs changed after the overlap run")
    if summary["subset_files"] != _digest(select_run, SUBSET_FILES):
        raise LineageError("subset files differ from those used by the overlap run")
    audit_now = hashlib.sha256((REPO_ROOT / run.config["p3"]["bundled_target_audit"]).read_bytes()).hexdigest()
    if summary.get("bundled_gate", {}).get("audit_sha256") != audit_now:
        raise LineageError("bundled_target_audit.csv changed after the overlap run")
    result = verify_invariants(inventory_run, select_run, overlap_run, php, run.config)
    result["overlap_run"] = overlap_run.name
    _json(run.path / "check_split.json", result)
    if result["violations"]:
        raise AssertionError(f"{result['violations']} split invariant violations, e.g. {result['violation_examples'][:3]}")
    return result


def verify_invariants(inventory_run: Path, select_run: Path, overlap_run: Path, php: bool, config: dict[str, Any]) -> dict[str, Any]:
    violations: list[str] = []
    assignment = {r["node"]: r for r in inv.read_rows(overlap_run / "split_assignment.csv.gz")}
    groups = {r["group_id"]: r for r in inv.read_rows(overlap_run / "pilot_groups.csv")}

    
    per_group: dict[str, set[tuple[str, str]]] = defaultdict(set)
    for row in assignment.values():
        per_group[row["group_id"]].add((row["split"], row["role"]))
    violations += [f"group {g} has members in {sorted(v)}" for g, v in per_group.items() if len(v) > 1]
    violations += [f"group {g} missing from pilot_groups.csv" for g in per_group if g not in groups]
    violations += [f"group {g} has role {r['role']}" for g, r in groups.items() if r["role"] not in ROLES]

    
    owners: dict[str, set[str]] = defaultdict(set)
    for row in inv.read_rows(overlap_run / "overlap_keys.csv.gz"):
        owners[row["key"]].add(row["node"])
    leaks = 0
    for key, nodes in owners.items():
        if any(n.startswith("secbench:") for n in nodes):
            for n in nodes:
                if n.startswith("jsvul:") and assignment[n]["role"] != "external":
                    leaks += 1
                    violations.append(f"{n} shares {key} with external but is {assignment[n]['role']}")
    bundled = bundled_to_retained = 0
    for e in inv.read_rows(overlap_run / "code_edges.csv.gz"):
        ends = (e["a"], e["b"])
        if e["type"].startswith("external_bundled_"):
            
            bundled += 1
            bundled_to_retained += assignment[e["b"]]["role"] != "external"
            continue
        if any(x.startswith("secbench:") for x in ends):
            for x in ends:
                if x.startswith("jsvul:") and assignment[x]["role"] != "external":
                    leaks += 1
                    violations.append(f"{x} has {e['type']} to external but is {assignment[x]['role']}")
        elif assignment[e["a"]]["group_id"] != assignment[e["b"]]["group_id"]:
            violations.append(f"code edge {e['a']}–{e['b']} crosses groups")

    
    for key, nodes in owners.items():
        gids = {assignment[n]["group_id"] for n in nodes}
        if len(gids) > 1:
            violations.append(f"key {key} spans groups {sorted(gids)[:3]}")
    jsvul = inv.read_rows(inventory_run / "inventory_jsvul.csv.gz")
    twins_split = 0
    for r in jsvul:
        if r["paired_id"] and r["record_id"] < r["paired_id"]:
            a, b = assignment[f"jsvul:{r['record_id']}"], assignment[f"jsvul:{r['paired_id']}"]
            if (a["split"], a["group_id"]) != (b["split"], b["group_id"]):
                twins_split += 1
                violations.append(f"twins {r['record_id']} / {r['paired_id']} split apart")

    
    
    audit_path = REPO_ROOT / config["p3"]["bundled_target_audit"]
    audit = load_bundled_audit(audit_path)
    gate_expected: dict[str, set[str]] = defaultdict(set)
    gate_missing: set[str] = set()
    gate_needed: set[str] = set()
    for e in inv.read_rows(overlap_run / "code_edges.csv.gz"):
        if e["type"].startswith("external_bundled_") and assignment[e["b"]]["role"] != "external":
            gate_needed.add(e["a"])
            row = audit.get(e["a"])
            if row is None:
                gate_missing.add(e["a"])
            elif row["decision"] == "unresolved":
                gate_expected[assignment[e["b"]]["group_id"]].add(e["a"])
            elif row["decision"] == "target_in_bundled_boundary" and \
                    f"nested_package:{row['boundary_package']}" in json.loads(e["evidence"])["reasons"]:
                violations.append(f"{e['a']} boundary {row['boundary_package']} still bundled for {e['b']}")
    violations += [f"gate 5c: no decision for {i}" for i in sorted(gate_missing)]
    gate_reason = {g: "bundled_audit_unresolved:" + ";".join(sorted(i)) for g, i in gate_expected.items()}

    
    
    fractions = config["p3"]["jsvul_split_fractions"]
    dates = {f"jsvul:{r['record_id']}": r.get("publish_date", "") for r in jsvul}
    retained_dates = [dates[n] for n, a in assignment.items() if n.startswith("jsvul:") and a["role"] != "external"]
    cutoffs = ov.temporal_cutoffs(retained_dates, fractions)
    names = list(fractions)
    group_windows: dict[str, set[int]] = defaultdict(set)
    group_split: dict[str, tuple[str, str]] = {}
    for n, a in assignment.items():
        if n.startswith("jsvul:") and a["role"] != "external":
            group_split[a["group_id"]] = (a["split"], a.get("split_reason", ""))
            if dates[n]:
                group_windows[a["group_id"]].add(sum(dates[n] >= c for c in cutoffs))
    for gid, (split, reason) in group_split.items():
        windows = group_windows.get(gid, set())
        if gid in gate_reason:
            expected = ("quarantine", gate_reason[gid])
        elif len(windows) == 1:
            expected = (names[next(iter(windows))], "temporal_window")
        else:
            expected = ("quarantine", "straddles_cutoff" if windows else "undated")
        if (split, reason) != expected:
            violations.append(f"group {gid} is {(split, reason)}, expected {expected} for windows {sorted(windows)}")
    temporal = {"cutoffs": dict(zip(names[1:], cutoffs)),
                "groups": dict(Counter(s for s, _ in group_split.values())),
                "reasons": dict(Counter(r.split(":")[0] for _, r in group_split.values()))}
    gate = {"audit_sha256": hashlib.sha256(audit_path.read_bytes()).hexdigest(),
            "instances_needing_decision": sorted(gate_needed),
            "decisions": {i: r["decision"] for i, r in sorted(audit.items())},
            "missing": sorted(gate_missing), "quarantined_groups": len(gate_reason)}

    
    prior = json.loads((REPO_ROOT / config["p2"]["prior_probe_ids"]).read_text())["record_ids"]
    touched = {f"jsvul:{i}" for i in prior} | {f"jsvul:{r['record_id']}" for r in inv.read_rows(select_run / "subset_jsvul.csv")}
    violations += [f"{n} touched in pilot but confirmatory_reserved" for n in touched if assignment[n]["role"] == "confirmatory_reserved"]
    pilot = {g for g, r in groups.items() if r["role"] == "pilot_dev"}
    confirm = {g for g, r in groups.items() if r["role"] == "confirmatory_reserved"}
    if pilot & confirm:
        violations.append("pilot_dev and confirmatory_reserved overlap")

    result: dict[str, Any] = {"nodes": len(assignment), "groups": len(groups), "external_leaks": leaks,
                              "bundled_edges_not_merged": bundled,
                              "bundled_edges_to_retained_records": bundled_to_retained, "temporal": temporal,
                              "gate_5c": gate,
                              "twins_split_apart": twins_split, "touched_records": len(touched)}

    
    if php:
        cases = inv.read_rows(overlap_run / "php_cases.csv.gz")
        pairs = inv.read_rows(overlap_run / "php_split.csv")
        split_of = {c["record_id"]: c["split"] for c in cases}
        by_case = {c["record_id"]: c for c in cases}
        held = _held_out_combos(cases, config)
        for c in cases:
            if c["split"] in ("train", "val") and (c["sanitize"], c["construction"]) in held:
                violations.append(f"held-out combo {(c['sanitize'], c['construction'])} in {c['split']} ({c['record_id']})")
        for p in pairs:
            bad, good = p["pair_id"].split("+")
            if not (split_of[bad] == split_of[good] == p["split"]):
                violations.append(f"pair {p['pair_id']} twins not in one split")
            touches_held = {(by_case[t]["sanitize"], by_case[t]["construction"]) for t in (bad, good)} & held
            if touches_held and p["split"] != "test":
                violations.append(f"pair {p['pair_id']} uses held-out combo but is in {p['split']}")
        violations += [f"php group {g['group_id']} split conflict" for g in groups.values()
                       if g["sources"] == "sard_php" and g["split"] == "conflict"]
        result["php"] = {"held_out_combos": len(held), "cases": len(cases), "pairs": len(pairs),
                         "pair_splits": dict(Counter(p["split"] for p in pairs))}

    result["violations"] = len(violations)
    result["violation_examples"] = violations[:50]
    return result


def _held_out_combos(cases: list[dict[str, str]], config: dict[str, Any]) -> set[tuple[str, str]]:
    pass
    fraction = config["p3"]["php"]["held_out_fraction"]
    combos = {(c["sanitize"], c["construction"]) for c in cases if c["sanitize"] and c["construction"]}
    return {k for k in combos if ov.hash_fraction(config["seed"], "sard_php_combo", f"{k[0]}|{k[1]}") < fraction}


def file_sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()
