"""P4 commands: SecBench reproduction, JsVul alignment, PHP twin validation, summary.

P4 reads only ``pilot_dev`` and ``external`` records (asserted against the P3 reservation)
and never imports the detector or selectors.
"""

from __future__ import annotations

import hashlib
import json
import shutil
import subprocess
import tempfile
import zipfile
from collections import Counter
from pathlib import Path
from typing import Any

from raven import inventory as inv
from raven import pairs
from raven.p2 import LineageError, _data_root, _digest, _from_run, _input, _json, check_lineage
from raven.runlog import Run

ALLOWED_ROLES = {"pilot_dev", "external"}


EXTERNAL_ALLOWED_FIELDS = {
    "record_id", "package", "status", "detail", "vulnerable_outcome", "fixed_outcome",
    "fixed_failed_after_import", "vulnerable_build_failure", "fixed_build_failure",
    "vulnerable_image", "fixed_image", "compat_patch", "vulnerable_ms", "fixed_ms",
    "timing_ratio", "timing_flag", "sides", "oracle", "oracle_rule", "oracle_reason", "oracle_evidence",
}
SECBENCH_OUTPUT_FIELDS = (
    "record_id", "package", "status", "detail", "vulnerable_outcome", "fixed_outcome",
    "fixed_failed_after_import", "vulnerable_ms", "fixed_ms", "timing_ratio", "timing_flag",
    "vulnerable_build_failure", "fixed_build_failure", "vulnerable_image", "fixed_image",
    "compat_patch", "oracle", "oracle_rule", "oracle_reason", "oracle_evidence", "sides",
)
GiB = 1 << 30


def _roles(overlap_run: Path) -> dict[str, str]:
    return {r["node"]: r["role"] for r in inv.read_rows(overlap_run / "split_assignment.csv.gz")}


def assert_allowed(nodes: list[str], roles: dict[str, str]) -> None:
    bad = sorted(n for n in nodes if roles.get(n) not in ALLOWED_ROLES)
    if bad:
        raise PermissionError(f"P4 may read only pilot_dev/external records; got {bad[:5]}")


def _inputs(run: Run, inventory_run: Path, select_run: Path, overlap_run: Path) -> tuple[Path, Path, Path, dict[str, Any]]:
    pass




    inventory_run = _from_run(inventory_run, "inventory")
    select_run = _from_run(select_run, "select-subsets")
    overlap_run = _from_run(overlap_run, "overlap")
    selection = check_lineage(run.config, inventory_run, select_run)
    summary = json.loads((overlap_run / "overlap_summary.json").read_text())
    if (summary["inventory_run"], summary["select_run"]) != (inventory_run.name, select_run.name):
        raise LineageError(f"{overlap_run.name} was not built from these inventory/select runs")
    if summary["subset_files"] != selection["subset_files"]:
        raise LineageError(f"{overlap_run.name} used different subset files")
    if _digest(overlap_run, tuple(summary["output_files"])) != summary["output_files"]:
        raise LineageError(f"{overlap_run.name} outputs changed after the overlap run")
    lineage = {
        "inventory_run": inventory_run.name, "select_run": select_run.name, "overlap_run": overlap_run.name,
        "inventory_files": selection["inventory_files"], "subset_files": selection["subset_files"],
        "overlap_output_files": summary["output_files"],
    }
    return inventory_run, select_run, overlap_run, lineage


def _recover(recover_run: Path, lineage: dict[str, Any], source: str) -> tuple[Path, dict[str, Any]]:
    pass
    recover_run = _from_run(recover_run, "recover")
    recovered = json.loads((recover_run / "recovery_summary.json").read_text())
    if (recovered.get("inventory_run"), recovered.get("select_run")) != (lineage["inventory_run"], lineage["select_run"]):
        raise LineageError(f"{recover_run.name} was not recovered from these inventory/select runs")
    if recovered.get("subset_files") != lineage["subset_files"]:
        raise LineageError(f"{recover_run.name} used different subset files")
    if _digest(recover_run, tuple(recovered["output_files"])) != recovered["output_files"]:
        raise LineageError(f"{recover_run.name} outputs changed after recovery")
    if f"audit_provenance_{source}.csv" not in recovered["output_files"]:
        raise LineageError(f"{recover_run.name} did not recover {source}")
    return recover_run, {**lineage, "recover_run": recover_run.name, "recover_output_files": recovered["output_files"]}


def config_sha256(config: dict[str, Any]) -> str:
    pass
    return hashlib.sha256(json.dumps(config["p4"], sort_keys=True).encode()).hexdigest()


def _finish(run: Run, summary: dict[str, Any], lineage: dict[str, Any], outputs: tuple[str, ...], name: str) -> None:
    pass
    summary["inputs"] = lineage
    summary["p4_config_sha256"] = config_sha256(run.config)
    summary["output_files"] = _digest(run.path, outputs)
    if set(summary["output_files"]) != set(outputs):
        raise RuntimeError(f"missing outputs: {sorted(set(outputs) - set(summary['output_files']))}")
    _json(run.path / name, summary)





DEBIAN_ARCHIVE_PATCH = (
    "# RAVEN compatibility (docs/pilot-decisions.md, P4 exception 1): Debian 11 security\n"
    "# pool moved to archive.debian.org after LTS end; same package versions.\n"
    "RUN sed -i 's|http://deb.debian.org/debian-security|http://archive.debian.org/debian-security|g; "
    "s|http://security.debian.org/debian-security|http://archive.debian.org/debian-security|g' "
    "/etc/apt/sources.list && echo 'Acquire::Check-Valid-Until \"false\";' > /etc/apt/apt.conf.d/99raven-archive\n"
)


JEST_UNPINNED = "npm install -g --no-audit --no-fund jest\n"
JEST_PINNED = "npm install -g --no-audit --no-fund jest@29.7.0\n"


def prefer_checkout(text: str, refs: list[str] | str) -> str:
    pass
    refs = [refs] if isinstance(refs, str) else refs
    marker = 'if ! (git checkout -q "'
    if marker not in text:
        raise ValueError("no git checkout to override")
    first = "".join(f'git checkout -q "{ref}" || ' for ref in refs)
    return text.replace(marker, f'if ! ({first}git checkout -q "', 1)


def fixed_release_refs(fixed_version: str) -> list[str]:
    pass
    from raven import provenance as prov

    return [f"v{fixed_version}", fixed_version] if prov.is_exact_version(fixed_version) else []


def patch_dockerfile(text: str, copy_utils: bool) -> str:
    pass




    if JEST_UNPINNED in text:
        text = text.replace(JEST_UNPINNED, JEST_PINNED)
    lines = text.splitlines(keepends=True)
    index = next(i for i, line in enumerate(lines) if line.lstrip().upper().startswith("FROM "))
    out = lines[: index + 1] + ["\n", DEBIAN_ARCHIVE_PATCH] + lines[index + 1:]
    if copy_utils:
        out.append("\n# RAVEN compatibility (P4 exception 2): helper required by the PoC\n"
                   "COPY _raven_utils.js /exploit/utils.js\n")
    return "".join(out)


def _extract_instance(archive: zipfile.ZipFile, root: str, record_id: str, dest: Path,
                     fixed_refs: list[str] | None = None) -> dict[str, Any]:
    pass
    if dest.exists():
        shutil.rmtree(dest)
    dest.mkdir(parents=True)
    prefix = f"{root}/{record_id}/"
    for name in archive.namelist():
        if name.startswith(prefix) and not name.endswith("/"):
            target = dest / name[len(prefix):]
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(archive.read(name))
    patch: dict[str, Any] = {"debian_security_archive": True}
    utils = f"{root}/{record_id.split('/')[0]}/utils.js"
    copy_utils = utils in archive.namelist()
    if copy_utils:
        data = archive.read(utils)
        (dest / "_raven_utils.js").write_bytes(data)
        patch["utils"] = {"file": utils, "sha256": hashlib.sha256(data).hexdigest(), "target": "/exploit/utils.js"}
    for name in ("Dockerfile", "Dockerfile.fixed"):
        if not (dest / name).is_file():
            patch[f"{name}_missing"] = True
            continue
        patched = patch_dockerfile((dest / name).read_text(encoding="utf-8"), copy_utils)
        if name == "Dockerfile.fixed" and fixed_refs:
            try:
                patched = prefer_checkout(patched, fixed_refs)
                patch["fixed_checkout_refs"] = fixed_refs
            except ValueError:
                patch["fixed_checkout_refs"] = "no_git_checkout_in_dockerfile"
        (dest / f"{name}.raven").write_text(patched, encoding="utf-8")
        patch[f"{name}.raven_sha256"] = hashlib.sha256(patched.encode()).hexdigest()
    return patch


BUILD_CAUSES = (
    ("could not read Username for 'https://github.com'", "upstream_repo_unavailable"),
    ("Repository not found", "upstream_repo_unavailable"),
    ("cannot check out", "version_not_in_upstream_repo"),
    ("404  Not Found", "apt_package_unavailable"),
    ("npm ERR!", "npm_install_failed"),
    ("npm error", "npm_install_failed"),
)


class DockerUnavailable(RuntimeError):
    pass


DOCKER_DOWN = ("Cannot connect to the Docker daemon", "error during connect", "docker daemon is not running")


def ensure_docker_reachable(text: str) -> None:
    pass
    if any(marker in text for marker in DOCKER_DOWN):
        raise DockerUnavailable(f"Docker daemon unavailable: {text.strip()[:200]}")


def check_docker(run: Run) -> None:
    result = run.run_subprocess(["docker", "info", "--format", "{{.ServerVersion}}"], "docker-info", timeout=60)
    err = (run.path / "subprocess" / f"{run._calls:03d}-docker-info.stderr").read_text(errors="replace")
    if result.returncode != 0:
        raise DockerUnavailable(f"docker info failed: {err.strip()[:200]}")


def build_failure_cause(stderr: str) -> str:
    pass
    ensure_docker_reachable(stderr)
    for marker, cause in BUILD_CAUSES:
        if marker in stderr:
            return cause
    errors = [line.strip() for line in stderr.splitlines() if "ERROR" in line]
    return f"other: {errors[-1][:160]}" if errors else "other"


def _docker_id(run: Run, image: str) -> str:
    result = run.run_subprocess(["docker", "image", "inspect", "--format", "{{.Id}}", image], "inspect")
    out = (run.path / "subprocess" / f"{run._calls:03d}-inspect.stdout").read_text().strip()
    return out if result.returncode == 0 else ""


def _run_side(run: Run, image: str, name: str, workdir: str, policy: dict[str, Any]) -> tuple[dict[str, Any] | None, bool, str]:
    cmd = ["docker", "run", *pairs.isolation_args(name, policy), image,
           *pairs.jest_command(workdir, force_exit=policy.get("force_exit", True))]
    try:
        run.run_subprocess(cmd, f"poc-{name}", timeout=policy["timeout_s"])
    except subprocess.TimeoutExpired:
        subprocess.run(["docker", "rm", "-f", name], capture_output=True, check=False)
        return None, True, ""
    stdout_path = run.path / "subprocess" / f"{run._calls:03d}-poc-{name}.stdout"
    ensure_docker_reachable(stdout_path.with_suffix(".stderr").read_text(encoding="utf-8", errors="replace"))
    text = stdout_path.read_text(encoding="utf-8", errors="replace")
    return pairs.parse_jest(text), False, str(stdout_path.relative_to(run.path))


def _run_evidence(run: Run, image: str, name: str, workdir: str, package: str, specifier: str,
                  policy: dict[str, Any]) -> tuple[dict[str, Any] | None, str]:
    pass
    cmd = ["docker", "run", *pairs.isolation_args(name, policy), image,
           *pairs.evidence_command(workdir, package, specifier)]
    try:
        run.run_subprocess(cmd, f"evidence-{name}", timeout=2 * policy["timeout_s"])
    except subprocess.TimeoutExpired:
        subprocess.run(["docker", "rm", "-f", name], capture_output=True, check=False)
        return None, ""
    stem = run.path / "subprocess" / f"{run._calls:03d}-evidence-{name}"
    ensure_docker_reachable(Path(f"{stem}.stderr").read_text(encoding="utf-8", errors="replace"))
    out = Path(f"{stem}.stdout")
    return pairs.parse_evidence(out.read_text(encoding="utf-8", errors="replace")), str(out.relative_to(run.path))


def run_secbench_repro(run: Run, inventory_run: Path, select_run: Path, overlap_run: Path, recover_run: Path) -> dict[str, Any]:
    inventory_run, select_run, overlap_run, lineage = _inputs(run, inventory_run, select_run, overlap_run)
    recover_run, lineage = _recover(recover_run, lineage, "secbench")
    cfg = run.config["p4"]
    policy = cfg["isolation"]
    from raven.config import REPO_ROOT

    adjudication_path = REPO_ROOT / cfg["oracle_adjudication"]
    adjudications = pairs.load_adjudications(inv.read_rows(adjudication_path))
    lineage["oracle_adjudication_sha256"] = hashlib.sha256(adjudication_path.read_bytes()).hexdigest()
    roles = _roles(overlap_run)
    recovered = {r["record_id"]: r for r in inv.read_rows(recover_run / "audit_provenance_secbench.csv")}
    eligible = sorted(rid for rid, r in recovered.items() if r["status"] == "recovered_c2")
    eligible = eligible[: cfg["secbench_reproduction_cap"]]
    assert_allowed([f"secbench:{rid}" for rid in eligible], roles)
    secbench = {r["record_id"]: r for r in inv.read_rows(inventory_run / "inventory_secbench.csv.gz")
                if r["record_id"] in set(eligible)}

    base = cfg["base_image"]
    check_docker(run)
    run.run_subprocess(["docker", "pull", base], "pull-base", timeout=1800)
    run.run_subprocess(["docker", "image", "inspect", "--format", "{{json .RepoDigests}}", base], "base-digest")
    base_digest = (run.path / "subprocess" / f"{run._calls:03d}-base-digest.stdout").read_text().strip()

    path, _ = _input(run.config["p2"]["manifest"]["secbench"], run)
    work = _data_root() / "work" / "p4" / "secbench"
    rows = []
    with zipfile.ZipFile(path) as archive:
        root = archive.namelist()[0].split("/", 1)[0]
        for rid in eligible:
            free = shutil.disk_usage("/").free
            if free < cfg["min_internal_free_gib"] * GiB:
                raise RuntimeError(f"internal disk free {free / GiB:.1f} GiB below guard; Docker images live there")
            slug = rid.replace("/", "__")
            ctx = work / slug
            refs = fixed_release_refs(secbench[rid]["fixed_version"]) if cfg.get("fixed_release_tag_first") else []
            same_version = secbench[rid]["fixed_version"] == secbench[rid]["vulnerable_version"]
            patch = _extract_instance(archive, root, rid, ctx, [] if same_version else refs)
            if same_version:
                patch["fixed_version_equals_vulnerable"] = True
            dirname = rid.split("/")[-1]
            test_files = sorted(ctx.glob("*.test.js"))
            test_source = test_files[0].read_text(encoding="utf-8") if test_files else ""
            package = secbench[rid]["package"]
            row: dict[str, Any] = {"record_id": rid, "package": package, "compat_patch": json.dumps(patch) if patch else ""}
            built, sides = [], {}
            for side, dockerfile in (("vulnerable", "Dockerfile"), ("fixed", "Dockerfile.fixed")):
                df = ctx / f"{dockerfile}.raven"
                tag = f"raven-p4/{slug.lower()}:{side}"
                if not df.is_file():
                    built.append(False)
                    row[f"{side}_build_failure"] = "no_dockerfile_in_benchmark"
                    row[f"{side}_outcome"] = "not_run"
                    continue
                result = run.run_subprocess(["docker", "build", "--pull=false", "-f", str(df), "-t", tag, str(ctx)],
                                            f"build-{slug}-{side}", timeout=cfg["build_timeout_s"])
                ok = result.returncode == 0
                built.append(ok)
                if not ok:
                    log = run.path / "subprocess" / f"{run._calls:03d}-build-{slug}-{side}.stderr"
                    row[f"{side}_build_failure"] = build_failure_cause(log.read_text(errors="replace"))
                row[f"{side}_image"] = _docker_id(run, tag) if ok else ""
                if ok:
                    report, timed_out, out = _run_side(run, tag, f"raven-p4-{slug.lower()}-{side}".replace(".", "-"), f"/exploit/{dirname}", policy)
                    sides[side] = pairs.classify_side(report, timed_out, test_source, package)
                    sides[side]["stdout"] = out
                row[f"{side}_outcome"] = sides.get(side, {}).get("outcome", "not_run")
            oracle = None
            vuln, fixed = sides.get("vulnerable"), sides.get("fixed")
            if all(built) and vuln and fixed and vuln["outcome"] == "pass" and fixed["outcome"] == "assertion_fail" \
                    and fixed["failed_after_import"]:
                spec = pairs.package_specifier(test_source, package)
                evidence = {side: _run_evidence(run, f"raven-p4/{slug.lower()}:{side}",
                                                f"raven-p4-ev-{slug.lower()}-{side}".replace(".", "-"),
                                                f"/exploit/{dirname}", package, spec, policy)
                            for side in ("vulnerable", "fixed")}
                oracle = pairs.oracle_evidence(evidence["vulnerable"][0], evidence["fixed"][0], vuln["outcome"],
                                               secbench[rid].get("sink", ""), adjudications.get(rid))
                oracle["evidence_stdout"] = {side: evidence[side][1] for side in evidence}
            elif rid in adjudications:
                raise RuntimeError(f"adjudication for {rid} but its pair cannot be validated")
            status, detail = pairs.classify_pair(vuln, fixed, tuple(built), oracle)
            if status == "build_failed":
                causes = [f"{s}: {row[f'{s}_build_failure']}" for s in ("vulnerable", "fixed") if f"{s}_build_failure" in row]
                detail = "; ".join(causes)
            vms = sides.get("vulnerable", {}).get("duration_ms", "")
            fms = sides.get("fixed", {}).get("duration_ms", "")
            timing = pairs.redos_flags(status, vms, fms, cfg["redos"]) if rid.startswith("redos/") else {"ratio": "", "flag": ""}
            row.update(status=status, detail=detail,
                       fixed_failed_after_import=sides.get("fixed", {}).get("failed_after_import", ""),
                       vulnerable_ms=vms, fixed_ms=fms, timing_ratio=timing["ratio"], timing_flag=timing["flag"],
                       oracle=("" if oracle is None else "confirmed" if oracle["confirmed"] else "unconfirmed"),
                       oracle_rule=(oracle or {}).get("rule", ""), oracle_reason=(oracle or {}).get("reason", ""),
                       oracle_evidence=json.dumps(oracle, sort_keys=True) if oracle else "",
                       sides=json.dumps(sides, sort_keys=True))
            rows.append(row)
            run.logger.info("%s: %s %s", rid, status, detail[:80])
            for side in ("vulnerable", "fixed"):
                subprocess.run(["docker", "rmi", f"raven-p4/{slug.lower()}:{side}"], capture_output=True, check=False)
    for row in rows:
        row.setdefault("vulnerable_build_failure", "")
        row.setdefault("fixed_build_failure", "")
    assert set(SECBENCH_OUTPUT_FIELDS) <= EXTERNAL_ALLOWED_FIELDS
    inv.write_rows(run.path / "secbench_reproduction.csv", SECBENCH_OUTPUT_FIELDS, rows)
    summary = {
        "overlap_run": overlap_run.name, "recover_run": recover_run.name, "base_image": base,
        "base_digest": base_digest, "eligible": len(eligible), "policy": policy,
        "statuses": dict(Counter(r["status"] for r in rows)),
        "by_category": {c: dict(Counter(r["status"] for r in rows if r["record_id"].startswith(c + "/")))
                        for c in sorted({r["record_id"].split("/")[0] for r in rows})},
        "compat_patches": sum(bool(r["compat_patch"]) for r in rows),
        "force_exit": policy.get("force_exit", True),
        "fixed_release_tag_first": bool(cfg.get("fixed_release_tag_first")),
        "timing_flags": {r["record_id"]: r["timing_flag"] for r in rows if r["timing_flag"]},
        "oracle": {r["record_id"]: {"oracle": r["oracle"], "rule": r["oracle_rule"], "reason": r["oracle_reason"]}
                   for r in rows if r["oracle"]},
        "adjudications": sorted(adjudications),
    }
    assert all(r["status"] in pairs.PAIR_STATUSES for r in rows)
    _finish(run, summary, lineage, ("secbench_reproduction.csv",), "secbench_reproduction_summary.json")
    return summary





def _bodies(path: Path, ids: set[str]) -> dict[str, str]:
    out = {}
    with zipfile.ZipFile(path) as zf:
        for split in inv.JSVUL_SPLITS:
            for raw in zf.open(f"{split}.jsonl"):
                rec = json.loads(raw)
                if rec["id"] in ids:
                    out[rec["id"]] = rec.get("body") or ""
    return out


def run_jsvul_align(run: Run, inventory_run: Path, select_run: Path, overlap_run: Path, recover_run: Path) -> dict[str, Any]:
    from raven import overlap as ov

    inventory_run, select_run, overlap_run, lineage = _inputs(run, inventory_run, select_run, overlap_run)
    recover_run, lineage = _recover(recover_run, lineage, "jsvul")
    cfg = run.config["p4"]["alignment"]
    roles = _roles(overlap_run)
    
    inventory = {r["record_id"]: r for r in inv.read_rows(inventory_run / "inventory_jsvul.csv.gz")
                 if roles.get(f"jsvul:{r['record_id']}") in ALLOWED_ROLES}
    recovered = {r["record_id"]: r for r in inv.read_rows(recover_run / "audit_provenance_jsvul.csv")}
    subset = [r["record_id"] for r in inv.read_rows(select_run / "subset_jsvul.csv")]
    usable = [rid for rid in subset if roles.get(f"jsvul:{rid}") == "pilot_dev"]
    partners = {inventory[r]["paired_id"] for r in usable if inventory[r]["paired_id"]}
    assert_allowed([f"jsvul:{r}" for r in partners], roles)  
    records = sorted(set(usable) | partners)
    path, _ = _input(run.config["p2"]["manifest"]["jsvul"], run)
    bodies = _bodies(path, set(records))

    rows = []
    for rid in records:
        rec = inventory[rid]
        file_path = _data_root() / "files" / "jsvul" / rec["project"].replace("/", "__") / rec["revision"] / rec["file"]
        row: dict[str, Any] = {"record_id": rid, "project": rec["project"], "revision": rec["revision"], "file": rec["file"],
                               "label": rec["label"], "paired_id": rec["paired_id"], "in_subset": rid in usable}
        if not file_path.is_file():
            row.update(status="file_missing", start_line="", end_line="", score="", runner_up="", candidates=0)
        else:
            source = file_path.read_bytes()
            candidates = list(ov.functions_in(source, rec["extension"], 1))
            body_tokens, how = ov.snippet_tokens(bodies[rid].encode(), rec["extension"])
            result = pairs.align_body(body_tokens, candidates, cfg)
            row.update(result, candidates=len(candidates), body_tokens=len(body_tokens), tokenization=how,
                       file_sha256=hashlib.sha256(source).hexdigest())
        row.setdefault("note", "")
        snapshot_ok = recovered.get(rid, {}).get("status") == "recovered_c2" or (
            rid not in recovered and recovered.get(rec["paired_id"], {}).get("status") == "recovered_c2")
        row["availability"] = pairs.availability_level(
            "jsvul", file_ok=file_path.is_file(), snapshot_ok=snapshot_ok,
            aligned=row["status"] in ("unique_exact", "unique_near"), reproduced=False)
        rows.append(row)
    by_id = {r["record_id"]: r for r in rows}
    pair_rows = []
    for row in rows:
        partner = by_id.get(row["paired_id"])
        if partner and row["label"] == "1":
            status, detail = pairs.jsvul_pair_status(row, partner)
            pair_rows.append({"pair_id": f"{row['record_id']}+{partner['record_id']}", "project": row["project"],
                              "cwe": inventory[row["record_id"]]["cwe"] or "unknown",
                              "vulnerable_status": row["status"], "fixed_status": partner["status"],
                              "status": status, "detail": detail})
    fields = ("record_id", "project", "revision", "file", "label", "paired_id", "in_subset", "status", "start_line",
              "end_line", "score", "runner_up", "best_start", "best_end", "candidates", "body_tokens", "tokenization",
              "file_sha256", "availability", "note")
    for row in rows:
        for key in ("body_tokens", "tokenization", "file_sha256", "best_start", "best_end"):
            row.setdefault(key, "")
    inv.write_rows(run.path / "jsvul_alignment.csv", fields, rows)
    inv.write_rows(run.path / "jsvul_pairs.csv",
                   ("pair_id", "project", "cwe", "vulnerable_status", "fixed_status", "status", "detail"), pair_rows)

    
    from raven import provenance as prov

    aligned = [p["pair_id"] for p in pair_rows if p["status"] == "aligned_not_reproduced"]
    sample = prov.select_subset(aligned, run.config["seed"], "p4-alignment-review", min(cfg["review"], len(aligned)))
    review = []
    for s in sample:
        sides = []
        for rid in s["record_id"].split("+"):
            row, rec = by_id[rid], inventory[rid]
            lines = (_data_root() / "files" / "jsvul" / rec["project"].replace("/", "__") / rec["revision"] / rec["file"]).read_text(errors="replace").splitlines()
            sides.append({"record_id": rid, "status": row["status"], "span": [row["start_line"], row["end_line"]],
                          "span_text": "\n".join(lines[int(row["start_line"]) - 1:int(row["end_line"])]), "body": bodies[rid]})
        review.append({"pair_id": s["record_id"], "sides": sides, "verdict": "", "reviewer": "", "note": ""})
    _json(run.path / "alignment_review_sample.json", review)

    
    
    def record_sample(name: str, statuses: set[str], size: int) -> list[dict[str, Any]]:
        pool = [r["record_id"] for r in rows if r["status"] in statuses]
        chosen = prov.select_subset(pool, run.config["seed"], f"p4-alignment-{name}", min(size, len(pool)))
        out = []
        for c in chosen:
            row, rec = by_id[c["record_id"]], inventory[c["record_id"]]
            src = _data_root() / "files" / "jsvul" / rec["project"].replace("/", "__") / rec["revision"] / rec["file"]
            lines = src.read_text(errors="replace").splitlines() if src.is_file() else []
            start, end = row.get("best_start") or 0, row.get("best_end") or 0
            out.append({"record_id": c["record_id"], "status": row["status"], "score": row["score"],
                        "runner_up": row["runner_up"], "best_span": [start, end],
                        "best_text": "\n".join(lines[int(start) - 1:int(end)]) if start else "",
                        "body": bodies[c["record_id"]], "verdict": "", "reviewer": "", "note": ""})
        return out

    _json(run.path / "alignment_review_strata.json", {
        "unique_near": record_sample("near", {"unique_near"}, cfg["review_strata"]),
        "ambiguous_or_unresolved": record_sample("miss", {"ambiguous", "unresolved"}, cfg["review_strata"]),
    })
    summary = {
        "overlap_run": overlap_run.name, "records": len(rows), "subset_records": len(usable),
        "statuses": dict(Counter(r["status"] for r in rows)),
        "subset_statuses": dict(Counter(r["status"] for r in rows if r["in_subset"])),
        "availability": dict(Counter(r["availability"] for r in rows)),
        "pairs": len(pair_rows), "pair_statuses": dict(Counter(p["status"] for p in pair_rows)),
        "typescript": dict(Counter(r["status"] for r in rows if inventory[r["record_id"]]["typescript_original"] == "True")),
        "tokenization": dict(Counter(r.get("tokenization", "") for r in rows)),
    }
    _finish(run, summary, lineage, ("jsvul_alignment.csv", "jsvul_pairs.csv", "alignment_review_sample.json",
                                    "alignment_review_strata.json"), "jsvul_alignment_summary.json")
    return summary





def php_lint_result(returncode: int, output: str) -> str:
    pass
    if returncode == 0 and "No syntax errors detected" in output:
        return "ok"
    if "Parse error" in output or "Errors parsing" in output:
        return "syntax_error"
    return "lint_failed"


def run_php_twins(run: Run, inventory_run: Path, select_run: Path, overlap_run: Path) -> dict[str, Any]:
    inventory_run, select_run, overlap_run, lineage = _inputs(run, inventory_run, select_run, overlap_run)
    cfg = run.config["p4"]
    check_docker(run)
    php_roles = {r["record_id"]: r["role"] for r in inv.read_rows(overlap_run / "php_cases.csv.gz")}
    cases = {r["record_id"]: r for r in inv.read_rows(inventory_run / "inventory_sard_php.csv.gz")
             if php_roles.get(r["record_id"]) in ALLOWED_ROLES}
    subset = [r["record_id"] for r in inv.read_rows(select_run / "subset_sard_php.csv")]
    root = _data_root() / "snapshots" / "sard_php"
    rows = []
    for pair_id in subset:
        bad, good = pair_id.split("+")
        bad_role, good_role = php_roles.get(bad), php_roles.get(good)
        if bad_role not in ALLOWED_ROLES or good_role not in ALLOWED_ROLES:
            raise PermissionError(f"P4 may read only pilot_dev/external records; {pair_id} is {bad_role}/{good_role}")
        sources = {}
        for side, cid in (("bad", bad), ("good", good)):
            src = root / cid / cases[cid]["src_file"]
            sources[side] = src.read_text(encoding="utf-8", errors="replace") if src.is_file() else None
        lint = {}
        for side, cid in (("bad", bad), ("good", good)):
            if sources[side] is None:
                lint[side] = "missing"
                continue
            
            
            with tempfile.TemporaryDirectory(prefix="raven-php-") as staging:
                name = Path(cases[cid]["src_file"]).name
                shutil.copyfile(root / cid / cases[cid]["src_file"], Path(staging) / name)
                mount = f"type=bind,source={staging},target=/case,readonly"
                cmd = ["docker", "run", "--rm", "--name", f"raven-p4-php-{cid}", "--network", "none",
                       "--cap-drop", "ALL", "--security-opt", "no-new-privileges", "--read-only",
                       "--user", "65534:65534", "--pids-limit", "64", "--memory", "256m",
                       "--mount", mount, cfg["php_image"], "php", "-l", f"/case/{name}"]
                try:
                    result = run.run_subprocess(cmd, f"php-lint-{cid}", timeout=60)
                    
                    stem = f"{run._calls:03d}-php-lint-{cid}"
                    output = ((run.path / "subprocess" / f"{stem}.stdout").read_text(errors="replace")
                              + (run.path / "subprocess" / f"{stem}.stderr").read_text(errors="replace"))
                    ensure_docker_reachable(output)
                    lint[side] = php_lint_result(result.returncode, output)
                    if lint[side] == "lint_failed":
                        raise RuntimeError(f"php -l did not run for {cid}: {output.strip()[:200]}")
                except subprocess.TimeoutExpired:
                    subprocess.run(["docker", "rm", "-f", f"raven-p4-php-{cid}"], capture_output=True, check=False)
                    lint[side] = "timeout"
        if None in sources.values():
            check = {"valid": False, "reason": "case_missing"}
        else:
            names = (Path(cases[bad]["src_file"]).name, Path(cases[good]["src_file"]).name)
            check = pairs.php_twin_check(sources["bad"], sources["good"], cases[bad]["cwe"], names)
        status = "aligned_not_reproduced" if check["valid"] else "invalid_twin"
        if check["valid"] and set(lint.values()) != {"ok"}:
            
            failed = [f"{side}:{result}" for side, result in sorted(lint.items()) if result != "ok"]
            status, check = "invalid_twin", {**check, "valid": False, "reason": "php_lint_" + ",".join(failed)}
        rows.append({
            "pair_id": pair_id, "cwe": cases[bad]["cwe"], "bad_sanitize": cases[bad]["sanitize"],
            "good_sanitize": cases[good]["sanitize"], "construction": cases[bad]["construction"],
            "status": status, "reason": check.get("reason", ""), "hunks": check.get("hunks", ""),
            "prefix_lines": check.get("prefix_lines", ""), "suffix_lines": check.get("suffix_lines", ""),
            "source_line": check.get("source_line", ""), "sink_line": check.get("sink_line", ""),
            "lint_bad": lint["bad"], "lint_good": lint["good"],
            "availability": pairs.availability_level("sard", file_ok=True, snapshot_ok=None not in sources.values(),
                                                     aligned=check["valid"], reproduced=False),
        })
    fields = ("pair_id", "cwe", "bad_sanitize", "good_sanitize", "construction", "status", "reason", "hunks",
              "prefix_lines", "suffix_lines", "source_line", "sink_line", "lint_bad", "lint_good", "availability")
    inv.write_rows(run.path / "php_twins.csv", fields, rows)
    summary = {"overlap_run": overlap_run.name, "pairs": len(rows), "image": cfg["php_image"],
               "statuses": dict(Counter(r["status"] for r in rows)),
               "reasons": dict(Counter(r["reason"] for r in rows if r["reason"])),
               "lint": dict(Counter(f"{r['lint_bad']}/{r['lint_good']}" for r in rows)),
               "by_cwe": {c: dict(Counter(r["status"] for r in rows if r["cwe"] == c)) for c in sorted({r["cwe"] for r in rows})},
               "behaviour_reproduction": "not run (structural twin check and php -l only)",
               "structural_check": "metadata agree except sanitizer; source in common prefix; last CWE sink "
                                   "identical and in common suffix; no sink call in changed region"}
    _finish(run, summary, lineage, ("php_twins.csv",), "php_twins_summary.json")
    return summary





def check_gate_5c(overlap_run: Path, audit_path: Path) -> dict[str, Any]:
    pass

    from raven import p3

    audit = p3.load_bundled_audit(audit_path)
    assignment = {r["node"]: r for r in inv.read_rows(overlap_run / "split_assignment.csv.gz")}
    needed, problems = set(), []
    for e in inv.read_rows(overlap_run / "code_edges.csv.gz"):
        if e["type"].startswith("external_bundled_") and assignment[e["b"]]["role"] != "external":
            needed.add(e["a"])
            row = audit.get(e["a"])
            if row and row["decision"] == "unresolved" and assignment[e["b"]]["split"] != "quarantine":
                problems.append(f"{e['b']} linked to unresolved {e['a']} but in {assignment[e['b']]['split']}")
    missing = sorted(needed - set(audit))
    problems += [f"no decision for {i}" for i in missing]
    return {"instances_needing_decision": sorted(needed), "decided": sorted(set(audit) & needed),
            "decisions": {i: audit[i]["decision"] for i in sorted(needed & set(audit))},
            "missing": missing, "problems": problems, "pass": not problems}


def verify_p4_runs(config: dict[str, Any], overlap_run: Path, runs: dict[str, tuple[Path, str]]) -> dict[str, Any]:
    pass





    overlap = json.loads((overlap_run / "overlap_summary.json").read_text())
    if _digest(overlap_run, tuple(overlap["output_files"])) != overlap["output_files"]:
        raise LineageError(f"{overlap_run.name} outputs changed after the overlap run")
    shared_keys = ("inventory_run", "select_run", "overlap_run", "inventory_files", "subset_files", "overlap_output_files")
    verified: dict[str, Any] = {"overlap_run": overlap_run.name, "runs": {}}
    shared = None
    for source, (path, name) in runs.items():
        summary = json.loads((path / name).read_text())
        if "output_files" not in summary or "inputs" not in summary:
            raise LineageError(f"{path.name} has no input/output record")
        if _digest(path, tuple(summary["output_files"])) != summary["output_files"]:
            raise LineageError(f"{path.name} outputs changed after the run")
        ids = {k: summary["inputs"].get(k) for k in shared_keys}
        if ids["overlap_run"] != overlap_run.name or ids["overlap_output_files"] != overlap["output_files"]:
            raise LineageError(f"{path.name} used overlap {ids['overlap_run']} or different overlap outputs")
        if shared is None:
            shared = ids
        elif ids != shared:
            raise LineageError(f"{path.name} used different inventory/selection/overlap inputs")
        if summary.get("p4_config_sha256") != config_sha256(config):
            raise LineageError(f"{path.name} ran under a different p4 config")
        verified["runs"][source] = {"run": path.name, "output_files": summary["output_files"],
                                    **{k: v for k, v in summary["inputs"].items() if k not in shared_keys}}
    verified.update(shared or {})
    return verified


def run_summary(run: Run, overlap_run: Path, check_run: Path, secbench_run: Path, align_run: Path, php_run: Path) -> dict[str, Any]:
    from raven.config import REPO_ROOT

    overlap_run = _from_run(overlap_run, "overlap")
    check_run = _from_run(check_run, "check-split")
    secbench_run = _from_run(secbench_run, "secbench-repro")
    align_run = _from_run(align_run, "jsvul-align")
    php_run = _from_run(php_run, "php-twins")
    inputs = verify_p4_runs(run.config, overlap_run, {
        "secbench": (secbench_run, "secbench_reproduction_summary.json"),
        "jsvul": (align_run, "jsvul_alignment_summary.json"),
        "sard_php": (php_run, "php_twins_summary.json"),
    })
    check = json.loads((check_run / "check_split.json").read_text())
    if check["overlap_run"] != overlap_run.name or check["violations"]:
        raise RuntimeError("check-split must pass on this overlap run")
    inputs["check_split_sha256"] = hashlib.sha256((check_run / "check_split.json").read_bytes()).hexdigest()
    gate = check_gate_5c(overlap_run, REPO_ROOT / run.config["p3"]["bundled_target_audit"])

    sb = inv.read_rows(secbench_run / "secbench_reproduction.csv")
    js = inv.read_rows(align_run / "jsvul_pairs.csv")
    ph = inv.read_rows(php_run / "php_twins.csv")
    pair_rows = (
        [{"source": "secbench", "pair_id": r["record_id"], "status": r["status"], "detail": r["detail"],
          "weakness": r["record_id"].split("/")[0], "family": r["package"]} for r in sb]
        + [{"source": "jsvul", "pair_id": r["pair_id"], "status": r["status"], "detail": r["detail"],
            "weakness": r["cwe"], "family": r["project"]} for r in js]
        + [{"source": "sard_php", "pair_id": r["pair_id"], "status": r["status"], "detail": r["reason"],
            "weakness": r["cwe"], "family": r["cwe"]} for r in ph]
    )
    bad = [r for r in pair_rows if r["status"] not in pairs.PAIR_STATUSES]
    if bad:
        raise RuntimeError(f"unknown pair statuses: {bad[:3]}")
    inv.write_rows(run.path / "pair_validation.csv", ("source", "pair_id", "status", "detail", "weakness", "family"), pair_rows)

    availability = (
        
        
        [{"source": "secbench", "record_id": r["record_id"],
          "level": "C3" if r["status"] == "validated" else "C0"} for r in sb]
        + [{"source": "jsvul", "record_id": r["record_id"], "level": r["availability"]}
           for r in inv.read_rows(align_run / "jsvul_alignment.csv")]
        + [{"source": "sard_php", "record_id": r["pair_id"], "level": r["availability"]} for r in ph]
    )
    inv.write_rows(run.path / "availability.csv", ("source", "record_id", "level"), availability)
    summary = {
        "overlap_run": overlap_run.name, "check_run": check_run.name, "secbench_run": secbench_run.name,
        "align_run": align_run.name, "php_run": php_run.name, "inputs": inputs, "gate_5c": gate,
        "pairs_by_source": {s: dict(Counter(r["status"] for r in pair_rows if r["source"] == s))
                            for s in ("secbench", "jsvul", "sard_php")},
        "pairs_by_weakness": {f"{r['source']}:{r['weakness']}": None for r in pair_rows},
        "validated_by_weakness": dict(Counter(f"{r['source']}:{r['weakness']}" for r in pair_rows if r["status"] == "validated")),
        "validated_families": len({(r["source"], r["family"]) for r in pair_rows if r["status"] == "validated"}),
        "secbench_timing_flags": {r["record_id"]: {"flag": r["timing_flag"], "ratio": r["timing_ratio"],
                                                   "vulnerable_ms": r["vulnerable_ms"], "fixed_ms": r["fixed_ms"]}
                                  for r in sb if r.get("timing_flag")},
        "availability": {s: dict(Counter(r["level"] for r in availability if r["source"] == s))
                         for s in ("secbench", "jsvul", "sard_php")},
    }
    summary["pairs_by_weakness"] = {
        k: dict(Counter(r["status"] for r in pair_rows if f"{r['source']}:{r['weakness']}" == k))
        for k in sorted(summary["pairs_by_weakness"])
    }
    summary["output_files"] = _digest(run.path, ("pair_validation.csv", "availability.csv"))
    _json(run.path / "p4_summary.json", summary)
    if not gate["pass"]:
        raise RuntimeError(f"gate 5c failed: {gate['problems'][:3]}")
    return summary
