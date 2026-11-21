"""P2 commands: full inventory, capped subsets, snapshot recovery and the audit summary.

Each command runs inside :func:`raven.runlog.start_run`; the next command reads the
previous run's directory (``--from-run``) so the chain stays traceable.
"""

from __future__ import annotations

import difflib
import hashlib
import json
import os
import re
import zipfile
from collections import Counter
from pathlib import Path
from typing import Any

from raven import inventory as inv
from raven import provenance as prov
from raven.config import REPO_ROOT
from raven.manifest import read_manifest, resolve_local_path, verify_row
from raven.runlog import Run

SOURCES = ("jsvul", "secbench", "sard_php")
MANIFEST = REPO_ROOT / "artifacts" / "data" / "manifest.csv"

AUDIT_FIELDS = (
    "source", "record_id", "rank", "stage", "status", "detail", "revisions_required",
    "revisions_c1", "revisions_c2", "typescript_original", "family",
)


def _data_root() -> Path:
    root = os.environ.get("RAVEN_DATA_ROOT")
    if not root:
        raise RuntimeError("RAVEN_DATA_ROOT is not set (source artifacts/configs/pilot/local.env.example)")
    return Path(root)


def _input(manifest_id: str, run: Run) -> tuple[Path, str]:
    pass
    rows = {row["id"]: row for row in read_manifest(MANIFEST)}
    row = rows[manifest_id]
    result = verify_row(row, _data_root())
    if not result.ok:
        raise RuntimeError(f"manifest {manifest_id}: {result.reason}")
    run.logger.info("input %s verified (%s)", manifest_id, row["sha256"])
    return resolve_local_path(row["local_path"], _data_root()), row["sha256"]


def _json(path: Path, data: Any) -> None:
    path.write_text(json.dumps(data, indent=2, sort_keys=True, default=str) + "\n", encoding="utf-8")


def _from_run(path: Path, command: str) -> Path:
    status = json.loads((path / "status.json").read_text())
    identity = json.loads((path / "run.json").read_text())
    if identity["command"] != command or status["status"] != "completed":
        raise RuntimeError(f"{path} is not a completed '{command}' run")
    return path


class LineageError(RuntimeError):
    pass


INVENTORY_FILES = (
    "inventory_jsvul.csv.gz", "inventory_secbench.csv.gz", "inventory_sard_php.csv.gz",
    "sard_candidate_pairs.csv.gz", "inventory_summary.json",
)
SUBSET_FILES = tuple(f"subset_{source}.csv" for source in SOURCES)

LINEAGE_KEYS = ("seed", "cap")
LINEAGE_P2_KEYS = ("manifest", "prior_probe_ids")


def _digest(run_dir: Path, names: tuple[str, ...]) -> dict[str, str]:
    return {
        name: hashlib.sha256((run_dir / name).read_bytes()).hexdigest()
        for name in names
        if (run_dir / name).exists()
    }


def _lineage_config(config: dict[str, Any]) -> dict[str, Any]:
    return {
        **{key: config[key] for key in LINEAGE_KEYS},
        **{f"p2.{key}": config["p2"][key] for key in LINEAGE_P2_KEYS},
    }


def check_lineage(config: dict[str, Any], inventory_run: Path, select_run: Path) -> dict[str, Any]:
    pass





    lineage = json.loads((select_run / "selection.json").read_text()).get("lineage")
    if lineage is None:
        raise LineageError(f"{select_run.name} has no lineage record")
    problems = []
    if lineage["inventory_run"] != inventory_run.name:
        problems.append(f"selection built from {lineage['inventory_run']}, not {inventory_run.name}")
    if _digest(inventory_run, INVENTORY_FILES) != lineage["inventory_files"]:
        problems.append("inventory files differ from those the selection recorded")
    if _digest(select_run, SUBSET_FILES) != lineage["subset_files"]:
        problems.append("subset files changed after selection")
    if _lineage_config(config) != lineage["config"]:
        problems.append(f"config {_lineage_config(config)} != selection config {lineage['config']}")
    inputs = json.loads((inventory_run / "inventory_summary.json").read_text())["inputs"]
    manifest = {row["id"]: row["sha256"] for row in read_manifest(MANIFEST)}
    for source, manifest_id in config["p2"]["manifest"].items():
        if inputs.get(source) != manifest.get(manifest_id):
            problems.append(f"{source} inventory input {inputs.get(source)} != manifest {manifest_id}")
    if problems:
        raise LineageError("; ".join(problems))
    return lineage





def run_inventory(run: Run) -> dict[str, Any]:
    cfg = run.config["p2"]
    summary: dict[str, Any] = {"inputs": {}, "sources": {}}

    path, sha = _input(cfg["manifest"]["jsvul"], run)
    summary["inputs"]["jsvul"] = sha
    rows = list(inv.jsvul_records(path))
    expected = inv.jsvul_line_count(path)
    assert len(rows) == expected, f"jsvul inventory {len(rows)} != {expected} records in archive"
    assert len({r["record_id"] for r in rows}) == len(rows), "duplicate jsvul record ids"
    inv.write_rows(run.path / "inventory_jsvul.csv.gz", inv.JSVUL_FIELDS, rows)
    summary["sources"]["jsvul"] = {
        "rows": len(rows), "archive_records": expected,
        "projects": len({r["project"] for r in rows}),
        "labels": dict(Counter(str(r["label"]) for r in rows)),
        "paired_records": sum(bool(r["paired_id"]) for r in rows),
        "typescript_original": sum(r["typescript_original"] for r in rows),
        "missing": inv.missing_counts(rows, inv.JSVUL_FIELDS),
    }
    run.logger.info("jsvul inventory: %d rows", len(rows))

    path, sha = _input(cfg["manifest"]["secbench"], run)
    summary["inputs"]["secbench"] = sha
    rows = list(inv.secbench_records(path))
    expected = inv.secbench_instance_count(path)
    official = [r for r in rows if r["official"]]
    assert len(official) == expected["official"] and len(rows) - len(official) == expected["incubator"]
    inv.write_rows(run.path / "inventory_secbench.csv.gz", inv.SECBENCH_FIELDS, rows)
    fields = tuple(f for f in inv.SECBENCH_FIELDS if f != "parse_error")
    summary["sources"]["secbench"] = {
        "rows": len(rows), "official": len(official), "incubator": len(rows) - len(official),
        "categories": dict(Counter(r["category"] for r in rows)),
        "parse_errors": sum(bool(r["parse_error"]) for r in rows),
        "multi_dependency": sum(r["dependency_count"] not in ("", 1) for r in rows),
        "official_without_fixed_version": sum(not r["has_fixed_version"] for r in official),
        "official_versions_normalized": sum(
            r["fixed_version"] != r["fixed_version_raw"]
            or r["vulnerable_version"] != r["vulnerable_version_raw"]
            for r in official
        ),
        "missing_official": inv.missing_counts(official, fields),
    }
    run.logger.info("secbench inventory: %d rows (%d official)", len(rows), len(official))

    path, sha = _input(cfg["manifest"]["sard_php"], run)
    summary["inputs"]["sard_php"] = sha
    rows = list(inv.sard_records(path))
    expected = inv.sard_case_count(path)
    assert len(rows) == expected, f"sard inventory {len(rows)} != {expected} cases"
    inv.write_rows(run.path / "inventory_sard_php.csv.gz", inv.SARD_FIELDS, rows)
    pairs = inv.sard_candidate_pairs(rows, run.config["seed"])
    inv.write_rows(run.path / "sard_candidate_pairs.csv.gz", inv.SARD_PAIR_FIELDS, pairs)
    summary["sources"]["sard_php"] = {
        "rows": len(rows), "archive_cases": expected,
        "states": dict(Counter(r["state"] for r in rows)),
        "cwe": dict(Counter(r["cwe"] for r in rows)),
        "unparsed_file_names": sum(not r["construction"] for r in rows),
        "candidate_pairs": len(pairs),
        "missing": inv.missing_counts(rows, inv.SARD_FIELDS),
    }
    run.logger.info("sard inventory: %d cases, %d candidate pairs", len(rows), len(pairs))
    _json(run.path / "inventory_summary.json", summary)
    return summary





def _family(source: str, row: dict[str, str]) -> str:
    return {"jsvul": row.get("project", ""), "secbench": row.get("package", ""),
            "sard_php": row.get("cwe", "")}[source]


def run_select(run: Run, inventory_run: Path) -> dict[str, Any]:
    inventory_run = _from_run(inventory_run, "inventory")
    cfg, seed = run.config["p2"], run.config["seed"]
    caps = run.config["cap"]
    prior = json.loads((REPO_ROOT / cfg["prior_probe_ids"]).read_text())["record_ids"]
    pools = {
        "jsvul": (inv.read_rows(inventory_run / "inventory_jsvul.csv.gz"), "record_id",
                  "all inventory records", prior),
        "secbench": ([r for r in inv.read_rows(inventory_run / "inventory_secbench.csv.gz")
                      if r["official"] == "True"], "record_id",
                     "official instances (5 categories); incubator excluded", []),
        "sard_php": (inv.read_rows(inventory_run / "sard_candidate_pairs.csv.gz"), "pair_id",
                     "metadata candidate pairs frozen in the inventory run", []),
    }
    inputs = json.loads((inventory_run / "inventory_summary.json").read_text())["inputs"]
    manifest = {row["id"]: row["sha256"] for row in read_manifest(MANIFEST)}
    for source, manifest_id in cfg["manifest"].items():
        if inputs.get(source) != manifest.get(manifest_id):
            raise LineageError(f"{source}: inventory input does not match manifest row {manifest_id}")
    report: dict[str, Any] = {"inventory_run": inventory_run.name, "seed": seed, "sources": {}}
    for source, (rows, id_field, rule, preselected) in pools.items():
        subset = prov.select_subset((r[id_field] for r in rows), seed, source, caps[source], preselected)
        by_id = {r[id_field]: r for r in rows}
        for item in subset:
            item["family"] = _family(source, by_id[item["record_id"]])
        inv.write_rows(run.path / f"subset_{source}.csv",
                       ("rank", "record_id", "stage", "selection_sha256", "family"), subset)
        report["sources"][source] = {
            "eligibility": rule, "pool": len(rows), "cap": caps[source], "selected": len(subset),
            "stages": dict(Counter(i["stage"] for i in subset)),
            "subset_families": len({i["family"] for i in subset}),
            "pool_families": len({_family(source, r) for r in rows}),
            "subset_family_top": Counter(i["family"] for i in subset).most_common(10),
            "id_list_sha256": hashlib.sha256("\n".join(i["record_id"] for i in subset).encode()).hexdigest(),
        }
        run.logger.info("%s subset: %d of %d", source, len(subset), len(rows))
    report["lineage"] = {
        "inventory_run": inventory_run.name,
        "inventory_files": _digest(inventory_run, INVENTORY_FILES),
        "subset_files": _digest(run.path, SUBSET_FILES),
        "config": _lineage_config(run.config),
    }
    _json(run.path / "selection.json", report)
    return report





def _guard(run: Run) -> prov.StorageGuard:
    guard = prov.StorageGuard.from_config(_data_root(), run.config["p2"]["storage"])
    run.logger.info("storage: %.1f GiB used under data root at start", guard.used_at_start / prov.GiB)
    return guard


def _recover_jsvul(run: Run, inventory_run: Path, subset: list[dict[str, str]], fetcher: prov.Fetcher) -> list[dict[str, Any]]:
    cfg = run.config["p2"]
    by_id = {r["record_id"]: r for r in inv.read_rows(inventory_run / "inventory_jsvul.csv.gz")}
    rec = prov.JsVulRecovery(fetcher, _data_root(), cfg["snapshot_max_mib"] * prov.MiB, cfg["file_max_mib"] * prov.MiB)
    plans = {item["record_id"]: prov.jsvul_revisions(by_id[item["record_id"]], by_id) for item in subset}
    snapshot_keys = sorted({(r.project, r.sha) for revs, _ in plans.values() for r in revs})
    run.logger.info("jsvul: %d records need %d snapshots", len(subset), len(snapshot_keys))
    snapshots = dict(zip(snapshot_keys, prov.run_parallel(lambda k: rec.fetch_snapshot(*k), snapshot_keys, cfg["workers"])))

    def one(item: dict[str, str]) -> dict[str, Any]:
        revs, note = plans[item["record_id"]]
        checks = [rec.check_revision(r, snapshots[(r.project, r.sha)]) for r in revs]
        repo_http = None
        if not any(c["c1"] for c in checks):
            repo_http = rec.repo_status(revs[0].project)
        status, detail = prov.classify_jsvul(checks, note, repo_http)
        row = by_id[item["record_id"]]
        return {
            "audit": {
                "source": "jsvul", "record_id": item["record_id"], "rank": item["rank"],
                "stage": item["stage"], "status": status, "detail": detail,
                "revisions_required": len(revs) + (1 if note else 0),
                "revisions_c1": sum(c["c1"] for c in checks),
                "revisions_c2": sum(c["c2"] for c in checks),
                "typescript_original": row["typescript_original"], "family": row["project"],
            },
            "revisions": checks,
        }

    return prov.run_parallel(one, subset, cfg["workers"])


def _recover_secbench(run: Run, inventory_run: Path, subset: list[dict[str, str]], fetcher: prov.Fetcher) -> list[dict[str, Any]]:
    cfg = run.config["p2"]
    by_id = {r["record_id"]: r for r in inv.read_rows(inventory_run / "inventory_secbench.csv.gz")}
    npm = prov.NpmRecovery(fetcher, _data_root(), cfg["npm_tarball_max_mib"] * prov.MiB)

    def one(item: dict[str, str]) -> dict[str, Any]:
        row = by_id[item["record_id"]]
        vuln = fixed = None
        if not row["parse_error"] and row["dependency_count"] == "1":
            vuln = npm.fetch_version(row["package"], row["vulnerable_version"])
            if row["has_fixed_version"] == "True":
                fixed = npm.fetch_version(row["package"], row["fixed_version"])
        status, detail = prov.classify_secbench(row, vuln, fixed)
        return {
            "audit": {
                "source": "secbench", "record_id": item["record_id"], "rank": item["rank"],
                "stage": item["stage"], "status": status, "detail": detail,
                "revisions_required": 2,
                "revisions_c1": 0,
                "revisions_c2": sum(bool(v and v["ok"]) for v in (vuln, fixed)),
                "typescript_original": "", "family": row["package"],
            },
            "revisions": [v for v in (vuln, fixed) if v is not None],
        }

    return prov.run_parallel(one, subset, cfg["workers"])


def _recover_sard(run: Run, inventory_run: Path, subset: list[dict[str, str]], guard: prov.StorageGuard) -> list[dict[str, Any]]:
    cases = {r["record_id"]: r for r in inv.read_rows(inventory_run / "inventory_sard_php.csv.gz")}
    pairs = {r["pair_id"]: r for r in inv.read_rows(inventory_run / "sard_candidate_pairs.csv.gz")}
    path, _ = _input(run.config["p2"]["manifest"]["sard_php"], run)
    dest = _data_root() / "snapshots" / "sard_php"
    out = []
    with zipfile.ZipFile(path) as archive:
        for item in subset:
            pair = pairs[item["record_id"]]
            twins = [prov.extract_sard_case(archive, cid, dest, cases[cid]["src_sha256"], guard)
                     for cid in (pair["bad_record_id"], pair["good_record_id"])]
            ok = [t["ok"] for t in twins]
            if all(ok):
                status, detail = "recovered_c2", ""
            elif any(ok):
                status, detail = "recovered_one_revision", ";".join(t["error"] for t in twins if t["error"])
            else:
                status, detail = "other", ";".join(t["error"] for t in twins)
            out.append({
                "audit": {
                    "source": "sard_php", "record_id": item["record_id"], "rank": item["rank"],
                    "stage": item["stage"], "status": status, "detail": detail,
                    "revisions_required": 2, "revisions_c1": sum(ok), "revisions_c2": sum(ok),
                    "typescript_original": "", "family": pair["cwe"],
                },
                "revisions": twins,
            })
    return out


def run_recover(run: Run, inventory_run: Path, select_run: Path, sources: list[str]) -> dict[str, Any]:
    inventory_run = _from_run(inventory_run, "inventory")
    select_run = _from_run(select_run, "select-subsets")
    lineage = check_lineage(run.config, inventory_run, select_run)
    guard = _guard(run)
    fetcher = prov.Fetcher(guard, run.logger.info, token=prov.github_token())
    summary: dict[str, Any] = {
        "inventory_run": inventory_run.name, "select_run": select_run.name,
        "subset_files": lineage["subset_files"],
    }
    for source in sources:
        subset = inv.read_rows(select_run / f"subset_{source}.csv")
        if source == "jsvul":
            results = _recover_jsvul(run, inventory_run, subset, fetcher)
        elif source == "secbench":
            results = _recover_secbench(run, inventory_run, subset, fetcher)
        else:
            results = _recover_sard(run, inventory_run, subset, guard)
        audits = [r["audit"] for r in results]
        statuses = Counter(a["status"] for a in audits)
        unknown = set(statuses) - set(prov.STATUSES)
        assert not unknown, f"unknown statuses {unknown}"
        assert sum(statuses.values()) == len(subset) == len({a["record_id"] for a in audits})
        inv.write_rows(run.path / f"audit_provenance_{source}.csv", AUDIT_FIELDS, audits)
        _json(run.path / f"recovery_details_{source}.json", results)
        summary[source] = {"inspected": len(subset), "statuses": dict(statuses)}
        run.logger.info("%s recovery: %s", source, dict(statuses))
    _json(run.path / "fetch_log.json", fetcher.records)
    summary["bytes_written"] = guard.written
    summary["output_files"] = _digest(
        run.path, tuple(f"{kind}_{s}.{ext}" for s in sources
                        for kind, ext in (("audit_provenance", "csv"), ("recovery_details", "json")))
    )
    _json(run.path / "recovery_summary.json", summary)
    return summary





def _norm(text: str) -> str:
    return re.sub(r"\s+", " ", text).strip()


def _jsvul_bodies(path: Path, ids: set[str]) -> dict[str, str]:
    bodies = {}
    with zipfile.ZipFile(path) as zf:
        for split in inv.JSVUL_SPLITS:
            for raw in zf.open(f"{split}.jsonl"):
                rec = json.loads(raw)
                if rec["id"] in ids:
                    bodies[rec["id"]] = rec["body"]
    return bodies


def run_audit(run: Run, inventory_run: Path, select_run: Path, recover_runs: list[Path]) -> dict[str, Any]:
    pass
    inventory_run = _from_run(inventory_run, "inventory")
    select_run = _from_run(select_run, "select-subsets")
    lineage = check_lineage(run.config, inventory_run, select_run)
    cfg, seed = run.config["p2"], run.config["seed"]
    audits: dict[str, list[dict[str, str]]] = {}
    details: dict[str, dict[str, Any]] = {}
    for recover_run in recover_runs:
        recover_run = _from_run(recover_run, "recover")
        recovered = json.loads((recover_run / "recovery_summary.json").read_text())
        if (recovered.get("inventory_run"), recovered.get("select_run")) != (inventory_run.name, select_run.name):
            raise LineageError(f"{recover_run.name} was not recovered from these inventory/select runs")
        if recovered.get("subset_files") != lineage["subset_files"]:
            raise LineageError(f"{recover_run.name} used different subset files")
        if _digest(recover_run, tuple(recovered["output_files"])) != recovered["output_files"]:
            raise LineageError(f"{recover_run.name} outputs changed after recovery")
        for source in SOURCES:
            if (recover_run / f"audit_provenance_{source}.csv").exists():
                if source in audits:
                    raise RuntimeError(f"{source} recovered in more than one run")
                audits[source] = inv.read_rows(recover_run / f"audit_provenance_{source}.csv")
                for res in json.loads((recover_run / f"recovery_details_{source}.json").read_text()):
                    details.setdefault(source, {})[res["audit"]["record_id"]] = res
    summary: dict[str, Any] = {"sources": {}}
    all_rows = []
    for source, rows in audits.items():
        subset = inv.read_rows(select_run / f"subset_{source}.csv")
        assert {r["record_id"] for r in rows} == {s["record_id"] for s in subset}, source
        statuses = Counter(r["status"] for r in rows)
        by_stage: dict[str, Counter] = {}
        for r in rows:
            by_stage.setdefault(r["stage"], Counter())[r["status"]] += 1
        summary["sources"][source] = {
            "inspected": len(rows), "statuses": dict(statuses),
            "status_total_matches_inspected": sum(statuses.values()) == len(rows),
            "by_stage": {k: dict(v) for k, v in by_stage.items()},
            "c1_records": sum(int(r["revisions_c1"]) > 0 for r in rows),
            "c2_records": statuses.get("recovered_c2", 0),
        }
        if source == "jsvul":
            ts = [r for r in rows if r["typescript_original"] == "True"]
            summary["sources"][source]["typescript_original"] = {
                "inspected": len(ts), "recovered_c2": sum(r["status"] == "recovered_c2" for r in ts)}
        all_rows += rows
    inv.write_rows(run.path / "audit_provenance.csv", AUDIT_FIELDS, all_rows)

    
    c2 = [r["record_id"] for r in audits.get("jsvul", []) if r["status"] == "recovered_c2"]
    sample = prov.select_subset(c2, seed, "jsvul-p2-spotcheck", min(cfg["spot_check"], len(c2)))
    inventory = {r["record_id"]: r for r in inv.read_rows(inventory_run / "inventory_jsvul.csv.gz")}
    revision_ids = {rev["record_id"] for s in sample for rev in details["jsvul"][s["record_id"]]["revisions"]}
    path, _ = _input(cfg["manifest"]["jsvul"], run)
    bodies = _jsvul_bodies(path, revision_ids)
    checks = []
    for s in sample:
        for rev in details["jsvul"][s["record_id"]]["revisions"]:
            row = inventory[rev["record_id"]]
            local = _data_root() / "files" / "jsvul" / row["project"].replace("/", "__") / row["revision"] / row["file"]
            text = local.read_text(encoding="utf-8", errors="replace") if local.is_file() else ""
            lines = text.splitlines()
            start, end = int(row["start_line"] or 0), int(row["end_line"] or 0)
            span = "\n".join(lines[start - 1:end]) if 0 < start <= end <= len(lines) else ""
            body = bodies.get(rev["record_id"], "")
            checks.append({
                "sample_record_id": s["record_id"], "revision_record_id": rev["record_id"],
                "snapshot_member_present": bool(rev["snapshot_member_sha256"]),
                "snapshot_equals_raw": rev["snapshot_member_sha256"] == rev["raw_sha256"] != "",
                "body_sha256_matches_inventory": hashlib.sha256(body.encode()).hexdigest() == row["body_sha256"],
                "loc_within_file": bool(span), "file_lines": len(lines),
                "start_line": start, "end_line": end,
                "span_body_exact": _norm(span) == _norm(body),
                "span_body_similarity": round(difflib.SequenceMatcher(None, _norm(span), _norm(body)).ratio(), 3),
            })
    _json(run.path / "spot_check_jsvul.json", {"sample": sample, "checks": checks})
    summary["spot_check_jsvul"] = {
        "records": len(sample), "revisions": len(checks),
        "snapshot_member_present": sum(c["snapshot_member_present"] for c in checks),
        "snapshot_equals_raw": sum(c["snapshot_equals_raw"] for c in checks),
        "loc_within_file": sum(c["loc_within_file"] for c in checks),
        "span_body_exact": sum(c["span_body_exact"] for c in checks),
        "span_body_similarity_median": sorted(c["span_body_similarity"] for c in checks)[len(checks) // 2] if checks else None,
    }
    _json(run.path / "audit_summary.json", summary)
    return summary
