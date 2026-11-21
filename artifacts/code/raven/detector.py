"""Detector (P7A) entry points and the scoring-role guard (plan §P7 AC 1): pilot training and
scoring may touch ``pilot_dev`` groups only. ``confirmatory_reserved`` and ``external``
(SecBench.js) groups are refused, as is any sample whose role is unknown. Training, threshold
calibration and scoring live in ``raven.p7a``."""

from __future__ import annotations

from collections.abc import Iterable, Mapping

SCORABLE_ROLES = frozenset({"pilot_dev"})
REFUSED_ROLES = frozenset({"confirmatory_reserved", "external"})


class ScoringRoleError(ValueError):
    pass


def assert_scorable(sample_ids: Iterable[str], roles: Mapping[str, str]) -> None:
    pass
    bad: dict[str, list[str]] = {}
    for sid in sample_ids:
        role = roles.get(sid, "")
        if role not in SCORABLE_ROLES:
            bad.setdefault(role or "unknown", []).append(sid)
    if bad:
        detail = "; ".join(f"{role}: {len(ids)} (e.g. {ids[0]})" for role, ids in sorted(bad.items()))
        raise ScoringRoleError(f"pilot scoring accepts pilot_dev only; refused {detail}")



import csv
import hashlib
import json
from pathlib import Path
from typing import Any


def load_roles(pilot_groups: Path, sample_families: Mapping[str, str]) -> dict[str, str]:
    pass

    with Path(pilot_groups).open(newline="", encoding="utf-8") as fh:
        groups = {r["group_id"]: r["role"] for r in csv.DictReader(fh)}
    return {sid: groups.get(fam, "") for sid, fam in sample_families.items()}


def cohort_from_pack_run(pack_run: Path, level: str, budget: str, method: str) -> dict[str, str]:
    pass
    out = {}
    with (Path(pack_run) / "pack_cells.csv").open(newline="", encoding="utf-8") as fh:
        for r in csv.DictReader(fh):
            if r["level"] == level and r["budget_name"] == budget and r["method"] == method:
                out[r["sample_id"]] = r["family"]
    return out


def full_context_cohort(pack_run: Path, level: str, budget: str, method: str, limit: int) -> dict[str, Any]:
    pass






    eligible, long_input, members = set(), set(), {}
    with (Path(pack_run) / "pack_cells.csv").open(newline="", encoding="utf-8") as fh:
        for r in csv.DictReader(fh):
            if r["level"] != level or r["budget_name"] != budget or r["method"] != method:
                continue
            members.setdefault(r["family"], set()).add(r["sample_id"])
            if r["target_fits_budget"] != "true":
                continue
            (eligible if int(r["full_tokens"]) <= int(limit) else long_input).add(r["sample_id"])
    complete = {fam for fam, ids in members.items() if ids <= eligible}
    return {"limit": int(limit), "eligible": sorted(eligible), "long_input_stratum": sorted(long_input),
            "family_complete": sorted(complete),
            "family_complete_samples": sorted(s for fam in complete for s in members[fam])}


def guarded_cohort(cfg: dict[str, Any], pack_run: Path) -> tuple[dict[str, str], dict[str, Any]]:
    pass

    d = cfg["p7"]["detector"]
    groups = Path(d["pilot_groups"])
    sha = hashlib.sha256(groups.read_bytes()).hexdigest()
    if d.get("pilot_groups_sha256") and sha != d["pilot_groups_sha256"]:
        raise ScoringRoleError(f"{groups} SHA-256 {sha[:12]}… differs from the pinned value")
    families = cohort_from_pack_run(pack_run, d["level"], str(d["budget"]), d["method"])
    if not families:
        raise ScoringRoleError("detector cohort is empty for the configured level/budget/method")
    roles = load_roles(groups, families)
    assert_scorable(families, roles)
    return families, {"pilot_groups": str(groups), "pilot_groups_sha256": sha, "samples": len(families)}


def run_train(run, pack_run: Path, fold: str = "0", variant: str | None = None, extract_run: Path | None = None,
              build_run: Path | None = None, max_steps: int | None = None,
              resume: Path | None = None, stop_after: int | None = None) -> dict[str, Any]:
    pass


    d = run.config["p7"]["detector"]
    if not d.get("training_enabled", False) and "operation_manifest" not in d:
        _families, info = guarded_cohort(run.config, pack_run)
        (run.path / "cohort_guard.json").write_text(json.dumps(info, indent=2, sort_keys=True) + "\n")
        raise RuntimeError("detector training is not enabled (p7.detector.training_enabled=false)")
    from raven import p7a

    kwargs = {}
    if resume is not None or stop_after is not None:
        kwargs = {"resume": resume, "stop_after": stop_after}
    return p7a.run_train(run, pack_run, fold, variant or d["primary_variant"], Path(extract_run or d["extract_run"]),
                         Path(build_run or d["build_run"]), max_steps, **kwargs)


def run_score(run, pack_run: Path, train_run: Path | None = None) -> dict[str, Any]:
    pass


    if run.config["p7"]["detector"].get("input_bundle"):
        from raven import p7a

        if train_run is None:
            raise NotImplementedError("detector scoring needs --train-run")
        return p7a.run_score(run, pack_run, Path(train_run))
    if "operation_manifest" in run.config["p7"]["detector"]:
        from raven import p5, p7debug
        from raven.p2 import LineageError

        _roles, _texts, info = p7debug.operation_cohort(run.config, "final", run.path,
                                                        lambda: p5.load_tokenizer(run.config))
        (run.path / "cohort_guard.json").write_text(json.dumps(info, indent=2, sort_keys=True) + "\n")
        raise LineageError("operation-manifest scoring inputs (reference/target_only views) are not defined "
                           "(D3 input contract); refusing to score")
    _families, info = guarded_cohort(run.config, pack_run)
    (run.path / "cohort_guard.json").write_text(json.dumps(info, indent=2, sort_keys=True) + "\n")
    if train_run is None:
        raise NotImplementedError("detector scoring needs --train-run (a frozen checkpoint)")
    from raven import p7a

    return p7a.run_score(run, pack_run, Path(train_run))
