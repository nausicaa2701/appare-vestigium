"""Full-source metadata inventory (P2). Covers every record of each source; no cap applies.

Each reader yields one flat row per record using only metadata already in the pinned
archive: nothing is downloaded and no snapshot is recovered here. Rows carry hashes of
code fields instead of the code itself, so inventories stay small enough to keep.
"""

from __future__ import annotations

import ast
import csv
import gzip
import hashlib
import io
import json
import re
import zipfile
from collections import Counter
from collections.abc import Iterable, Iterator
from pathlib import Path, PurePosixPath
from typing import Any

JSVUL_SPLITS = ("train", "val", "test")
TYPESCRIPT_EXTENSIONS = {"ts", "tsx", "mts", "cts"}

JSVUL_FIELDS = (
    "source", "record_id", "upstream_split", "project", "repo_url", "revision", "file",
    "extension", "typescript_original", "start_line", "start_column", "end_line",
    "end_column", "label", "paired_id", "name", "cve", "cwe", "ghsa", "snyk", "other",
    "publish_date", "body_sha256",
)
SECBENCH_CATEGORIES = (
    "code-injection", "command-injection", "path-traversal", "prototype-pollution", "redos",
)
SECBENCH_FIELDS = (
    "source", "record_id", "category", "official", "advisory_id", "package",
    "vulnerable_version", "vulnerable_version_raw", "dependency_count", "fixed_version",
    "fixed_version_raw", "has_fixed_version", "fix_commit_url", "fix_repo",
    "fix_commit", "links", "sink", "file_count", "has_fixed_dockerfile", "parse_error",
)
SARD_FIELDS = (
    "source", "record_id", "case_id", "case_version", "state", "status", "cwe", "input",
    "sanitize", "construction", "src_file", "src_sha256", "artifact_count",
    "description_input", "description_sanitize", "description_construction",
)

_GITHUB_COMMIT = re.compile(r"github\.com/([^/]+/[^/]+)/commit/([0-9a-fA-F]{7,40})")
_SARD_CASE = re.compile(r"^(\d+)-v([^/]+)/manifest\.sarif$")


class InventoryError(RuntimeError):
    pass


def _literal(value: Any) -> Any:
    pass
    if isinstance(value, str) and value[:1] in "[{(":
        try:
            return ast.literal_eval(value)
        except (ValueError, SyntaxError):
            return value
    return value


def _joined(value: Any) -> str:
    value = _literal(value)
    if value is None:
        return ""
    if isinstance(value, (list, tuple, set)):
        return ";".join(str(v) for v in value)
    return str(value)


def _date(value: Any) -> str:
    value = _literal(value)
    if isinstance(value, dict) and {"year", "month", "day"} <= set(value):
        return f"{int(value['year']):04d}-{int(value['month']):02d}-{int(value['day']):02d}"
    return ""


def _sha256_text(text: str | None) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest() if text is not None else ""


def jsvul_records(archive: Path) -> Iterator[dict[str, Any]]:
    with zipfile.ZipFile(archive) as zf:
        names = set(zf.namelist())
        for split in JSVUL_SPLITS:
            member = f"{split}.jsonl"
            if member not in names:
                raise InventoryError(f"{archive}: missing {member}")
            with zf.open(member) as handle:
                for line_no, raw in enumerate(handle, 1):
                    if not raw.strip():
                        continue
                    try:
                        rec = json.loads(raw)
                    except json.JSONDecodeError as exc:
                        raise InventoryError(f"{member}:{line_no}: {exc}") from exc
                    loc = _literal(rec.get("loc")) or {}
                    file = rec.get("file", "")
                    ext = PurePosixPath(file).suffix.lstrip(".").lower()
                    yield {
                        "source": "jsvul",
                        "record_id": rec["id"],
                        "upstream_split": split,
                        "project": rec.get("project", ""),
                        "repo_url": f"https://github.com/{rec['project']}" if rec.get("project") else "",
                        "revision": rec.get("sha", ""),
                        "file": file,
                        "extension": ext,
                        "typescript_original": ext in TYPESCRIPT_EXTENSIONS,
                        "start_line": loc.get("start_line", "") if isinstance(loc, dict) else "",
                        "start_column": loc.get("start_column", "") if isinstance(loc, dict) else "",
                        "end_line": loc.get("end_line", "") if isinstance(loc, dict) else "",
                        "end_column": loc.get("end_column", "") if isinstance(loc, dict) else "",
                        "label": int(rec["label"]) if str(rec.get("label", "")).strip() else "",
                        "paired_id": rec.get("paired_id") or "",
                        "name": rec.get("name") or "",
                        "cve": _joined(rec.get("cve")),
                        "cwe": _joined(rec.get("cwe")),
                        "ghsa": _joined(rec.get("ghsa")),
                        "snyk": _joined(rec.get("snyk")),
                        "other": _joined(rec.get("other")),
                        "publish_date": _date(rec.get("publish_time")),
                        "body_sha256": _sha256_text(rec.get("body")),
                    }


def jsvul_line_count(archive: Path) -> int:
    with zipfile.ZipFile(archive) as zf:
        return sum(
            1
            for split in JSVUL_SPLITS
            for raw in zf.open(f"{split}.jsonl")
            if raw.strip()
        )


NO_FIX_MARKERS = {"", "n/a", "na", "none", "null"}


def normalize_version(value: str) -> str:
    pass
    value = value.strip()
    if value.startswith("=") and not value.startswith("=="):
        value = value[1:].strip()
    return value


def _secbench_instances(names: Iterable[str]) -> list[tuple[str, str, bool]]:
    pass
    found = []
    for name in names:
        parts = name.split("/")
        if parts[-1] != "package.json" or len(parts) < 4:
            continue
        category = parts[1]
        if category in SECBENCH_CATEGORIES and len(parts) == 4:
            found.append((name, f"{category}/{parts[2]}", True))
        elif category == "incubator" and len(parts) in (4, 5):
            found.append((name, "/".join(parts[1:-1]), False))
    return sorted(found, key=lambda item: item[1])


def secbench_records(archive: Path) -> Iterator[dict[str, Any]]:
    with zipfile.ZipFile(archive) as zf:
        names = zf.namelist()
        for member, record_id, official in _secbench_instances(names):
            directory = member.rsplit("/", 1)[0] + "/"
            members = [n for n in names if n.startswith(directory) and not n.endswith("/")]
            row: dict[str, Any] = {f: "" for f in SECBENCH_FIELDS}
            row.update(
                source="secbench",
                record_id=record_id,
                category=record_id.split("/")[0],
                official=official,
                file_count=len(members),
                has_fixed_dockerfile=f"{directory}Dockerfile.fixed" in members,
            )
            try:
                meta = json.loads(zf.read(member))
            except (json.JSONDecodeError, UnicodeDecodeError) as exc:
                row["parse_error"] = f"{type(exc).__name__}: {exc}"
                yield row
                continue
            deps = meta.get("dependencies") or {}
            row["dependency_count"] = len(deps)
            if len(deps) == 1:
                (row["package"], raw_version), = deps.items()
                row["vulnerable_version_raw"] = str(raw_version)
                row["vulnerable_version"] = normalize_version(str(raw_version))
            elif deps:
                row["package"] = ";".join(deps)
                row["vulnerable_version_raw"] = ";".join(str(v) for v in deps.values())
                row["vulnerable_version"] = row["vulnerable_version_raw"]
            fixed_raw = str(meta.get("fixedVersion") or "")
            fix = str(meta.get("fixCommit") or "")
            match = _GITHUB_COMMIT.search(fix)
            links = meta.get("links") or {}
            row.update(
                advisory_id=str(meta.get("id") or ""),
                fixed_version_raw=fixed_raw,
                fixed_version=normalize_version(fixed_raw),
                has_fixed_version=fixed_raw.strip().lower() not in NO_FIX_MARKERS,
                fix_commit_url=fix,
                fix_repo=match.group(1) if match else "",
                fix_commit=match.group(2).lower() if match else "",
                links=";".join(str(v) for v in links.values() if v) if isinstance(links, dict) else str(links),
                sink=str(meta.get("sink") or ""),
            )
            yield row


def secbench_instance_count(archive: Path) -> dict[str, int]:
    with zipfile.ZipFile(archive) as zf:
        found = _secbench_instances(zf.namelist())
    return {"official": sum(o for _, _, o in found), "incubator": sum(not o for _, _, o in found)}


def _description_fields(text: str) -> dict[str, str]:
    fields = {"input": "", "sanitize": "", "construction": ""}
    for line in text.splitlines():
        key, sep, value = line.partition(":")
        if sep and key.strip().lower() in fields:
            fields[key.strip().lower()] = value.strip()
    return fields


def sard_records(archive: Path) -> Iterator[dict[str, Any]]:
    with zipfile.ZipFile(archive) as zf:
        for name in sorted(n for n in zf.namelist() if _SARD_CASE.match(n)):
            case_id, case_version = _SARD_CASE.match(name).groups()
            run = json.loads(zf.read(name))["runs"][0]
            props = run.get("properties", {})
            artifacts = run.get("artifacts", [])
            src = [a for a in artifacts if a.get("location", {}).get("uri", "").startswith("src/")]
            src_uri = src[0]["location"]["uri"] if len(src) == 1 else ""
            stem = PurePosixPath(src_uri).stem
            parts = stem.split("__") if stem else []
            described = _description_fields(props.get("description", ""))
            cwe = re.match(r"CWE_(\d+)", parts[0]) if parts else None
            yield {
                "source": "sard_php",
                "record_id": f"{case_id}-v{case_version}",
                "case_id": case_id,
                "case_version": case_version,
                "state": props.get("state", ""),
                "status": props.get("status", ""),
                "cwe": f"CWE-{cwe.group(1)}" if cwe else "",
                "input": parts[1] if len(parts) == 4 else "",
                "sanitize": parts[2] if len(parts) == 4 else "",
                "construction": parts[3] if len(parts) == 4 else "",
                "src_file": src_uri,
                "src_sha256": src[0].get("hashes", {}).get("sha-256", "") if len(src) == 1 else "",
                "artifact_count": len(artifacts),
                "description_input": described["input"],
                "description_sanitize": described["sanitize"],
                "description_construction": described["construction"],
            }


def sard_case_count(archive: Path) -> int:
    with zipfile.ZipFile(archive) as zf:
        return sum(1 for n in zf.namelist() if _SARD_CASE.match(n))


def write_rows(path: Path, fields: tuple[str, ...], rows: Iterable[dict[str, Any]]) -> int:
    pass





    count = 0
    with path.open("wb") as raw:
        binary = gzip.GzipFile(filename="", mode="wb", fileobj=raw, mtime=0) if path.suffix == ".gz" else raw
        with binary, io.TextIOWrapper(binary, encoding="utf-8", newline="") as handle:
            writer = csv.DictWriter(handle, fieldnames=fields, extrasaction="raise", lineterminator="\n")
            writer.writeheader()
            for row in rows:
                writer.writerow(row)
                count += 1
    return count


def read_rows(path: Path) -> list[dict[str, str]]:
    opener = gzip.open if path.suffix == ".gz" else open
    with opener(path, "rt", newline="", encoding="utf-8") as handle:
        return list(csv.DictReader(handle))


def missing_counts(rows: list[dict[str, Any]], fields: tuple[str, ...]) -> dict[str, int]:
    counts = Counter()
    for row in rows:
        for field in fields:
            if row.get(field) in ("", None):
                counts[field] += 1
    return {field: counts[field] for field in fields if counts[field]}


SARD_PAIR_FIELDS = (
    "pair_id", "cwe", "input", "construction", "bad_record_id", "bad_sanitize",
    "good_record_id", "good_sanitize", "group_bad_cases", "group_good_cases",
)


def sard_candidate_pairs(rows: list[dict[str, Any]], seed: int) -> list[dict[str, Any]]:
    pass






    def key(record_id: str) -> str:
        return hashlib.sha256(f"{seed}\0sard_php_pairing\0{record_id}".encode()).hexdigest()

    groups: dict[tuple[str, str, str], dict[str, list[dict[str, Any]]]] = {}
    for row in rows:
        if not (row["cwe"] and row["input"] and row["construction"]) or row["state"] not in ("good", "bad"):
            continue
        group = groups.setdefault((row["cwe"], row["input"], row["construction"]), {"good": [], "bad": []})
        group[row["state"]].append(row)
    pairs = []
    for (cwe, inp, construction), group in sorted(groups.items()):
        if not group["good"] or not group["bad"]:
            continue
        bad = min(group["bad"], key=lambda r: key(r["record_id"]))
        good = min(group["good"], key=lambda r: key(r["record_id"]))
        if bad["sanitize"] == good["sanitize"]:
            continue
        pairs.append({
            "pair_id": f"{bad['record_id']}+{good['record_id']}",
            "cwe": cwe, "input": inp, "construction": construction,
            "bad_record_id": bad["record_id"], "bad_sanitize": bad["sanitize"],
            "good_record_id": good["record_id"], "good_sanitize": good["sanitize"],
            "group_bad_cases": len(group["bad"]), "group_good_cases": len(group["good"]),
        })
    return pairs
