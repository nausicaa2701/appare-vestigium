"""Data manifest schema and SHA-256 verification.

``local_path`` is resolved against ``RAVEN_DATA_ROOT`` (data stays outside Git) unless it
is absolute. Each row must point to a single file whose SHA-256 matches ``sha256``.
"""

from __future__ import annotations

import csv
import hashlib
import os
import re
from dataclasses import dataclass
from pathlib import Path

COLUMNS = ("id", "kind", "uri", "version", "sha256", "license", "local_path", "split", "notes")
KINDS = {"dataset", "archive", "model", "tool"}
_SHA256 = re.compile(r"^[0-9a-f]{64}$")


class ManifestError(ValueError):
    pass


@dataclass
class RowResult:
    id: str
    ok: bool
    reason: str


def sha256_file(path: Path, chunk: int = 1 << 20) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        while block := handle.read(chunk):
            digest.update(block)
    return digest.hexdigest()


def read_manifest(path: Path) -> list[dict[str, str]]:
    with path.open(newline="", encoding="utf-8") as handle:
        reader = csv.DictReader(handle)
        if tuple(reader.fieldnames or ()) != COLUMNS:
            raise ManifestError(f"header must be {','.join(COLUMNS)}; got {reader.fieldnames}")
        rows = []
        for row in reader:
            
            if None in row:
                raise ManifestError(
                    f"{path}:{reader.line_num}: {len(row[None])} extra cell(s) beyond "
                    f"{len(COLUMNS)} columns"
                )
            missing = [column for column in COLUMNS if row[column] is None]
            if missing:
                raise ManifestError(f"{path}:{reader.line_num}: missing column(s) {missing}")
            rows.append(row)
    ids = [row["id"] for row in rows]
    duplicates = sorted({i for i in ids if ids.count(i) > 1})
    if duplicates:
        raise ManifestError(f"duplicate ids: {duplicates}")
    return rows


def resolve_local_path(local_path: str, data_root: Path | None) -> Path:
    path = Path(local_path)
    if path.is_absolute():
        return path
    if data_root is None:
        raise ManifestError(f"relative local_path '{local_path}' needs RAVEN_DATA_ROOT")
    return data_root / path


def verify_row(row: dict[str, str], data_root: Path | None) -> RowResult:
    rid = row["id"]
    for field in ("id", "kind", "uri", "version", "license", "local_path"):
        if not row[field].strip():
            return RowResult(rid, False, f"empty {field}")
    if row["kind"] not in KINDS:
        return RowResult(rid, False, f"kind '{row['kind']}' not in {sorted(KINDS)}")
    if not _SHA256.match(row["sha256"]):
        return RowResult(rid, False, "sha256 is not 64 lowercase hex characters")
    try:
        path = resolve_local_path(row["local_path"], data_root)
    except ManifestError as exc:
        return RowResult(rid, False, str(exc))
    if not path.is_file():
        return RowResult(rid, False, f"missing file {path}")
    actual = sha256_file(path)
    if actual != row["sha256"]:
        return RowResult(rid, False, f"sha256 mismatch: expected {row['sha256']}, got {actual}")
    return RowResult(rid, True, "ok")


def verify_manifest(path: Path, data_root: Path | None = None) -> list[RowResult]:
    if data_root is None and os.environ.get("RAVEN_DATA_ROOT"):
        data_root = Path(os.environ["RAVEN_DATA_ROOT"])
    return [verify_row(row, data_root) for row in read_manifest(path)]
