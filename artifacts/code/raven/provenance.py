"""Snapshot recovery and provenance audit for the capped subset (P2).

Selection: records are ordered by ascending hex SHA-256 of ``"<seed>\\0<namespace>\\0<id>"``
(``docs/pilot-decisions.md``); records already touched by earlier probes are counted first.

Recovery only downloads pinned files and archives and verifies them. Nothing is
installed, built or executed: no npm install hooks, no exploit code.

Every record ends with exactly one status from ``STATUSES``; the detail field says why.
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
import shutil
import tarfile
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
import zipfile
from collections.abc import Callable, Iterable
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

STATUSES = (
    "recovered_c2",  
    "recovered_c1_only",  
    "recovered_one_revision",  
    "missing_revision",  
    "package_unavailable",  
    "repo_gone",  
    "ambiguous_target",  
    "license_blocked",
    "other",
)
GiB = 1 << 30
MiB = 1 << 20
USER_AGENT = "RAVEN-pilot-provenance (research; metadata-pinned downloads only)"


def selection_hash(seed: int, namespace: str, record_id: str) -> str:
    return hashlib.sha256(f"{seed}\0{namespace}\0{record_id}".encode()).hexdigest()


def select_subset(
    ids: Iterable[str], seed: int, namespace: str, cap: int, preselected: Iterable[str] = ()
) -> list[dict[str, Any]]:
    pass
    pool = sorted(set(ids))
    pool_set = set(pool)
    prior = [i for i in dict.fromkeys(preselected)]
    unknown = [i for i in prior if i not in pool_set]
    if unknown:
        raise ValueError(f"preselected ids not in the eligible pool: {unknown[:3]}")
    if len(prior) > cap:
        raise ValueError(f"{len(prior)} preselected ids exceed cap {cap}")
    ordered = sorted((selection_hash(seed, namespace, i), i) for i in pool if i not in set(prior))
    chosen = [("prior_probe", selection_hash(seed, namespace, i), i) for i in prior]
    chosen += [("hash_order", h, i) for h, i in ordered[: cap - len(prior)]]
    return [
        {"rank": n, "record_id": i, "stage": stage, "selection_sha256": h}
        for n, (stage, h, i) in enumerate(chosen, 1)
    ]





class StorageGuardError(RuntimeError):
    pass


@dataclass
class StorageGuard:
    data_root: Path
    volume: Path
    min_free_bytes: int
    envelope_bytes: int
    used_at_start: int = 0
    written: int = 0
    _lock: threading.Lock = field(default_factory=threading.Lock, repr=False)

    @classmethod
    def from_config(cls, data_root: Path, cfg: dict[str, Any]) -> StorageGuard:
        volume = Path(cfg["volume"])
        if not volume.is_mount():
            raise StorageGuardError(f"{volume} is not mounted; refusing to write elsewhere")
        if volume not in data_root.resolve().parents:
            raise StorageGuardError(f"data root {data_root} is not on {volume}")
        used = sum(p.stat().st_size for p in data_root.rglob("*") if p.is_file())
        return cls(
            data_root=data_root,
            volume=volume,
            min_free_bytes=int(cfg["min_free_gib"] * GiB),
            envelope_bytes=int(cfg["envelope_gib"] * GiB),
            used_at_start=used,
        )

    def _fits(self, incoming: int) -> str:
        free = shutil.disk_usage(self.volume).free
        if free - incoming < self.min_free_bytes:
            return f"free space {free / GiB:.1f} GiB would drop below minimum"
        if self.used_at_start + self.written + incoming > self.envelope_bytes:
            return "pilot storage envelope would be exceeded"
        return ""

    def check(self, incoming: int = 0) -> None:
        with self._lock:
            problem = self._fits(incoming)
        if problem:
            raise StorageGuardError(problem)

    def reserve(self, nbytes: int) -> None:
        pass
        with self._lock:
            problem = self._fits(nbytes)
            if not problem:
                self.written += nbytes
        if problem:
            raise StorageGuardError(problem)

    def release(self, nbytes: int) -> None:
        pass
        with self._lock:
            self.written -= nbytes





@dataclass
class Fetch:
    url: str
    ok: bool
    http_status: int | None = None
    path: str = ""
    bytes: int = 0
    sha256: str = ""
    error: str = ""
    cached: bool = False


class Fetcher:
    pass

    def __init__(
        self,
        guard: StorageGuard,
        log: Callable[[str], None],
        retries: int = 3,
        timeout: float = 60.0,
        token: str | None = None,
    ) -> None:
        self.guard = guard
        self.log = log
        self.retries = retries
        self.timeout = timeout
        self.token = token
        self.records: list[dict[str, Any]] = []
        self._lock = threading.Lock()
        self._dest_locks: dict[Path, threading.Lock] = {}

    def _dest_lock(self, dest: Path) -> threading.Lock:
        with self._lock:
            return self._dest_locks.setdefault(dest.resolve(), threading.Lock())

    def _request(self, url: str) -> urllib.request.Request:
        headers = {"User-Agent": USER_AGENT}
        if self.token and urllib.parse.urlparse(url).hostname == "api.github.com":
            headers["Authorization"] = f"Bearer {self.token}"
        return urllib.request.Request(url, headers=headers)

    def _record(self, result: Fetch) -> Fetch:
        with self._lock:
            self.records.append(result.__dict__.copy())
        return result

    def get_json(self, url: str) -> tuple[int | None, Any, str]:
        for attempt in range(1, self.retries + 1):
            try:
                with urllib.request.urlopen(self._request(url), timeout=self.timeout) as resp:
                    return resp.status, json.loads(resp.read()), ""
            except urllib.error.HTTPError as exc:
                if exc.code < 500 and exc.code != 429:
                    return exc.code, None, f"HTTP {exc.code}"
                error = f"HTTP {exc.code}"
            except (urllib.error.URLError, TimeoutError, json.JSONDecodeError) as exc:
                error = f"{type(exc).__name__}: {exc}"
            time.sleep(2**attempt)
        return None, None, error

    def download(self, url: str, dest: Path, max_bytes: int) -> Fetch:
        
        with self._dest_lock(dest):
            return self._download(url, dest, max_bytes)

    def _download(self, url: str, dest: Path, max_bytes: int) -> Fetch:
        if dest.is_file():
            data = dest.read_bytes()
            return self._record(Fetch(url, True, None, str(dest), len(data),
                                      hashlib.sha256(data).hexdigest(), cached=True))
        error = ""
        status: int | None = None
        for attempt in range(1, self.retries + 1):
            part = dest.with_name(f"{dest.name}.{os.getpid()}-{threading.get_ident()}.part")
            try:
                self.guard.check()
                with urllib.request.urlopen(self._request(url), timeout=self.timeout) as resp:
                    status = resp.status
                    declared = int(resp.headers.get("Content-Length") or 0)
                    if declared > max_bytes:
                        return self._record(Fetch(url, False, status, error=f"size_limit: declared {declared} bytes"))
                    dest.parent.mkdir(parents=True, exist_ok=True)
                    digest, reserved, over_cap = hashlib.sha256(), 0, False
                    try:
                        with part.open("wb") as out:
                            while chunk := resp.read(MiB):
                                if reserved + len(chunk) > max_bytes:
                                    over_cap = True
                                    break
                                
                                
                                self.guard.reserve(len(chunk))
                                reserved += len(chunk)
                                digest.update(chunk)
                                out.write(chunk)
                    except BaseException:
                        part.unlink(missing_ok=True)
                        self.guard.release(reserved)
                        raise
                    if over_cap:
                        part.unlink(missing_ok=True)
                        self.guard.release(reserved)
                        return self._record(Fetch(url, False, status, error=f"size_limit: exceeded {max_bytes} bytes"))
                part.replace(dest)
                size = reserved
                return self._record(Fetch(url, True, status, str(dest), size, digest.hexdigest()))
            except urllib.error.HTTPError as exc:
                part.unlink(missing_ok=True)
                status, error = exc.code, f"HTTP {exc.code}"
                if exc.code < 500 and exc.code != 429:
                    break
            except (urllib.error.URLError, TimeoutError, ConnectionError) as exc:
                part.unlink(missing_ok=True)
                status, error = None, f"{type(exc).__name__}: {exc}"
            self.log(f"retry {attempt}/{self.retries} {url}: {error}")
            time.sleep(2**attempt)
        return self._record(Fetch(url, False, status, error=error))





def _slug(project: str) -> str:
    return project.replace("/", "__")


def _tar_member(archive: Path, file: str) -> tuple[bytes | None, str]:
    pass
    try:
        with tarfile.open(archive, "r:gz") as tar:
            for member in tar:
                parts = member.name.split("/", 1)
                if len(parts) == 2 and parts[1] == file:
                    if not member.isfile():
                        return None, "target_not_regular_file"
                    handle = tar.extractfile(member)
                    return (handle.read() if handle else None), ""
    except (tarfile.TarError, OSError, EOFError) as exc:
        return None, f"snapshot_unreadable: {type(exc).__name__}"
    return None, "target_not_in_snapshot"


@dataclass
class Revision:
    record_id: str
    project: str
    sha: str
    file: str


def jsvul_revisions(record: dict[str, str], by_id: dict[str, dict[str, str]]) -> tuple[list[Revision], str]:
    pass
    revs = [Revision(record["record_id"], record["project"], record["revision"], record["file"])]
    pair = record.get("paired_id", "")
    if pair:
        other = by_id.get(pair)
        if other is None:
            return revs, "paired_id_not_in_inventory"
        revs.append(Revision(other["record_id"], other["project"], other["revision"], other["file"]))
    return revs, ""


class JsVulRecovery:
    def __init__(self, fetcher: Fetcher, data_root: Path, snapshot_max_bytes: int, file_max_bytes: int):
        self.fetcher = fetcher
        self.root = data_root / "snapshots" / "jsvul"
        self.files = data_root / "files" / "jsvul"
        self.snapshot_max = snapshot_max_bytes
        self.file_max = file_max_bytes
        self._repo_cache: dict[str, int | None] = {}
        self._lock = threading.Lock()

    def repo_status(self, project: str) -> int | None:
        with self._lock:
            if project in self._repo_cache:
                return self._repo_cache[project]
        status, _, _ = self.fetcher.get_json(f"https://api.github.com/repos/{project}")
        with self._lock:
            self._repo_cache[project] = status
        return status

    def fetch_file(self, rev: Revision) -> Fetch:
        url = (
            f"https://raw.githubusercontent.com/{rev.project}/{rev.sha}/"
            f"{urllib.parse.quote(rev.file)}"
        )
        dest = self.files / _slug(rev.project) / rev.sha / rev.file
        return self.fetcher.download(url, dest, self.file_max)

    def fetch_snapshot(self, project: str, sha: str) -> Fetch:
        url = f"https://codeload.github.com/{project}/tar.gz/{sha}"
        return self.fetcher.download(url, self.root / _slug(project) / f"{sha}.tar.gz", self.snapshot_max)

    def check_revision(self, rev: Revision, snapshot: Fetch) -> dict[str, Any]:
        pass
        file_fetch = self.fetch_file(rev)
        member, member_error = (None, snapshot.error)
        if snapshot.ok:
            member, member_error = _tar_member(Path(snapshot.path), rev.file)
        member_sha = hashlib.sha256(member).hexdigest() if member is not None else ""
        out: dict[str, Any] = {
            "record_id": rev.record_id, "project": rev.project, "revision": rev.sha,
            "file": rev.file, "raw_ok": file_fetch.ok, "raw_sha256": file_fetch.sha256,
            "raw_error": file_fetch.error, "raw_http": file_fetch.http_status,
            "snapshot_ok": snapshot.ok, "snapshot_sha256": snapshot.sha256,
            "snapshot_bytes": snapshot.bytes, "snapshot_member_sha256": member_sha,
            "c1": file_fetch.ok or member is not None, "c2": False, "c2_error": "",
        }
        if member is None:
            out["c2_error"] = member_error
        elif file_fetch.ok and member_sha != file_fetch.sha256:
            out["c2_error"] = "snapshot_file_differs_from_raw"
        else:
            out["c2"] = True
            if not file_fetch.ok:
                out["c2_error"] = "raw_unavailable_target_taken_from_snapshot"
        return out


def classify_jsvul(revs: list[dict[str, Any]], pair_note: str, repo_http: int | None) -> tuple[str, str]:
    c1 = [r["c1"] for r in revs]
    c2 = [r["c2"] for r in revs]
    if pair_note:
        
        return ("recovered_one_revision" if any(c1) else "missing_revision"), pair_note
    if all(c2):
        return "recovered_c2", ""
    if all(c1):
        reasons = sorted({r["c2_error"] for r in revs if not r["c2"]})
        return "recovered_c1_only", ";".join(reasons)
    if any(c1):
        missing = [r["revision"][:12] for r in revs if not r["c1"]]
        return "recovered_one_revision", f"revision unavailable: {','.join(missing)}"
    if repo_http == 404:
        return "repo_gone", "api.github.com/repos returned 404"
    errors = sorted({r["raw_error"] for r in revs})
    if all(r["raw_http"] == 404 for r in revs):
        return "missing_revision", ";".join(errors)
    return "other", ";".join(errors)





_EXACT_VERSION_CHARS = set("0123456789.-+abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ")


def is_exact_version(version: str) -> bool:
    return bool(version) and version[0].isdigit() and set(version) <= _EXACT_VERSION_CHARS


def verify_npm_integrity(data: bytes, dist: dict[str, Any]) -> tuple[bool, str]:
    integrity = dist.get("integrity", "")
    if integrity.startswith("sha512-"):
        expected = base64.b64decode(integrity[7:])
        return hashlib.sha512(data).digest() == expected, "sha512"
    if dist.get("shasum"):
        return hashlib.sha1(data).hexdigest() == dist["shasum"], "sha1"
    return False, "no_integrity_field"


class NpmRecovery:
    def __init__(self, fetcher: Fetcher, data_root: Path, max_bytes: int):
        self.fetcher = fetcher
        self.root = data_root / "snapshots" / "secbench"
        self.max_bytes = max_bytes
        self._meta: dict[str, tuple[int | None, Any]] = {}
        self._lock = threading.Lock()

    def metadata(self, package: str) -> tuple[int | None, Any]:
        with self._lock:
            if package in self._meta:
                return self._meta[package]
        url = "https://registry.npmjs.org/" + urllib.parse.quote(package, safe="@")
        status, body, _ = self.fetcher.get_json(url)
        with self._lock:
            self._meta[package] = (status, body)
        return status, body

    def fetch_version(self, package: str, version: str) -> dict[str, Any]:
        out: dict[str, Any] = {"package": package, "version": version, "ok": False, "error": ""}
        if not is_exact_version(version):
            out["error"] = f"non_exact_version: {version!r}"
            return out
        status, meta = self.metadata(package)
        if meta is None:
            out["error"] = f"registry_http_{status}"
            return out
        dist = (meta.get("versions", {}).get(version) or {}).get("dist")
        if not dist:
            out["error"] = "version_not_in_registry"
            return out
        dest = self.root / package.replace("/", "__") / f"{version}.tgz"
        fetch = self.fetcher.download(dist["tarball"], dest, self.max_bytes)
        out.update(tarball=dist["tarball"], sha256=fetch.sha256, bytes=fetch.bytes)
        if not fetch.ok:
            out["error"] = fetch.error
            return out
        ok, algo = verify_npm_integrity(Path(fetch.path).read_bytes(), dist)
        out["integrity_algorithm"] = algo
        if not ok:
            Path(fetch.path).unlink(missing_ok=True)
            out["error"] = f"integrity_mismatch ({algo})"
            return out
        out["ok"] = True
        return out


def _npm_failure(side: str, error: str) -> tuple[str, str]:
    if error.startswith(("registry_http_404", "version_not_in_registry")):
        return "package_unavailable", f"{side}: {error}"
    if error.startswith("non_exact_version"):
        return "ambiguous_target", f"{side}: {error}"
    return "other", f"{side}: {error}"


def classify_secbench(row: dict[str, str], vuln: dict[str, Any] | None, fixed: dict[str, Any] | None) -> tuple[str, str]:
    pass
    if row.get("parse_error"):
        return "ambiguous_target", f"package.json unreadable: {row['parse_error']}"
    if row.get("dependency_count") != "1":
        return "ambiguous_target", f"{row.get('dependency_count')} dependencies; target package not unique"
    assert vuln is not None
    no_fix = f"no_fixed_version (metadata {row.get('fixed_version_raw', '')!r})"
    vuln_ok = vuln["ok"]
    fixed_ok = bool(fixed and fixed["ok"])
    if vuln_ok and fixed_ok:
        return "recovered_c2", ""
    if vuln_ok:
        return "recovered_one_revision", no_fix if fixed is None else f"fixed: {fixed['error']}"
    if fixed_ok:
        return "recovered_one_revision", f"vulnerable: {vuln['error']}"
    status, detail = _npm_failure("vulnerable", vuln["error"])
    extra = no_fix if fixed is None else f"fixed: {fixed['error']}"
    return status, f"{detail}; {extra}"





def extract_sard_case(
    archive: zipfile.ZipFile, record_id: str, dest: Path, expected_src_sha: str, guard: StorageGuard
) -> dict[str, Any]:
    prefix = f"{record_id}/"
    members = [n for n in archive.namelist() if n.startswith(prefix) and not n.endswith("/")]
    out: dict[str, Any] = {"record_id": record_id, "ok": False, "files": len(members), "error": ""}
    if not members:
        out["error"] = "case_not_in_archive"
        return out
    src_hash = ""
    for name in members:
        data = archive.read(name)
        target = dest / name
        if not target.is_file():
            guard.reserve(len(data))
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(data)
        if name.startswith(f"{prefix}src/") and name.endswith(".php"):
            src_hash = hashlib.sha256(data).hexdigest()
    out["src_sha256"] = src_hash
    if not src_hash:
        out["error"] = "no_php_source"
    elif src_hash != expected_src_sha:
        out["error"] = "src_sha256_differs_from_sarif"
    else:
        out["ok"] = True
    return out


def run_parallel(func: Callable[[Any], Any], items: list[Any], workers: int) -> list[Any]:
    with ThreadPoolExecutor(max_workers=workers) as pool:
        return list(pool.map(func, items))


def github_token() -> str | None:
    return os.environ.get("GITHUB_TOKEN") or None

