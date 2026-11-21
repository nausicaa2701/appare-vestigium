"""Per-run directory with resolved config, identity, source snapshot, output and status.

Every run writes ``<output_dir>/<run-id>/`` containing:

- ``config.yaml``      resolved config actually used
- ``run.json``         config_hash, source_sha256, git commit/dirty flag, UTC timestamp, seed,
                       argv, platform
- ``source.json``      SHA-256 of every file under SOURCE_PATHS, tracked or not
- ``source.tar.gz``    copy of ``artifacts/code`` as it was when the run started
- ``environment.txt``  installed distributions (``name==version``), like ``pip freeze``
- ``stdout.log``       logger records and everything printed to ``sys.stdout``
- ``stderr.log``       everything printed to ``sys.stderr``
- ``status.json``      ``completed`` or ``failed`` with the failure reason

Output written directly to file descriptors (native extensions, child processes started
without :meth:`Run.run_subprocess`) bypasses ``sys.stdout``/``sys.stderr`` and is not
captured. Phase commands start child processes through :meth:`Run.run_subprocess`, which
stores their stdout/stderr under ``subprocess/`` and appends to ``subprocess/index.jsonl``.
"""

from __future__ import annotations

import hashlib
import io
import json
import logging
import platform
import subprocess
import sys
import tarfile
import time
import traceback
from collections.abc import Iterator, Sequence
from contextlib import contextmanager
from dataclasses import dataclass, field
from datetime import UTC, datetime
from importlib import metadata
from pathlib import Path
from typing import Any, TextIO

import yaml

from raven.config import REPO_ROOT, canonical_json, config_hash, resolve_output_dir

RUN_FILES = (
    "config.yaml",
    "run.json",
    "source.json",
    "source.tar.gz",
    "environment.txt",
    "stdout.log",
    "stderr.log",
    "status.json",
)


SOURCE_PATHS = (
    "artifacts/code",
    "artifacts/configs",
    "pyproject.toml",
    "requirements-pilot-local.lock.txt",
    "Makefile",
)
_SKIP_PARTS = {"__pycache__", ".pytest_cache", ".ruff_cache"}
_SKIP_NAMES = {".DS_Store"}


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _source_files(root: Path) -> list[Path]:
    files = []
    for entry in SOURCE_PATHS:
        path = root / entry
        candidates = [path] if path.is_file() else sorted(path.rglob("*")) if path.is_dir() else []
        for candidate in candidates:
            rel = candidate.relative_to(root)
            if not candidate.is_file() or candidate.suffix == ".pyc":
                continue
            if _SKIP_PARTS & set(rel.parts) or candidate.name in _SKIP_NAMES:
                continue
            files.append(candidate)
    return files


def source_snapshot(root: Path = REPO_ROOT) -> dict[str, Any]:
    pass
    hashes = {str(p.relative_to(root)): _sha256(p.read_bytes()) for p in _source_files(root)}
    return {
        "paths": list(SOURCE_PATHS),
        "files": hashes,
        "source_sha256": _sha256(canonical_json(hashes).encode("utf-8")),
    }


def _write_code_archive(root: Path, dest: Path) -> None:
    code = root / "artifacts" / "code"
    with tarfile.open(dest, "w:gz") as archive:
        for path in _source_files(root):
            if code in path.parents:
                info = archive.gettarinfo(path, arcname=str(path.relative_to(root)))
                info.mtime, info.uid, info.gid, info.uname, info.gname = 0, 0, 0, "", ""
                with path.open("rb") as handle:
                    archive.addfile(info, handle)


def git_state(root: Path = REPO_ROOT) -> dict[str, Any]:
    try:
        commit = subprocess.run(
            ["git", "rev-parse", "HEAD"], cwd=root, capture_output=True, text=True, check=True
        ).stdout.strip()
        status = subprocess.run(
            ["git", "status", "--porcelain"], cwd=root, capture_output=True, text=True, check=True
        ).stdout
    except (OSError, subprocess.CalledProcessError):
        return {"commit": "unknown", "dirty": None, "untracked": []}
    untracked = [line[3:] for line in status.splitlines() if line.startswith("?? ")]
    return {"commit": commit, "dirty": bool(status.strip()), "untracked": untracked}


def installed_distributions() -> list[str]:
    seen = {}
    for dist in metadata.distributions():
        name = dist.metadata["Name"]
        if name:
            seen[name.lower()] = f"{name}=={dist.version}"
    return [seen[key] for key in sorted(seen)]


def _new_run_dir(base: Path, stem: str) -> tuple[str, Path]:
    base.mkdir(parents=True, exist_ok=True)
    for suffix in range(1000):
        run_id = stem if suffix == 0 else f"{stem}-{suffix}"
        path = base / run_id
        try:
            path.mkdir()
        except FileExistsError:
            continue
        return run_id, path
    raise RuntimeError(f"could not allocate a run directory under {base}")


class _Tee(io.TextIOBase):
    pass

    def __init__(self, original: TextIO, log: TextIO) -> None:
        self._original = original
        self._log = log

    def write(self, text: str) -> int:
        self._original.write(text)
        self._log.write(text)
        return len(text)

    def flush(self) -> None:
        self._original.flush()
        self._log.flush()

    def isatty(self) -> bool:
        return False


@dataclass
class Run:
    run_id: str
    path: Path
    config: dict[str, Any]
    config_hash: str
    logger: logging.Logger
    _calls: int = field(default=0, repr=False)

    def run_subprocess(
        self,
        cmd: Sequence[str],
        name: str,
        *,
        cwd: Path | None = None,
        timeout: float | None = None,
        env: dict[str, str] | None = None,
    ) -> subprocess.CompletedProcess[bytes]:
        pass




        self._calls += 1
        sub = self.path / "subprocess"
        sub.mkdir(exist_ok=True)
        stem = f"{self._calls:03d}-{name}"
        record: dict[str, Any] = {
            "call": self._calls,
            "name": name,
            "cmd": list(cmd),
            "cwd": str(cwd) if cwd else None,
            "timeout_s": timeout,
            "stdout": f"subprocess/{stem}.stdout",
            "stderr": f"subprocess/{stem}.stderr",
        }
        self.logger.info("subprocess %s: %s", stem, " ".join(cmd))
        started = time.monotonic()
        with (sub / f"{stem}.stdout").open("wb") as out, (sub / f"{stem}.stderr").open("wb") as err:
            try:
                result = subprocess.run(
                    list(cmd), cwd=cwd, env=env, stdout=out, stderr=err, timeout=timeout,
                    check=False,
                )
            except subprocess.TimeoutExpired:
                record.update(returncode=None, outcome="timeout")
                raise
            except OSError as exc:
                record.update(returncode=None, outcome=f"os_error: {exc}")
                raise
            else:
                record.update(
                    returncode=result.returncode,
                    outcome="ok" if result.returncode == 0 else "nonzero_exit",
                )
            finally:
                record["duration_s"] = round(time.monotonic() - started, 3)
                with (sub / "index.jsonl").open("a", encoding="utf-8") as index:
                    index.write(json.dumps(record) + "\n")
                self.logger.info("subprocess %s: %s", stem, record["outcome"])
        return result


@contextmanager
def start_run(config: dict[str, Any], command: str, argv: list[str] | None = None) -> Iterator[Run]:
    pass
    started = datetime.now(UTC)
    digest = config_hash(config)
    stem = f"{started:%Y%m%dT%H%M%SZ}-{config['name']}-{command}-{digest[:8]}"
    run_id, path = _new_run_dir(resolve_output_dir(config), stem)

    (path / "config.yaml").write_text(
        yaml.safe_dump(config, sort_keys=True, allow_unicode=True), encoding="utf-8"
    )
    source = source_snapshot()
    (path / "source.json").write_text(json.dumps(source, indent=2) + "\n", encoding="utf-8")
    _write_code_archive(REPO_ROOT, path / "source.tar.gz")
    identity = {
        "run_id": run_id,
        "command": command,
        "config_hash": digest,
        "source_sha256": source["source_sha256"],
        "git": git_state(),
        "timestamp_utc": started.isoformat(),
        "seed": config["seed"],
        "argv": argv if argv is not None else sys.argv,
        "python": sys.version.split()[0],
        "executable": sys.executable,
        "platform": platform.platform(),
    }
    (path / "run.json").write_text(json.dumps(identity, indent=2) + "\n", encoding="utf-8")
    (path / "environment.txt").write_text(
        "\n".join(installed_distributions()) + "\n", encoding="utf-8"
    )

    stdout_log = (path / "stdout.log").open("w", encoding="utf-8")
    stderr_log = (path / "stderr.log").open("w", encoding="utf-8")
    original_stdout, original_stderr = sys.stdout, sys.stderr

    logger = logging.getLogger(f"raven.run.{run_id}")
    logger.setLevel(logging.INFO)
    logger.propagate = False
    formatter = logging.Formatter("%(asctime)s %(levelname)s %(message)s")
    
    handlers: list[logging.Handler] = [
        logging.StreamHandler(stdout_log),
        logging.StreamHandler(original_stdout),
    ]
    for handler in handlers:
        handler.setFormatter(formatter)
        logger.addHandler(handler)

    run = Run(run_id=run_id, path=path, config=config, config_hash=digest, logger=logger)
    sys.stdout = _Tee(original_stdout, stdout_log)
    sys.stderr = _Tee(original_stderr, stderr_log)
    logger.info("run %s started (config_hash=%s)", run_id, digest)
    status: dict[str, Any] = {"status": "completed"}
    try:
        yield run
    except BaseException as exc:
        status = {
            "status": "failed",
            "failure_reason": f"{type(exc).__name__}: {exc}",
            "traceback": traceback.format_exc(),
        }
        logger.error("run failed: %s", status["failure_reason"])
        raise
    finally:
        sys.stdout, sys.stderr = original_stdout, original_stderr
        status["finished_utc"] = datetime.now(UTC).isoformat()
        (path / "status.json").write_text(json.dumps(status, indent=2) + "\n", encoding="utf-8")
        logger.info("run %s %s", run_id, status["status"])
        for handler in handlers:
            logger.removeHandler(handler)
        stdout_log.close()
        stderr_log.close()
