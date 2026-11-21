"""Create or verify an inventory of this local artifact snapshot."""
from __future__ import annotations

import argparse
import hashlib
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
MANIFEST = ROOT / "SNAPSHOT_SHA256.json"
SKIP = {".git", ".venv", "__pycache__", ".pytest_cache", ".ruff_cache", ".DS_Store"}


def digest(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            h.update(block)
    return h.hexdigest()


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--create", action="store_true", help="write the snapshot inventory")
    args = ap.parse_args()
    if args.create:
        if MANIFEST.exists():
            raise SystemExit("manifest already exists; preserve or remove it explicitly")
        paths = [p for p in ROOT.rglob("*") if p.is_file() and p != MANIFEST
                 and not SKIP.intersection(p.relative_to(ROOT).parts)]
        files = {p.relative_to(ROOT).as_posix(): {"sha256": digest(p), "bytes": p.stat().st_size}
                 for p in sorted(paths)}
        MANIFEST.write_text(json.dumps({"schema": "local-artifact-snapshot-v1", "files": files}, indent=2) + "\n")
        print(f"created manifest for {len(files)} files")
        return 0
    manifest = json.loads(MANIFEST.read_text())
    failures = []
    for name, spec in manifest["files"].items():
        path = (ROOT / name).resolve()
        if not path.is_relative_to(ROOT.resolve()) or not path.is_file() or path.stat().st_size != spec["bytes"] or digest(path) != spec["sha256"]:
            failures.append(name)
    if failures:
        print(f"failed/missing files: {len(failures)}")
        for item in failures[:20]:
            print(item)
        return 1
    print(f"verified {len(manifest['files'])} inventoried files; extra files are not assessed")
    return 0


if __name__ == "__main__":
    sys.exit(main())
