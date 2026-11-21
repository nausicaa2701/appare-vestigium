"""Download or verify the pinned public datasets in artifacts/data/manifest.csv."""
from __future__ import annotations

import argparse
import csv
import hashlib
import os
import sys
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def digest(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            h.update(block)
    return h.hexdigest()


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--download", action="store_true", help="fetch missing files; never overwrite an existing file")
    ap.add_argument("--data-root", type=Path, default=Path(os.environ.get("RAVEN_DATA_ROOT", "data")))
    args = ap.parse_args()
    with (ROOT / "artifacts/data/manifest.csv").open(newline="") as f:
        rows = list(csv.DictReader(f))
    failures = 0
    root = args.data_root.resolve()
    for row in rows:
        destination = (root / row["local_path"]).resolve()
        if not destination.is_relative_to(root) or not row["uri"].startswith("https://"):
            raise ValueError("unexpected manifest path or URL")
        if not destination.exists() and args.download:
            destination.parent.mkdir(parents=True, exist_ok=True)
            partial = destination.with_name(destination.name + ".part")
            if partial.exists():
                raise RuntimeError(f"partial file already exists: {partial}")
            try:
                with urllib.request.urlopen(row["uri"], timeout=180) as response, partial.open("xb") as out:
                    while chunk := response.read(1024 * 1024):
                        out.write(chunk)
                if digest(partial) != row["sha256"]:
                    raise RuntimeError(f"download hash mismatch: {row['id']}")
                partial.replace(destination)
            except Exception:
                partial.unlink(missing_ok=True)
                raise
        status = "missing" if not destination.is_file() else "ok" if digest(destination) == row["sha256"] else "HASH_MISMATCH"
        print(f"{row['id']}: {status}", flush=True)
        failures += status != "ok"
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
