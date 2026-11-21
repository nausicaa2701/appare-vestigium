"""Download exactly the two model revisions used by the development protocol."""
from __future__ import annotations

import argparse
import os
from pathlib import Path


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--cache", type=Path, default=Path(os.environ.get("RAVEN_MODEL_CACHE", "models/hub")))
    args = parser.parse_args()
    from huggingface_hub import snapshot_download

    models = (("Qwen/Qwen2.5-Coder-1.5B", "df3ce67c0e24480f20468b6ef2894622d69eb73b"),
              ("Salesforce/codet5-small", "b1ee9570c289f21b5922b9c768a1ce12957bf968"))
    for repo, revision in models:
        path = snapshot_download(repo_id=repo, revision=revision, cache_dir=str(args.cache.resolve()))
        print(f"{repo}@{revision}: {path}", flush=True)


if __name__ == "__main__":
    main()
