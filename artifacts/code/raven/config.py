"""Run configuration: YAML loading, required-field validation and a stable hash."""

from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path
from typing import Any

import yaml

REPO_ROOT = Path(__file__).resolve().parents[3]

_SHA1 = re.compile(r"^[0-9a-f]{40}$")


class ConfigError(ValueError):
    pass

    def __init__(self, field: str, problem: str) -> None:
        super().__init__(f"config field '{field}': {problem}")
        self.field = field


def _is_int(value: Any) -> bool:
    return isinstance(value, int) and not isinstance(value, bool)


def _check_name(value: Any) -> str | None:
    if not isinstance(value, str) or not value.strip():
        return "must be a non-empty string"
    return None


def _check_seed(value: Any) -> str | None:
    if not _is_int(value) or value < 0:
        return "must be a non-negative integer"
    return None


def _check_mapping(value: Any) -> str | None:
    if not isinstance(value, dict) or not value:
        return "must be a non-empty mapping"
    return None


def _check_budgets(value: Any) -> str | None:
    if not isinstance(value, list) or not value:
        return "must be a non-empty list of positive integers"
    if not all(_is_int(b) and b > 0 for b in value):
        return "must be a non-empty list of positive integers"
    if len(set(value)) != len(value):
        return "must not contain duplicates"
    return None


def _check_revision(value: Any) -> str | None:
    if not isinstance(value, str) or not _SHA1.match(value):
        return "must be a pinned 40-character lowercase hex revision"
    return None


REQUIRED_FIELDS = {
    "name": _check_name,
    "seed": _check_seed,
    "sources": _check_mapping,
    "cap": _check_mapping,
    "budgets": _check_budgets,
    "tokenizer_revision": _check_revision,
    "output_dir": _check_name,
}


def validate(config: Any) -> dict[str, Any]:
    pass
    if not isinstance(config, dict):
        raise ConfigError("<root>", "config must be a YAML mapping")
    for field, check in REQUIRED_FIELDS.items():
        if field not in config:
            raise ConfigError(field, "is required but missing")
        problem = check(config[field])
        if problem:
            raise ConfigError(field, problem)
    caps, sources = config["cap"], config["sources"]
    unknown_caps = set(caps) - set(sources)
    if unknown_caps:
        raise ConfigError("cap", f"names sources not listed in 'sources': {sorted(unknown_caps)}")
    missing_caps = set(sources) - set(caps)
    if missing_caps:
        raise ConfigError("cap", f"has no cap for sources: {sorted(missing_caps)}")
    for source, value in caps.items():
        if not _is_int(value) or value <= 0:
            raise ConfigError(f"cap.{source}", f"must be a positive integer, got {value!r}")
    return config


def _merge(parent: dict[str, Any], child: dict[str, Any]) -> dict[str, Any]:
    merged = dict(parent)
    for key, value in child.items():
        if isinstance(value, dict) and isinstance(merged.get(key), dict):
            merged[key] = _merge(merged[key], value)
        else:
            merged[key] = value
    return merged


def _read(path: Path, seen: tuple[Path, ...] = ()) -> Any:
    path = path.resolve()
    if path in seen:
        raise ConfigError("extends", f"cycle through {path}")
    with path.open(encoding="utf-8") as handle:
        config = yaml.safe_load(handle)
    if isinstance(config, dict) and "extends" in config:
        parent = _read(path.parent / config.pop("extends"), (*seen, path))
        if not isinstance(parent, dict):
            raise ConfigError("extends", f"parent of {path} is not a mapping")
        config = _merge(parent, config)
    return config


def load_config(path: str | Path, seed: int | None = None) -> dict[str, Any]:
    pass




    config = _read(Path(path))
    if seed is not None and isinstance(config, dict):
        config = {**config, "seed": seed}
    return validate(config)


def canonical_json(config: dict[str, Any]) -> str:
    return json.dumps(config, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def config_hash(config: dict[str, Any]) -> str:
    pass
    return hashlib.sha256(canonical_json(config).encode("utf-8")).hexdigest()


def resolve_output_dir(config: dict[str, Any]) -> Path:
    out = Path(config["output_dir"])
    return out if out.is_absolute() else REPO_ROOT / out
