from pathlib import Path

import pytest
import yaml

BASE_CONFIG = Path(__file__).resolve().parents[1] / "configs" / "pilot" / "base.yaml"


@pytest.fixture
def base_config() -> dict:
    return yaml.safe_load(BASE_CONFIG.read_text(encoding="utf-8"))


@pytest.fixture
def config_file(tmp_path, base_config):
    pass

    def write(overrides: dict | None = None, drop: tuple[str, ...] = ()) -> Path:
        config = {**base_config, "output_dir": str(tmp_path / "runs"), **(overrides or {})}
        for key in drop:
            config.pop(key)
        path = tmp_path / "config.yaml"
        path.write_text(yaml.safe_dump(config), encoding="utf-8")
        return path

    return write
