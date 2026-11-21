"""S4 admission tests use metadata fixtures without loading model inputs."""

import json
from pathlib import Path
from types import SimpleNamespace

import pytest

from raven.p2 import LineageError, _digest
from raven.p7a import detector_manifest_identity
from raven.p7s4 import _selector_output_hashes, run_selector


@pytest.fixture
def marked_stage(tmp_path):
    detector = {
        "operation_manifest": {"path": "cohort.jsonl", "sha256": "a" * 64},
        "input_bundle": {"path": "marked-inputs", "sha256": "b" * 64},
        "primary_variant": "context_dropout",
        "train": {"epochs": 3},
        "gate": {"bootstrap": 10000},
    }
    config = {
        "p7": {
            "detector": detector,
            "s4": {"gate_run": str(tmp_path), "require_useful_gate": False},
        }
    }
    gate = {
        "manifest_run": detector_manifest_identity(config),
        "input_bundle": detector["input_bundle"],
        "primary_variant": detector["primary_variant"],
        "train_config": detector["train"],
        "gate": detector["gate"],
        "decisions": {
            "context_dropout": {"decision": "restrict"},
            "no_dropout": {"decision": "go"},
        },
    }
    (tmp_path / "status.json").write_text(json.dumps({"status": "completed"}))
    (tmp_path / "run.json").write_text(json.dumps({"command": "detector-gate"}))
    return SimpleNamespace(config=config), gate


@pytest.mark.parametrize(
    ("change", "expected"),
    [
        ("none", "found restrict"),
        ("missing_gate", "requires a pinned input bundle"),
        ("mixed_bundle", "different input or training contract"),
        ("wrong_primary", "different input or training contract"),
        ("edited_gate", "output hashes changed"),
    ],
)
def test_marked_input_never_reaches_legacy_runner(marked_stage, tmp_path, change, expected):
    run, gate = marked_stage
    if change == "missing_gate":
        run.config["p7"]["s4"].pop("gate_run")
    if change == "mixed_bundle":
        gate["input_bundle"] = {"path": "other", "sha256": "c" * 64}
    if change == "wrong_primary":
        gate["primary_variant"] = "no_dropout"

    path = tmp_path / "gate.json"
    path.write_text(json.dumps(gate))
    inventory = _digest(tmp_path, ("gate.json", "run.json"))
    (tmp_path / "output_hashes.json").write_text(json.dumps(inventory))
    if change == "edited_gate":
        path.write_text(path.read_text() + "\n")

    with pytest.raises(LineageError, match=expected):
        run_selector(run, Path("unused-train"), Path("unused-pack"))


def test_selector_output_hash_contract_is_branch_specific(tmp_path):
    for name in ("s4_log.jsonl", "s4_validation.csv", "policy.pt"):
        (tmp_path / name).write_text(name)
    legacy = _selector_output_hashes(tmp_path, marked=False)
    assert set(legacy) == {"s4_log.jsonl", "s4_validation.csv", "policy.pt"}
    with pytest.raises(FileNotFoundError):
        _selector_output_hashes(tmp_path, marked=True)
    (tmp_path / "s4_input_contract.json").write_text("{}")
    assert set(_selector_output_hashes(tmp_path, marked=True)) == set(legacy) | {"s4_input_contract.json"}


def test_marked_runner_training_validation_and_resume(marked_stage, tmp_path, monkeypatch):
    import csv

    import torch
    import yaml

    from raven import detector, encoder, p5, p6, p7a
    from raven import p7inputs as I

    run, gate = marked_stage
    cfg = run.config
    cfg.update(tokenizer_revision="fixture", compute={"device": "cpu"})
    cfg["p7"].update(input_serializer=I.SERIALIZER, packer_version="density-v2", s3={"params": {}})
    cfg["p7"]["s4"].update(
        seed=0, epochs=3, batch=1, budget=200, hidden=4, stop_logit=-2.0,
        lr=0.01, baseline_decay=0.9, temperature=1.0, lambda_y=0.5,
        action_cap=2, stop_mode="bernoulli",
    )
    d = cfg["p7"]["detector"]
    d["teacher_context_limit"] = 300
    parent = tmp_path / "bundle"
    parent.mkdir()
    (parent / "samples").mkdir()
    rows, entries = [], []
    for n, role in enumerate(("fit", "calibration", "assessment")):
        sid = f"sample-{n}"
        row = dict.fromkeys(I.COHORT_FIELDS, "")
        row.update(sample_id=sid, inner_role=role, label=n % 2)
        rows.append(row)
        target = f'const target = "é{n}";\n'.encode()
        raw = target + b"const optional = 1;\n"
        snapshot = {
            "sample_id": sid, "texts": {"fixture.js": raw.hex()}, "target_file": "fixture.js",
            "target": {"fixture.js": [(0, len(target))]}, "mandatory": {"fixture.js": [(0, len(target))]},
            "labels": None, "edges": [],
            "candidates": [{"uid": "optional", "file": "fixture.js", "ranges": [(len(target), len(raw))],
                            "closure": [], "score": 1.0}],
        }
        snapshot_path = parent / "samples" / f"{I.digest(sid)}.json"
        I.write_json(snapshot_path, snapshot)
        full = I.render_files(I.read_sample(snapshot_path), {"fixture.js": [(0, len(raw))]})[0]
        pack_path = f"{sid}.txt"
        (parent / pack_path).write_text(full)
        entries.append({
            "sample_id": sid, "view": "teacher", "fold": "", "epoch": -1, "serializer": I.SERIALIZER,
            "pack_path": pack_path, "pack_sha256": I.digest(full), "tokens": len(full), "teacher_eligible": True,
        })
    monkeypatch.setattr(I, "guarded_rows", lambda config: rows)
    I.write_rows(parent / "cohort_manifest.jsonl", rows)
    I.write_rows(parent / "input_manifest.jsonl", entries)
    I.write_json(parent / "input_preflight.json", {"passed": True, "d1_manifest_sha256": "a" * 64})
    (parent / "config.yaml").write_text(yaml.safe_dump(cfg))
    members = tuple(str(p.relative_to(parent)) for p in parent.rglob("*") if p.is_file())
    I.write_json(parent / "output_hashes.json", _digest(parent, members))
    d["input_bundle"] = {"path": str(parent), "sha256": I.dbg.sha_file(parent / "output_hashes.json")}

    gate.update(input_bundle=d["input_bundle"], manifest_run=detector_manifest_identity(cfg))
    gate["decisions"]["context_dropout"]["decision"] = "go"
    I.write_json(tmp_path / "gate.json", gate)
    I.write_json(tmp_path / "output_hashes.json", _digest(tmp_path, ("gate.json", "run.json")))

    seen = []

    class FixtureDetector(torch.nn.Module):
        def forward(self, ids):
            text = "".join(map(chr, ids[0].tolist()))
            assert text.count("<av-target>") == text.count("</av-target>") == 1
            assert "é2" not in text
            seen.append(text)
            return torch.tensor([[0.3, float("optional" in text)]])

    class FixtureEncoder:
        def __init__(self, device):
            assert device == "cpu"

        def embed(self, texts):
            return torch.eye(len(texts), 512), [False] * len(texts)

    class FixtureTokenizer:
        def __call__(self, text, **kwargs):
            return {"input_ids": list(map(ord, text))}

    def no_legacy_calls(*args, **kwargs):
        pytest.fail("the marked runner entered a legacy loader")

    monkeypatch.setattr(detector, "guarded_cohort", no_legacy_calls)
    monkeypatch.setattr(p6, "iter_samples", no_legacy_calls)
    monkeypatch.setattr(encoder, "EncoderCache", FixtureEncoder)
    monkeypatch.setattr(p5, "load_tokenizer", lambda config: FixtureTokenizer())
    monkeypatch.setattr(p5, "count_tokens", lambda tokenizer, text: len(text))
    monkeypatch.setattr(p7a, "load_qwen", lambda *args: FixtureDetector())
    monkeypatch.setattr(p7a, "load_trainable", lambda *args: None)
    monkeypatch.setattr(p7a, "trainable_state", lambda model: model.state_dict())

    train = tmp_path / "final"
    train.mkdir()
    I.write_json(train / "status.json", {"status": "completed"})
    I.write_json(train / "run.json", {"command": "detector-train"})
    ck = train / "trainable.pt"
    torch.save({}, ck)
    I.write_json(train / "train_summary.json", {
        "fold": "final", "variant": "context_dropout", "roundtrip_ok": True, "steps": 3, "planned_steps": 3,
        "losses_finite": True, "gradients_finite": True, "checkpoint_dir": str(train), "output_files": {},
        "input_bundle": d["input_bundle"], "manifest_run": detector_manifest_identity(cfg),
        "train_config": d["train"], "tokenizer_revision": cfg["tokenizer_revision"],
        "trainable_file_sha256": I.dbg.sha_file(ck), "trainable_sha256": p7a.state_sha256({}),
    })
    I.write_json(train / "output_hashes.json", _digest(train, ("run.json", "train_summary.json")))

    def execute(name, resume=None):
        run.path = tmp_path / name
        run.path.mkdir()
        return run_selector(run, train, None, resume)

    result = execute("whole")
    assert result["detector_calls"] == 5 and result["detector_unchanged"]
    assert result["teacher_calls"] == 2
    assert result["fit_records"] == result["validation_records"] == 1
    with (run.path / "s4_validation.csv").open() as f:
        val = list(csv.DictReader(f))
    assert [r["sample_id"] for r in val] == ["sample-1"]
    assert val[0]["sampled_sha256"] in {I.digest(text) for text in seen}
    logs = I.dbg._jsonl(run.path / "s4_log.jsonl")
    assert len(logs) == 3 and all(set(row["consumed_packs"]) == {"sample-0"} for row in logs)

    save = torch.save

    def interrupt_on_second_save(state, path):
        if state["next_epoch"] == 2:
            raise InterruptedError
        save(state, path)

    with monkeypatch.context() as interrupted:
        interrupted.setattr(torch, "save", interrupt_on_second_save)
        with pytest.raises(InterruptedError):
            execute("partial")
    execute("resumed", tmp_path / "partial" / "policy.pt")
    full = torch.load(tmp_path / "whole" / "policy.pt", weights_only=True)
    resumed = torch.load(run.path / "policy.pt", weights_only=True)
    assert all(torch.equal(v, resumed["net"][k]) for k, v in full["net"].items())
    assert full["optimizer"]["param_groups"] == resumed["optimizer"]["param_groups"]
    for param, state in full["optimizer"]["state"].items():
        assert all(torch.equal(v, resumed["optimizer"]["state"][param][k]) for k, v in state.items())
    assert full["baseline"] == resumed["baseline"]
    assert torch.equal(full["generator"], resumed["generator"])
