"""P7A: threshold rule, family bootstrap, train/resume/score cycle on a tiny CPU Qwen2."""

import hashlib
import math

import pytest
import torch

from raven import p7a

CFG = {"lr": 1e-3, "weight_decay": 0.0, "grad_clip": 1.0, "epochs": 2, "seed": 0,
       "lora": {"r": 4, "alpha": 8, "dropout": 0.0, "targets": ["q_proj", "k_proj", "v_proj", "o_proj"]}}


def tiny():
    from transformers import AutoModel, Qwen2Config

    torch.manual_seed(0)
    base = AutoModel.from_config(Qwen2Config(vocab_size=64, hidden_size=16, intermediate_size=32, num_hidden_layers=2,
                                             num_attention_heads=2, num_key_value_heads=1,
                                             max_position_embeddings=64))
    torch.manual_seed(1)
    return p7a.wrap_lora(base, CFG)


def encode(text):
    return [ord(c) % 64 for c in text][:40] or [0]


ITEMS = [p7a.TrainItem(f"s{i}", i % 2, [f"text {i} a", f"text {i} bb"]) for i in range(6)]


def test_consumed_views_record_changed_and_reference_equal_fit_inputs():
    items = {
        "changed": p7a.TrainItem("changed", 1, ["original", "changed view"]),
        "fallback": p7a.TrainItem("fallback", 0, ["reference", "reference"]),
    }
    record = {"epoch": 1, "sample_ids": ["fallback", "changed", "fallback"]}
    views = {"changed": {"reference": "original"}, "fallback": {"reference": "reference"}}
    consumed = p7a._consumed_views(record, "0", "context_dropout", items, views)
    assert [view["sample_id"] for view in consumed] == record["sample_ids"]
    assert [view["reference_equal"] for view in consumed] == [True, False, True]
    assert consumed[1] == {
        "sample_id": "changed",
        "fold": "0",
        "epoch": 1,
        "view": "dropout",
        "pack_sha256": hashlib.sha256(b"changed view").hexdigest(),
        "reference_equal": False,
    }


def test_threshold_rule_and_ties():
    th = p7a.select_threshold([0.1, 0.4, 0.6, 0.9], [0, 0, 1, 1])
    assert th["threshold"] == pytest.approx(0.5) and th["mcc"] == pytest.approx(1.0)  
    th = p7a.select_threshold([0.2, 0.3], [0, 0])  
    assert th["mcc"] == 0.0 and th["fpr"] == 0.0
    th = p7a.select_threshold([0.7, 0.8, 0.9, 0.95], [0, 1, 0, 1])
    assert th["threshold"] in (0.8, 0.95)
    assert p7a.mcc(5, 0, 5, 0) == 1.0 and p7a.mcc(0, 0, 5, 5) == 0.0


def test_family_bootstrap_counts_and_collapse():
    rows = [{"family": f"f{i % 4}", "pred": i % 2, "label": i % 2} for i in range(8)]
    st = p7a.family_bootstrap_mcc(rows, 200, 0)
    assert st["mcc"] == 1.0 and st["families"] == 4 and not st["collapsed"]
    rows = [{"family": "f", "pred": 0, "label": i % 2} for i in range(4)]
    assert p7a.family_bootstrap_mcc(rows, 50, 0)["collapsed"]


def test_train_finite_and_only_adapter_head_trainable():
    det = tiny()
    names = [n for n, p in det.named_parameters() if p.requires_grad]
    assert names and all("lora_" in n or n.startswith("head.") for n in names)
    base_before = {n: p.detach().clone() for n, p in det.named_parameters() if not p.requires_grad}
    logs = []
    out = p7a.train(det, ITEMS, encode, CFG, "cpu", logs.append)
    assert out["status"] == "completed" and out["steps"] == 12 and out["losses_finite"]
    assert all(r["finite"] for r in logs) and any(r["grad_norm"] > 0 for r in logs)
    assert out["w_pos"] == 1.0
    for n, p in det.named_parameters():
        if not p.requires_grad:
            assert torch.equal(p, base_before[n]), n


def test_resume_replays_uninterrupted_training_exactly():
    a = tiny()
    full = p7a.train(a, ITEMS, encode, CFG, "cpu", lambda r: None)
    b = tiny()
    half = p7a.train(b, ITEMS, encode, CFG, "cpu", lambda r: None, stop_after=5)
    assert half["status"] == "paused" and half["steps"] == 5
    c = tiny()
    rest = p7a.train(c, ITEMS, encode, CFG, "cpu", lambda r: None, resume=half)
    assert rest["steps"] == 12
    assert p7a.state_sha256(rest["state"]) == p7a.state_sha256(full["state"])


def test_checkpoint_roundtrip_reproduces_scores(tmp_path):
    det = tiny()
    out = p7a.train(det, ITEMS, encode, CFG, "cpu", lambda r: None)
    torch.save(out["state"], tmp_path / "t.pt")
    before = p7a.score(det, ["abc", "text 3 a"], encode, "cpu")
    other = tiny()
    p7a.load_trainable(other, torch.load(tmp_path / "t.pt"))
    after = p7a.score(other, ["abc", "text 3 a"], encode, "cpu")
    assert before == pytest.approx(after, abs=1e-9)
    assert p7a.state_sha256(p7a.trainable_state(other)) == p7a.state_sha256(out["state"])
    assert all(0 <= p <= 1 and math.isfinite(p) for p in after)


def test_class_weight_from_fit_records_only():
    items = [p7a.TrainItem(f"s{i}", int(i == 0), ["x"]) for i in range(4)]
    out = p7a.train(tiny(), items, encode, {**CFG, "epochs": 1}, "cpu", lambda r: None)
    assert out["w_pos"] == 3.0 and out["n_pos"] == 1


def test_dropout_keep_is_deterministic_and_varies_by_epoch():
    keeps0 = [p7a._keep(0, 0, "s", f"u{i}", 0.5) for i in range(200)]
    keeps1 = [p7a._keep(0, 1, "s", f"u{i}", 0.5) for i in range(200)]
    assert keeps0 == [p7a._keep(0, 0, "s", f"u{i}", 0.5) for i in range(200)]
    assert keeps0 != keeps1 and 70 < sum(keeps0) < 130


def test_weighted_ce_applies_class_weight_at_batch_size_one():
    import torch

    from raven.p7a import weighted_ce

    logits = torch.tensor([[0.3, -0.2]])
    w = torch.tensor([1.0, 4.0])
    plain = torch.nn.functional.cross_entropy(logits, torch.tensor([1]))
    assert float(weighted_ce(logits, 1, w)) == pytest.approx(4.0 * float(plain))
    assert float(weighted_ce(logits, 0, w)) == pytest.approx(
        float(torch.nn.functional.cross_entropy(logits, torch.tensor([0]))))
    
    assert float(torch.nn.functional.cross_entropy(logits, torch.tensor([1]), weight=w)) == pytest.approx(float(plain))


def test_prediction_probability_roundtrips_the_frozen_threshold_decision():
    import csv
    import io

    probability = 0.9982898831367493
    roles = {"s": {"family": "f", "split": "train", "label": 1}}
    row = p7a._pred("s", roles, "detector", "reference", "calibration", probability, probability)
    stream = io.StringIO()
    writer = csv.DictWriter(stream, fieldnames=p7a.PRED_FIELDS)
    writer.writeheader()
    writer.writerow(row)
    stream.seek(0)
    restored = next(csv.DictReader(stream))
    assert float(restored["prob"]) == probability
    assert int(float(restored["prob"]) >= float(restored["threshold"])) == int(restored["pred"]) == 1
    assert round(probability, 8) < probability  
