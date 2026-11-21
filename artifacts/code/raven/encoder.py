"""Unit encoder for P7 selectors: pinned CodeT5-small encoder, mask-mean pooling, L2 norm.

Pin (``tool-model-lock.json``): ``Salesforce/codet5-small`` revision
``b1ee9570c289f21b5922b9c768a1ce12957bf968``, encoder only (35,316,480 parameters). Inputs are
clipped at 256 encoder tokens (the profiled limit) and the clip is logged per text; detector
packing always uses complete source units. Embeddings are cached by ``sha256(text)`` within one
checkpoint (``EncoderCache``)."""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path

import torch

REPO = "Salesforce/codet5-small"
REVISION = "b1ee9570c289f21b5922b9c768a1ce12957bf968"
MAX_TOKENS = 256
PARAMETERS = 35_316_480


def snapshot_dir(revision: str = REVISION) -> Path:
    root = Path(os.environ.get("RAVEN_MODEL_CACHE", Path.home() / ".cache/huggingface/hub"))
    path = root / f"models--{REPO.replace('/', '--')}" / "snapshots" / revision
    if not path.is_dir():
        raise FileNotFoundError(f"CodeT5 snapshot {revision} not found under {root}")
    return path


def load(revision: str = REVISION, device: str = "cpu"):
    pass

    from tokenizers import AddedToken
    from transformers import AutoTokenizer, T5EncoderModel

    root = snapshot_dir(revision)
    model = T5EncoderModel.from_pretrained(root, local_files_only=True).eval().to(device)
    n = sum(p.numel() for p in model.parameters())
    if n != PARAMETERS:
        raise RuntimeError(f"CodeT5 encoder has {n} parameters, expected {PARAMETERS}")
    tok = AutoTokenizer.from_pretrained(root, local_files_only=True, additional_special_tokens=None)
    special = json.loads((root / "special_tokens_map.json").read_text())["additional_special_tokens"]
    tok.add_special_tokens({"additional_special_tokens": [
        AddedToken(**v, special=True) if isinstance(v, dict) else v for v in special]})
    expected = json.loads((root / "vocab.json").read_text())
    expected.update(json.loads((root / "added_tokens.json").read_text()))
    bad = [t for t, i in expected.items() if tok.convert_tokens_to_ids(t) != i]
    if bad:
        raise RuntimeError(f"CodeT5 token id mismatch: {bad[:5]}")
    return tok, model


class EncoderCache:
    pass

    def __init__(self, revision: str = REVISION, device: str = "cpu", batch: int = 16, max_tokens: int = MAX_TOKENS):
        self.revision, self.device, self.batch, self.max_tokens = revision, device, batch, max_tokens
        self.tok, self.model = load(revision, device)
        self.cache: dict[str, tuple[torch.Tensor, bool, int]] = {}

    @staticmethod
    def key(text: str) -> str:
        return hashlib.sha256(text.encode("utf-8")).hexdigest()

    def embed(self, texts: list[str]) -> tuple[torch.Tensor, list[bool]]:
        todo = [t for t in dict.fromkeys(texts) if self.key(t) not in self.cache]
        for i in range(0, len(todo), self.batch):
            chunk = todo[i:i + self.batch]
            full = self.tok(chunk, add_special_tokens=True)["input_ids"]
            enc = self.tok(chunk, return_tensors="pt", padding=True, truncation=True, max_length=self.max_tokens)
            enc = {k: v.to(self.device) for k, v in enc.items()}
            with torch.inference_mode():
                hidden = self.model(**enc).last_hidden_state
                mask = enc["attention_mask"].unsqueeze(-1).to(hidden.dtype)
                emb = torch.nn.functional.normalize((hidden * mask).sum(1) / mask.sum(1).clamp_min(1), p=2, dim=1)
            for t, e, ids in zip(chunk, emb.cpu().to(torch.float64), full, strict=True):
                self.cache[self.key(t)] = (e, len(ids) > self.max_tokens, len(ids))
        if not texts:
            return torch.zeros((0, 512), dtype=torch.float64), []
        rows = [self.cache[self.key(t)] for t in texts]
        return torch.stack([r[0] for r in rows]), [r[1] for r in rows]

    def info(self) -> dict:
        return {"repo": REPO, "revision": self.revision, "parameters": PARAMETERS, "pooling": "mask_mean_l2",
                "max_tokens": self.max_tokens, "device": self.device, "cached_texts": len(self.cache)}
