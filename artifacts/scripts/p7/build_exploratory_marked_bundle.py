"""Build a new MPS exploratory bundle from source-qualified complete pairs."""
from __future__ import annotations

import argparse
import hashlib
import json
from collections import Counter
from pathlib import Path

from raven import context, p5, p6, packer
from raven import p7inputs as I
from raven.config import load_config

ROOT = Path("artifacts/results/diagnostics/p7-independent-qualification-20261120")
SOURCE = ROOT / "v1-family-disjoint/runs/20261119T193923Z-source-qualification"
EXACT = ROOT / "v1-family-disjoint/runs/20261119T193838Z-source-qualification"


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def load(path):
    return [json.loads(line) for line in path.read_text().splitlines()]


def verify_run(path):
    summary = json.loads((path / "qualification_summary.json").read_text())
    for name, expected in summary["output_sha256"].items():
        if digest(path / name) != expected:
            raise RuntimeError(f"qualification changed: {name}")
    return summary


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    summary = verify_run(SOURCE)
    verify_run(EXACT)
    audit = ROOT / "v2-blind-target-review/llm_lineage_audit.json"
    if summary["alignment_review_mode"] != "llm_only_exploratory" or digest(audit) != summary["llm_lineage_audit_sha256"]:
        raise RuntimeError("LLM lineage changed")
    exact = {r["pair_id"] for r in load(EXACT / "pair_qualification.jsonl") if r["qualification_status"] == "qualified_pair_l1"}
    pairs = [r for r in load(SOURCE / "pair_qualification.jsonl") if r["qualification_status"] == "qualified_pair_l1"]
    records = {r["record_id"]: r for r in load(SOURCE / "record_qualification.jsonl") if r.get("status") == "qualified_l1"}
    args.output.mkdir(parents=True, exist_ok=False)
    (args.output / "packs").mkdir()
    tok = p5.load_tokenizer(load_config(Path("artifacts/configs/pilot/p7-epoch6-qualification.yaml")))
    count = lambda text: p5.count_tokens(tok, text)
    retained, excluded = [], []
    for pair in pairs:
        pending = []
        for rid in (pair["positive_id"], pair["negative_id"]):
            row = records[rid]
            raw = Path(row["source_path"]).read_bytes()
            if hashlib.sha256(raw).hexdigest() != row["source_sha256"]:
                raise RuntimeError(f"source mismatch: {rid}")
            file = rid.split("::")[2]
            fu = context.extract(raw, context.grammar_for(file))
            if fu.status != "parsed":
                raise RuntimeError(f"source parse changed: {rid}")
            candidates = [packer.Candidate(p6._uid(file, u), file, tuple(u.ranges), tuple(u.closure), order=(0, u.start)) for u in fu.units]
            sample = {"sample_id": row["sample_id"], "texts": {file: raw}, "target_file": file,
                      "target": {file: row["target_ranges"]},
                      "levels": {"L0": {file: row["target_ranges"] + row["closure_ranges"]}},
                      "pools": {"L1": candidates}, "labels": None}
            result = I.make_pack(sample, count, 2048, p6.method_scores("random", 42, row["sample_id"], candidates))
            if not result.target_fits_budget or not result.text or result.tokens <= 0 or result.tokens > 2048:
                pending = []
                excluded.append({"pair_id": pair["pair_id"], "reason": "marked_target_exceeds_budget", "sample_id": row["sample_id"]})
                break
            I.validate_map(sample, result.files, result.text)
            h = I.digest(result.text)
            pack_path = args.output / "packs" / (h + ".txt")
            pack_path.write_text(result.text)
            pending.append({"sample_id": row["sample_id"], "pair_id": pair["pair_id"], "family": pair["group_id"],
                            "role": pair["role"], "label": row["label"], "strict_fit": pair["pair_id"] in exact,
                            "tokens": result.tokens, "pack": str(pack_path.relative_to(args.output)), "pack_sha256": h,
                            "source_sha256": row["source_sha256"], "target_ranges": row["target_ranges"]})
        if len(pending) == 2:
            if pending[0]["pack_sha256"] == pending[1]["pack_sha256"]:
                excluded.append({"pair_id": pair["pair_id"], "reason": "identical_opposite_labels"})
            else:
                retained.extend(pending)
    I.write_rows(args.output / "cohort.jsonl", retained)
    I.write_rows(args.output / "excluded.jsonl", excluded)
    files = {str(p.relative_to(args.output)): digest(p) for p in args.output.rglob("*") if p.is_file()}
    I.write_json(args.output / "manifest.json", {"schema": "exploratory-marked-v1", "serializer": I.SERIALIZER,
                 "source_summary_sha256": digest(SOURCE / "qualification_summary.json"),
                 "exact_summary_sha256": digest(EXACT / "qualification_summary.json"), "llm_audit_sha256": digest(audit),
                 "tokenizer_revision": "df3ce67c0e24480f20468b6ef2894622d69eb73b", "budget": 2048,
                 "pair_counts": dict(Counter(r["role"] for r in retained if r["label"] == 1)),
                 "excluded_pairs": len(excluded), "files": files})
    print(json.dumps({"bundle": str(args.output), "manifest_sha256": digest(args.output / "manifest.json"),
                      "records": len(retained), "excluded_pairs": len(excluded)}, indent=2))


if __name__ == "__main__":
    main()
