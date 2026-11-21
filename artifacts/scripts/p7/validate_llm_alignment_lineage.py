"""Validate LLM-only alignment evidence; never qualifies or trains records."""
from __future__ import annotations

import csv
import hashlib
import json
from collections import Counter
from pathlib import Path

BASE = Path("artifacts/results/diagnostics/p7-independent-qualification-20261120")
REVIEW = BASE / "v2-blind-target-review"
SOURCE = BASE / "v1-family-disjoint/runs/20261119T181404Z-source-qualification"


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def csv_rows(path):
    with path.open(newline="") as stream:
        return list(csv.DictReader(stream))


def jsonl(path):
    return [json.loads(line) for line in path.read_text().splitlines()]


def main():
    manifest = json.loads((REVIEW / "review_manifest.json").read_text())
    api = json.loads((REVIEW / "llm_judge_manifest.json").read_text())
    summary = json.loads((SOURCE / "qualification_summary.json").read_text())
    packet, mapping, output = (REVIEW / "human-reviewer.csv", REVIEW / "reviewer_admin_mapping.csv",
                               REVIEW / "llm_judge_results.jsonl")
    for path, expected in ((packet, manifest["reviewer_packet_sha256"][packet.name]),
                           (mapping, manifest["reviewer_packet_sha256"][mapping.name]),
                           (output, api["output_sha256"])):
        if digest(path) != expected:
            raise RuntimeError(f"hash mismatch: {path}")
    if api["packet_sha256"] != digest(packet) or api["status"] != "completed":
        raise RuntimeError("LLM run does not match the reviewed packet")
    if digest(Path("artifacts/scripts/p7/target_alignment_llm_judge_prompt.md")) != api["prompt_sha256"]:
        raise RuntimeError("judge prompt differs from the completed review")
    for name, expected in summary["output_sha256"].items():
        if digest(SOURCE / name) != expected:
            raise RuntimeError(f"qualification output changed: {name}")
    packets = {r["blind_packet_id"]: r for r in csv_rows(packet)}
    maps = {r["blind_packet_id"]: r for r in csv_rows(mapping)}
    results = jsonl(output)
    ids = [r["blind_packet_id"] for r in results]
    if len(ids) != 87 or len(set(ids)) != 87 or set(ids) != set(packets) or set(ids) != set(maps):
        raise RuntimeError("review IDs are missing or duplicated")
    records = {r.get("record_id", r["sample_id"].removeprefix("jsvul:")): r
               for r in jsonl(SOURCE / "record_qualification.jsonl")}
    audited = []
    for result in results:
        sid = result["blind_packet_id"]
        row, meta, decision = packets[sid], maps[sid], result["decision"]
        if result.get("status") != "completed" or result.get("prompt_sha256") != api["prompt_sha256"] or result.get("packet_sha256") != api["packet_sha256"]:
            raise RuntimeError(f"result provenance mismatch: {sid}")
        matches = []
        for side in ("a", "b"):
            rec = records[meta[f"side_{side}_record_id"]]
            if digest(Path(rec["source_path"])) != rec["source_sha256"]:
                raise RuntimeError(f"source snapshot changed for {sid}")
            align = rec["alignment"]
            support = decision[f"side_{side}_support"]
            span = row.get(f"side_{side}_{support}_lines", "")
            matches.append(span == f"{align['start_line']}-{align['end_line']}")
        passed = (decision["side_a_verdict"] == decision["side_b_verdict"] == "unique_match"
                  and decision["same_target"] == "yes")
        audited.append({"blind_packet_id": sid, "pair_id": meta["internal_pair_id"], "kind": meta["packet_kind"],
                        "role": meta["role"], "llm_pass": passed, "selected_span_matches_alignment": matches})
    report = {"status": "lineage_validated_not_qualified", "total": len(audited),
              "counts": dict(Counter(f"{r['kind']}:{r['role']}" for r in audited)),
              "llm_pass": sum(r["llm_pass"] for r in audited),
              "both_spans_match_algorithm": sum(all(r["selected_span_matches_alignment"]) for r in audited),
              "review_output_sha256": digest(output), "source_summary_sha256": digest(SOURCE / "qualification_summary.json"),
              "source_qualification_tokenizer_invalid": True,
              "reason": "historical tokenizer returned zero tokens; all packs must be rebuilt with the pinned complete tokenizer",
              "rows": audited}
    destination = BASE / "v2-blind-target-review/llm_lineage_audit.json"
    destination.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
    print(json.dumps({k: v for k, v in report.items() if k != "rows"}, indent=2))


if __name__ == "__main__":
    main()
