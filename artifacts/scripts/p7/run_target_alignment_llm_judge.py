"""Blinded GPT-5.6 Sol review; defaults to offline preflight and never sends without --run."""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import os
import urllib.error
import urllib.request
from datetime import UTC, datetime
from pathlib import Path

ROOT = Path("artifacts/results/diagnostics/p7-independent-qualification-20261120/v2-blind-target-review")
PACKET = ROOT / "human-reviewer.csv"
MANIFEST = ROOT / "review_manifest.json"
PROMPT_PATH = Path("artifacts/scripts/p7/target_alignment_llm_judge_prompt.md")
OUTPUT = ROOT / "llm_judge_results.jsonl"
EVENTS = ROOT / "llm_judge_events.jsonl"
ADMIN = ROOT / "reviewer_admin_mapping.csv"
RESULT_MANIFEST = ROOT / "llm_judge_manifest.json"
MODEL = "gpt-5.6-sol"
ENDPOINT = "https://api.openai.com/v1/responses"
PILOT_CONTROLS = 4
PILOT_NEAR = 8

SCHEMA = {
    "type": "object",
    "properties": {
        "side_a_verdict": {"type": "string", "enum": ["unique_match", "multiple_matches", "no_match", "insufficient_context"]},
        "side_a_support": {"type": "string", "enum": ["candidate_alpha", "candidate_beta", "both", "none", "uncertain"]},
        "side_b_verdict": {"type": "string", "enum": ["unique_match", "multiple_matches", "no_match", "insufficient_context"]},
        "side_b_support": {"type": "string", "enum": ["candidate_alpha", "candidate_beta", "both", "none", "uncertain"]},
        "same_target": {"type": "string", "enum": ["yes", "no", "uncertain"]},
        "confidence": {"type": "number", "minimum": 0, "maximum": 1},
        "rationale": {"type": "string"},
    },
    "required": ["side_a_verdict", "side_a_support", "side_b_verdict", "side_b_support",
                 "same_target", "confidence", "rationale"],
    "additionalProperties": False,
}


def sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def read_csv(path: Path) -> list[dict[str, str]]:
    with path.open(newline="") as stream:
        return list(csv.DictReader(stream))


def judge_payload(row: dict[str, str]) -> dict:
    payload = {"blind_packet_id": row["blind_packet_id"], "sides": {}}
    for side in ("a", "b"):
        payload["sides"][side.upper()] = {
            "project": row[f"side_{side}_project"],
            "revision": row[f"side_{side}_revision"],
            "file": row[f"side_{side}_file"],
            "source_url": row[f"side_{side}_source_url"],
            "curated_body": row[f"side_{side}_body"],
            "curated_body_truncated": row[f"side_{side}_body_truncated"] == "True",
            "candidate_alpha_lines": row[f"side_{side}_candidate_alpha_lines"],
            "candidate_alpha": row[f"side_{side}_candidate_alpha"],
            "candidate_alpha_truncated": row[f"side_{side}_candidate_alpha_truncated"] == "True",
            "candidate_beta_lines": row[f"side_{side}_candidate_beta_lines"],
            "candidate_beta": row[f"side_{side}_candidate_beta"],
            "candidate_beta_truncated": row[f"side_{side}_candidate_beta_truncated"] == "True",
        }
    return payload


def response_text(result: dict) -> str:
    chunks = []
    for item in result.get("output", []):
        if item.get("type") != "message":
            continue
        for part in item.get("content", []):
            if part.get("type") == "output_text":
                chunks.append(part.get("text", ""))
            elif part.get("type") == "refusal":
                raise RuntimeError("model refusal")
    if not chunks:
        raise RuntimeError("API response contained no structured output text")
    return "".join(chunks)


def finalize(output_rows: list[dict], prompt_hash: str, packet_hash: str) -> None:
    with OUTPUT.open("x") as stream:
        for result in output_rows:
            stream.write(json.dumps(result, sort_keys=True) + "\n")
    usage_totals = {key: sum(int(row.get("usage", {}).get(key, 0)) for row in output_rows)
                    for key in ("input_tokens", "output_tokens", "total_tokens")}
    log = {"status": "completed", "mode": "pilot" if "pilot" in OUTPUT.name else "full",
           "model": MODEL, "packet_count": len(output_rows),
           "prompt_sha256": prompt_hash, "packet_sha256": packet_hash,
           "output_sha256": sha(OUTPUT.read_bytes()), "usage_totals": usage_totals,
           "api_storage": False, "completed_at_utc": datetime.now(UTC).isoformat()}
    RESULT_MANIFEST.write_text(json.dumps(log, indent=2, sort_keys=True) + "\n")
    print(json.dumps(log, indent=2, sort_keys=True))


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--run", action="store_true", help="send paid Responses API requests")
    parser.add_argument("--pilot", action="store_true", help="review 4 exact controls and 8 near pairs, with isolated output")
    args = parser.parse_args()

    global OUTPUT, EVENTS, RESULT_MANIFEST
    if args.pilot:
        OUTPUT = ROOT / "llm_judge_pilot_results.jsonl"
        EVENTS = ROOT / "llm_judge_pilot_events.jsonl"
        RESULT_MANIFEST = ROOT / "llm_judge_pilot_manifest.json"

    manifest = json.loads(MANIFEST.read_text())
    prompt = PROMPT_PATH.read_text()
    rows = read_csv(PACKET)
    if args.pilot:
        if manifest["reviewer_packet_sha256"].get("reviewer_admin_mapping.csv") != sha(ADMIN.read_bytes()):
            raise RuntimeError("admin mapping differs from the pinned review manifest")
        admin_rows = read_csv(ADMIN)
        kind_by_id = {row["blind_packet_id"]: row["packet_kind"] for row in admin_rows}
        if set(kind_by_id) != {row["blind_packet_id"] for row in rows}:
            raise RuntimeError("admin mapping does not cover the pinned review packet IDs")
        controls = sorted((row for row in rows if kind_by_id.get(row["blind_packet_id"]) == "exact_control"),
                          key=lambda row: row["blind_packet_id"])
        near = sorted((row for row in rows if kind_by_id.get(row["blind_packet_id"]) == "near_review"),
                      key=lambda row: row["blind_packet_id"])
        if len(controls) < PILOT_CONTROLS or len(near) < PILOT_NEAR:
            raise RuntimeError("review packet lacks the required blinded pilot mix")
        rows = controls[:PILOT_CONTROLS] + near[:PILOT_NEAR]
    packet_hash = sha(PACKET.read_bytes())
    prompt_hash = sha(prompt.encode())
    packet_ids = [row["blind_packet_id"] for row in rows]
    expected_count = PILOT_CONTROLS + PILOT_NEAR if args.pilot else 87
    if len(rows) != expected_count or len(set(packet_ids)) != expected_count:
        raise RuntimeError(f"expected {expected_count} unique blind review packets")
    forbidden_headers = {"label", "role", "family_id", "algorithm_alignment_status", "score", "mcc", "auroc"}
    if forbidden_headers & {key.lower() for key in rows[0]}:
        raise RuntimeError("review packet exposes prohibited metadata")
    if manifest["reviewer_packet_sha256"].get("human-reviewer.csv") != packet_hash:
        raise RuntimeError("human packet differs from the pinned review manifest")

    inputs = [judge_payload(row) for row in rows]
    input_hashes = {row["blind_packet_id"]: sha(json.dumps(data, sort_keys=True).encode())
                    for row, data in zip(rows, inputs, strict=True)}
    total_chars = sum(len(json.dumps(data, ensure_ascii=False)) for data in inputs) + len(prompt) * len(inputs)
    preflight = {
        "status": "ready_to_send" if os.environ.get("OPENAI_API_KEY") else "waiting_for_openai_api_key_and_credit",
        "model": MODEL, "packet_count": len(inputs), "prompt_sha256": prompt_hash,
        "human_packet_sha256": packet_hash, "estimated_request_characters": total_chars,
        "approx_input_tokens_at_3_chars_per_token": (total_chars + 2) // 3,
        "model_page": "https://developers.openai.com/api/docs/models/gpt-5.6-sol",
        "api_calls_send_only_after_run_flag": True,
        "api_storage": False,
        "api_key_present": bool(os.environ.get("OPENAI_API_KEY")),
        "mode": "pilot" if args.pilot else "full",
        "selection": "4 exact controls + 8 near-review packets, chosen by blind packet ID order" if args.pilot else "all 87 pinned packets",
    }
    print(json.dumps(preflight, indent=2, sort_keys=True))
    if not args.run:
        return 0
    if args.pilot and (ROOT / "llm_judge_results.jsonl").exists():
        raise SystemExit("full judge results already exist; derive pilot results from them instead of sending duplicate requests")
    api_key = os.environ.get("OPENAI_API_KEY")
    if not api_key:
        raise SystemExit("OPENAI_API_KEY is missing; no API request was sent")
    if OUTPUT.exists():
        raise SystemExit(f"judge output already exists: {OUTPUT}")
    if EVENTS.exists():
        events = [json.loads(line) for line in EVENTS.read_text().splitlines()]
        starts = [event for event in events if event.get("status") == "run_started"]
        if (len(starts) != 1 or starts[0].get("model") != MODEL
                or starts[0].get("prompt_sha256") != prompt_hash
                or starts[0].get("packet_sha256") != packet_hash
                or starts[0].get("packet_count") != len(rows)):
            raise SystemExit("existing judge events belong to a different run contract; inspect them before recovery")
        completed = {event["blind_packet_id"]: event for event in events if event.get("status") == "completed"}
        if any(event.get("prompt_sha256") != prompt_hash or event.get("packet_sha256") != packet_hash
               or event.get("input_sha256") != input_hashes.get(sid)
               for sid, event in completed.items()):
            raise SystemExit("completed judge events do not match the current inputs; inspect them before recovery")
        errors = [event for event in events if event.get("status") == "http_error"]
        pending = {event["blind_packet_id"] for event in events if event.get("status") == "request_started"} - set(completed)
        if pending:
            raise SystemExit("an earlier request may have been billed but has no recorded response; reconcile it manually before retrying")
        if errors:
            raise SystemExit("an earlier API request failed; inspect the event log and reconcile before retrying")
        if completed:
            if set(completed) != set(packet_ids):
                raise SystemExit("partial judge events exist; inspect the event log before issuing new paid requests")
            finalize(list(completed.values()), prompt_hash, packet_hash)
            return 0
        raise SystemExit("judge event log exists without completed requests; inspect it before retrying")

    with EVENTS.open("x") as events_stream:
        events_stream.write(json.dumps({"status": "run_started", "model": MODEL, "prompt_sha256": prompt_hash,
                                        "packet_sha256": packet_hash, "packet_count": len(rows)}) + "\n")
        events_stream.flush()
    output_rows = []
    for row, data in zip(rows, inputs, strict=True):
        started = {"status": "request_started", "blind_packet_id": row["blind_packet_id"],
                   "prompt_sha256": prompt_hash, "input_sha256": input_hashes[row["blind_packet_id"]],
                   "started_at_utc": datetime.now(UTC).isoformat()}
        with EVENTS.open("a") as events_stream:
            events_stream.write(json.dumps(started, sort_keys=True) + "\n")
            events_stream.flush()
        request_body = {
            "model": MODEL,
            "instructions": prompt,
            "input": json.dumps(data, ensure_ascii=False, sort_keys=True),
            "reasoning": {"effort": "high"},
            "text": {"format": {"type": "json_schema", "name": "target_alignment_review",
                                  "strict": True, "schema": SCHEMA}},
            "max_output_tokens": 1200,
            "store": False,
        }
        request = urllib.request.Request(
            ENDPOINT,
            data=json.dumps(request_body).encode(),
            headers={"Authorization": f"Bearer {api_key}", "Content-Type": "application/json"},
            method="POST",
        )
        try:
            with urllib.request.urlopen(request, timeout=180) as response:
                api_result = json.loads(response.read())
        except urllib.error.HTTPError as error:
            with EVENTS.open("a") as events_stream:
                events_stream.write(json.dumps({"status": "http_error", "blind_packet_id": row["blind_packet_id"],
                                                "http_status": error.code}, sort_keys=True) + "\n")
                events_stream.flush()
            raise RuntimeError(f"Responses API returned HTTP {error.code}; stopped to avoid duplicate paid calls") from None
        except (OSError, urllib.error.URLError, TimeoutError):
            raise RuntimeError("Responses API request failed or timed out; stopped to avoid duplicate paid calls") from None
        if api_result.get("status") != "completed":
            raise RuntimeError(f"judge response was not completed for packet {row['blind_packet_id']}")
        decision = json.loads(response_text(api_result))
        usage = api_result.get("usage", {})
        output_rows.append({
            "blind_packet_id": row["blind_packet_id"], "status": "completed",
            "model": api_result.get("model", MODEL), "api_response_id": api_result.get("id"),
            "created_at_utc": datetime.now(UTC).isoformat(), "prompt_sha256": prompt_hash,
            "packet_sha256": packet_hash, "input_sha256": input_hashes[row["blind_packet_id"]],
            "decision": decision, "usage": usage,
        })
        with EVENTS.open("a") as events_stream:
            events_stream.write(json.dumps(output_rows[-1], sort_keys=True) + "\n")
            events_stream.flush()

    finalize(output_rows, prompt_hash, packet_hash)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
