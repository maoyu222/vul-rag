"""Invoke the unchanged original five-field extraction method, with an audit ledger."""
from __future__ import annotations

import time
from copy import deepcopy

from build_vulnerability_knowledge import _build_record, _extract_condition_fields, _knowledge_source_input
from .mechanism_extractor import now
from .mechanism_io import fingerprint


def validate_baseline(record: dict, row: dict) -> dict:
    rebuilt = _build_record(row, record).to_dict()
    if rebuilt != record:
        raise ValueError(f"{row['sample_id']}: baseline metadata/reviewed evidence mismatch")
    return record


def extract_baseline(client, row: dict, retries: int, checkpoint: dict | None, save) -> tuple[dict | None, dict]:
    identity = {"source_fingerprint": fingerprint(row), "runtime": client.runtime_info(),
                "method": "unchanged_original_five_field_prompt_v1"}
    log = deepcopy(checkpoint) if checkpoint else {
        "source_sample_id": row["sample_id"], "identity": identity, "status": "running",
        "source_input": _knowledge_source_input(row), "stages": {"baseline": {"attempts": []}}}
    if log.get("identity") != identity:
        raise ValueError("baseline resume identity mismatch")

    class Adapter:
        def generate(self, system, user):
            stage = log["stages"]["baseline"]
            stage.update(system=system, user=user)
            attempt = {"number": len(stage["attempts"]) + 1, "status": "started", "started_at": now()}
            stage["attempts"].append(attempt)
            save(log)
            start = time.monotonic()
            try:
                client.last_response = {}
                response = client.generate_with_metadata(system, user)
                attempt.update(status="completed", response=response)
                return response["content"]
            except (RuntimeError, ValueError, OSError, TimeoutError) as error:
                attempt.update(status="failed", error=str(error), response=getattr(client, "last_response", {}))
                raise
            finally:
                attempt["duration_seconds"] = round(time.monotonic() - start, 3)
                attempt["finished_at"] = now()
                save(log)

    for _ in range(retries + 1):
        try:
            generated = _extract_condition_fields(Adapter(), row)
            record = _build_record(row, generated).to_dict()
            log.update(status="completed", record=record)
            save(log)
            return record, log
        except (RuntimeError, ValueError, OSError, TimeoutError, TypeError, KeyError) as error:
            log.update(status="failed", error=str(error))
            attempts = log["stages"]["baseline"]["attempts"]
            if attempts and attempts[-1]["status"] == "completed":
                attempts[-1].update(status="invalid_output", error=str(error))
            save(log)
            if getattr(error, "http_status", None) in {400, 401, 403, 404, 422}:
                break
    return None, log
