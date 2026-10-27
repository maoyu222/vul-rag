"""Frozen cohorts, exclusive run locks, append-only predictions and strict resume."""
from __future__ import annotations

import fcntl
import json
import os
import sqlite3
import uuid
from pathlib import Path

from .io_utils import (EXPERIMENT_ROOT, append_json, atomic_json, canonical, file_hash,
                       fingerprint, fresh_directory, output_path, utc_now)
from .readers import records
from .schemas import normalize_sample
from .output_parser import parse_output


def source_fingerprint():
    paths = sorted((EXPERIMENT_ROOT / "src").rglob("*.py")) + sorted(EXPERIMENT_ROOT.glob("*.py"))
    return fingerprint({str(p.relative_to(EXPERIMENT_ROOT)): file_hash(p) for p in paths})


def read_ledger(path, repair_tail=False):
    """Only repair a final incomplete line; preserve its bytes before truncation."""
    path = Path(path)
    if not path.exists():
        return
    with path.open("rb") as handle:
        while True:
            offset = handle.tell()
            line = handle.readline()
            if not line:
                return
            try:
                value = json.loads(line)
            except (ValueError, UnicodeDecodeError):
                if not repair_tail or line.endswith(b"\n") or handle.read(1):
                    raise ValueError(f"corrupt JSONL record at byte {offset}: {path}")
                output_path(path)
                atomic_json(path.parent / ("recovery_" + uuid.uuid4().hex + ".json"),
                    {"file": path.name, "offset": offset, "tail_hex": line.hex(), "timestamp": utc_now()})
                with path.open("r+b") as target:
                    target.truncate(offset)
                    target.flush()
                    os.fsync(target.fileno())
                return
            unterminated = not line.endswith(b"\n")
            if unterminated:
                if not repair_tail:
                    raise ValueError(f"unterminated JSONL record: {path}")
                # A complete JSON value survived but its newline did not.
                with output_path(path).open("ab") as target:
                    target.write(b"\n")
                    target.flush()
                    os.fsync(target.fileno())
            if not isinstance(value, dict):
                raise ValueError(f"non-object ledger entry: {path}")
            yield value
            if unterminated:
                return


class RunStore:
    def __init__(self, directory: Path, inputs: list[Path], settings, prompt, resume=False,
                 limit=None, datasets=(), splits=("test",)):
        self.directory = output_path(directory)
        if not resume:
            fresh_directory(self.directory)
        elif not (self.directory / "run_config.json").is_file():
            raise ValueError("--resume requires an existing complete run_config.json")
        self.directory.mkdir(parents=True, exist_ok=True)
        for name in ("run.lock", "run_cache.sqlite3", "run_cache.sqlite3-journal", "run_config.json", "samples.jsonl", "results.jsonl", "requests.jsonl"):
            output_path(self.directory / name)  # reject existing symlinks outside the allowed output tree
        self.lock = (self.directory / "run.lock").open("a+")
        try:
            fcntl.flock(self.lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            self.lock.close()
            raise ValueError("another process holds this experiment's run lock") from None
        self.db = None
        try:
            input_info = [{"path": str(p.resolve()), "sha256": file_hash(p)} for p in inputs]
            if limit is not None and limit < 1:
                raise ValueError("--limit must be a positive sample cap")
            contract = {"inputs": input_info, "settings": settings.public_dict(), "prompt_version": prompt.version,
                "protocol": prompt.protocol,
                "prompt_sha256": prompt.sha256, "implementation_sha256": source_fingerprint(),
                "selection": {"limit": limit, "seed": settings.seed, "datasets": sorted(datasets), "splits": sorted(splits)}}
            self.contract_hash = fingerprint(contract)
            self.db = sqlite3.connect(self.directory / "run_cache.sqlite3")
            self.db.execute("PRAGMA temp_store=MEMORY")
            if resume:
                self.config = json.loads((self.directory / "run_config.json").read_text(encoding="utf-8"))
                if self.config.get("protocol") != prompt.protocol:
                    raise ValueError("resume refused: a different classification protocol requires a NEW output directory")
                if fingerprint({k: v for k, v in self.config.items() if k not in {"created_at", "config_hash"}}) != self.config.get("config_hash"):
                    raise ValueError("saved run_config.json fingerprint mismatch")
                if self.config["contract_hash"] != self.contract_hash:
                    raise ValueError("resume refused: input/config/prompt/implementation changed; use a NEW output directory")
                if file_hash(self.directory / "samples.jsonl") != self.config["samples_sha256"]:
                    raise ValueError("frozen samples.jsonl changed")
                # Rebuild cache from the immutable cohort, not mutable SQLite state.
                self.db.execute("DROP TABLE IF EXISTS cohort")
                self.db.execute("CREATE TABLE cohort(sid TEXT PRIMARY KEY, shash TEXT, payload TEXT)")
                for _, sample in records(self.directory / "samples.jsonl", "jsonl"):
                    checked = normalize_sample(sample)
                    if checked["sample_hash"] != sample.get("sample_hash"):
                        raise ValueError("frozen sample fingerprint mismatch")
                    self.db.execute("INSERT INTO cohort VALUES(?,?,?)", (sample["sample_id"], sample["sample_hash"], canonical(sample)))
            else:
                self.config = self._build(inputs, contract, settings.seed, limit, datasets, splits, prompt)
            self.config_hash = self.config["config_hash"]
            self.db.execute("DROP TABLE IF EXISTS latest")
            self.db.execute("CREATE TABLE latest(sid TEXT PRIMARY KEY, status TEXT, payload TEXT)")
            for result in read_ledger(self.directory / "results.jsonl", repair_tail=resume):
                self.validate_result(result)
                self.db.execute("INSERT OR REPLACE INTO latest VALUES(?,?,?)", (result["sample_id"], result["status"], canonical(result)))
            # Audit attempt logs too; no silently ignored middle corruption.
            recoverable = {}
            for event in read_ledger(self.directory / "requests.jsonl", repair_tail=resume):
                if event.get("config_hash") != self.config_hash:
                    raise ValueError("request ledger belongs to a different configuration")
                if event.get("event") == "finished":
                    sid = event.get("sample_id")
                    existing = self.db.execute("SELECT status FROM latest WHERE sid=?", (sid,)).fetchone()
                    if existing and existing[0] == "success":
                        continue
                    if event.get("status") == "success":
                        recoverable[sid] = event
                    else:
                        recoverable.pop(sid, None)
            self.db.commit()
            self.results = (self.directory / "results.jsonl").open("a", encoding="utf-8")
            self.requests = (self.directory / "requests.jsonl").open("a", encoding="utf-8")
            for sid, event in recoverable.items():
                row = self.db.execute("SELECT payload FROM cohort WHERE sid=?", (sid,)).fetchone()
                if not row:
                    raise ValueError("request journal contains a sample outside the frozen cohort")
                sample = json.loads(row[0])
                if sample["sample_hash"] != event.get("sample_hash"):
                    raise ValueError("request journal sample fingerprint mismatch")
                prediction = parse_output(event.get("raw_response"), sample["code"], event.get("finish_reason"))
                if prediction["status"] != "success":
                    continue
                recovered = {key: sample.get(key) for key in ("sample_id", "sample_hash", "normalized_code_hash", "dataset", "dataset_version", "split", "pair_id", "variant", "cwe_ids")}
                recovered.update(prediction, true_label=sample["label"], config_hash=self.config_hash,
                    model=self.config["settings"]["model"], prompt_version=self.config["prompt_version"],
                    raw_response=event.get("raw_response"), attempt_id=event.get("attempt_id"),
                    prompt_tokens=None, completion_tokens=None, total_tokens=None,
                    observed_token_lower_bounds=event.get("usage"), usage_incomplete=True,
                    latency_ms=event.get("latency_ms"), latency_scope="last_request_recovered_from_journal",
                    attempt_count=event.get("attempt_number"), recovered_from_journal=True, finished_at=utc_now())
                self.save(recovered)
        except BaseException:
            self.close()
            raise

    def _build(self, inputs, contract, seed, limit, datasets, splits, prompt):
        self.db.execute("CREATE TABLE candidates(sid TEXT PRIMARY KEY, gid TEXT, payload TEXT)")
        self.db.execute("CREATE TABLE groups(gid TEXT PRIMARY KEY, rank TEXT, n INTEGER)")
        cohort_mode = None
        for path in inputs:
            for _, source in records(path, "jsonl"):
                sample = normalize_sample(source)
                if source.get("sample_hash") and sample["sample_hash"] != source["sample_hash"]:
                    raise ValueError("normalized input sample_hash mismatch")
                if datasets and sample["dataset"] not in datasets or splits and sample["split"] not in splits:
                    continue
                mode = "paired" if sample["pair_id"] else "ordinary"
                if cohort_mode is not None and mode != cohort_mode:
                    raise ValueError("ordinary and paired inputs require separate run directories")
                cohort_mode = mode
                gid = canonical([sample["dataset"], sample.get("dataset_version"), "pair", sample["pair_id"]]) if sample["pair_id"] else canonical(["sample", sample["sample_id"]])
                try:
                    self.db.execute("INSERT INTO candidates VALUES(?,?,?)", (sample["sample_id"], gid, canonical(sample)))
                except sqlite3.IntegrityError:
                    raise ValueError("duplicate sample_id across input files; ordinary and paired cohorts must be separate runs") from None
        self.db.execute("CREATE INDEX candidate_groups ON candidates(gid)")
        for gid, n in self.db.execute("SELECT gid,COUNT(*) FROM candidates GROUP BY gid"):
            members = [json.loads(row[0]) for row in self.db.execute("SELECT payload FROM candidates WHERE gid=?", (gid,))]
            if members[0]["pair_id"]:
                if n != 2 or {s["variant"] for s in members} != {"before", "after"}:
                    raise ValueError("incomplete/ambiguous pair in input or after split/dataset filtering")
                for key in ("dataset", "dataset_version", "split", "project", "fix_commit"):
                    if len({s.get(key) for s in members}) != 1:
                        raise ValueError("pair metadata mismatch: " + key)
            self.db.execute("INSERT INTO groups VALUES(?,?,?)", (gid, fingerprint([seed, gid]), n))
        self.db.execute("CREATE TABLE cohort(sid TEXT PRIMARY KEY, shash TEXT, payload TEXT)")
        selected = 0
        for gid, n in self.db.execute("SELECT gid,n FROM groups ORDER BY rank,gid"):
            if limit is not None and selected + n > limit:
                continue
            for payload, in self.db.execute("SELECT payload FROM candidates WHERE gid=? ORDER BY sid", (gid,)):
                sample = json.loads(payload)
                self.db.execute("INSERT INTO cohort VALUES(?,?,?)", (sample["sample_id"], sample["sample_hash"], payload))
            selected += n
        if not selected:
            raise ValueError("no samples selected; inspect input/filtering, or use --limit >= 2 for a paired cohort")
        # Do not retain a second full copy of the unselected code in the run.
        self.db.execute("DELETE FROM candidates")
        self.db.commit()
        path = self.directory / "samples.jsonl"
        with path.open("x", encoding="utf-8") as handle:
            for payload, in self.db.execute("SELECT payload FROM cohort ORDER BY sid"):
                append_json(handle, json.loads(payload))
        for info in contract["inputs"]:
            if file_hash(Path(info["path"])) != info["sha256"]:
                raise ValueError("an input file changed during cohort preparation")
        config = {**contract, "contract_hash": self.contract_hash, "created_at": utc_now(), "sample_count": selected,
                  "samples_sha256": file_hash(path), "system_prompt": prompt.system, "user_prompt_template": prompt.user,
                  "protocol": prompt.protocol}
        config["config_hash"] = fingerprint({k: v for k, v in config.items() if k != "created_at"})
        atomic_json(self.directory / "run_config.json", config)
        return config

    def validate_result(self, result):
        row = self.db.execute("SELECT shash,payload FROM cohort WHERE sid=?", (result.get("sample_id"),)).fetchone()
        if not row or result.get("sample_hash") != row[0] or result.get("config_hash") != self.config_hash:
            raise ValueError("result fingerprint/config/sample does not match frozen cohort")
        if type(result.get("true_label")) is not int or result["true_label"] != json.loads(row[1])["label"]:
            raise ValueError("saved true_label differs from frozen cohort")
        if result.get("status") not in {"success", "error"}:
            raise ValueError("invalid saved result status")
        pred = result.get("predicted_label")
        if result["status"] == "success" and (type(pred) is not int or pred not in (0, 1)):
            raise ValueError("invalid successful result label")
        if result["status"] != "success" and pred is not None:
            raise ValueError("execution errors must not contain fabricated binary predictions")

    def pending(self, retry_failed=False):
        query = """SELECT c.payload FROM cohort c LEFT JOIN latest l ON c.sid=l.sid
                   WHERE l.sid IS NULL OR (?=1 AND l.status='error') ORDER BY c.sid"""
        for payload, in self.db.execute(query, (int(retry_failed),)):
            yield json.loads(payload)

    def log_attempt(self, event):
        append_json(self.requests, {**event, "config_hash": self.config_hash})

    def save(self, result):
        self.validate_result(result)
        append_json(self.results, result)  # durable before checkpoint update
        self.db.execute("INSERT OR REPLACE INTO latest VALUES(?,?,?)", (result["sample_id"], result["status"], canonical(result)))
        self.db.commit()

    def counts(self):
        counts = dict(self.db.execute("SELECT status,COUNT(*) FROM latest GROUP BY status"))
        counts["selected"] = self.config["sample_count"]
        counts["not_completed"] = counts["selected"] - sum(v for k, v in counts.items() if k != "selected")
        return counts

    def close(self):
        for name in ("results", "requests", "db", "lock"):
            value = getattr(self, name, None)
            if value is not None:
                value.close()
                setattr(self, name, None)

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.close()
