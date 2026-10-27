"""Streaming JSON arrays/JSONL/CSV, without loading multi-GB input files."""
from __future__ import annotations

import csv
import json
import sys
from pathlib import Path
from typing import Iterator


def json_array(path: Path, max_record_bytes: int = 64 * 1024 * 1024) -> Iterator[dict]:
    decoder = json.JSONDecoder()
    with path.open(encoding="utf-8-sig") as handle:
        buffer, position, eof = "", 0, False

        def refill():
            nonlocal buffer, position, eof
            buffer = buffer[position:] + handle.read(65536)
            position = 0
            eof = len(buffer) == 0 or handle.tell() == path.stat().st_size

        def whitespace():
            nonlocal position
            while True:
                while position < len(buffer) and buffer[position].isspace():
                    position += 1
                if position < len(buffer) or eof:
                    return
                refill()

        refill()
        whitespace()
        if position >= len(buffer) or buffer[position] != "[":
            raise ValueError(f"{path}: expected top-level JSON array; use explicit JSONL/object mapping")
        position += 1
        first = True
        while True:
            whitespace()
            if position < len(buffer) and buffer[position] == "]":
                position += 1
                whitespace()
                if position < len(buffer):
                    raise ValueError(f"{path}: trailing data after JSON array")
                return
            if not first:
                if position >= len(buffer) or buffer[position] != ",":
                    raise ValueError(f"{path}: missing array separator")
                position += 1
                whitespace()
                if position < len(buffer) and buffer[position] == "]":
                    raise ValueError(f"{path}: trailing array comma")
            while True:
                try:
                    record, end = decoder.raw_decode(buffer, position)
                    position = end
                    break
                except json.JSONDecodeError as error:
                    if eof:
                        raise ValueError(f"{path}: invalid/incomplete JSON array item") from error
                    if len(buffer) - position > max_record_bytes:
                        raise ValueError(f"{path}: one record exceeds configured reader budget") from error
                    refill()
            if not isinstance(record, dict):
                raise ValueError(f"{path}: array item must be an object")
            yield record
            first = False


def records(path: Path, format: str = "auto") -> Iterator[tuple[int, dict]]:
    if format == "json":
        format = "array"
    if format == "auto":
        if path.suffix.lower() == ".csv":
            format = "csv"
        elif path.suffix.lower() in {".jsonl", ".ndjson"}:
            format = "jsonl"
        else:
            with path.open(encoding="utf-8-sig") as handle:
                format = "array" if handle.read(4096).lstrip().startswith("[") else "jsonl"
    if format == "array":
        yield from enumerate(json_array(path))
    elif format == "jsonl":
        with path.open(encoding="utf-8-sig") as handle:
            ordinal = 0
            for line_number, line in enumerate(handle, 1):
                if not line.strip():
                    continue
                try:
                    row = json.loads(line)
                except json.JSONDecodeError as error:
                    raise ValueError(f"{path}:{line_number}: malformed JSONL") from error
                if not isinstance(row, dict):
                    raise ValueError(f"{path}:{line_number}: record must be an object")
                yield ordinal, row
                ordinal += 1
    elif format == "csv":
        csv.field_size_limit(min(sys.maxsize, 2 ** 31 - 1))
        with path.open(encoding="utf-8-sig", newline="") as handle:
            yield from enumerate(csv.DictReader(handle))
    else:
        raise ValueError(f"unsupported format: {format}")
