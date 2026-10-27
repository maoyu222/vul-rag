"""Confined writes, fingerprints and fsync-based artifact IO."""
from __future__ import annotations

import hashlib
import json
import os
import sys
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

EXPERIMENT_ROOT = Path(__file__).resolve().parents[1]
PROJECT_ROOT = EXPERIMENT_ROOT.parents[1]
ALLOWED_ROOT = Path("/home/PublicData/LX-data")


def configure_runtime() -> None:
    sys.dont_write_bytecode = True
    if not EXPERIMENT_ROOT.is_relative_to(ALLOWED_ROOT.resolve()):
        raise ValueError("this experiment must stay inside /home/PublicData/LX-data")
    runtime = EXPERIMENT_ROOT / ".runtime"
    for name in ("tmp", "cache"):
        output_path(runtime / name).mkdir(parents=True, exist_ok=True)
    os.environ["TMPDIR"] = str(runtime / "tmp")
    os.environ["XDG_CACHE_HOME"] = str(runtime / "cache")
    os.environ["PYTHONDONTWRITEBYTECODE"] = "1"
    tempfile.tempdir = str(runtime / "tmp")


def output_path(path: Path) -> Path:
    resolved = path.expanduser().resolve()
    if not resolved.is_relative_to(EXPERIMENT_ROOT.resolve()):
        raise ValueError(f"outputs must be inside {EXPERIMENT_ROOT}: {path}")
    return resolved


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def canonical(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False)


def fingerprint(value: Any) -> str:
    return hashlib.sha256(canonical(value).encode()).hexdigest()


def file_hash(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def atomic_json(path: Path, value: Any) -> None:
    path = output_path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, temporary = tempfile.mkstemp(prefix="." + path.name, dir=path.parent)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            json.dump(value, handle, ensure_ascii=False, indent=2, allow_nan=False)
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)  # only this operation's newly created temporary file


def append_json(handle, value: Any) -> None:
    handle.write(canonical(value) + "\n")
    handle.flush()
    os.fsync(handle.fileno())


def read_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def open_new_jsonl(path: Path):
    path = output_path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    return path.open("x", encoding="utf-8", newline="\n")


def fresh_directory(path: Path) -> Path:
    path = output_path(path)
    if path.exists() and any(path.iterdir()):
        raise ValueError(f"refusing to overwrite nonempty directory: {path}")
    path.mkdir(parents=True, exist_ok=True)
    return path
