from __future__ import annotations

import hashlib
import json
import math
import os
import re
import tempfile
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

ID_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}\Z")


class ControlError(RuntimeError):
    def __init__(self, state: str, message: str):
        if state not in {"failed", "ambiguous", "blocked", "cancelled", "needs_user"}:
            raise ValueError("invalid control error state")
        self.state = state
        super().__init__(f"[{state}] {message}")


def identifier(value: Any, name: str = "id") -> str:
    if not isinstance(value, str) or not ID_RE.fullmatch(value):
        raise ValueError(f"invalid {name}")
    reserved = {"CON", "PRN", "AUX", "NUL", *(f"COM{i}" for i in range(1,10)), *(f"LPT{i}" for i in range(1,10))}
    if value.endswith(".") or value.split(".",1)[0].upper() in reserved:
        raise ValueError(f"invalid {name}: ambiguous Windows filename")
    return value


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def timestamp(value: Any) -> datetime:
    if not isinstance(value, str):
        raise ValueError("timestamp must be a timezone-qualified string")
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if parsed.tzinfo is None:
        raise ValueError("timestamp must include a timezone")
    return parsed.astimezone(timezone.utc)


def canonical(value: Any) -> bytes:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False).encode("utf-8")


def digest(value: Any) -> str:
    return hashlib.sha256(canonical(value)).hexdigest()


def atomic_json(path: Path, value: Any) -> None:
    data = canonical(value) + b"\n"
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, temp = tempfile.mkstemp(prefix=".gpt-", dir=path.parent)
    try:
        with os.fdopen(fd, "wb") as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        # Windows readers may briefly hold a handle without FILE_SHARE_DELETE.
        # Retry only this publication of the same fully-written temporary file;
        # never repeat the Action, its steps, or any external side effects.
        for attempt in range(8):
            try:
                os.replace(temp, path)
                break
            except PermissionError as exc:
                if getattr(exc, "winerror", None) not in {5, 32, 33} or attempt == 7:
                    raise
                time.sleep(min(0.005 * (2 ** attempt), 0.08))
        if os.name != "nt":
            fd_dir = os.open(path.parent, os.O_RDONLY)
            try:
                os.fsync(fd_dir)
            finally:
                os.close(fd_dir)
    finally:
        if os.path.exists(temp):
            os.unlink(temp)


def load_json(path: Path, max_bytes: int = 8_000_000) -> Any:
    with path.open("rb") as stream:
        data = stream.read(max_bytes + 1)
    if len(data) > max_bytes:
        raise ValueError("JSON exceeds configured limit")
    def invalid(value: str) -> None:
        raise ValueError(f"non-finite JSON number: {value}")
    def pairs(items):
        out = {}
        for key, value in items:
            if key in out:
                raise ValueError(f"duplicate JSON key: {key}")
            out[key] = value
        return out
    return json.loads(data.decode("utf-8-sig"), parse_constant=invalid, object_pairs_hook=pairs)


def bounded_number(value: Any, name: str, minimum: float, maximum: float, integer: bool = False) -> float:
    if type(value) not in ({int} if integer else {int, float}) or not math.isfinite(value):
        raise ValueError(f"{name} must be a finite {'integer' if integer else 'number'}")
    if not minimum <= value <= maximum:
        raise ValueError(f"{name} must be between {minimum} and {maximum}")
    return value


def state_root(config: Any) -> Path:
    return config.repo_path.parent / "state" / "hardening" / identifier(config.agent_id, "agent_id")


def step_context(action: dict, parent: dict, child: dict) -> dict:
    result = dict(child)
    for key in ("workspace", "timeout_seconds"):
        if key not in result:
            if key in parent:
                result[key] = parent[key]
            elif key in action:
                result[key] = action[key]
    return result
