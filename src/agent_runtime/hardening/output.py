from __future__ import annotations

import os
import itertools
import math
import json
import re
from typing import Any
from .common import canonical

SENSITIVE = re.compile(r"password|passwd|secret|authorization|access.?token|refresh.?token|api.?key|private.?key|cookie", re.I)
ASSIGNMENT = re.compile(r'(?i)\b(password|passwd|secret|token|api[_-]?key|authorization)\b([\s\"\']*[:=][\s\"\']*)([^\s,;\"\']+)')
BEARER = re.compile(r"(?i)\bBearer\s+[A-Za-z0-9._~+/=-]+")
PRIVATE_KEY = re.compile(r"-----BEGIN [^-]*PRIVATE KEY-----.*?-----END [^-]*PRIVATE KEY-----", re.S)
TOKENS = re.compile(r"\b(?:gh[pousr]_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,}|sk-[A-Za-z0-9_-]{20,})\b")


def redact(value: Any, *, known: tuple[str, ...] = (), depth: int = 0, max_chars: int = 2_000_000) -> Any:
    budget = {"chars": max_chars, "nodes": 10000}
    def visit(item, level):
        budget["nodes"] -= 1
        if level > 24 or budget["nodes"] < 0 or budget["chars"] <= 0:
            return {"truncated": True, "reason": "output traversal budget"}
        if isinstance(item, dict):
            out = {}
            for key, val in itertools.islice(item.items(), 5000):
                if budget["nodes"] < 0 or budget["chars"] <= 0:
                    out["output_truncated"] = True
                    break
                key = str(key)[:256]
                budget["chars"] -= len(key)
                out[key] = "[REDACTED]" if SENSITIVE.search(key) and key not in {"secret_ref", "credential_ref"} else visit(val, level + 1)
            if len(item) > 5000:
                out["output_truncated"] = True
            return out
        if isinstance(item, (list, tuple)):
            out = []
            for val in itertools.islice(item, 5000):
                if budget["nodes"] < 0 or budget["chars"] <= 0:
                    out.append({"truncated": True})
                    break
                out.append(visit(val, level + 1))
            if len(item) > 5000:
                out.append({"truncated": True})
            return out
        if isinstance(item, str):
            length = len(item)
            # Do not persist partial strings: a truncated credential could defeat
            # otherwise correct token redaction and is not valid goal evidence.
            if length > budget["chars"]:
                budget["chars"] = 0
                return {"truncated": True, "characters": length}
            budget["chars"] -= length
            for secret in known:
                if len(secret) >= 8:
                    item = item.replace(secret, "[REDACTED]")
            item = PRIVATE_KEY.sub("[REDACTED_PRIVATE_KEY]", item)
            item = TOKENS.sub("[REDACTED_TOKEN]", item)
            item = BEARER.sub("Bearer [REDACTED]", item)
            return ASSIGNMENT.sub(lambda m: m[1] + m[2] + "[REDACTED]", item)
        if item is None or type(item) in (int, bool):
            return item
        if type(item) is float and math.isfinite(item):
            return item
        return {"truncated": True, "reason": "unsupported output value"}
    return visit(value, depth)


def contains_truncation(value: Any, depth: int = 0) -> bool:
    if depth > 30:
        return True
    if isinstance(value, dict):
        return value.get("truncated") is True or value.get("output_truncated") is True or any(contains_truncation(x, depth + 1) for x in value.values())
    if isinstance(value, (list, tuple)):
        return any(contains_truncation(x, depth + 1) for x in value)
    return False


class BoundedOutputs(list):
    """Bound aggregate retained observations; exhausted evidence is not success.

    This bounds Python-side retention only. It cannot bound a web page's renderer
    or the allocation made by a third-party API before returning its result.
    """
    def __init__(self, max_bytes: int):
        super().__init__()
        self.max_bytes = max_bytes
        self.total = 2
    def append(self, value):
        from .common import ControlError
        value = safe_output(value, self.max_bytes)
        size = len(canonical(value)) + 1
        if self.total + size > self.max_bytes:
            raise ControlError("blocked", "aggregate observation output budget exceeded; no further operations")
        self.total += size
        super().append(value)

def known_environment_secrets() -> tuple[str, ...]:
    return tuple(v for k, v in os.environ.items() if SENSITIVE.search(k) and len(v) >= 8)


def safe_output(value: Any, max_bytes: int = 2_000_000) -> Any:
    """Bound the serialized result, retaining status/evidence of truncation.

    Pattern redaction is defense-in-depth, NOT a guarantee for arbitrary unlabelled
    secrets. Sensitive browser outputs are separately forbidden/kept local.
    """
    cleaned = redact(value, known=known_environment_secrets(), max_chars=max_bytes)
    payload = canonical(cleaned)
    if len(payload) <= max_bytes:
        return cleaned
    if not isinstance(cleaned, dict):
        return {"truncated": True, "original_bytes": len(payload)}
    keep = {k: cleaned[k] for k in ("protocol", "id", "action_id", "action_sha256", "agent_id", "status", "execution_finished", "started_at", "finished_at") if k in cleaned}
    keep.update(output_truncated=True, original_bytes=len(payload), steps=[],
                error="Result exceeded output budget. Detailed payload was not persisted.")
    if len(canonical(keep)) > max_bytes:
        keep = {"status": "ambiguous", "output_truncated": True, "error": "Envelope exceeds the result budget"}
    return keep
