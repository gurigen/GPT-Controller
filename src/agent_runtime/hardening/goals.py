from __future__ import annotations

import csv
import hashlib
import io
from pathlib import Path
from typing import Any
from .common import bounded_number, utc_now
from .validation import goal_shape


def resolve(config: Any, workspace: str, value: str) -> Path:
    if workspace not in config.workspaces:
        raise ValueError("unknown workspace")
    root = config.workspaces[workspace].resolve()
    candidate = Path(value).expanduser()
    if candidate.is_absolute():
        if not config.allow_absolute_paths:
            raise ValueError("absolute paths disabled")
        return candidate.resolve()
    target = (root / candidate).resolve()
    if not target.is_relative_to(root):
        raise ValueError("path escapes workspace")
    return target


def match(outputs: list, condition: dict) -> bool:
    from .output import contains_truncation
    if contains_truncation(outputs):
        return False
    """Bounded comparisons; missing paths cannot accidentally satisfy a negation."""
    def evaluate(cond):
        if "all" in cond:
            vals = [evaluate(x) for x in cond["all"]]
            return None if None in vals else all(vals)
        if "any" in cond:
            vals = [evaluate(x) for x in cond["any"]]
            return True if True in vals else None if None in vals else False
        if "not" in cond:
            val = evaluate(cond["not"])
            return None if val is None else not val
        source = cond.get("source", "last")
        try:
            value = outputs[-1] if source == "last" else outputs if source == "outputs" else outputs[source]
            for part in cond.get("path", "").split(".") if cond.get("path") else []:
                value = value[int(part)] if isinstance(value, list) else value[part]
        except (KeyError, IndexError, ValueError, TypeError):
            if "exists" in cond:
                return not cond["exists"]
            return None
        if "exists" in cond:
            return cond["exists"]
        if "equals" in cond:
            return type(value) is type(cond["equals"]) and value == cond["equals"]
        if "not_equals" in cond:
            return type(value) is not type(cond["not_equals"]) or value != cond["not_equals"]
        if "contains" in cond:
            try:
                return cond["contains"] in value
            except TypeError:
                return False
        if "truthy" in cond:
            return bool(value) == cond["truthy"]
        return False
    return evaluate(condition) is True


def verify(config: Any, goal: dict, outputs: list) -> dict:
    goal_shape(goal)
    evidence = []
    for condition in goal["conditions"]:
        kind = condition["type"]
        item = {"type": kind, "passed": False}
        try:
            if kind == "output.matches":
                item["passed"] = match(outputs, condition["condition"])
            else:
                path = resolve(config, condition["workspace"], condition["path"])
                item["workspace"] = condition["workspace"]
                item["path"] = condition["path"]
                if kind == "file.exists":
                    item["observed_exists"] = path.exists()
                    item["passed"] = item["observed_exists"] == condition.get("exists", True)
                elif kind == "file.sha256":
                    hasher = hashlib.sha256()
                    with path.open("rb") as stream:
                        before = __import__("os").fstat(stream.fileno())
                        if before.st_size > 1_000_000_000:
                            raise ValueError("verification file exceeds 1 GB budget")
                        for chunk in iter(lambda: stream.read(65536), b""):
                            hasher.update(chunk)
                        after = path.stat()
                    if (before.st_ino, before.st_size, before.st_mtime_ns) != (after.st_ino, after.st_size, after.st_mtime_ns):
                        raise ValueError("file changed during verification")
                    item["observed_sha256"] = hasher.hexdigest()
                    item["passed"] = hasher.hexdigest() == condition["sha256"]
                elif kind == "file.text_contains":
                    limit = int(bounded_number(condition.get("max_bytes", 2_000_000), "max_bytes", 1, 2_000_000, True))
                    with path.open("rb") as stream:
                        data = stream.read(limit + 1)
                    if len(data) > limit:
                        raise ValueError("file exceeds verification budget; no success inferred from a prefix")
                    item["passed"] = condition["text"] in data.decode(condition.get("encoding", "utf-8-sig"))
                elif kind == "csv.columns":
                    with path.open("rb") as stream:
                        data = stream.read(65537)
                    if len(data) > 65536:
                        # Read at most the first complete logical header within the bound.
                        data = data[:65536]
                        if b"\n" not in data:
                            raise ValueError("CSV header exceeds verification budget")
                    reader = csv.reader(io.StringIO(data.decode(condition.get("encoding", "utf-8-sig"))), strict=True)
                    columns = next(reader)
                    item["observed_columns"] = columns
                    item["passed"] = set(condition["columns"]).issubset(columns)
        except (OSError, ValueError, UnicodeError, StopIteration, csv.Error) as exc:
            item["error"] = str(exc)
        evidence.append(item)
    return {"description": goal["description"], "goal_achieved": all(x["passed"] for x in evidence),
            "checked_at": utc_now(), "evidence": evidence}
