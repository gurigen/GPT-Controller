from __future__ import annotations

import hashlib
import time
from pathlib import Path
from typing import Any

from .common import ControlError, atomic_json, digest, identifier, load_json, state_root
from .output import safe_output
from .policy import security


def assert_new_claim(bus: Any, pending: Path, action: dict) -> str:
    ident = identifier(action["id"])
    if pending.name != f"{ident}.json":
        raise ValueError("pending filename must exactly match Action ID")
    for parent in ("claims", "results", "queue/done", "queue/ambiguous"):
        if any(path.name.casefold() == f"{ident.casefold()}.json" or (parent == "queue/ambiguous" and path.name.casefold().startswith(ident.casefold() + ".")) for path in (bus.repo / parent).glob("*.json")):
            raise ValueError("REPLAY_REJECTED: Action ID already recorded")
    for path in (bus.repo / "queue/running").glob("*.json"):
        try:
            previous = load_json(path)
        except (ValueError, OSError):
            raise ValueError("cannot establish unique Action ownership while running ledger is corrupt")
        if str(previous.get("id", "")).casefold() == ident.casefold():
            raise ValueError("REPLAY_REJECTED: Action ID is already running")
    return digest(action)


def porcelain_paths(text: str) -> list[str]:
    """Parse porcelain=v1 -z, preserving leading spaces and rename source paths."""
    fields = text.split("\0")
    paths = []
    index = 0
    while index < len(fields):
        record = fields[index]
        index += 1
        if not record:
            continue
        if len(record) < 4 or record[2] != " ":
            raise ValueError("malformed NUL-delimited porcelain record")
        status, path = record[:2], record[3:]
        paths.append(path)
        if "R" in status or "C" in status:
            if index >= len(fields) or not fields[index]:
                raise ValueError("missing rename/copy source path")
            paths.append(fields[index])
            index += 1
    return paths


def finish(bus: Any, action: dict, running_path: Path, result: dict) -> None:
    ident = identifier(action["id"])
    expected = digest(action)
    if result.get("action_id") != ident or result.get("action_sha256", expected) != expected:
        raise ControlError("ambiguous", "result does not identify the executed Action payload")
    result = {**result, "action_sha256": expected}
    result = safe_output(result, security(bus.c).get("max_result_bytes", bus.c.max_output_bytes))
    outbox = state_root(bus.c) / "outbox" / f"{ident}.json"
    atomic_json(outbox, {"action_id": ident, "action_sha256": expected, "result": result})
    publish_outbox(bus, outbox, running_path)


def publish_outbox(bus: Any, outbox: Path, running_path: Path | None = None) -> None:
    record = load_json(outbox)
    ident = identifier(record["action_id"])
    result = record["result"]
    if result.get("action_id") != ident or result.get("action_sha256") != record["action_sha256"]:
        raise ControlError("ambiguous", "outbox integrity mismatch")
    result_path = bus.repo / "results" / f"{ident}.json"
    if result_path.exists():
        existing = load_json(result_path)
        if existing != result:
            raise ControlError("ambiguous", "refusing to overwrite a conflicting durable result")
    else:
        atomic_json(result_path, result)
    if running_path is None:
        candidates = list((bus.repo / "queue/running").glob(f"{ident}.*.json"))
    else:
        candidates = [running_path]
    for running in candidates:
        if running.exists():
            contents = load_json(running)
            if contents.get("id") != ident or digest(contents) != record["action_sha256"]:
                raise ControlError("ambiguous", "running action differs from result payload")
            done = bus.repo / "queue/done" / f"{ident}.json"
            done.parent.mkdir(parents=True, exist_ok=True)
            if done.exists():
                if digest(load_json(done)) != record["action_sha256"]:
                    raise ControlError("ambiguous", "conflicting done Action")
                running.unlink()
            else:
                running.replace(done)
    bus._git("add", "queue", "results", "claims")
    changed = bus._git("diff", "--cached", "--quiet", check=False)
    if changed["exit_code"] == 1:
        bus._git("commit", "-m", f"gpt-controller result {ident} {result['status']}")
    elif changed["exit_code"] != 0:
        raise RuntimeError("cannot inspect staged result")
    for attempt in range(5):
        pushed = bus._git("push", bus.c.remote, bus.c.branch, check=False)
        if pushed["exit_code"] == 0:
            outbox.unlink(missing_ok=True)
            return
        # Keep outbox/result even if the network or rebase fails. Never repeat PC work.
        pulled = bus._git("pull", "--rebase", bus.c.remote, bus.c.branch, check=False)
        if pulled["exit_code"] != 0:
            raise RuntimeError("result publication failed; durable outbox retained")
        time.sleep(min(2 ** attempt, 8))
    raise RuntimeError("result publication exhausted retries; durable outbox retained")


def flush_outbox(bus: Any) -> int:
    count = 0
    for outbox in sorted((state_root(bus.c) / "outbox").glob("*.json")):
        publish_outbox(bus, outbox)
        count += 1
    return count
