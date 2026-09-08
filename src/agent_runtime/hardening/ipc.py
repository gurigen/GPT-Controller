from __future__ import annotations

import hashlib
import hmac
import os
import secrets
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from .common import ControlError, atomic_json, canonical, load_json, utc_now
from .control import Control


def ipc_key(root: Path) -> bytes:
    root.mkdir(parents=True, exist_ok=True)
    path = root / "ipc-auth.key"
    try:
        fd = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    except FileExistsError:
        for _ in range(50):
            value = path.read_bytes()
            if len(value) == 32:
                return value
            time.sleep(0.01)
        raise ControlError("blocked", "invalid/incomplete local IPC authentication key")
    else:
        value = secrets.token_bytes(32)
        with os.fdopen(fd, "wb") as stream:
            stream.write(value)
            stream.flush()
            os.fsync(stream.fileno())
        return value


def sign(root: Path, payload: dict) -> dict:
    body = {k: v for k, v in payload.items() if k != "signature"}
    return {**body, "signature": hmac.new(ipc_key(root), canonical(body), hashlib.sha256).hexdigest()}


def authenticated(root: Path, payload: dict) -> bool:
    signature = payload.get("signature")
    if not isinstance(signature, str):
        return False
    expected = sign(root, payload)["signature"]
    return hmac.compare_digest(signature, expected)


def request(client: Any, step: dict, timeout_seconds: float) -> dict:
    if type(timeout_seconds) not in (int, float) or not 0 < timeout_seconds <= 86400:
        raise ValueError("invalid interactive timeout")
    root = client.config.interactive_spool
    for name in ("requests", "processing", "responses", "cancel", "quarantine"):
        (root / name).mkdir(parents=True, exist_ok=True)
    from .policy import effect
    Control(client.config).check(input_operation=effect(step) != "read_only")
    ident = secrets.token_hex(16)
    pending = root / "requests" / f"{ident}.json"
    response_path = root / "responses" / f"{ident}.json"
    expires = (datetime.now(timezone.utc) + timedelta(seconds=timeout_seconds)).isoformat()
    record = {"protocol": "q-agent-v4-interactive-request", "id": ident, "created_at": utc_now(), "expires_at": expires,
              "action_id": getattr(client, "action_id", None), "action_sha256": getattr(client, "action_sha256", None),
              "step": step}
    atomic_json(pending, sign(root, record))
    deadline = time.monotonic() + timeout_seconds
    while time.monotonic() < deadline:
        if response_path.exists():
            response = load_json(response_path)
            if response.get("protocol") != "q-agent-v4-interactive-response" or not authenticated(root, response) or response.get("id") != ident or response.get("action_sha256") != record["action_sha256"]:
                Control(client.config).quarantine(ident, "response authentication mismatch")
                raise ControlError("ambiguous", "GUI response identity/authentication mismatch")
            if response.get("execution_finished") is not True:
                Control(client.config).quarantine(ident, "termination unconfirmed")
                raise ControlError("ambiguous", "GUI termination not confirmed")
            response_path.unlink(missing_ok=True)
            pending.unlink(missing_ok=True)
            (root / "quarantine" / f"{ident}.json").unlink(missing_ok=True)
            if response.get("status") != "succeeded":
                state = response.get("status")
                if state not in {"blocked", "cancelled", "needs_user", "ambiguous", "failed"}:
                    state = "ambiguous"
                raise ControlError(state, response.get("error", "GUI operation failed"))
            return response.get("result", {})
        action_id = getattr(client, "action_id", None)
        try:
            Control(client.config).check({"id": action_id} if action_id else None)
        except ControlError:
            break
        time.sleep(0.05)
    # Always signal cancellation BEFORE trying to remove pending work. The host
    # authenticates and checks this signal before each operation.
    atomic_json(root / "cancel" / f"{ident}.json", sign(root, {"id": ident, "requested_at": utc_now()}))
    try:
        # unlink and the host's rename compete atomically. A successful unlink means
        # the host cannot have claimed this exact request; no side effect was started.
        pending.unlink()
    except FileNotFoundError:
        pass
    else:
        (root / "cancel" / f"{ident}.json").unlink(missing_ok=True)
        raise ControlError("cancelled", "GUI request was removed before host claim; no operation started")
    Control(client.config).quarantine(ident, "caller timed out or cancelled")
    raise ControlError("ambiguous", "GUI wait ended; cancellation requested but termination has not been acknowledged")
