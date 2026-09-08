from __future__ import annotations

import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from .common import ControlError, atomic_json, identifier, load_json, state_root, timestamp, utc_now


class Control:
    def __init__(self, config: Any):
        self.root = state_root(config)
        self.config = config

    def cancel(self, action_id: str, reason: str = "user requested cancellation") -> dict:
        identifier(action_id)
        record = {"action_id": action_id, "requested_at": utc_now(), "reason": reason[:500]}
        atomic_json(self.root / "cancel" / f"{action_id}.json", record)
        return {**record, "cancellation_requested": True, "stopped_confirmed": False}

    def pause(self, paused: bool) -> dict:
        record = {"paused": paused, "updated_at": utc_now()}
        atomic_json(self.root / "pause.json", record)
        return record

    def quarantine(self, request_id: str, reason: str) -> None:
        identifier(request_id, "request id")
        atomic_json(self.config.interactive_spool / "quarantine" / f"{request_id}.json", {
            "request_id": request_id, "reason": reason, "created_at": utc_now(),
        })

    def check(self, action: dict | None = None, *, input_operation: bool = False, deadline: float | None = None) -> None:
        if deadline is not None and time.monotonic() >= deadline:
            raise ControlError("cancelled", "execution deadline reached")
        if action:
            ident = identifier(action["id"])
            if (self.root / "cancel" / f"{ident}.json").exists():
                raise ControlError("cancelled", "cancellation requested")
            now = datetime.now(timezone.utc)
            if action.get("expires_at") and timestamp(action["expires_at"]) <= now:
                raise ControlError("cancelled", "Action expired")
            if action.get("not_before") and timestamp(action["not_before"]) > now:
                raise ControlError("blocked", "Action not_before has not been reached")
            settings = getattr(self.config, "security", {})
            max_age = settings.get("max_action_age_seconds")
            if max_age is not None:
                if not action.get("created_at"):
                    raise ControlError("blocked", "created_at required by local maximum Action age")
                age = (now - timestamp(action["created_at"])).total_seconds()
                if age > max_age or age < -60:
                    raise ControlError("cancelled", "Action age outside local limit")
        if input_operation:
            pause = self.root / "pause.json"
            if pause.exists() and load_json(pause).get("paused"):
                raise ControlError("blocked", "desktop is paused locally")
            quarantine_dir = self.config.interactive_spool / "quarantine"
            for path in quarantine_dir.glob("*.json"):
                request_id = path.stem
                response = self.config.interactive_spool / "responses" / f"{request_id}.json"
                if response.exists():
                    record = load_json(response)
                    from .ipc import authenticated
                    if authenticated(self.config.interactive_spool, record) and record.get("protocol") == "q-agent-v4-interactive-response" and record.get("id") == request_id and record.get("execution_finished") is True:
                        path.unlink(missing_ok=True)
                        continue
                raise ControlError("ambiguous", "previous GUI request has not confirmed termination; input is quarantined")


def check_host_request(config: Any, request: dict, *, side_effect: bool) -> None:
    """Runs before every GUI primitive, not just at the beginning of a batch."""
    req_id = identifier(request.get("id"), "request id")
    cancel_path = config.interactive_spool / "cancel" / f"{req_id}.json"
    if cancel_path.exists():
        raise ControlError("cancelled", "GUI request cancellation received")
    if not request.get("expires_at") or timestamp(request["expires_at"]) <= datetime.now(timezone.utc):
        raise ControlError("cancelled", "GUI request expired or lacks a deadline")
    action_id = request.get("action_id")
    Control(config).check({"id": action_id} if action_id else None, input_operation=side_effect)
