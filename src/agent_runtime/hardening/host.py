from __future__ import annotations

import os
import threading
import time
from datetime import datetime, timezone
from typing import Any, Callable

from .common import ControlError, atomic_json, digest, identifier, load_json, timestamp, utc_now
from .control import check_host_request
from .ipc import authenticated, ipc_key, sign
from .output import safe_output
from .policy import effect, local_ui_check
from .validation import validate_operation

_current_request = threading.local()


def before_operation(config: Any, step: dict, operation: dict) -> None:
    local_ui_check(config, {**step, "type": "windows.ui", "actions": [operation]})
    request = getattr(_current_request, "value", None)
    if request is None:
        raise ControlError("blocked", "GUI calls require an authenticated request context")
    check_host_request(config, request, side_effect=effect({**step, "type": "windows.ui", "actions": [operation]}) != "read_only")
    from .desktop import enforce_observation_guard
    enforce_observation_guard(step)


def check_input_continuation(config=None, step=None, operation=None) -> None:
    """Recheck cancellation/session/foreground between Unicode characters.

    Pixel equality is not rechecked after the first character, because our own
    input necessarily changes the image. Foreground identity is still mandatory.
    """
    request = getattr(_current_request, "value", None)
    config = config or getattr(_current_request, "config", None)
    if not request or config is None:
        raise ControlError("blocked", "text input requires authenticated GUI context")
    step = step or request["step"]
    operation = operation or {"op": "type_text", "text": ""}
    local_ui_check(config, {**step, "type": "windows.ui", "actions": [operation]})
    check_host_request(config, request, side_effect=True)
    from .desktop import foreground_handle
    expected = step.get("__gpt_observation", {}).get("foreground_handle") or getattr(_current_request, "input_foreground", None)
    current = foreground_handle()
    if expected and current != expected:
        raise ControlError("ambiguous", "foreground changed during text input; remaining text was not sent")
    _current_request.input_foreground = current
    from agent_runtime.interactive_host import _input_desktop_name
    if _input_desktop_name() != "Default":
        raise ControlError("needs_user", "Windows session no longer available for text input")


def serve(config: Any, execute_ui: Callable[[Any, dict], dict]) -> None:
    from agent_runtime.lock import RuntimeLock
    from .desktop import set_dpi_awareness
    set_dpi_awareness()
    root = config.interactive_spool
    for name in ("requests", "processing", "responses", "cancel", "quarantine"):
        (root / name).mkdir(parents=True, exist_ok=True)
    ipc_key(root)
    state = {"state": "idle", "step_started_at": None, "step_timeout_seconds": None, "request_id": None}
    state_lock = threading.Lock()
    stop = threading.Event()
    def heartbeat():
        while not stop.is_set():
            with state_lock:
                record = {"protocol": "q-agent-v4-interactive-heartbeat", "agent_id": config.agent_id,
                          "pid": os.getpid(), "updated_at": utc_now(), **state}
            try:
                import psutil
                record["process_created_unix"] = psutil.Process().create_time()
            except (ImportError, OSError):
                pass
            atomic_json(root / "host-heartbeat.json", record)
            stop.wait(1)
    # One host per spool, including manual launches outside Task Scheduler.
    with RuntimeLock(root / "host.lock"):
        for processing in (root / "processing").glob("*.json"):
            ident = identifier(processing.stem)
            try:
                previous = load_json(processing)
                if not authenticated(root, previous):
                    processing.rename(processing.with_suffix(".untrusted"))
                    continue
            except (OSError, ValueError):
                processing.rename(processing.with_suffix(".invalid"))
                continue
            response = {"protocol": "q-agent-v4-interactive-response", "id": ident,
                        "action_sha256": previous.get("action_sha256"), "finished_at": utc_now(),
                        "status": "ambiguous", "execution_finished": True,
                        "error": "Host restarted after claim; request was NOT replayed"}
            atomic_json(root / "responses" / processing.name, sign(root, response))
            processing.unlink()
        thread = threading.Thread(target=heartbeat, name="gpt-host-heartbeat", daemon=True)
        thread.start()
        try:
            while True:
                did_work = False
                for pending in sorted((root / "requests").glob("*.json")):
                    did_work = True
                    processing = root / "processing" / pending.name
                    try:
                        ident = identifier(pending.stem)
                        pending.replace(processing)
                    except FileNotFoundError:
                        continue
                    response_path = root / "responses" / pending.name
                    request = {}
                    started = False
                    try:
                        request = load_json(processing)
                        if request.get("id") != ident or request.get("protocol") != "q-agent-v4-interactive-request" or not authenticated(root, request):
                            raise ControlError("blocked", "request identity/authentication mismatch")
                        if response_path.exists():
                            existing = load_json(response_path)
                            if authenticated(root, existing) and existing.get("id") == ident:
                                processing.unlink(missing_ok=True)
                                continue
                            raise ControlError("blocked", "conflicting response record")
                        step = request["step"]
                        if step.get("type") != "windows.ui":
                            raise ControlError("blocked", "host accepts windows.ui only")
                        ops = step.get("actions")
                        if not isinstance(ops, list) or not 1 <= len(ops) <= 500:
                            raise ValueError("invalid GUI operation list")
                        for operation in ops:
                            validate_operation(operation, False)
                        local_ui_check(config, step)
                        check_host_request(config, request, side_effect=effect(step) != "read_only")
                        with state_lock:
                            state.update(state="executing", step_started_at=utc_now(), step_timeout_seconds=max(1, int((timestamp(request["expires_at"]) - datetime.now(timezone.utc)).total_seconds())),
                                         request_id=ident, action_id=request.get("action_id"), step_type="windows.ui", step_index=0)
                        _current_request.value = request
                        _current_request.config = config
                        _current_request.input_foreground = None
                        started = True
                        result = execute_ui(config, step)
                        response = {"status": "succeeded", "result": result}
                    except ControlError as exc:
                        response = {"status": exc.state, "error": str(exc)}
                    except Exception as exc:
                        response = {"status": "ambiguous" if started else "failed", "error": str(exc)}
                    finally:
                        _current_request.value = None
                        _current_request.config = None
                        _current_request.input_foreground = None
                        with state_lock:
                            state.update(state="idle", step_started_at=None, step_timeout_seconds=None, request_id=None)
                    response.update(protocol="q-agent-v4-interactive-response", id=ident,
                                    action_sha256=request.get("action_sha256"), finished_at=utc_now(), execution_finished=True)
                    response = safe_output(response, config.max_output_bytes)
                    atomic_json(response_path, sign(root, response))
                    processing.unlink(missing_ok=True)
                    (root / "cancel" / pending.name).unlink(missing_ok=True)
                    # Acknowledgement, not a timer, removes the quarantine.
                    (root / "quarantine" / pending.name).unlink(missing_ok=True)
                if not did_work:
                    time.sleep(0.1)
        finally:
            stop.set()
            thread.join(timeout=2)
