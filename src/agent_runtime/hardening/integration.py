from __future__ import annotations

import copy
import hashlib
import importlib.util
import os
import platform
import shutil
import time
from typing import Any, Callable

from .common import ControlError, atomic_json, digest, state_root, step_context, utc_now
from .control import Control
from .goals import verify
from .output import safe_output
from .policy import effect, local_ui_check, preflight, security
from .state import Ledger
from .validation import validate_action_extra
from .workflow import desktop_loop


def normalize(action: dict) -> dict:
    result = copy.deepcopy(action)
    def visit(items: list, parent: dict):
        out = []
        for raw in items:
            item = step_context(result, parent, raw)
            if item.get("type") == "desktop.loop":
                item["steps"] = visit(item["steps"], item)
            out.append(item)
        return out
    result["steps"] = visit(result["steps"], result)
    return result


def execute(executor: Any, action: dict, legacy: Callable[[dict], dict], *, validator=None) -> dict:
    started = utc_now()
    result = {"protocol": "q-agent-v4-result", "action_id": action.get("id"), "agent_id": executor.config.agent_id,
              "started_at": started, "finished_at": None, "status": "failed", "error": None, "steps": []}
    ledger = None
    began = False
    settings = security(executor.config)
    maximum = settings.get("max_result_bytes", executor.config.max_output_bytes)
    try:
        if validator is not None:
            validator(action)
        validate_action_extra(action)
        payload_hash = digest(action)
        result["action_sha256"] = payload_hash
        control = Control(executor.config)
        control.check(action)
        ledger = Ledger(state_root(executor.config) / "execution.sqlite3")
        existing = ledger.action(action["id"])
        if existing:
            cached = ledger.begin(action["id"], payload_hash)
            return {**cached, "replayed": False, "cached_result": True}
        from .dependencies import check as check_dependencies
        check_dependencies(executor.config, action)
        preflight(executor.config, action, ledger, payload_hash)
        cached = ledger.begin(action["id"], payload_hash)
        if cached is not None:
            return {**cached, "replayed": False, "cached_result": True}
        began = True
        prepared = normalize(action)
        executor._hardening_ledger = ledger
        executor._hardening_halted = None
        executor._hardening_action = action
        executor._hardening_step_path = None
        executor._hardening_nested_path = None
        executor.interactive.action_id = action["id"]
        executor.interactive.action_sha256 = payload_hash
        result = legacy(prepared)
        result["action_sha256"] = payload_hash
        errors = [str(item.get("error", "")) for item in result.get("steps", [])]
        for state in ("ambiguous", "cancelled", "blocked", "needs_user"):
            if any(message.startswith(f"[{state}]") for message in errors):
                result["status"] = state
                break
        if action.get("goal") and result["status"] == "succeeded":
            result["goal"] = verify(executor.config, action["goal"], result["steps"])
            if not result["goal"]["goal_achieved"]:
                result["status"] = "failed"
                result["error"] = "Steps executed, but the declared goal was not verified. No automatic repeat."
        elif action.get("goal"):
            result["goal"] = {"description": action["goal"]["description"], "goal_achieved": False, "verification_skipped": True}
    except ControlError as exc:
        result.update(status=exc.state, error=str(exc))
    except Exception as exc:
        result.update(status="ambiguous" if began else "failed", error=str(exc))
    finally:
        executor._hardening_ledger = None
        executor._hardening_action = None
        executor._hardening_nested_path = None
    result["finished_at"] = utc_now()
    result = safe_output(result, maximum)
    if began and ledger:
        ledger.finish(action["id"], result)
    return result


def step(executor: Any, action: dict, item: dict, legacy: Callable[[dict, dict], Any]) -> Any:
    config = executor.config
    halted = getattr(executor, "_hardening_halted", None)
    if halted is not None:
        raise halted
    kind = item["type"]
    path = getattr(executor, "_hardening_nested_path", None)
    if path is None:
        path = str(next((i for i, entry in enumerate(action["steps"]) if entry is item), -1))
    previous = getattr(executor, "_hardening_step_path", None)
    executor._hardening_step_path = path
    ledger = getattr(executor, "_hardening_ledger", None)
    if ledger is None:
        raise ControlError("blocked", "steps must pass through Executor.execute validation and policy")
    side_effect = effect(item)
    control = Control(config)
    local_ui_check(config, item)
    control.check(action, input_operation=kind in {"windows.ui", "desktop.act", "browser.playwright", "browser.interactive"} and side_effect != "read_only")
    cached = ledger.begin_step(action["id"], path, digest(item), side_effect)
    if cached is not None:
        executor._hardening_step_path = previous
        return cached
    try:
        if kind == "desktop.loop":
            result = desktop_loop(executor, action, item, item.get("timeout_seconds", config.default_timeout_seconds))
        elif kind in {"agent.doctor", "agent.manifest"}:
            result = doctor(config, probe_git=kind == "agent.doctor", probe_host=kind == "agent.doctor")
        elif kind in {"goal.verify", "desktop.verify"}:
            result = verify(config, item["goal"], [])
            if not result["goal_achieved"]:
                raise ControlError("failed", "declared verification conditions did not pass")
        elif kind in {"file.list", "file.stat"}:
            from .goals import resolve as resolve_path
            target = resolve_path(config, item["workspace"], item["path"])
            if kind == "file.stat":
                stat = target.stat()
                result = {"path": item["path"], "bytes": stat.st_size, "modified_ns": stat.st_mtime_ns, "is_dir": target.is_dir()}
            else:
                limit = min(1000, max(1, int(item.get("limit", 200))))
                rows = []
                with os.scandir(target) as listing:
                    for entry in listing:
                        if len(rows) == limit:
                            break
                        stat = entry.stat(follow_symlinks=False)
                        rows.append({"name": entry.name, "is_dir": entry.is_dir(follow_symlinks=False), "bytes": stat.st_size})
                    truncated = len(rows) == limit
                result = {"entries": rows, "possibly_truncated": truncated}
        elif kind == "process.list":
            import psutil
            rows = []
            for process in psutil.process_iter(["pid", "name", "status"]):
                rows.append(process.info)
                if len(rows) >= 1000:
                    break
            result = {"processes": rows}
        elif kind == "artifact.get":
            from .artifacts import ArtifactStore
            result = ArtifactStore(config).chunk(item["artifact_id"], item.get("offset", 0), item.get("max_bytes", 49152))
        elif kind == "desktop.pause":
            result = control.pause(item["paused"])
        elif kind == "action.cancel":
            result = control.cancel(item["action_id"])
        elif kind == "approval.request":
            result = {"approval_required": True, "action_id": item["action"]["id"], "action_sha256": digest(item["action"]),
                      "approval_method": "local CLI only; no approval is granted by this request"}
        elif kind == "desktop.observe":
            from .desktop import observe
            result = observe(executor, item)
        elif kind == "desktop.act":
            from .desktop import act
            result = act(executor, item)
        elif kind == "file.read":
            from .goals import resolve as resolve_path
            target = resolve_path(config, item["workspace"], item["path"])
            limit = min(config.max_output_bytes, int(item.get("max_bytes", config.max_output_bytes)))
            if not 1 <= limit <= 10_000_000:
                raise ValueError("invalid read limit")
            with target.open("rb") as stream:
                data = stream.read(limit + 1)
            result = {"path": str(target), "text": data[:limit].decode(item.get("encoding", "utf-8"), errors="replace"), "truncated": len(data) > limit}
        elif kind in {"file.write", "file.append", "file.mkdir", "file.delete", "file.copy", "file.move"}:
            from .filesystem import execute as file_execute
            result = file_execute(config, item)
        else:
            result = legacy(action, item)
        if isinstance(result, dict) and result.get("exit_code", 0) != 0:
            raise ControlError("failed" if side_effect == "read_only" else "ambiguous", "process returned non-zero; side effects may already exist")
        result = register_captures(executor, item, result)
        result = safe_output(result, config.max_output_bytes)
        ledger.finish_step(action["id"], path, "succeeded", result)
        return result
    except ControlError as exc:
        if exc.state in {"ambiguous", "cancelled", "blocked", "needs_user"}:
            executor._hardening_halted = exc
        ledger.finish_step(action["id"], path, exc.state, {"error": str(exc)})
        raise
    except Exception as exc:
        state = "failed" if side_effect == "read_only" else "ambiguous"
        message = safe_output({"error": str(exc)}, config.max_output_bytes)
        ledger.finish_step(action["id"], path, state, message)
        failure = ControlError(state, str(exc))
        if state == "ambiguous":
            executor._hardening_halted = failure
        raise failure from exc
    finally:
        executor._hardening_step_path = previous


def register_captures(executor: Any, item: dict, result: Any) -> Any:
    if item["type"] not in {"windows.ui", "browser.playwright"} or not isinstance(result, dict):
        return result
    from pathlib import Path
    from .artifacts import ArtifactStore
    for row in result.get("outputs", []):
        if not isinstance(row, dict) or row.get("op") not in {"capture", "capture_desktop", "screenshot", "pdf"} or not row.get("path"):
            continue
        row["artifact"] = ArtifactStore(executor.config).add_file(Path(row["path"]), metadata={
            "operation": row["op"], "agent_id": executor.config.agent_id,
            **{key: row[key] for key in ("display", "pixel_sha256", "size") if key in row},
        })
    return result


def doctor(config: Any, *, probe_git: bool = False, probe_host: bool = False) -> dict:
    from . import VERSION
    from .processes import run_process
    from .common import load_json
    report = {"agent_id": config.agent_id, "runtime_extension": VERSION, "platform": platform.system(),
              "python": platform.python_version(), "configured_capabilities": sorted(config.capabilities),
              "security_mode": security(config).get("mode", "trusted"), "checked_at": utc_now(),
              "interactive_probe": {"status": "unknown"}, "dependencies": {}, "git": {"status": "not_probed"},
              "permissions": {"physical_input": config.allow_physical_input, "foreground": config.allow_foreground_activation,
                              "visible_launch": config.allow_visible_gui_launch}}
    for name in ("pywinauto", "PIL", "playwright", "cryptography", "psutil"):
        report["dependencies"][name] = importlib.util.find_spec(name) is not None
    heartbeat = config.interactive_spool / "host-heartbeat.json"
    if heartbeat.exists():
        report["interactive_probe"] = {"status": "heartbeat_only", "heartbeat": load_json(heartbeat),
                                       "warning": "a fresh heartbeat is not proof that UI operations complete"}
    if probe_git:
        result = run_process([config.git, "ls-remote", "--heads", config.remote, config.branch], config.repo_path, 10, max_output_bytes=8192)
        report["git"] = {"status": "reachable" if result["exit_code"] == 0 and result["stdout"].strip() else "unavailable", "exit_code": result["exit_code"]}
    report["gui_ready"] = None  # never infer readiness from package installation alone
    if probe_host and os.name == 'nt' and 'windows-ui' in config.capabilities:
        try:
            from agent_runtime.interactive_ipc import InteractiveClient
            response = InteractiveClient(config).request({'type':'windows.ui','desktop':True,'actions':[{'op':'input_desktop'}]}, 3)
            record = response['outputs'][0]
            report['gui_ready'] = record.get('name') == 'Default' and record.get('cursor_accessible') is True
            report['interactive_probe'] = {'status':'responded','input_desktop':record.get('name'),'checked_at':utc_now()}
        except Exception as exc:
            report['gui_ready'] = False
            report['interactive_probe'] = {'status':'unavailable','reason':type(exc).__name__}
    elif probe_host and os.name != 'nt':
        report['interactive_probe'] = {'status':'not_applicable_on_this_platform'}
    return report
