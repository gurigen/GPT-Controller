from __future__ import annotations

import time
from typing import Any
from .common import ControlError, atomic_json, digest, identifier, load_json, state_root, step_context
from .control import Control
from .goals import match
from .output import safe_output, contains_truncation
from .policy import effect, security


def desktop_loop(executor: Any, action: dict, step: dict, timeout: int) -> dict:
    config = executor.config
    session = identifier(step["session"], "session")
    children = [step_context(action, step, x) for x in step["steps"]]
    fingerprint = digest({"agent": config.agent_id, "session": session, "steps": children,
                          "workspaces": {k: str(v) for k, v in config.workspaces.items()},
                          "until": step.get("until"), "require_until": step.get("require_until", True),
                          "max_cycles": step.get("max_cycles", 1), "security": security(config),
                          "interaction": {key: getattr(config, key, None) for key in ("non_interference", "allow_physical_input", "allow_foreground_activation", "allow_visible_gui_launch", "allow_absolute_paths")}})
    path = state_root(config) / "workflows" / f"{session}.json"
    checkpoint = load_json(path) if step.get("resume", True) and path.exists() else None
    if checkpoint:
        if checkpoint.get("fingerprint") != fingerprint:
            raise ControlError("blocked", "checkpoint does not match this workflow, workspace or policy")
        if checkpoint.get("action_id") != action["id"] and step.get("resume_from_action") != checkpoint.get("action_id"):
            raise ControlError("blocked", "cross-Action resume requires an explicit resume_from_action")
        in_progress = checkpoint.get("in_progress")
        if in_progress and in_progress.get("effect") != "read_only":
            raise ControlError("ambiguous", "checkpoint records an unconfirmed side effect; no replay")
        if checkpoint.get("status") == "ambiguous":
            raise ControlError("ambiguous", "workflow requires state inspection, not automatic retry")
        if checkpoint.get("status") == "completed" and step.get("reuse_completed", True):
            if step.get("until") and not match(checkpoint.get("outputs", []), step["until"]):
                raise ControlError("failed", "stored checkpoint does not satisfy goal")
            return {"session": session, "completed": True, "resumed": True,
                    "reason": "confirmed_checkpoint", "last_outputs": checkpoint.get("outputs", [])}
        if checkpoint.get("status") in {"failed", "exhausted"}:
            raise ControlError("failed", "failed/exhausted checkpoint is not a completed workflow; start a NEW session")
    cycle = checkpoint.get("cycle", 0) if checkpoint else 0
    next_step = checkpoint.get("next_step", 0) if checkpoint else 0
    outputs = checkpoint.get("outputs", []) if checkpoint else []
    if not isinstance(outputs, list) or contains_truncation(outputs):
        raise ControlError("blocked", "checkpoint evidence was truncated; cannot safely resume")
    count = 0
    limit = step.get("max_cycles", 1)
    control = Control(config)
    deadline = time.monotonic() + timeout
    base = {"session": session, "fingerprint": fingerprint, "action_id": action["id"], "agent_id": config.agent_id}
    def save(status: str, *, in_progress=None):
        bounded = safe_output(outputs, config.max_output_bytes)
        if not isinstance(bounded, list) or contains_truncation(bounded):
            status = "ambiguous"
            atomic_json(path, {**base, "status": status, "cycle": cycle, "next_step": next_step, "outputs": [], "in_progress": in_progress, "reason": "evidence budget exceeded"})
            raise ControlError("ambiguous", "workflow evidence exceeded budget; explicit inspection required")
        atomic_json(path, {**base, "status": status, "cycle": cycle, "next_step": next_step,
                           "outputs": safe_output(outputs, config.max_output_bytes), "in_progress": in_progress})
    def check():
        control.check(action, deadline=deadline)
    while cycle < limit:
        check()
        while next_step < len(children):
            check()
            child = dict(children[next_step])
            child["timeout_seconds"] = max(1, min(child.get("timeout_seconds", timeout), int(deadline - time.monotonic()) + 1))
            if (child.get("run_if") and not match(outputs, child["run_if"])) or (child.get("skip_if") and match(outputs, child["skip_if"])):
                outputs.append({"index": next_step, "type": child["type"], "status": "skipped"})
                next_step += 1
                save("running")
                continue
            side_effect = effect(child)
            attempts = min(20, child.get("retry_attempts", step.get("retry_attempts", 3))) if side_effect == "read_only" else 1
            parent_path = getattr(executor, "_hardening_step_path", "loop")
            error = None
            for attempt in range(attempts):
                check()
                save("running", in_progress={"step": next_step, "effect": side_effect, "attempt": attempt + 1})
                try:
                    executor._hardening_nested_path = f"{parent_path}/{cycle}/{next_step}"
                    result = executor._step(action, child)
                    if isinstance(result, dict) and result.get("exit_code", 0) != 0:
                        raise ControlError("failed" if side_effect == "read_only" else "ambiguous", "nested process returned non-zero")
                    error = None
                    break
                except ControlError as exc:
                    error = exc
                    if exc.state in {"ambiguous", "cancelled", "blocked", "needs_user"}:
                        break
                except Exception as exc:
                    error = ControlError("failed" if side_effect == "read_only" else "ambiguous", str(exc))
                finally:
                    executor._hardening_nested_path = None
                if attempt + 1 < attempts:
                    remaining = max(0, deadline - time.monotonic())
                    time.sleep(min(child.get("retry_delay_seconds", step.get("retry_delay_seconds", 0.5)), remaining, 30))
            count += 1
            if error:
                save(error.state)
                # continue_on_error does not override ambiguous or cancelled execution.
                if child.get("continue_on_error") and error.state == "failed":
                    outputs.append({"index": next_step, "type": child["type"], "status": "failed", "error": str(error)})
                    next_step += 1
                    save("running")
                    continue
                raise error
            outputs.append({"index": next_step, "type": child["type"], "status": "succeeded", "result": result})
            next_step += 1
            save("running")
        if step.get("until") and match(outputs, step["until"]):
            save("completed")
            return {"session": session, "completed": True, "reason": "until_matched", "last_outputs": outputs, "executed_steps": count}
        cycle += 1
        if cycle < limit:
            outputs = []
            next_step = 0
            save("running")
    if step.get("until"):
        save("exhausted")
        raise ControlError("failed", "workflow exhausted without satisfying until; not completed")
    if any(x.get("status") == "failed" for x in outputs):
        save("failed")
        raise ControlError("failed", "workflow contains failed steps")
    save("completed")
    return {"session": session, "completed": True, "reason": "steps_completed", "last_outputs": outputs, "executed_steps": count}
