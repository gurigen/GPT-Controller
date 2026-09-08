from __future__ import annotations
from typing import Any
from .common import ControlError
from .validation import READ_BROWSER, READ_UI, PHYSICAL, FOREGROUND


def effect(step: dict) -> str:
    kind = step.get("type", "")
    if kind in {"noop", "agent.info", "agent.doctor", "agent.manifest", "file.read", "file.list", "file.stat", "process.list", "desktop.observe", "desktop.verify", "goal.verify", "artifact.get", "download.wait", "approval.request"}:
        return "read_only"
    if kind == "desktop.checkpoint" and step.get("op", "read") == "read":
        return "read_only"
    if kind == "browser.interactive" and step.get("op") == "status":
        return "read_only"
    if kind == "windows.ui" and "start" not in step and all(op.get("op") in READ_UI for op in step.get("actions", [])):
        return "read_only"
    # A managed browser launch/navigation changes state even when only reading text.
    if kind == "browser.playwright" and step.get("connection") == "cdp" and step.get("reuse_page") and all(op.get("op") in READ_BROWSER for op in step.get("actions", [])):
        return "read_only"
    if kind == "file.mkdir":
        return "idempotent"
    return "non_idempotent"


def permissions(step: dict) -> set[str]:
    kind = step.get("type", "")
    mapping = {
        "powershell.exec": "shell.exec", "process.exec": "shell.exec", "git.exec": "shell.exec",
        "deploy.exec": "shell.exec", "file.read": "filesystem.read", "file.list": "filesystem.read",
        "file.stat": "filesystem.read", "file.write": "filesystem.write", "file.append": "filesystem.write",
        "file.mkdir": "filesystem.write", "file.copy": "filesystem.write", "file.move": "filesystem.write",
        "file.delete": "filesystem.delete", "workspace.git_sync": "workspace.sync", "process.list": "system.read",
        "artifact.get": "artifact.export", "desktop.observe": "ui.observe", "desktop.verify": "filesystem.read",
        "goal.verify": "filesystem.read", "desktop.pause": "control.pause", "action.cancel": "control.cancel",
        "download.wait": "filesystem.read",
    }
    result = {mapping[kind]} if kind in mapping else set()
    if kind == "desktop.pause" and step.get("paused") is False:
        result = {"control.resume"}
    if kind == "browser.interactive":
        result.add("system.read" if step.get("op") == "status" else "browser.launch")
    if kind == "browser.playwright":
        result.add("browser.control")
        for op in step.get("actions", []):
            if op.get("op") == "close_page" and op.get("allow_borrowed_close"):
                result.add("browser.close_user_tab")
            if op.get("op") in {"evaluate", "wait_for_function"}:
                result.add("browser.evaluate")
            if op.get("op") in {"cookies_get", "storage_state", "input_value"}:
                result.add("secrets.read")
    if kind in {"windows.ui", "desktop.act"}:
        result.add("ui.observe" if effect(step) == "read_only" else "ui.input")
        if "start" in step:
            result.add("shell.exec")  # arbitrary GUI command, not a sandboxed app launcher
        for op in step.get("actions", []):
            if op.get("op", "").startswith("clipboard_"):
                result.add("clipboard.read" if op["op"] == "clipboard_get" else "clipboard.write")
    return result


def local_ui_check(config: Any, step: dict) -> None:
    if step.get("type") == "browser.playwright":
        if any(op.get("op") == "bring_to_front" for op in step.get("actions", [])) and not config.allow_foreground_activation:
            raise ControlError("blocked", "browser foreground activation is disabled locally")
        if step.get("connection") == "cdp" and getattr(config, "non_interference", True):
            raise ControlError("blocked", "visible CDP control requires local non_interference=false")
        if step.get("headless") is False and not config.allow_visible_gui_launch:
            raise ControlError("blocked", "visible browser launch is disabled locally")
        return
    if step.get("type") not in {"windows.ui", "desktop.act"}:
        return
    if "start" in step and not config.allow_visible_gui_launch:
        raise ControlError("blocked", "visible application launch is disabled locally")
    for op in step.get("actions", []):
        name = op.get("op")
        if name in PHYSICAL and not config.allow_physical_input:
            raise ControlError("blocked", f"{name}: physical input disabled locally")
        if name in FOREGROUND and not config.allow_foreground_activation:
            raise ControlError("blocked", f"{name}: foreground activation disabled locally")
        if name == "clipboard_set" and getattr(config, "non_interference", True):
            raise ControlError("blocked", "clipboard write disabled in non-interference mode")


def security(config: Any) -> dict:
    return dict(getattr(config, "security", {}) or {})


def policy_decision(config: Any, permission: str) -> str:
    settings = security(config)
    rules = settings.get("rules", {})
    if permission in rules:
        return rules[permission]
    if permission in {"control.resume", "artifact.export", "secrets.read", "filesystem.delete", "browser.close_user_tab"}:
        return "ask"
    if settings.get("mode", "trusted") == "restricted":
        if permission in {"shell.exec", "workspace.sync", "browser.evaluate"}:
            return "deny"
        if permission in {"filesystem.delete", "browser.launch", "ui.input", "clipboard.write"}:
            return "ask"
    return "allow"


def preflight(config: Any, action: dict, ledger, payload_hash: str) -> None:
    permissions_needed = set()
    target = action.get("target", {})
    if target.get("mode") == "agent" and target.get("agent") != config.agent_id:
        raise ControlError("blocked", "Action belongs to a different agent")
    if action.get("target_agent") not in (None, "*", config.agent_id):
        raise ControlError("blocked", "legacy target_agent belongs to another agent")
    if not set(action.get("requires", [])).issubset(config.capabilities):
        raise ControlError("blocked", "required capability is absent locally")
    def visit(steps):
        for step in steps:
            kind = step.get("type")
            if kind in {"windows.ui", "desktop.observe", "desktop.act"} and "windows-ui" not in config.capabilities:
                raise ControlError("blocked", "windows-ui capability is absent locally")
            if kind in {"browser.playwright", "browser.interactive"} and "browser" not in config.capabilities:
                raise ControlError("blocked", "browser capability is absent locally")
            local_ui_check(config, step)
            permissions_needed.update(permissions(step))
            if step.get("type") == "desktop.loop":
                visit(step["steps"])
    visit(action["steps"])
    if action.get("goal"):
        permissions_needed.add("filesystem.read")
    asks = []
    for permission in sorted(permissions_needed):
        decision = policy_decision(config, permission)
        if decision == "deny":
            raise ControlError("blocked", f"local policy denies {permission}")
        if decision == "ask":
            asks.append(permission)
    if asks and not ledger.consume_approval(action["id"], payload_hash):
        raise ControlError("needs_user", "local approval required for: " + ", ".join(asks))


def validate_security(raw: dict) -> None:
    if not isinstance(raw, dict) or set(raw) - {"mode", "rules", "max_action_age_seconds", "artifact_max_bytes", "artifact_total_bytes", "artifact_ttl_seconds", "max_result_bytes", "host_timeout_seconds", "agent_publish_seconds"}:
        raise ValueError("invalid security configuration")
    if raw.get("mode", "trusted") not in {"trusted", "restricted"}:
        raise ValueError("security.mode must be trusted or restricted")
    if not isinstance(raw.get("rules", {}), dict) or any(value not in {"allow", "ask", "deny"} for value in raw.get("rules", {}).values()):
        raise ValueError("security.rules must map permissions to allow/ask/deny")
    from .common import bounded_number
    for key, low, high in (("max_action_age_seconds", 1, 86400), ("artifact_max_bytes", 1024, 100_000_000), ("artifact_total_bytes", 1024, 1_000_000_000), ("artifact_ttl_seconds", 1, 604800), ("max_result_bytes", 1024, 10_000_000), ("host_timeout_seconds", 1, 86400), ("agent_publish_seconds", 60, 86400)):
        if key in raw:
            bounded_number(raw[key], key, low, high, True)
