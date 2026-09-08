from __future__ import annotations

import math
from datetime import datetime, timezone
from typing import Any

from .common import bounded_number, identifier, step_context, timestamp

BROWSER_OPS = set('goto click dblclick fill press check uncheck select_option hover wait_for wait_for_url wait_for_load_state reload wait_for_text wait_for_function bring_to_front sleep text content attribute input_value count screenshot evaluate upload download click_popup new_page pages switch_page_matching switch_page close_page cookies_get cookies_add cookies_clear storage_state pdf url title snapshot'.split())
UI_OPS = set('discover_dialog file_dialog_path file_dialog_filename file_dialog_accept file_dialog_cancel explorer_navigate explorer_select explorer_open explorer_new_folder explorer_rename explorer_delete explorer_copy explorer_cut explorer_paste list_windows cursor_position input_desktop active_window dump_tree wait_ready wait_visible invoke set_value set_text get_text exists is_visible is_enabled get_rect summary select toggle expand collapse close focus set_focus maximize minimize restore move_resize click click_input type_keys move_mouse click_at double_click_at right_click_at scroll drag hotkey type_text clipboard_get clipboard_set sleep capture capture_desktop'.split())
LEGACY_TYPES = set("noop agent.info powershell.exec process.exec file.read file.write file.append file.mkdir file.delete file.copy file.move git.exec workspace.git_sync browser.playwright browser.interactive windows.ui download.wait desktop.checkpoint desktop.loop deploy.exec".split())
NEW_TYPES = set('agent.doctor agent.manifest file.list file.stat process.list artifact.get desktop.observe desktop.act desktop.verify desktop.pause action.cancel approval.request goal.verify'.split())
READ_UI = set('list_windows cursor_position input_desktop active_window dump_tree wait_ready wait_visible get_text exists is_visible is_enabled get_rect summary clipboard_get sleep capture capture_desktop discover_dialog'.split())
READ_BROWSER = set('wait_for wait_for_url wait_for_load_state wait_for_text sleep text content attribute input_value count screenshot pages url title snapshot cookies_get storage_state'.split())
PHYSICAL = set('click click_input type_keys move_mouse click_at double_click_at right_click_at scroll drag hotkey type_text file_dialog_path file_dialog_filename file_dialog_accept file_dialog_cancel explorer_navigate explorer_select explorer_open explorer_new_folder explorer_rename explorer_delete explorer_copy explorer_cut explorer_paste'.split())
FOREGROUND = set('focus set_focus maximize minimize restore move_resize hotkey type_text file_dialog_path file_dialog_filename file_dialog_accept file_dialog_cancel explorer_navigate explorer_select explorer_open explorer_new_folder explorer_rename explorer_delete explorer_copy explorer_cut explorer_paste'.split())
BOOL_FIELDS = set('permanent recursive allow_absolute_paths resume_from_checkpoint continue_on_error require_until resume reuse_completed allow_dirty allow_branch_mismatch non_interference allow_physical_input allow_foreground_activation allow_visible_gui_launch headless headless_only auto_recover reuse_page full_page desktop restore_clipboard allow_existing overwrite allow_partial clipboard_restore verify_unchanged allow_borrowed_close paused'.split())


# These are the extension's contract. Legacy envelopes retain forward-compatible
# metadata, but executable op names, value types and required inputs are validated.
def finite_tree(value: Any, depth: int = 0, budget: list[int] | None = None) -> None:
    if budget is None:
        budget = [50_000]
    budget[0] -= 1
    if budget[0] < 0 or depth > 30:
        raise ValueError("payload exceeds node/depth budget")
    if isinstance(value, float) and not math.isfinite(value):
        raise ValueError("non-finite number")
    if isinstance(value, str) and len(value.encode('utf-8')) > 2_000_000:
        raise ValueError("string exceeds payload budget")
    if isinstance(value, dict):
        for key, item in value.items():
            if not isinstance(key, str):
                raise ValueError("JSON keys must be strings")
            if key.startswith("__gpt_"):
                raise ValueError("reserved internal field")
            if key in BOOL_FIELDS and type(item) is not bool:
                raise ValueError(f"{key} must be boolean (JSON true/false)")
            finite_tree(item, depth + 1, budget)
    elif isinstance(value, list):
        for item in value:
            finite_tree(item, depth + 1, budget)
    elif value is not None and type(value) not in (str, bool, int, float):
        raise ValueError("payload must contain JSON values only")


def required(obj: dict, key: str, kind= str) -> None:
    if not isinstance(obj.get(key), kind) or (kind is str and not obj[key]):
        raise ValueError(f"{key} is required and must be a non-empty {kind.__name__}")


def exact_target(action: dict) -> None:
    target = action.get("target")
    if not isinstance(target, dict) or target.get("mode") != "agent":
        raise ValueError("operation requires exact target.mode='agent'")
    identifier(target.get("agent"), "target.agent")
    if "agent_id" in target:
        raise ValueError("q-agent-v4 uses target.agent, not target.agent_id")


def condition_shape(condition: Any, depth: int = 0) -> None:
    if depth > 12 or not isinstance(condition, dict) or not condition:
        raise ValueError("invalid condition")
    boolean = set(condition) & {"all", "any", "not"}
    if boolean:
        if len(boolean) != 1 or len(condition) != 1:
            raise ValueError("boolean condition must have one operator")
        key = next(iter(boolean))
        items = condition[key]
        if key == "not":
            condition_shape(items, depth + 1)
        else:
            if not isinstance(items, list) or not 1 <= len(items) <= 100:
                raise ValueError("boolean conditions require a non-empty bounded list")
            for item in items:
                condition_shape(item, depth + 1)
        return
    if set(condition) - {"source", "path", "equals", "not_equals", "contains", "truthy", "exists", "missing"}:
        raise ValueError("unknown condition operator (regex conditions are not enabled)")
    ops = set(condition) & {"equals", "not_equals", "contains", "truthy", "exists"}
    if len(ops) != 1:
        raise ValueError("condition requires exactly one comparison")
    if "path" in condition and (not isinstance(condition["path"], str) or len(condition["path"]) > 512):
        raise ValueError("condition path must be a bounded string")
    source = condition.get("source", "last")
    if not (type(source) is int and 0 <= source <= 999 or source in ("last", "outputs")):
        raise ValueError("invalid condition source")
    for key in ("truthy", "exists", "missing"):
        if key in condition and type(condition[key]) is not bool:
            raise ValueError(f"condition {key} must be boolean")


def goal_shape(goal: Any) -> None:
    if not isinstance(goal, dict) or set(goal) - {"description", "conditions"}:
        raise ValueError("goal must contain description and conditions only")
    required(goal, "description")
    conditions = goal.get("conditions")
    if not isinstance(conditions, list) or not 1 <= len(conditions) <= 100:
        raise ValueError("goal requires 1..100 verification conditions")
    for item in conditions:
        if not isinstance(item, dict):
            raise ValueError("goal condition must be an object")
        kind = item.get("type")
        fields = {
            "file.exists": {"type", "workspace", "path", "exists"},
            "file.sha256": {"type", "workspace", "path", "sha256"},
            "file.text_contains": {"type", "workspace", "path", "text", "encoding", "max_bytes"},
            "csv.columns": {"type", "workspace", "path", "columns", "encoding"},
            "output.matches": {"type", "condition"},
        }
        if kind not in fields or set(item) - fields[kind]:
            raise ValueError("unknown goal condition or field")
        if kind == "output.matches":
            condition_shape(item.get("condition"))
        else:
            required(item, "path")
            required(item, "workspace")
        if kind == "file.exists" and "exists" in item and type(item["exists"]) is not bool:
            raise ValueError("file.exists expected value must be boolean")
        if kind == "file.sha256":
            import re
            if not isinstance(item.get("sha256"), str) or not re.fullmatch("[a-f0-9]{64}", item["sha256"]):
                raise ValueError("invalid expected SHA256")
        if kind == "file.text_contains":
            required(item, "text")
        if kind == "csv.columns":
            columns = item.get("columns")
            if not isinstance(columns, list) or not columns or not all(isinstance(x, str) and x for x in columns):
                raise ValueError("csv.columns requires non-empty column names")


def validate_operation(op: dict, browser: bool) -> None:
    if not isinstance(op, dict) or op.get("op") not in (BROWSER_OPS if browser else UI_OPS):
        raise ValueError("unknown browser/UI operation")
    from .operations import check_arguments
    check_arguments(op, browser)
    name = op["op"]
    for key, minimum, maximum in (("timeout_ms", 1, 300_000), ("timeout_seconds", 0, 86400), ("settle_seconds", 0, 30), ("after_seconds", 0, 30), ("seconds", 0, 60), ("pause", 0, 5)):
        if key in op:
            bounded_number(op[key], key, minimum, maximum)
    if browser:
        selectors = set('click dblclick fill press check uncheck select_option hover wait_for text attribute input_value count upload download click_popup'.split())
        if name in selectors:
            required(op, "selector")
        keys = {"goto": "url", "wait_for_url": "url", "press": "key", "attribute": "name", "evaluate": "expression", "wait_for_function": "expression", "wait_for_text": "text", "screenshot": "path", "pdf": "path", "download": "save_as"}
        if name in keys:
            required(op, keys[name])
        if name == "switch_page":
            bounded_number(op.get("index"), "index", 0, 10000, True)
        if name == "switch_page_matching":
            match = op.get("match")
            if not isinstance(match, dict) or not match or set(match) - {"url", "url_contains", "title", "title_contains"}:
                raise ValueError("invalid page match")
    else:
        if name == "type_keys" and not isinstance(op.get("keys"), str):
            raise ValueError("type_keys requires a string keys value")
        keys = {"type_keys": "keys", "hotkey": "keys", "file_dialog_path": "path", "explorer_navigate": "path", "file_dialog_filename": "filename", "explorer_new_folder": "name", "explorer_select": "name", "explorer_open": "name", "explorer_rename": "name", "explorer_delete": "name", "explorer_copy": "name", "explorer_cut": "name"}
        if name in keys:
            required(op, keys[name])
        if name == "explorer_rename":
            required(op, "new_name")
        if name in {"type_text", "clipboard_set", "set_value", "set_text"} and not isinstance(op.get("text"), str):
            raise ValueError("text must be a string")
        points = ["coords"] if name in {"click_at", "double_click_at", "right_click_at"} else ["start", "end"] if name == "drag" else []
        if "coords" in op and "coords" not in points:
            points.append("coords")
        for key in points:
            point = op.get(key)
            if not isinstance(point, list) or len(point) != 2:
                raise ValueError(f"{name} requires {key} coordinates [x,y]")
            for val in point:
                bounded_number(val, key, -100000, 100000, True)
        if name == "move_resize":
            for key in ("x", "y", "width", "height"):
                bounded_number(op.get(key), key, 1 if key in {"width", "height"} else -100000, 100000, True)


def validate_action_extra(action: dict) -> None:
    if not isinstance(action, dict):
        raise ValueError("Action must be an object")
    finite_tree(action)
    identifier(action.get("id"))
    if action.get("protocol") != "q-agent-v4":
        raise ValueError("protocol must be q-agent-v4")
    for key in ("created_at", "expires_at", "not_before"):
        if key in action:
            timestamp(action[key])
    if "created_at" in action and "expires_at" in action and timestamp(action["expires_at"]) <= timestamp(action["created_at"]):
        raise ValueError("expires_at must follow created_at")
    if "not_before" in action and "expires_at" in action and timestamp(action["expires_at"]) <= timestamp(action["not_before"]):
        raise ValueError("expires_at must follow not_before")
    if "timeout_seconds" in action:
        bounded_number(action["timeout_seconds"], "timeout_seconds", 1, 86400, True)
    if "goal" in action:
        goal_shape(action["goal"])
    from .dependencies import validate as validate_dependencies
    validate_dependencies(action.get("depends_on", []), action["id"])
    steps = action.get("steps")
    if not isinstance(steps, list) or not 1 <= len(steps) <= 500:
        raise ValueError("Action requires 1..500 steps")
    paths = set()
    if "target" in action and not isinstance(action["target"], dict):
        raise ValueError("target must be an object")
    def visit(items: list, parent: dict, in_loop=False):
        for index, raw in enumerate(items):
            if not isinstance(raw, dict):
                raise ValueError("step must be an object")
            step = step_context(action, parent, raw)
            if "id" in step:
                identifier(step["id"], "step.id")
                if step["id"] in paths:
                    raise ValueError("duplicate step id")
                paths.add(step["id"])
            if "timeout_seconds" in step:
                bounded_number(step["timeout_seconds"], "timeout_seconds", 1, 86400, True)
            kind = step.get("type")
            if kind not in LEGACY_TYPES | NEW_TYPES:
                raise ValueError("unknown step type")
            if kind == "desktop.loop":
                if in_loop:
                    raise ValueError("nested desktop.loop is not supported")
                identifier(step.get("session"), "session")
                children = step.get("steps")
                if not isinstance(children, list) or not 1 <= len(children) <= 500:
                    raise ValueError("loop requires bounded non-empty steps")
                bounded_number(step.get("max_cycles", 1), "max_cycles", 1, 1000, True)
                if "until" in step:
                    condition_shape(step["until"])
                exact_target(action)
                visit(children, step, True)
            elif kind in {"browser.playwright", "windows.ui", "desktop.act"}:
                ops = step.get("actions")
                if not isinstance(ops, list) or not 1 <= len(ops) <= 500:
                    raise ValueError("actions must contain 1..500 operations")
                for op in ops:
                    validate_operation(op, kind == "browser.playwright")
                if kind == "desktop.act" or step.get("connection") == "cdp" or any(op["op"] == "bring_to_front" for op in ops):
                    exact_target(action)
                if kind == "desktop.act":
                    identifier(step.get("observation_id"), "observation_id")
            elif kind == "browser.interactive":
                if step.get("op") != "status":
                    exact_target(action)
            elif kind in NEW_TYPES:
                if kind != "approval.request":
                    exact_target(action)
                if kind in {"file.list", "file.stat"}:
                    required(step, "workspace")
                    required(step, "path")
                if kind == "artifact.get":
                    identifier(step.get("artifact_id"), "artifact_id")
                    bounded_number(step.get("offset", 0), "offset", 0, 100_000_000, True)
                    bounded_number(step.get("max_bytes", 49152), "max_bytes", 1, 49152, True)
                if kind == "action.cancel":
                    identifier(step.get("action_id"), "action_id")
                if kind == "desktop.pause" and type(step.get("paused")) is not bool:
                    raise ValueError("paused must be boolean")
                if kind in {"goal.verify", "desktop.verify"}:
                    goal_shape(step.get("goal"))
                if kind == "approval.request":
                    required(step, "action", dict)
                    if step["action"].get("steps") and any(s.get("type") == "approval.request" for s in step["action"]["steps"]):
                        raise ValueError("nested approval requests are not supported")
                    validate_action_extra(step["action"])
            for key in ("run_if", "skip_if"):
                if key in step:
                    condition_shape(step[key])
            if "retry_attempts" in step:
                bounded_number(step["retry_attempts"], "retry_attempts", 1, 20, True)
    visit(steps, action)
