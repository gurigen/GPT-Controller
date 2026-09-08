from __future__ import annotations
import time
from typing import Any
from .common import ControlError


def wrapper(value):
    return value.wrapper_object() if hasattr(value, "wrapper_object") else value


def looks_like_file_dialog(window: Any) -> bool:
    try:
        if not window.is_visible() or not window.is_enabled():
            return False
        ids = {str(getattr(item.element_info, "automation_id", "")) for item in window.descendants()}
        # #32770 alone also includes unrelated confirmation/credential dialogs.
        return "FileNameControlHost" in ids or (window.class_name() == "#32770" and "1" in ids and "1148" in ids)
    except Exception:
        return False


def discover_dialog(desktop: Any, current_window: Any, action: dict) -> Any:
    current = wrapper(current_window) if current_window is not None else None
    pid = action.get("process_id") or (current.process_id() if current else None)
    if type(pid) is not int or pid <= 0:
        raise ControlError("blocked", "dialog discovery requires an exact process_id or selected parent window")
    kind = action.get("kind", "file")
    if kind not in {"file", "any"}:
        raise ValueError("invalid dialog kind")
    deadline = time.monotonic() + min(120, max(0.1, float(action.get("timeout_seconds", 30))))
    while time.monotonic() < deadline:
        candidates = []
        for candidate in desktop.windows():
            try:
                if candidate.process_id() != pid or not candidate.is_visible() or not candidate.is_enabled():
                    continue
                if current is not None and candidate.handle == current.handle:
                    continue
                if kind == "file" and not looks_like_file_dialog(candidate):
                    continue
                if action.get("title") and candidate.window_text() != action["title"]:
                    continue
                if action.get("title_contains") and action["title_contains"].casefold() not in candidate.window_text().casefold():
                    continue
                if action.get("class_names") and candidate.class_name() not in action["class_names"]:
                    continue
                candidates.append(candidate)
            except Exception:
                continue
        if len(candidates) > 1:
            raise ControlError("blocked", "multiple matching dialogs; an exact target is required")
        if candidates:
            return desktop.window(handle=int(candidates[0].handle))
        time.sleep(0.05)
    raise TimeoutError("no uniquely identified dialog in the selected process")


def explorer_item(target: Any, name: str) -> Any:
    candidates = []
    for item in wrapper(target).descendants():
        try:
            if getattr(item.element_info, "control_type", "") not in {"ListItem", "DataItem"}:
                continue
            if item.is_visible() and item.is_enabled() and str(item.window_text()).casefold() == name.casefold():
                candidates.append(item)
        except Exception:
            continue
    if len(candidates) != 1:
        raise ControlError("blocked", "Explorer requires exactly one visible item with the full name")
    return candidates[0]


def assert_single_selection(target: Any, selected: Any) -> None:
    chosen = []
    for item in wrapper(target).descendants():
        try:
            if getattr(item.element_info, "control_type", "") in {"ListItem", "DataItem"} and item.is_selected():
                chosen.append(item)
        except Exception:
            raise ControlError("blocked", "cannot verify Explorer selection")
    if len(chosen) != 1 or chosen[0].element_info != selected.element_info:
        raise ControlError("blocked", "Explorer selection is not uniquely verified")


def accept_dialog(target: Any, action: dict) -> dict:
    dialog = wrapper(target)
    ids = {str(x) for x in action.get("button_automation_ids", ["1"])}
    if not looks_like_file_dialog(dialog):
        raise ControlError("blocked", "target is not a verified file dialog")
    candidates = [button for button in dialog.descendants(control_type="Button")
                  if str(getattr(button.element_info, "automation_id", "")) in ids and button.is_visible() and button.is_enabled()]
    if len(candidates) != 1:
        raise ControlError("blocked", "file dialog accept button is not unique")
    button = candidates[0]
    try:
        button.invoke()
    except Exception as exc:
        raise ControlError("ambiguous", "button invocation result unknown; click/Enter fallback was NOT attempted") from exc
    return {"op": "file_dialog_accept", "button": button.window_text(), "fallback_enter": False}
