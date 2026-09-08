from __future__ import annotations

import argparse
import ctypes
import logging
import re
import subprocess
import sys
import time
import traceback
from pathlib import Path
from typing import Any

from .config import Config
from .util import atomic_write_json, configure_file_logging, load_json, utc_now

log = logging.getLogger("q-agent-v4.interactive")


def _target(window: Any, spec: dict[str, Any] | None) -> Any:
    if window is None:
        raise RuntimeError("this operation requires a selected window")
    return window.child_window(**spec) if spec else window


def _require_physical_input(config: Config, op: str) -> None:
    if not config.allow_physical_input:
        raise RuntimeError(f"{op} requires interaction_policy.allow_physical_input=true on this agent")


def _require_foreground(config: Config, op: str) -> None:
    if not config.allow_foreground_activation:
        raise RuntimeError(f"{op} requires interaction_policy.allow_foreground_activation=true on this agent")


def _input_desktop_name() -> str | None:
    # Return the desktop currently receiving physical input (for example Default or Screen-saver).
    try:
        from ctypes import wintypes

        user32 = ctypes.WinDLL("user32", use_last_error=True)
        user32.OpenInputDesktop.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
        user32.OpenInputDesktop.restype = wintypes.HANDLE
        user32.GetUserObjectInformationW.argtypes = [
            wintypes.HANDLE, ctypes.c_int, wintypes.LPVOID, wintypes.DWORD,
            ctypes.POINTER(wintypes.DWORD),
        ]
        user32.GetUserObjectInformationW.restype = wintypes.BOOL
        user32.CloseDesktop.argtypes = [wintypes.HANDLE]
        user32.CloseDesktop.restype = wintypes.BOOL

        handle = user32.OpenInputDesktop(0, False, 0x0001)
        if not handle:
            return None
        try:
            buffer = ctypes.create_unicode_buffer(256)
            needed = wintypes.DWORD()
            ok = user32.GetUserObjectInformationW(
                handle, 2, buffer, ctypes.sizeof(buffer), ctypes.byref(needed)
            )
            return buffer.value if ok else None
        finally:
            user32.CloseDesktop(handle)
    except Exception:
        return None


def _cursor_accessible() -> bool:
    # Input desktop may report Default slightly before this long-lived host regains User32 access.
    try:
        from ctypes import wintypes

        user32 = ctypes.WinDLL("user32", use_last_error=True)
        user32.GetCursorPos.argtypes = [ctypes.POINTER(wintypes.POINT)]
        user32.GetCursorPos.restype = wintypes.BOOL
        point = wintypes.POINT()
        return bool(user32.GetCursorPos(ctypes.byref(point)))
    except Exception:
        return False


_WAKE_INPUT_DESKTOP_CODE = (
    "import ctypes;"
    "from ctypes import wintypes as w;"
    "u=ctypes.WinDLL('user32',use_last_error=True);"
    "u.OpenInputDesktop.argtypes=[w.DWORD,w.BOOL,w.DWORD];"
    "u.OpenInputDesktop.restype=w.HANDLE;"
    "u.SetThreadDesktop.argtypes=[w.HANDLE];"
    "u.SetThreadDesktop.restype=w.BOOL;"
    "h=u.OpenInputDesktop(0,False,0x01ff);"
    "assert h,ctypes.get_last_error();"
    "assert u.SetThreadDesktop(h),ctypes.get_last_error();"
    "u.mouse_event(1,12,7,0,0);"
    "u.keybd_event(0x10,0,0,0);"
    "u.keybd_event(0x10,0,2,0)"
)


def _ensure_default_input_desktop(config: Config, op: str) -> str:
    current = _input_desktop_name()
    if current != "Default" or not _cursor_accessible():
        from .hardening.common import ControlError
        raise ControlError("needs_user", "unlock/activate the Windows session manually; no lock or UAC bypass")
    return current


_INTRUSIVE_UI_OPS = {
    "focus", "set_focus", "maximize", "minimize", "restore", "move_resize",
    "click", "click_input", "type_keys", "move_mouse", "click_at",
    "double_click_at", "right_click_at", "scroll", "drag", "hotkey", "type_text",
    "file_dialog_path", "file_dialog_filename", "file_dialog_accept", "file_dialog_cancel",
    "explorer_navigate", "explorer_select", "explorer_open", "explorer_new_folder",
    "explorer_rename", "explorer_delete", "explorer_copy", "explorer_cut", "explorer_paste",
}


def _window_summary(wrapper: Any) -> dict[str, Any]:
    out: dict[str, Any] = {}
    for name, getter in (
        ("title", lambda: wrapper.window_text()),
        ("handle", lambda: int(wrapper.handle)),
        ("process_id", lambda: int(wrapper.process_id())),
        ("class_name", lambda: wrapper.class_name()),
        ("control_type", lambda: getattr(wrapper.element_info, "control_type", None)),
        ("visible", lambda: bool(wrapper.is_visible())),
        ("enabled", lambda: bool(wrapper.is_enabled())),
    ):
        try:
            out[name] = getter()
        except Exception:
            out[name] = None
    try:
        rect = wrapper.rectangle()
        out["rect"] = [int(rect.left), int(rect.top), int(rect.right), int(rect.bottom)]
    except Exception:
        out["rect"] = None
    return out


def _tree(wrapper: Any, max_depth: int, max_nodes: int) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []

    def visit(node: Any, depth: int) -> None:
        if len(rows) >= max_nodes or depth > max_depth:
            return
        row = _window_summary(node)
        row["depth"] = depth
        try:
            row["automation_id"] = getattr(node.element_info, "automation_id", None)
            row["name"] = getattr(node.element_info, "name", None)
        except Exception:
            row["automation_id"] = None
            row["name"] = None
        rows.append(row)
        if depth == max_depth:
            return
        try:
            children = node.children()
        except Exception:
            return
        for child in children:
            if len(rows) >= max_nodes:
                break
            visit(child, depth + 1)

    visit(wrapper, 0)
    return rows


def _coords(action: dict[str, Any], key: str = "coords") -> tuple[int, int]:
    value = action.get(key)
    if not isinstance(value, (list, tuple)) or len(value) != 2:
        raise ValueError(f"{key} must be [x, y]")
    return int(value[0]), int(value[1])


def _clipboard_get_text() -> str | None:
    try:
        import win32clipboard
    except ImportError as exc:
        raise RuntimeError("clipboard support requires pywin32") from exc
    win32clipboard.OpenClipboard()
    try:
        if not win32clipboard.IsClipboardFormatAvailable(win32clipboard.CF_UNICODETEXT):
            return None
        return str(win32clipboard.GetClipboardData(win32clipboard.CF_UNICODETEXT))
    finally:
        win32clipboard.CloseClipboard()


def _clipboard_set_text(text: str) -> None:
    try:
        import win32clipboard
    except ImportError as exc:
        raise RuntimeError("clipboard support requires pywin32") from exc
    win32clipboard.OpenClipboard()
    try:
        win32clipboard.EmptyClipboard()
        win32clipboard.SetClipboardText(text, win32clipboard.CF_UNICODETEXT)
    finally:
        win32clipboard.CloseClipboard()


def _paste_unicode(keyboard: Any, text: str) -> None:
    from .hardening.desktop import send_unicode
    from .hardening.host import check_input_continuation
    send_unicode(text, check=check_input_continuation)


def _wrapper(target: Any) -> Any:
    try:
        return target.wrapper_object()
    except Exception:
        return target


def _best_dialog_edit(target: Any, automation_ids: list[str] | None = None) -> Any:
    wrapper = _wrapper(target)
    preferred = set(automation_ids or ["1001", "1148"])
    try:
        if str(getattr(wrapper.element_info, "control_type", "")) == "Edit" and wrapper.is_visible() and wrapper.is_enabled():
            return wrapper
    except Exception:
        pass
    try:
        edits = list(wrapper.descendants(control_type="Edit"))
    except Exception:
        edits = []
    visible = []
    for edit in edits:
        try:
            if edit.is_visible() and edit.is_enabled():
                visible.append(edit)
        except Exception:
            continue
    for edit in visible:
        try:
            if str(getattr(edit.element_info, "automation_id", "")) in preferred:
                return edit
        except Exception:
            pass
    hints = ("file name", "filename", "ファイル名", "名前")
    for edit in visible:
        try:
            label = str(getattr(edit.element_info, "name", "") or edit.window_text() or "").casefold()
            if any(hint in label for hint in hints):
                return edit
        except Exception:
            pass
    if visible:
        return visible[-1]
    raise RuntimeError("no visible enabled Edit control found in file dialog")


def _looks_like_file_dialog(wrapper: Any) -> bool:
    from .hardening.selectors import looks_like_file_dialog
    return looks_like_file_dialog(wrapper)


def _win32_dialog_handles() -> list[dict[str, Any]]:
    try:
        from ctypes import wintypes
        user32 = ctypes.WinDLL("user32", use_last_error=True)
        rows: list[dict[str, Any]] = []
        callback_type = ctypes.WINFUNCTYPE(wintypes.BOOL, wintypes.HWND, wintypes.LPARAM)

        @callback_type
        def callback(hwnd: int, _lparam: int) -> bool:
            try:
                if not user32.IsWindowVisible(hwnd) or not user32.IsWindowEnabled(hwnd):
                    return True
                title = ctypes.create_unicode_buffer(512)
                klass = ctypes.create_unicode_buffer(256)
                user32.GetWindowTextW(hwnd, title, len(title))
                user32.GetClassNameW(hwnd, klass, len(klass))
                pid = wintypes.DWORD()
                user32.GetWindowThreadProcessId(hwnd, ctypes.byref(pid))
                rows.append({
                    "handle": int(hwnd),
                    "title": title.value,
                    "class_name": klass.value,
                    "process_id": int(pid.value),
                })
            except Exception:
                pass
            return True

        user32.EnumWindows(callback, 0)
        return rows
    except Exception:
        return []


def _discover_dialog(desktop: Any, current_window: Any, action: dict[str, Any]) -> Any:
    from .hardening.selectors import discover_dialog
    return discover_dialog(desktop, current_window, action)


def _explorer_item(target: Any, name: str) -> Any:
    from .hardening.selectors import explorer_item
    return explorer_item(target, name)


def _force_foreground_window(handle: int) -> bool:
    """Activate a same-session top-level window despite the normal foreground lock.

    Windows may reject SetForegroundWindow from a long-lived automation host even when
    that host runs in the interactive user session. Temporarily attaching this thread
    to the foreground/target input queues makes activation deterministic without
    requiring a synthetic click.
    """
    try:
        from ctypes import wintypes

        user32 = ctypes.WinDLL("user32", use_last_error=True)
        kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
        user32.GetForegroundWindow.restype = wintypes.HWND
        user32.GetWindowThreadProcessId.argtypes = [wintypes.HWND, ctypes.POINTER(wintypes.DWORD)]
        user32.GetWindowThreadProcessId.restype = wintypes.DWORD
        user32.AttachThreadInput.argtypes = [wintypes.DWORD, wintypes.DWORD, wintypes.BOOL]
        user32.AttachThreadInput.restype = wintypes.BOOL
        user32.ShowWindow.argtypes = [wintypes.HWND, ctypes.c_int]
        user32.ShowWindow.restype = wintypes.BOOL
        user32.BringWindowToTop.argtypes = [wintypes.HWND]
        user32.BringWindowToTop.restype = wintypes.BOOL
        user32.SetForegroundWindow.argtypes = [wintypes.HWND]
        user32.SetForegroundWindow.restype = wintypes.BOOL
        user32.SetActiveWindow.argtypes = [wintypes.HWND]
        user32.SetActiveWindow.restype = wintypes.HWND
        user32.SetFocus.argtypes = [wintypes.HWND]
        user32.SetFocus.restype = wintypes.HWND
        kernel32.GetCurrentThreadId.restype = wintypes.DWORD

        hwnd = wintypes.HWND(handle)
        current_tid = int(kernel32.GetCurrentThreadId())
        foreground = user32.GetForegroundWindow()
        foreground_tid = int(user32.GetWindowThreadProcessId(foreground, None)) if foreground else 0
        target_tid = int(user32.GetWindowThreadProcessId(hwnd, None))
        attached: list[int] = []
        try:
            for tid in {foreground_tid, target_tid}:
                if tid and tid != current_tid and user32.AttachThreadInput(current_tid, tid, True):
                    attached.append(tid)
            user32.ShowWindow(hwnd, 9)  # SW_RESTORE
            user32.BringWindowToTop(hwnd)
            user32.SetForegroundWindow(hwnd)
            user32.SetActiveWindow(hwnd)
            user32.SetFocus(hwnd)
            time.sleep(0.06)
            return int(user32.GetForegroundWindow() or 0) == int(handle)
        finally:
            for tid in reversed(attached):
                try:
                    user32.AttachThreadInput(current_tid, tid, False)
                except Exception:
                    pass
    except Exception:
        return False


def _physical_focus_fallback(wrapper: Any, config: Config | None, op: str) -> bool:
    # Never click an inferred title-bar point merely to acquire foreground.
    return False


def _focus_window(target: Any, config: Config | None = None, op: str = "focus") -> Any:
    wrapper = _wrapper(target)
    handle = None
    try:
        handle = int(wrapper.handle)
    except Exception:
        handle = None
    last_error: Exception | None = None
    for attempt in range(4):
        if config is not None:
            _ensure_default_input_desktop(config, op)
        try:
            try:
                if hasattr(wrapper, "is_minimized") and wrapper.is_minimized():
                    wrapper.restore()
            except Exception:
                pass
            try:
                wrapper.set_focus()
            except Exception as exc:
                last_error = exc
            if not handle:
                return wrapper
            try:
                import win32gui
                if int(win32gui.GetForegroundWindow()) == handle:
                    return wrapper
            except Exception as exc:
                last_error = exc
            if _force_foreground_window(handle):
                return wrapper
            if attempt >= 1 and _physical_focus_fallback(wrapper, config, op):
                return wrapper
        except Exception as exc:
            last_error = exc
        time.sleep(0.12 * (attempt + 1))
    raise RuntimeError(f"could not focus target window for {op}: {last_error}")


def execute_windows_ui(config: Config, step: dict[str, Any]) -> dict[str, Any]:
    from .hardening.policy import local_ui_check
    from .hardening.validation import validate_operation
    from .hardening.desktop import set_dpi_awareness
    set_dpi_awareness()
    for operation in step.get("actions", []):
        validate_operation(operation, False)
    local_ui_check(config, step)
    actions = step.get("actions", [])
    intrusive = next(
        (str(action.get("op")) for action in actions if action.get("op") in _INTRUSIVE_UI_OPS),
        None,
    )
    input_desktop = _ensure_default_input_desktop(config, intrusive) if intrusive else _input_desktop_name()

    try:
        from pywinauto import Application, Desktop, keyboard, mouse
    except ImportError as exc:
        raise RuntimeError("Windows UI support requires pywinauto") from exc

    backend = step.get("backend", "uia")
    app: Any | None = None
    desktop = Desktop(backend=backend)
    window: Any | None = None

    if "start" in step:
        if not config.allow_visible_gui_launch:
            raise RuntimeError("visible GUI launch is disabled by interaction_policy.allow_visible_gui_launch")
        start_timeout = int(step.get("start_timeout_seconds", 30))

        # Snapshot visible top-level windows before launch. Modern packaged apps may
        # delegate from the launcher process to a different process without becoming
        # foreground immediately, so process ownership/foreground alone is insufficient.
        before_handles: set[int] = set()
        try:
            for existing in desktop.windows():
                try:
                    if existing.is_visible():
                        before_handles.add(int(existing.handle))
                except Exception:
                    pass
        except Exception:
            pass

        from .hardening.host import before_operation
        before_operation(config, step, {"op": "sleep", "seconds": 0})
        app = Application(backend=backend).start(step["start"], timeout=start_timeout)
        window_spec = step.get("window", {})
        if window_spec:
            candidate = desktop.window(**window_spec)
            candidate.wait("exists visible", timeout=start_timeout)
            window = candidate
        else:
            deadline = time.monotonic() + start_timeout
            last_error: Exception | None = None
            while time.monotonic() < deadline:
                # Fast path for ordinary Win32 apps whose launched process owns the window.
                try:
                    candidate = app.top_window()
                    candidate.wait("exists visible", timeout=0.5)
                    window = candidate
                    break
                except Exception as exc:
                    last_error = exc

                # Launcher/package fallback: discover a new visible top-level window,
                # regardless of which process ultimately owns it.
                try:
                    new_candidates: list[Any] = []
                    for candidate in desktop.windows():
                        try:
                            handle = int(candidate.handle)
                            if handle in before_handles or not candidate.is_visible():
                                continue
                            new_candidates.append(candidate)
                        except Exception:
                            continue
                    if new_candidates:
                        # Prefer an enabled non-empty window, then take the first new one.
                        new_candidates.sort(
                            key=lambda c: (
                                0 if (c.is_enabled() and bool(c.window_text().strip())) else 1,
                                int(c.handle),
                            )
                        )
                        window = desktop.window(handle=int(new_candidates[0].handle))
                        break
                except Exception as exc:
                    last_error = exc

                time.sleep(0.2)

            if window is None:
                raise RuntimeError(
                    f"visible application launched but no new window became available: {last_error}"
                )
    elif "connect" in step:
        app = Application(backend=backend).connect(**step["connect"])
        window_spec = step.get("window", {})
        window = app.window(**window_spec) if window_spec else app.top_window()
    elif step.get("desktop") is True:
        window_spec = step.get("window")
        if isinstance(window_spec, dict) and window_spec:
            window = desktop.window(**window_spec)
    else:
        raise ValueError("windows.ui requires exactly one of connect, start, or desktop=true")

    from .hardening.output import BoundedOutputs
    outputs: list[Any] = BoundedOutputs(config.max_output_bytes)

    for action in step.get("actions", []):
        op = action["op"]
        from .hardening.host import before_operation
        before_operation(config, step, action)
        if op in _INTRUSIVE_UI_OPS:
            # Long GUI steps can outlive a saver transition or Explorer shell handoff.
            # Re-validate the input desktop immediately before every physical/foreground op.
            input_desktop = _ensure_default_input_desktop(config, op)
        target = _target(window, action.get("control")) if op not in {
            "list_windows", "active_window", "click_at", "double_click_at", "right_click_at",
            "move_mouse", "scroll", "drag", "hotkey", "type_text", "clipboard_get",
            "clipboard_set", "sleep", "capture_desktop", "cursor_position", "input_desktop",
            "discover_dialog",
        } else None

        if op == "discover_dialog":
            window = _discover_dialog(desktop, window, action)
            outputs.append({"op": op, "window": _window_summary(_wrapper(window))})
        elif op == "file_dialog_path":
            _require_physical_input(config, op)
            _require_foreground(config, op)
            wrapper = _focus_window(target, config, op)
            path = str(action.get("path", ""))
            if not path:
                raise ValueError("file_dialog_path requires path")
            keyboard.send_keys("^l", pause=0.02)
            time.sleep(float(action.get("settle_seconds", 0.15)))
            _paste_unicode(keyboard, path)
            keyboard.send_keys("{ENTER}", pause=0.02)
            time.sleep(float(action.get("after_seconds", 0.35)))
            outputs.append({"op": op, "path": path, "window": _window_summary(wrapper)})
        elif op == "file_dialog_filename":
            _require_physical_input(config, op)
            _require_foreground(config, op)
            text = str(action.get("filename", ""))
            if not text:
                raise ValueError("file_dialog_filename requires filename")
            edit = _best_dialog_edit(target, action.get("automation_ids"))
            try:
                edit.set_edit_text(text)
            except Exception:
                edit.set_focus()
                keyboard.send_keys("^a", pause=0.02)
                _paste_unicode(keyboard, text)
            outputs.append({"op": op, "filename": text})
        elif op == "file_dialog_accept":
            _require_physical_input(config, op)
            _require_foreground(config, op)
            from .hardening.selectors import accept_dialog
            outputs.append(accept_dialog(target, action))
        elif op == "file_dialog_cancel":
            _require_physical_input(config, op)
            _require_foreground(config, op)
            _focus_window(target, config, op)
            keyboard.send_keys("{ESC}", pause=0.02)
            outputs.append({"op": op})
        elif op == "explorer_navigate":
            _require_physical_input(config, op)
            _require_foreground(config, op)
            wrapper = _focus_window(target, config, op)
            path = str(action.get("path", ""))
            if not path:
                raise ValueError("explorer_navigate requires path")
            keyboard.send_keys("^l", pause=0.02)
            _paste_unicode(keyboard, path)
            keyboard.send_keys("{ENTER}", pause=0.02)
            time.sleep(float(action.get("after_seconds", 0.5)))
            outputs.append({"op": op, "path": path, "window": _window_summary(wrapper)})
        elif op in {"explorer_select", "explorer_open", "explorer_rename", "explorer_delete", "explorer_copy", "explorer_cut"}:
            _require_physical_input(config, op)
            _require_foreground(config, op)
            wrapper = _focus_window(target, config, op)
            name = str(action.get("name", ""))
            if not name:
                raise ValueError(f"{op} requires name")
            item = _explorer_item(wrapper, name)
            item.select()
            from .hardening.selectors import assert_single_selection
            assert_single_selection(wrapper, item)
            if op == "explorer_open":
                keyboard.send_keys("{ENTER}", pause=0.02)
            elif op == "explorer_rename":
                new_name = str(action.get("new_name", ""))
                if not new_name:
                    raise ValueError("explorer_rename requires new_name")
                keyboard.send_keys("{F2}", pause=0.02)
                time.sleep(0.1)
                keyboard.send_keys("^a", pause=0.02)
                _paste_unicode(keyboard, new_name)
                keyboard.send_keys("{ENTER}", pause=0.02)
            elif op == "explorer_delete":
                keyboard.send_keys("{DELETE}", pause=0.02)
            elif op == "explorer_copy":
                keyboard.send_keys("^c", pause=0.02)
            elif op == "explorer_cut":
                keyboard.send_keys("^x", pause=0.02)
            outputs.append({"op": op, "name": name})
        elif op == "explorer_new_folder":
            _require_physical_input(config, op)
            _require_foreground(config, op)
            _focus_window(target, config, op)
            name = str(action.get("name", ""))
            if not name:
                raise ValueError("explorer_new_folder requires name")
            keyboard.send_keys("^+n", pause=0.02)
            time.sleep(0.15)
            _paste_unicode(keyboard, name)
            keyboard.send_keys("{ENTER}", pause=0.02)
            outputs.append({"op": op, "name": name})
        elif op == "explorer_paste":
            _require_physical_input(config, op)
            _require_foreground(config, op)
            _focus_window(target, config, op)
            keyboard.send_keys("^v", pause=0.02)
            outputs.append({"op": op})
        elif op == "list_windows":
            limit = max(1, min(int(action.get("limit", 100)), 500))
            title_contains = str(action.get("title_contains", "")).casefold()
            class_name = str(action.get("class_name", "")).casefold()
            rows = []
            for wrapper in desktop.windows():
                summary = _window_summary(wrapper)
                if title_contains and title_contains not in str(summary.get("title") or "").casefold():
                    continue
                if class_name and class_name != str(summary.get("class_name") or "").casefold():
                    continue
                rows.append(summary)
                if len(rows) >= limit:
                    break
            outputs.append({"op": op, "windows": rows})
        elif op == "cursor_position":
            try:
                from ctypes import wintypes
                user32 = ctypes.WinDLL("user32", use_last_error=True)
                point = wintypes.POINT()
                if not user32.GetCursorPos(ctypes.byref(point)):
                    raise OSError(ctypes.get_last_error(), "GetCursorPos failed")
                outputs.append({"op": op, "coords": [int(point.x), int(point.y)]})
            except Exception as exc:
                outputs.append({"op": op, "coords": None, "error": str(exc)})
        elif op == "input_desktop":
            outputs.append({"op": op, "name": _input_desktop_name(), "cursor_accessible": _cursor_accessible()})
        elif op == "active_window":
            try:
                import win32gui
                handle = int(win32gui.GetForegroundWindow())
                wrapper = desktop.window(handle=handle).wrapper_object() if handle else None
                outputs.append({"op": op, "window": _window_summary(wrapper) if wrapper else None})
            except Exception as exc:
                outputs.append({"op": op, "window": None, "error": str(exc)})
        elif op == "dump_tree":
            wrapper = target.wrapper_object()
            outputs.append({
                "op": op,
                "nodes": _tree(
                    wrapper,
                    max_depth=max(0, min(int(action.get("max_depth", 4)), 12)),
                    max_nodes=max(1, min(int(action.get("max_nodes", 250)), 2000)),
                ),
            })
        elif op == "wait_ready":
            target.wait("exists enabled visible ready", timeout=int(action.get("timeout_seconds", 30)))
            outputs.append({"op": op})
        elif op == "wait_visible":
            target.wait("exists visible", timeout=int(action.get("timeout_seconds", 30)))
            outputs.append({"op": op})
        elif op == "invoke":
            target.invoke()
            outputs.append({"op": op})
        elif op in {"set_value", "set_text"}:
            target.set_edit_text(action.get("text", ""))
            outputs.append({"op": op})
        elif op == "get_text":
            outputs.append({"op": op, "text": target.window_text()})
        elif op == "exists":
            outputs.append({"op": op, "exists": bool(target.exists(timeout=float(action.get("timeout_seconds", 0))))})
        elif op == "is_visible":
            try:
                value = bool(target.is_visible())
            except Exception:
                value = False
            outputs.append({"op": op, "visible": value})
        elif op == "is_enabled":
            try:
                value = bool(target.is_enabled())
            except Exception:
                value = False
            outputs.append({"op": op, "enabled": value})
        elif op == "get_rect":
            rect = target.rectangle()
            outputs.append({"op": op, "rect": [int(rect.left), int(rect.top), int(rect.right), int(rect.bottom)]})
        elif op == "summary":
            outputs.append({"op": op, "window": _window_summary(target.wrapper_object())})
        elif op == "select":
            target.select()
            outputs.append({"op": op})
        elif op == "toggle":
            target.toggle()
            outputs.append({"op": op})
        elif op == "expand":
            target.expand()
            outputs.append({"op": op})
        elif op == "collapse":
            target.collapse()
            outputs.append({"op": op})
        elif op == "close":
            target.close()
            outputs.append({"op": op})
        elif op in {"focus", "set_focus"}:
            _require_foreground(config, op)
            _focus_window(target, config, op)
            outputs.append({"op": op})
        elif op == "maximize":
            _require_foreground(config, op)
            target.maximize()
            outputs.append({"op": op})
        elif op == "minimize":
            _require_foreground(config, op)
            target.minimize()
            outputs.append({"op": op})
        elif op == "restore":
            _require_foreground(config, op)
            target.restore()
            outputs.append({"op": op})
        elif op == "move_resize":
            _require_foreground(config, op)
            target.move_window(
                x=int(action["x"]), y=int(action["y"]),
                width=int(action["width"]), height=int(action["height"]),
                repaint=True,
            )
            outputs.append({"op": op})
        elif op == "click":
            _require_physical_input(config, op)
            target.click()
            outputs.append({"op": op})
        elif op == "click_input":
            _require_physical_input(config, op)
            kwargs: dict[str, Any] = {}
            for key in ("button", "coords", "double", "wheel_dist", "pressed"):
                if key in action:
                    kwargs[key] = action[key]
            target.click_input(**kwargs)
            outputs.append({"op": op})
        elif op == "type_keys":
            _require_physical_input(config, op)
            keys = action.get("keys")
            if not isinstance(keys, str):
                raise ValueError("type_keys requires a string keys value")
            kwargs = {"set_foreground": config.allow_foreground_activation}
            for key in ("pause", "with_spaces", "with_tabs", "with_newlines"):
                if key in action:
                    kwargs[key] = action[key]
            target.type_keys(keys, **kwargs)
            outputs.append({"op": op})
        elif op == "move_mouse":
            _require_physical_input(config, op)
            if action.get("coords") is not None:
                point = _coords(action)
            elif window is not None:
                rect = _target(window, action.get("control")).rectangle()
                mid = rect.mid_point()
                point = (int(mid.x), int(mid.y))
            else:
                raise ValueError("move_mouse requires coords in desktop mode")
            mouse.move(coords=point)
            outputs.append({"op": op, "coords": list(point)})
        elif op in {"click_at", "double_click_at", "right_click_at"}:
            _require_physical_input(config, op)
            point = _coords(action)
            if op == "click_at":
                mouse.click(button=str(action.get("button", "left")), coords=point)
            elif op == "double_click_at":
                mouse.double_click(button=str(action.get("button", "left")), coords=point)
            else:
                mouse.right_click(coords=point)
            outputs.append({"op": op, "coords": list(point)})
        elif op == "scroll":
            _require_physical_input(config, op)
            point = _coords(action) if "coords" in action else None
            mouse.scroll(coords=point, wheel_dist=int(action.get("wheel_dist", 1)))
            outputs.append({"op": op, "coords": list(point) if point else None})
        elif op == "drag":
            _require_physical_input(config, op)
            start = _coords(action, "start")
            end = _coords(action, "end")
            button = str(action.get("button", "left"))
            mouse.move(coords=start)
            mouse.press(button=button, coords=start)
            try:
                mouse.move(coords=end)
            finally:
                mouse.release(button=button, coords=end)
            outputs.append({"op": op, "start": list(start), "end": list(end)})
        elif op == "hotkey":
            _require_physical_input(config, op)
            _require_foreground(config, op)
            keys = action.get("keys")
            if not isinstance(keys, str) or not keys:
                raise ValueError("hotkey requires a non-empty string keys value")
            keyboard.send_keys(keys, pause=float(action.get("pause", 0.02)))
            outputs.append({"op": op})
        elif op == "type_text":
            _require_physical_input(config, op)
            _require_foreground(config, op)
            text = action.get("text")
            if not isinstance(text, str):
                raise ValueError("type_text requires a string text value")
            from .hardening.desktop import send_unicode
            from .hardening.host import check_input_continuation
            send_unicode(text, check=lambda: check_input_continuation(config, step, action))
            outputs.append({"op": op, "length": len(text)})
        elif op == "clipboard_get":
            outputs.append({"op": op, "text": _clipboard_get_text()})
        elif op == "clipboard_set":
            text = action.get("text")
            if not isinstance(text, str):
                raise ValueError("clipboard_set requires a string text value")
            _clipboard_set_text(text)
            outputs.append({"op": op, "length": len(text)})
        elif op == "sleep":
            seconds = max(0.0, min(float(action.get("seconds", 1.0)), 60.0))
            time.sleep(seconds)
            outputs.append({"op": op, "seconds": seconds})
        elif op in {"capture", "capture_desktop"}:
            name = str(action.get("name", f"capture-{int(time.time() * 1000)}.png"))
            safe_name = Path(name).name
            if not safe_name.lower().endswith(".png"):
                safe_name += ".png"
            capture_dir = config.repo_path.parent / "scratch" / "ui-captures"
            capture_dir.mkdir(parents=True, exist_ok=True)
            path = capture_dir / safe_name
            if op == "capture_desktop":
                try:
                    from PIL import ImageGrab
                except ImportError as exc:
                    raise RuntimeError("desktop capture requires Pillow") from exc
                image = ImageGrab.grab(all_screens=True)
            else:
                image = target.capture_as_image()
            image.save(path, format="PNG")
            from .hardening.desktop import display_metadata
            import hashlib
            outputs.append({"op": op, "path": str(path), "size": list(image.size), "pixel_sha256": hashlib.sha256(image.tobytes()).hexdigest(), "captured_unix": time.time(), "display": display_metadata() if op == "capture_desktop" else None})
        else:
            raise ValueError(f"unsupported windows.ui op: {op}")

    return {
        "backend": backend,
        "outputs": outputs,
        "non_interference": config.non_interference,
        "physical_input_allowed": config.allow_physical_input,
        "foreground_activation_allowed": config.allow_foreground_activation,
        "visible_gui_launch_allowed": config.allow_visible_gui_launch,
        "input_desktop": input_desktop,
    }


def serve(config: Config) -> None:
    from .hardening.host import serve as hardened_serve
    hardened_serve(config, execute_windows_ui)


def main() -> None:
    parser = argparse.ArgumentParser(description="GPT Controller user-session Interactive Host")
    parser.add_argument("--config", required=True)
    parser.add_argument("--log-level", default="INFO")
    args = parser.parse_args()
    config = Config.load(Path(args.config))
    level = getattr(logging, args.log_level.upper(), logging.INFO)
    configure_file_logging(config.repo_path.parent / "logs" / "interactive.log", level)
    serve(config)


if __name__ == "__main__":
    main()
