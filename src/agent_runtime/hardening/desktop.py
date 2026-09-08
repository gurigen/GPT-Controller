from __future__ import annotations

import ctypes
import hashlib
import os
import secrets
import time
from pathlib import Path
from typing import Any

from .common import ControlError, atomic_json, identifier, load_json, state_root, utc_now


def set_dpi_awareness() -> bool:
    if os.name != "nt":
        return False
    from ctypes import wintypes
    user32 = ctypes.WinDLL("user32", use_last_error=True)
    try:
        user32.SetProcessDpiAwarenessContext.argtypes = [wintypes.HANDLE]
        user32.SetProcessDpiAwarenessContext.restype = wintypes.BOOL
        if user32.SetProcessDpiAwarenessContext(ctypes.c_void_p(-4)):
            return True
        user32.GetThreadDpiAwarenessContext.restype = wintypes.HANDLE
        user32.GetAwarenessFromDpiAwarenessContext.argtypes = [wintypes.HANDLE]
        user32.GetAwarenessFromDpiAwarenessContext.restype = ctypes.c_int
        return user32.GetAwarenessFromDpiAwarenessContext(user32.GetThreadDpiAwarenessContext()) == 2
    except (AttributeError, OSError):
        return False


def display_metadata() -> dict:
    if os.name != "nt":
        raise ControlError("blocked", "desktop observation requires Windows")
    from ctypes import wintypes
    user32 = ctypes.WinDLL("user32", use_last_error=True)
    origin = [user32.GetSystemMetrics(76), user32.GetSystemMetrics(77)]
    size = [user32.GetSystemMetrics(78), user32.GetSystemMetrics(79)]
    rows = []
    callback_type = ctypes.WINFUNCTYPE(wintypes.BOOL, wintypes.HANDLE, wintypes.HDC, ctypes.POINTER(wintypes.RECT), wintypes.LPARAM)
    @callback_type
    def callback(monitor, _hdc, rect, _param):
        r = rect.contents
        row = {"monitor": int(monitor), "rect": [r.left, r.top, r.right, r.bottom], "dpi": None}
        try:
            dpi_x, dpi_y = wintypes.UINT(), wintypes.UINT()
            shcore = ctypes.WinDLL("shcore")
            shcore.GetDpiForMonitor.argtypes = [wintypes.HANDLE, ctypes.c_int, ctypes.POINTER(wintypes.UINT), ctypes.POINTER(wintypes.UINT)]
            if shcore.GetDpiForMonitor(monitor, 0, ctypes.byref(dpi_x), ctypes.byref(dpi_y)) == 0:
                row["dpi"] = [dpi_x.value, dpi_y.value]
        except (AttributeError, OSError):
            pass
        rows.append(row)
        return True
    user32.EnumDisplayMonitors.argtypes = [wintypes.HDC, ctypes.POINTER(wintypes.RECT), callback_type, wintypes.LPARAM]
    if not user32.EnumDisplayMonitors(None, None, callback, 0):
        raise ControlError("blocked", "monitor enumeration failed")
    return {"coordinate_space": "physical_pixels", "origin": origin, "size": size, "monitors": rows,
            "per_monitor_dpi_aware": set_dpi_awareness()}


def image_to_screen(point: list[int], observation: dict) -> list[int]:
    width, height = observation["size"]
    x, y = point
    if type(x) is not int or type(y) is not int or not 0 <= x < width or not 0 <= y < height:
        raise ControlError("blocked", "image coordinate lies outside the observed screen")
    origin = observation["display"]["origin"]
    return [x + origin[0], y + origin[1]]


def validate_observation(observation: dict, current: dict, *, max_age: float = 10, verify_pixels: bool = True) -> None:
    if not 0 < max_age <= 30:
        raise ValueError("max_age must be in (0,30]")
    age = time.time() - observation["captured_unix"]
    if age < 0 or age > max_age:
        raise ControlError("blocked", "observation expired; capture a new screen")
    if observation["foreground_handle"] != current["foreground_handle"]:
        raise ControlError("blocked", "foreground window changed since observation")
    if observation["display"] != current["display"]:
        raise ControlError("blocked", "display geometry or DPI changed")
    if verify_pixels and observation["pixel_sha256"] != current["pixel_sha256"]:
        raise ControlError("blocked", "screen changed since observation; no stale coordinate click")


def foreground_handle() -> int:
    if os.name != "nt":
        raise ControlError("blocked", "foreground verification requires Windows")
    from ctypes import wintypes
    user32 = ctypes.WinDLL("user32", use_last_error=True)
    user32.GetForegroundWindow.restype = wintypes.HWND
    return int(user32.GetForegroundWindow() or 0)


def enforce_observation_guard(step: dict) -> None:
    expected = step.get("__gpt_observation")
    if not expected:
        return
    from PIL import ImageGrab
    image = ImageGrab.grab(all_screens=True)
    current = {"foreground_handle": foreground_handle(), "display": display_metadata(),
               "pixel_sha256": hashlib.sha256(image.tobytes()).hexdigest()}
    validate_observation(expected, current, max_age=step.get("__gpt_max_age", 10), verify_pixels=step.get("__gpt_verify_pixels", True))


def observe(executor: Any, step: dict) -> dict:
    from .artifacts import ArtifactStore
    raw = executor.interactive.request({"type": "windows.ui", "desktop": True,
                                       "actions": [{"op": "input_desktop"}, {"op": "active_window"}, {"op": "capture_desktop"}]}, 15)
    rows = raw["outputs"]
    desktop = next(row for row in rows if row["op"] == "input_desktop")
    if desktop.get("name") != "Default":
        raise ControlError("needs_user", "unlock the Windows session manually")
    active = next(row for row in rows if row["op"] == "active_window").get("window")
    capture = next(row for row in rows if row["op"] == "capture_desktop")
    if not active or not capture.get("display", {}).get("per_monitor_dpi_aware"):
        raise ControlError("blocked", "no verified foreground window or DPI coordinate mapping")
    ident = "observation-" + secrets.token_hex(16)
    record = {"observation_id": ident, "agent_id": executor.config.agent_id, "captured_at": utc_now(),
              "captured_unix": capture.get("captured_unix", time.time()), "foreground_handle": active["handle"],
              "window": active, "size": capture["size"], "display": capture["display"],
              "pixel_sha256": capture["pixel_sha256"]}
    record["artifact"] = ArtifactStore(executor.config).add_file(Path(capture["path"]), metadata=record)
    atomic_json(state_root(executor.config) / "observations" / f"{ident}.json", record)
    return record


def act(executor: Any, step: dict) -> dict:
    ident = identifier(step["observation_id"], "observation id")
    observation = load_json(state_root(executor.config) / "observations" / f"{ident}.json")
    if observation.get("agent_id") != executor.config.agent_id:
        raise ControlError("blocked", "observation belongs to another agent")
    if len(step["actions"]) != 1:
        raise ValueError("desktop.act accepts exactly one operation per observation")
    op = dict(step["actions"][0])
    for key in ("coords", "start", "end"):
        if key in op:
            op[key] = image_to_screen(op[key], observation)
    payload = {"type": "windows.ui", "desktop": True, "window": {"handle": observation["foreground_handle"]},
               "actions": [op], "__gpt_observation": observation,
               "__gpt_max_age": step.get("max_age_seconds", 10), "__gpt_verify_pixels": step.get("verify_unchanged", True)}
    return executor.interactive.request(payload, min(step.get("timeout_seconds", 15), executor.config.interactive_timeout_seconds))


def send_unicode(text: str, check=lambda: None) -> None:
    """Inject UTF-16 through SendInput without touching the user's clipboard.

    Delivery does not mean the application's value changed: verify it separately.
    """
    if os.name != "nt":
        raise ControlError("blocked", "Unicode input requires Windows")
    if not isinstance(text, str) or "\x00" in text:
        raise ValueError("text must be a string without NUL")
    from ctypes import wintypes
    ULONG_PTR = ctypes.c_size_t
    class MOUSEINPUT(ctypes.Structure):
        _fields_ = [("dx", wintypes.LONG), ("dy", wintypes.LONG), ("mouseData", wintypes.DWORD), ("dwFlags", wintypes.DWORD), ("time", wintypes.DWORD), ("dwExtraInfo", ULONG_PTR)]
    class KEYBDINPUT(ctypes.Structure):
        _fields_ = [("wVk", wintypes.WORD), ("wScan", wintypes.WORD), ("dwFlags", wintypes.DWORD), ("time", wintypes.DWORD), ("dwExtraInfo", ULONG_PTR)]
    class HARDWAREINPUT(ctypes.Structure):
        _fields_ = [("uMsg", wintypes.DWORD), ("wParamL", wintypes.WORD), ("wParamH", wintypes.WORD)]
    class INPUTUNION(ctypes.Union):
        _fields_ = [("mi", MOUSEINPUT), ("ki", KEYBDINPUT), ("hi", HARDWAREINPUT)]
    class INPUT(ctypes.Structure):
        _anonymous_ = ("u",)
        _fields_ = [("type", wintypes.DWORD), ("u", INPUTUNION)]
    user32 = ctypes.WinDLL("user32", use_last_error=True)
    user32.SendInput.argtypes = [wintypes.UINT, ctypes.POINTER(INPUT), ctypes.c_int]
    user32.SendInput.restype = wintypes.UINT
    for char in text.replace("\r\n", "\n").replace("\r", "\n"):
        check()
        if char in {"\n", "\t"}:
            pairs = [(0x0D if char == "\n" else 0x09, 0, 0)]
        else:
            units = char.encode("utf-16-le")
            pairs = [(0, int.from_bytes(units[i:i+2], "little"), 4) for i in range(0, len(units), 2)]
        events = []
        for vk, scan, flags in pairs:
            events.extend([INPUT(type=1, ki=KEYBDINPUT(vk, scan, flags, 0, 0)), INPUT(type=1, ki=KEYBDINPUT(vk, scan, flags | 2, 0, 0))])
        batch = (INPUT * len(events))(*events)
        sent = user32.SendInput(len(events), batch, ctypes.sizeof(INPUT))
        if sent != len(events):
            # Release only keys introduced by this failed batch, never all user keys.
            ups = (INPUT * len(pairs))(*(INPUT(type=1, ki=KEYBDINPUT(vk, scan, flags | 2, 0, 0)) for vk, scan, flags in pairs))
            user32.SendInput(len(ups), ups, ctypes.sizeof(INPUT))
            raise ControlError("ambiguous", "SendInput did not acknowledge the complete text batch")
