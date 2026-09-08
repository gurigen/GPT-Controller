import ctypes
import json
import os
from pathlib import Path
import threading
import pytest
from agent_runtime.hardening import common


def test_transient_windows_publication_error_retries_only_replace(tmp_path, monkeypatch):
    path = tmp_path / "state.json"
    common.atomic_json(path, {"old": True})
    original = common.os.replace
    calls = []
    def replace(source, destination):
        calls.append((str(source), str(destination)))
        if len(calls) < 3:
            error = PermissionError("sharing violation")
            error.winerror = 32
            raise error
        return original(source, destination)
    monkeypatch.setattr(common.os, "replace", replace)
    monkeypatch.setattr(common.time, "sleep", lambda delay: None)
    common.atomic_json(path, {"new": True})
    assert len(calls) == 3 and len(set(calls)) == 1
    assert common.load_json(path) == {"new": True}
    assert not list(tmp_path.glob(".gpt-*"))


def test_permanent_windows_publication_failure_is_bounded_and_keeps_old_json(tmp_path, monkeypatch):
    path = tmp_path / "state.json"
    common.atomic_json(path, {"old": True})
    calls = []
    def replace(source, destination):
        calls.append(str(source))
        error = PermissionError("persistent denial")
        error.winerror = 5
        raise error
    monkeypatch.setattr(common.os, "replace", replace)
    monkeypatch.setattr(common.time, "sleep", lambda delay: None)
    with pytest.raises(PermissionError):
        common.atomic_json(path, {"new": True})
    assert len(calls) == 8 and len(set(calls)) == 1
    assert common.load_json(path) == {"old": True}
    assert not list(tmp_path.glob(".gpt-*"))


def test_non_windows_permission_failure_is_not_retried(tmp_path, monkeypatch):
    calls = []
    def replace(source, destination):
        calls.append(1)
        raise PermissionError("unrelated permission failure")
    monkeypatch.setattr(common.os, "replace", replace)
    with pytest.raises(PermissionError):
        common.atomic_json(tmp_path / "state.json", {"new": True})
    assert len(calls) == 1
    assert not list(tmp_path.glob(".gpt-*"))


@pytest.mark.skipif(os.name != "nt", reason="Requires native Windows file sharing")
def test_native_windows_reader_release_allows_atomic_publication(tmp_path, monkeypatch):
    from ctypes import wintypes
    required = os.environ.get("GPT_TEST_REQUIRED_SOURCE")
    if required:
        assert Path(common.__file__).resolve().is_relative_to(Path(required).resolve()), common.__file__
    path = tmp_path / "state.json"
    common.atomic_json(path, {"old": True})
    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel.CreateFileW.argtypes = [wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD,
                                  ctypes.c_void_p, wintypes.DWORD, wintypes.DWORD, wintypes.HANDLE]
    kernel.CreateFileW.restype = wintypes.HANDLE
    kernel.CloseHandle.argtypes = [wintypes.HANDLE]
    kernel.CloseHandle.restype = wintypes.BOOL
    handle = kernel.CreateFileW(str(path), 0x80000000, 1, None, 3, 0, None)
    assert handle not in (None, ctypes.c_void_p(-1).value), ctypes.get_last_error()
    release = threading.Timer(0.1, lambda: kernel.CloseHandle(handle))
    actual_replace = common.os.replace
    attempted = []
    def replace(source, destination):
        if not attempted:
            release.start()
        attempted.append(1)
        return actual_replace(source, destination)
    monkeypatch.setattr(common.os, "replace", replace)
    try:
        common.atomic_json(path, {"new": True})
    finally:
        if release.ident is not None:
            release.join(timeout=2)
        else:
            kernel.CloseHandle(handle)
    assert len(attempted) > 1
    assert common.load_json(path) == {"new": True}
    assert not list(tmp_path.glob(".gpt-*"))


def test_browser_fixture_declares_automation_without_disabling_windows_sandbox():
    text = (Path(__file__).with_name("test_real_browser.py")).read_text(encoding="utf-8")
    assert "'--enable-automation'" in text
    assert "--no-sandbox" not in text
