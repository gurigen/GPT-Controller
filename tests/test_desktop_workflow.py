from __future__ import annotations

import threading
import time
from pathlib import Path
from types import SimpleNamespace

from agent_runtime.desktop_stability import (
    clear_checkpoint,
    condition_matches,
    load_checkpoint,
    wait_for_download,
    write_checkpoint,
)
from agent_runtime.protocol import validate_action


def _config(tmp_path: Path):
    control = tmp_path / "control"
    control.mkdir()
    return SimpleNamespace(repo_path=control, agent_id="worker-pc")


def test_checkpoint_roundtrip(tmp_path: Path):
    config = _config(tmp_path)
    assert load_checkpoint(config, "job-1") is None
    record = write_checkpoint(config, "job-1", {"status": "running", "cycle": 2, "next_step": 4})
    assert record["cycle"] == 2
    loaded = load_checkpoint(config, "job-1")
    assert loaded and loaded["next_step"] == 4
    assert clear_checkpoint(config, "job-1") is True
    assert load_checkpoint(config, "job-1") is None


def test_loop_condition_language_supports_nested_paths_and_boolean_composition():
    outputs = [
        {"status": "succeeded", "result": {"outputs": [{"exists": True, "text": "ready now"}]}}
    ]
    assert condition_matches(outputs, {"source": 0, "path": "result.outputs.0.exists", "equals": True})
    assert condition_matches(outputs, {"all": [
        {"source": 0, "path": "status", "equals": "succeeded"},
        {"source": 0, "path": "result.outputs.0.text", "contains": "ready"},
    ]})
    assert condition_matches(outputs, {"not": {"source": 0, "path": "status", "equals": "failed"}})


def test_download_wait_tracks_new_file_until_stable(tmp_path: Path):
    target = tmp_path / "report.zip"

    def writer():
        time.sleep(0.05)
        target.write_bytes(b"abc")
        time.sleep(0.05)
        target.write_bytes(b"abcdef")

    thread = threading.Thread(target=writer)
    thread.start()
    result = wait_for_download(
        str(tmp_path), patterns=["*.zip"], timeout_seconds=2, stable_seconds=0.05, poll_seconds=0.01
    )
    thread.join()
    assert result["name"] == "report.zip"
    assert result["bytes"] == 6


def test_protocol_accepts_resumable_desktop_loop_and_high_level_ui_ops():
    validate_action({
        "protocol": "q-agent-v4",
        "id": "desktop-loop-test",
        "target": {"mode": "agent", "agent": "worker-pc"},
        "resume_from_checkpoint": True,
        "resume_attempts": 4,
        "steps": [{
            "type": "desktop.loop",
            "session": "desktop-loop-test",
            "max_cycles": 500,
            "timeout_seconds": 3600,
            "until": {"source": 0, "path": "result.outputs.0.exists", "equals": True},
            "steps": [
                {"type": "windows.ui", "desktop": True, "window": {"title_re": ".*Explorer.*"}, "actions": [
                    {"op": "explorer_navigate", "path": "C:/Temp"},
                    {"op": "explorer_new_folder", "name": "Agent1"},
                ]},
                {"type": "download.wait", "directory": "C:/Users/test/Downloads", "patterns": ["*.zip"]},
            ],
        }],
    })


def test_protocol_accepts_file_dialog_ops():
    validate_action({
        "protocol": "q-agent-v4",
        "id": "dialog-test",
        "target": {"mode": "agent", "agent": "worker-pc"},
        "steps": [{
            "type": "windows.ui",
            "desktop": True,
            "window": {"title_re": ".*"},
            "actions": [
                {"op": "file_dialog_path", "path": "C:/Temp"},
                {"op": "file_dialog_filename", "filename": "result.txt"},
                {"op": "file_dialog_accept"},
            ],
        }],
    })


def test_resilient_bus_never_requeues_claim_after_unknown_side_effect(tmp_path):
    import json
    from agent_runtime.resilient_bus import ResilientGitBus
    bus = ResilientGitBus.__new__(ResilientGitBus)
    bus.repo = tmp_path
    bus.c = SimpleNamespace(agent_id='test-agent')
    bus._publish_recovery_commit = lambda message: None
    running = tmp_path/'queue/running/action.test-agent.json'
    running.parent.mkdir(parents=True)
    running.write_text(json.dumps({'id':'action','resume_from_checkpoint':True,'steps':[{'type':'desktop.loop'}]}))
    assert bus.recover_ambiguous() == 1
    assert not (tmp_path/'queue/pending/action.json').exists()
    assert json.loads((tmp_path/'results/action.json').read_text())['status'] == 'ambiguous'


def test_supervisor_does_not_retry_ambiguous_infrastructure_failure():
    from agent_runtime.process_supervisor import ActionSupervisor
    supervisor = ActionSupervisor.__new__(ActionSupervisor)
    calls = []
    def attempt(action, on_progress=None):
        calls.append(action)
        return {'status':'ambiguous','steps':[],'supervisor':{'timed_out':True}}
    supervisor._execute_once = attempt
    result = supervisor.execute({'resume_from_checkpoint':True,'resume_attempts':10})
    assert result['status'] == 'ambiguous'
    assert len(calls) == 1


def test_interactive_host_contains_dialog_and_explorer_primitives():
    source = (Path(__file__).resolve().parents[1] / "src/agent_runtime/interactive_host.py").read_text(encoding="utf-8")
    for token in (
        'file_dialog_path', 'file_dialog_filename', 'file_dialog_accept',
        'explorer_navigate', 'explorer_select', 'explorer_open', 'explorer_new_folder',
        'explorer_rename', 'explorer_delete', 'explorer_copy', 'explorer_cut', 'explorer_paste',
    ):
        assert token in source


def test_executor_recurses_into_loop_for_managed_workspace_guards():
    source = (Path(__file__).resolve().parents[1] / "src/agent_runtime/executor.py").read_text(encoding="utf-8")
    assert 'if kind == "desktop.loop"' in source
    assert 'visit(nested, workspace)' in source


def test_recovery_handles_malformed_running_action_without_unbound_local():
    source = (Path(__file__).resolve().parents[1] / "src/agent_runtime/resilient_bus.py").read_text(encoding="utf-8")
    assert 'except Exception:\n                action = None' in source


def test_protocol_checks_resume_attempts_range():
    bad = {
        "protocol": "q-agent-v4", "id": "bad-resume",
        "target": {"mode": "agent", "agent": "worker-pc"},
        "resume_from_checkpoint": True, "resume_attempts": 11,
        "steps": [{"type": "desktop.loop", "session": "bad-resume", "steps": [{"type": "noop"}]}],
    }
    try:
        validate_action(bad)
    except ValueError as exc:
        assert "resume_attempts" in str(exc)
    else:
        raise AssertionError("resume_attempts=11 should be rejected")


def test_interactive_revalidates_input_desktop_per_intrusive_action():
    source = (Path(__file__).resolve().parents[1] / "src/agent_runtime/interactive_host.py").read_text(encoding="utf-8")
    assert 'if op in _INTRUSIVE_UI_OPS:' in source
    assert 'input_desktop = _ensure_default_input_desktop(config, op)' in source


def test_explorer_item_requires_unique_full_name():
    import pytest
    from agent_runtime.hardening.selectors import explorer_item
    from agent_runtime.hardening.common import ControlError
    def item(name):
        return SimpleNamespace(element_info=SimpleNamespace(control_type='ListItem'), window_text=lambda:name,
                               is_visible=lambda:True,is_enabled=lambda:True)
    exact, other = item('report.csv'), item('report.csv.backup')
    assert explorer_item(SimpleNamespace(descendants=lambda:[other,exact]),'report.csv') is exact
    with pytest.raises(ControlError):
        explorer_item(SimpleNamespace(descendants=lambda:[other]),'report.csv')
    with pytest.raises(ControlError):
        explorer_item(SimpleNamespace(descendants=lambda:[exact,item('report.csv')]),'report.csv')


def test_focus_window_verifies_foreground_instead_of_silently_ignoring_failure():
    source = (Path(__file__).resolve().parents[1] / "src/agent_runtime/interactive_host.py").read_text(encoding="utf-8")
    assert 'def _focus_window(target: Any, config: Config | None = None, op: str = "focus")' in source
    assert 'GetForegroundWindow' in source
    assert 'could not focus target window' in source


def test_focus_window_has_thread_input_activation_fallback():
    source = (Path(__file__).resolve().parents[1] / "src/agent_runtime/interactive_host.py").read_text(encoding="utf-8")
    assert "def _force_foreground_window(handle: int) -> bool:" in source
    assert "AttachThreadInput" in source
    assert "BringWindowToTop" in source
    assert "SetForegroundWindow" in source


def test_focus_window_has_physical_fallback_only_for_dedicated_input_policy():
    source = (Path(__file__).resolve().parents[1] / "src/agent_runtime/interactive_host.py").read_text(encoding="utf-8")
    assert "def _physical_focus_fallback" in source
    assert "not config.allow_physical_input" in source
    assert "_ensure_default_input_desktop(config, op)" in source
    assert "mouse.click" in source


def test_unicode_entry_does_not_touch_clipboard(monkeypatch):
    from agent_runtime import interactive_host
    from agent_runtime.hardening import desktop
    calls = []
    monkeypatch.setattr(desktop,'send_unicode',lambda text,check: calls.append(text))
    monkeypatch.setattr(interactive_host,'_clipboard_set_text',lambda text: (_ for _ in ()).throw(AssertionError('clipboard touched')))
    interactive_host._paste_unicode(None,'日本語😀')
    assert calls == ['日本語😀']


def test_interactive_host_run_level_is_machine_configurable_and_defaults_limited():
    source = (Path(__file__).resolve().parents[1] / "scripts/install-interactive-host.ps1").read_text(encoding="utf-8")
    assert "$configData.interactive_host.run_level" in source
    assert "$runLevel = 'Limited'" in source
    assert "$runLevel = 'Highest'" in source
    assert "-RunLevel $runLevel" in source


def test_dialog_discovery_requires_process_identity():
    import pytest
    from agent_runtime.hardening.selectors import discover_dialog
    from agent_runtime.hardening.common import ControlError
    with pytest.raises(ControlError,match='process_id'):
        discover_dialog(None,None,{'kind':'file'})


def test_auto_dialog_discovery_retargets_following_file_dialog_ops():
    source = (Path(__file__).resolve().parents[1] / "src/agent_runtime/interactive_host.py").read_text(encoding="utf-8")
    discover = source.index('if op == "discover_dialog":')
    retarget = source.index('window = _discover_dialog(desktop, window, action)', discover)
    filename = source.index('elif op == "file_dialog_path":', retarget)
    assert discover < retarget < filename


def test_native_class_alone_is_not_a_file_dialog():
    from agent_runtime.hardening.selectors import looks_like_file_dialog
    window = SimpleNamespace(is_visible=lambda:True,is_enabled=lambda:True,class_name=lambda:'#32770',descendants=lambda:[])
    assert not looks_like_file_dialog(window)


def test_dialog_discovery_timeout_is_bounded_and_process_scoped():
    import pytest
    from agent_runtime.hardening.selectors import discover_dialog
    start = time.monotonic()
    with pytest.raises(TimeoutError,match='selected process'):
        discover_dialog(SimpleNamespace(windows=lambda:[]),None,{'process_id':42,'timeout_seconds':0.1})
    assert time.monotonic()-start < 1


def test_dialog_discovery_does_not_select_foreground_of_another_process():
    from agent_runtime.hardening.selectors import discover_dialog
    def window(pid, hwnd):
        return SimpleNamespace(process_id=lambda:pid,handle=hwnd,is_visible=lambda:True,is_enabled=lambda:True,
            class_name=lambda:'#32770',window_text=lambda:'Save',descendants=lambda:[SimpleNamespace(element_info=SimpleNamespace(automation_id='FileNameControlHost'))])
    desktop = SimpleNamespace(windows=lambda:[window(99,99),window(42,42)],window=lambda handle:handle)
    assert discover_dialog(desktop,None,{'process_id':42,'timeout_seconds':0.1}) == 42


def test_dialog_classifier_requires_filename_controls():
    from agent_runtime.hardening.selectors import looks_like_file_dialog
    window = SimpleNamespace(is_visible=lambda:True,is_enabled=lambda:True,class_name=lambda:'Custom',
        window_text=lambda:'Open and Save',descendants=lambda:[])
    assert not looks_like_file_dialog(window)
    window.descendants = lambda:[SimpleNamespace(element_info=SimpleNamespace(automation_id='FileNameControlHost'))]
    assert looks_like_file_dialog(window)


def test_file_dialog_accept_does_not_retry_after_invoke_failure():
    import pytest
    from agent_runtime.hardening.selectors import accept_dialog
    from agent_runtime.hardening.common import ControlError
    calls = []
    def invoke():
        calls.append('invoke')
        raise RuntimeError('response lost after click')
    button = SimpleNamespace(element_info=SimpleNamespace(automation_id='1'),is_visible=lambda:True,is_enabled=lambda:True,
        invoke=invoke,window_text=lambda:'Save')
    filename = SimpleNamespace(element_info=SimpleNamespace(automation_id='1148'))
    dialog = SimpleNamespace(is_visible=lambda:True,is_enabled=lambda:True,class_name=lambda:'#32770',
        descendants=lambda **kwargs:[button] if kwargs else [button,filename])
    with pytest.raises(ControlError,match='ambiguous'):
        accept_dialog(dialog,{})
    assert calls == ['invoke']

