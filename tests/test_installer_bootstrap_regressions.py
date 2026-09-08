from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def test_bootstrap_rejects_windows_store_python_alias_and_probes_real_python():
    text = (ROOT / "scripts" / "bootstrap-windows.ps1").read_text(encoding="utf-8")
    assert "Microsoft\\\\WindowsApps\\\\python" in text
    assert "Test-PythonExecutable" in text
    assert "sys.version_info.major" in text
    assert "Ensure-Python" in text


def test_bootstrap_configures_gh_as_git_credential_helper():
    text = (ROOT / "scripts" / "bootstrap-install.ps1").read_text(encoding="utf-8")
    assert "@('auth','setup-git')" in text
    assert "Authenticated GitHub user:" in text


def test_candidate_wrappers_stage_without_activating_or_bootstrapping():
    for name in ('Install GPT Controller.bat','Update GPT Controller.bat'):
        text = (ROOT/name).read_text(encoding='utf-8')
        assert 'install-candidate.ps1' in text
        assert '-Activate' not in text
        assert 'bootstrap-windows.ps1' not in text
        assert 'Candidate is staged only.' in text
