import hashlib
import json
from pathlib import Path
import subprocess
import sys
import pytest
from agent_runtime.hardening.common import identifier
from agent_runtime.hardening.operations import BROWSER, UI, schema
from agent_runtime.hardening.validation import BROWSER_OPS, UI_OPS
from agent_runtime import __version__
from test_real_runtime import make_config
ROOT=Path(__file__).resolve().parents[1]


def test_manifest_is_complete_and_matches_static_source():
    manifest=json.loads((ROOT/'SOURCE_MANIFEST.json').read_text())
    assert manifest['base_tree']=='158f8361cba27442fa5b7cb1b1d47f04f8940593'
    assert len(manifest['files'])>=100
    for name, expected in manifest['files'].items():
        assert hashlib.sha256((ROOT/name).read_bytes()).hexdigest()==expected,name
    assert __version__=='4.1.0rc2'


def test_operation_registry_and_published_schema_are_consistent():
    assert set(BROWSER)==BROWSER_OPS
    assert set(UI)==UI_OPS
    public=json.loads((ROOT/'schemas/action.schema.json').read_text())
    assert public['$defs']['browserOperation']==schema(True)
    assert public['$defs']['uiOperation']==schema(False)


def test_doctor_required_git_fails_for_unavailable_remote(tmp_path):
    _, path=make_config(tmp_path)
    process=subprocess.run([sys.executable,'-m','agent_runtime.hardening.cli','--config',str(path),
        'doctor','--no-ui','--require-git'],capture_output=True,text=True,timeout=15)
    assert process.returncode!=0
    result=json.loads(process.stdout)
    assert result['git']['status']=='unavailable'


def test_doctor_cannot_claim_gui_verified_without_probe(tmp_path):
    _, path=make_config(tmp_path)
    process=subprocess.run([sys.executable,'-m','agent_runtime.hardening.cli','--config',str(path),
        'doctor','--no-ui','--require-ui'],capture_output=True,text=True,timeout=10)
    assert process.returncode!=0


def test_installation_activation_is_opt_in_and_preserves_old_environment():
    # Static Windows script contract only; actual task-switch/rollback is NOT tested here.
    text=(ROOT/'scripts/install-candidate.ps1').read_text()
    assert '[switch]$Activate' in text
    assert 'SOURCE_MANIFEST.json' in text
    assert 'requirements-frozen.txt' in text
    assert 'Register-ScheduledTask -TaskName $saved.Name -Xml $saved.Xml' in text
    assert 'Old process termination was not confirmed' in text
    assert 'git reset' not in text
    assert 'Remove-Item -LiteralPath $ControlPath' not in text


@pytest.mark.parametrize("value",["CON","con.txt","PRN","AUX","NUL","COM1","LPT9","trailing."])
def test_ids_reject_windows_device_names_and_aliases(value):
    with pytest.raises(ValueError):
        identifier(value)


def test_candidate_staging_uses_complete_evidence_and_does_not_accept_skips():
    text=(ROOT/'scripts/install-candidate.ps1').read_text()
    assert 'scripts\\run-verification.py' in text
    assert 'coverage_complete -ne $true' in text
    assert 'source_unchanged -ne $true' in text
    assert 'skipped -gt 0' in text
    assert 'verification_status_sha256=' in text
