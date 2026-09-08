import os
from pathlib import Path
import shutil
import subprocess
import pytest

ROOT = Path(__file__).resolve().parents[1]


def test_installer_identity_guard_compares_resolved_sids():
    text = (ROOT / "scripts/install-candidate.ps1").read_text(encoding="utf-8")
    assert "Test-SameWindowsIdentity -Principal $principal -Identity $current" in text
    assert "Translate([Security.Principal.SecurityIdentifier])" in text
    assert "if ($principal -notin" not in text


@pytest.mark.skipif(os.name != "nt", reason="Windows identity APIs require Windows")
@pytest.mark.parametrize("shell", ["powershell.exe", "pwsh.exe"])
@pytest.mark.parametrize("case", ["short", "qualified", "sid", "other_sid", "unknown", "empty"])
def test_native_installer_identity_resolution(shell, case):
    exe = shutil.which(shell)
    if not exe:
        pytest.skip(shell + " unavailable")
    source = str(ROOT / "scripts/install-candidate.ps1").replace("'", "''")
    script = """$ErrorActionPreference='Stop'
$tokens=$null; $errors=$null
$ast=[System.Management.Automation.Language.Parser]::ParseFile('%s',[ref]$tokens,[ref]$errors)
if($errors.Count){throw 'Installer parse error'}
$function=$ast.Find({param($node) $node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -eq 'Test-SameWindowsIdentity'},$true)
if($null -eq $function){throw 'Identity helper missing'}
. ([scriptblock]::Create($function.Extent.Text))
$current=[Security.Principal.WindowsIdentity]::GetCurrent()
$case='%s'
switch($case){
 'short' {$value=$env:USERNAME;$expected=$true}
 'qualified' {$value=$current.Name;$expected=$true}
 'sid' {$value=$current.User.Value;$expected=$true}
 'other_sid' {$value='S-1-0-0';$expected=$false}
 'unknown' {$value='GPTControllerNoSuchUser9382';$expected=$false}
 'empty' {$value='';$expected=$false}
 default {throw 'Unexpected test case'}
}
$actual=Test-SameWindowsIdentity -Principal $value -Identity $current
if($actual -ne $expected){throw 'Identity comparison returned an unexpected decision'}
'passed'
""" % (source, case)
    p = subprocess.run([exe, "-NoLogo", "-NoProfile", "-NonInteractive", "-Command", script],
                       capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=30)
    assert p.returncode == 0, p.stderr
    assert "passed" in p.stdout
