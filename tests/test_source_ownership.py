from pathlib import Path
ROOT = Path(__file__).resolve().parents[1]


def test_bootstrap_uses_gurigen_source_by_default():
    text = (ROOT / "scripts/bootstrap-windows.ps1").read_text(encoding="utf-8")
    assert "https://github.com/gurigen/GPT-Controller.git" in text
    assert "umimi893/GPT-Controller" not in text


def test_operational_scripts_do_not_depend_on_old_account():
    for path in (ROOT / "scripts").glob("*.ps1"):
        assert "umimi893/GPT-Controller" not in path.read_text(encoding="utf-8"), str(path)


def test_source_does_not_contain_private_command_bus():
    for name in ("queue", "results", "claims", "agent.config.json"):
        assert not (ROOT / name).exists(), name
