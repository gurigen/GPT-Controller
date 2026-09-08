"""Exercise evidence failures with real, isolated miniature pytest subprocesses."""
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
RUNNER = ROOT / 'scripts/run-verification.py'


def run_suite(tmp_path, files, *, timeout=10, output=None):
    root = tmp_path / 'miniature'
    root.mkdir(exist_ok=True)
    tests = root / 'tests'; tests.mkdir(exist_ok=True)
    for name, source in files.items():
        (tests / name).write_text(source, encoding='utf-8')
    output = output or tmp_path / 'evidence'
    command = [sys.executable, str(RUNNER), '--root', str(root), '--output', str(output),
               '--timeout', str(timeout)]
    env = dict(os.environ)
    env['PYTEST_DISABLE_PLUGIN_AUTOLOAD'] = '1'
    result = subprocess.run(command, env=env, text=True, capture_output=True, timeout=40)
    state = json.loads((output / 'status.json').read_text())
    assert state['finished_at'] and state['status'] != 'running', result.stdout + result.stderr
    return result, state, output


def test_runner_passes_exact_inventory_with_skips_and_unique_run_evidence(tmp_path):
    files = {'test_ok.py': "import pytest\n@pytest.mark.parametrize('n',[1,2],ids=['dotted.id','other'])\ndef test_case(n): assert n>0\n@pytest.mark.skip(reason='explicit platform acceptance not run')\ndef test_skipped(): pass\n"}
    result, state, output = run_suite(tmp_path, files)
    assert result.returncode == 0 and state['coverage_complete']
    assert (state['collected'], state['passed'], state['skipped'], state['failed']) == (3, 2, 1, 0)
    assert any('[dotted.id]' in case['nodeid'] for case in state['cases'])
    assert state['source_unchanged']
    _, next_state, _ = run_suite(tmp_path, files, output=output)
    assert next_state['run_id'] != state['run_id']
    assert (output / state['run_id'] / 'status.json').exists()


def test_runner_invalidates_old_success_and_continues_after_test_failure(tmp_path):
    output = tmp_path / 'evidence'; output.mkdir()
    (output / 'status.json').write_text('{"status":"passed","passed":999}')
    result, state, _ = run_suite(tmp_path, {
        'test_a.py': 'def test_failure(): assert False\n',
        'test_z.py': 'def test_still_runs(): assert True\n'}, output=output)
    assert result.returncode != 0 and state['status'] == 'failed'
    assert state['coverage_complete']
    assert (state['passed'], state['failed']) == (1, 1)
    assert len(state['runs']) == 2


def test_runner_records_collection_errors_and_still_runs_other_files(tmp_path):
    result, state, _ = run_suite(tmp_path, {
        'test_a.py': 'def broken(:\n', 'test_z.py': 'def test_still_runs(): pass\n'})
    assert result.returncode != 0 and not state['coverage_complete']
    assert state['collection_exit_code'] != 0
    assert state['passed'] == 1
    assert len(state['runs']) == 2


def test_runner_does_not_count_process_crash_as_success(tmp_path):
    result, state, _ = run_suite(tmp_path, {
        'test_a.py': 'import os\ndef test_crash(): os._exit(12)\n',
        'test_z.py': 'def test_still_runs(): pass\n'})
    assert result.returncode != 0 and not state['coverage_complete']
    assert state['incomplete'] == 1 and state['passed'] == 1
    assert any('completion' in msg for msg in state['evidence_errors'])


def test_runner_terminates_timed_out_file_and_continues(tmp_path):
    result, state, _ = run_suite(tmp_path, {
        'test_a.py': 'import time\ndef test_hang(): time.sleep(20)\n',
        'test_z.py': 'def test_still_runs(): pass\n'}, timeout=1.5)
    assert result.returncode != 0 and not state['coverage_complete']
    assert state['runs'][0]['timed_out']
    assert state['passed'] == 1 and state['incomplete'] == 1


def test_runner_rejects_source_mutation_during_run(tmp_path):
    result, state, _ = run_suite(tmp_path, {
        'test_change.py': "from pathlib import Path\ndef test_modify():\n p=Path(__file__)\n p.write_text(p.read_text()+'\\n# changed')\n"})
    assert result.returncode != 0 and state['passed'] == 1
    assert not state['source_unchanged'] and not state['coverage_complete']


def test_runner_rejects_duplicate_phase_evidence():
    spec = importlib.util.spec_from_file_location('runner_test_module', RUNNER)
    module = importlib.util.module_from_spec(spec); spec.loader.exec_module(module)
    node = 'tests/test_a.py::test_a'
    events = [{'event': 'inventory', 'nodeids': [node]}, *[
        {'event': 'phase', 'nodeid': node, 'when': phase, 'outcome': 'passed', 'seconds': 0}
        for phase in ('setup', 'call', 'call', 'teardown')]]
    state = module.summarize([node], [{'target': 'a', 'return_code': 0, 'timed_out': False,
                                     'errors': [], 'junit_cases': 1, 'events': events}])
    assert not state['coverage_complete'] and state['incomplete'] == 1


def test_runner_keeps_git_temporary_paths_short_with_deep_evidence_path(tmp_path):
    output = tmp_path / ('deep-' * 15) / 'evidence'
    result, state, _ = run_suite(tmp_path, {'test_tmp.py':
        "def test_local_git(tmp_path):\n import subprocess\n p=tmp_path/'repo.git'\n subprocess.run(['git','init','--bare',str(p)],check=True,capture_output=True)\n"}, output=output)
    assert result.returncode == 0 and state['passed'] == 1
    temporary = Path(state['runs'][0]['temporary_directory'])
    assert temporary.is_dir()
    assert not temporary.is_relative_to(output)
