"""Observe the real worker interpreter and imports before executing an Action."""
import json
import os
from pathlib import Path
import sys
from test_real_runtime import make_config, job, supervisor


def test_real_worker_and_child_use_candidate_interpreter_and_source(tmp_path, monkeypatch):
    config, path = make_config(tmp_path)
    runner = supervisor(config, path)
    original = runner._worker_argv
    observed = tmp_path / "worker-identity.json"
    probe = "import sys,os,json; from pathlib import Path; import agent_runtime,agent_runtime.hardening.common as common; "
    payload = "dict(executable=sys.executable,package=agent_runtime.__file__,common=common.__file__,path=sys.path,pythonpath=os.environ.get('PYTHONPATH'),cwd=os.getcwd())"
    wrapper = probe + "Path(" + repr(str(observed)) + ").write_text(json.dumps(" + payload + "),encoding='utf-8'); import runpy; runpy.run_module('agent_runtime.worker',run_name='__main__')"
    def argv(*args):
        value = original(*args)
        assert value[1:3] == ['-m', 'agent_runtime.worker']
        return [value[0], '-c', wrapper, *value[3:]]
    monkeypatch.setattr(runner, '_worker_argv', argv)
    child = probe + "Path('child-identity.json').write_text(json.dumps(" + payload + "),encoding='utf-8')"
    result = runner.execute(job([{'type':'process.exec','program':sys.executable,'args':['-c',child]}]))
    assert result['status'] == 'succeeded', result
    expected = Path(__file__).resolve().parents[1] / 'src'
    for file in (observed, config.workspaces['scratch'] / 'child-identity.json'):
        record = json.loads(file.read_text(encoding='utf-8'))
        assert Path(record['executable']).resolve() == Path(sys.executable).resolve()
        assert Path(record['package']).resolve().is_relative_to(expected)
        assert Path(record['common']).resolve().is_relative_to(expected)
        assert record['pythonpath'] == os.environ.get('PYTHONPATH')
