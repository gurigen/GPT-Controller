from __future__ import annotations
import sys
from pathlib import Path
from types import SimpleNamespace
import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT/'src'))
sys.path.insert(0, str(ROOT))

from agent_runtime.hardening import integration
from agent_runtime.hardening.processes import run_process


@pytest.fixture
def config(tmp_path):
    control = tmp_path/'control'
    control.mkdir()
    workspace = tmp_path/'scratch'
    workspace.mkdir()
    return SimpleNamespace(
        repo_path=control, agent_id='test-agent', capabilities=frozenset({'general','git','browser','windows-ui'}),
        workspaces={'scratch':workspace}, allow_absolute_paths=False,
        max_output_bytes=65536, default_timeout_seconds=10,
        interactive_spool=tmp_path/'interactive', interactive_timeout_seconds=5,
        non_interference=True, allow_physical_input=False, allow_foreground_activation=False,
        allow_visible_gui_launch=False, browser_headless_only=True,
        security={}, git='git', powershell='pwsh', remote='origin', branch='gpt-controller-control', poll_seconds=1,
    )


def action(steps, ident='action-1', **kwargs):
    return {'protocol':'q-agent-v4','id':ident,'target':{'mode':'agent','agent':'test-agent'},
            'workspace':'scratch','steps':steps, **kwargs}


class FixtureExecutor:
    """Adapter harness, NOT a claim to execute the unmodified upstream repository.

    Uses the new production guards, filesystem/process code and real SQLite/files.
    Legacy completion/exception handling is represented by the small loop below.
    """
    def __init__(self, config, handler=None):
        self.config=config
        self.interactive=SimpleNamespace()
        self.handler=handler
        self.calls=0
    def execute(self, value):
        return integration.execute(self,value,self.legacy)
    def legacy(self,value):
        result={'protocol':'q-agent-v4-result','action_id':value['id'],'agent_id':self.config.agent_id,
                'status':'succeeded','steps':[],'error':None}
        for index,item in enumerate(value['steps']):
            try:
                output=self._step(value,item)
                result['steps'].append({'index':index,'type':item['type'],'status':'succeeded','result':output})
            except Exception as exc:
                result['status']='failed'; result['error']=str(exc)
                result['steps'].append({'index':index,'type':item['type'],'status':'failed','error':str(exc)})
                if not item.get('continue_on_error'):break
        return result
    def _step(self,value,item):
        return integration.step(self,value,item,self.raw)
    def raw(self,value,item):
        self.calls+=1
        if self.handler:
            return self.handler(value,item)
        if item['type']=='noop':return {'ok':True}
        if item['type']=='process.exec':
            return run_process([item['program'],*item.get('args',[])],self.config.workspaces.get(item.get('workspace','scratch')),item.get('timeout_seconds',10),max_output_bytes=self.config.max_output_bytes)
        raise RuntimeError('legacy adapter not represented in this harness')
