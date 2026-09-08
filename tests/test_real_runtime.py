"""Integration tests against the patched upstream Config/Executor/Worker/Supervisor.

Uses only temporary files and local Python children, never a user's PC or account.
"""
import json
import os
import sys
import threading
import time
from dataclasses import replace
from pathlib import Path
import pytest
from agent_runtime.config import Config
from agent_runtime.executor import Executor
from agent_runtime.process_supervisor import ActionSupervisor
from agent_runtime.hardening.common import atomic_json, digest, state_root
from agent_runtime.hardening.control import Control
from agent_runtime.hardening.state import Ledger


def make_config(root, **overrides):
    root.mkdir(parents=True,exist_ok=True)
    control=root/'control'; control.mkdir(exist_ok=True)
    scratch=root/'scratch'; scratch.mkdir(exist_ok=True)
    raw={'control_repo':str(control),'agent_id':'test-agent','workspaces':{'scratch':str(scratch)},
         'capabilities':['general','git','browser','windows-ui'],'default_timeout_seconds':10,
         'max_output_bytes':65536,'managed_git_workspaces':[],
         'interactive_host':{'spool':str(root/'ipc'),'timeout_seconds':3},**overrides}
    path=root/'config.json';atomic_json(path,raw)
    return Config.load(path),path


def job(steps, ident='job', **extra):
    return {'protocol':'q-agent-v4','id':ident,'workspace':'scratch',
            'target':{'mode':'agent','agent':'test-agent'},'steps':steps,**extra}


def supervisor(config,path):
    item=ActionSupervisor(config,path);item.POLL_SECONDS=.02
    return item


def test_real_worker_writes_unicode_csv_and_verifies_goal(tmp_path):
    config,path=make_config(tmp_path)
    action=job([{'type':'file.write','path':'sample.csv','text':'名前,score\n日本😀,42\n'}],
        goal={'description':'CSV saved','conditions':[{'type':'csv.columns','workspace':'scratch','path':'sample.csv','columns':['名前','score']}]})
    result=supervisor(config,path).execute(action)
    assert result['status']=='succeeded',result
    assert result['goal']['goal_achieved'] is True
    assert result['supervisor']['isolated_worker'] is True
    assert result['action_sha256']==digest(action)
    assert (config.workspaces['scratch']/'sample.csv').read_text(encoding='utf-8')=='名前,score\n日本😀,42\n'


def test_real_worker_deduplicates_across_distinct_worker_processes(tmp_path):
    config,path=make_config(tmp_path)
    action=job([{'type':'file.append','path':'count.txt','text':'x'}])
    runner=supervisor(config,path)
    assert runner.execute(action)['status']=='succeeded'
    result=runner.execute(action)
    assert result['cached_result'] is True
    assert (config.workspaces['scratch']/'count.txt').read_text()=='x'


def test_real_worker_side_effect_then_error_is_never_replayed(tmp_path):
    config,path=make_config(tmp_path)
    code='from pathlib import Path; p=Path("count.txt"); p.open("a").write("x"); raise RuntimeError("reply lost")'
    action=job([{'type':'desktop.loop','session':'failure','retry_attempts':20,'steps':[
        {'type':'process.exec','program':sys.executable,'args':['-c',code]}]}],resume_from_checkpoint=True,resume_attempts=10)
    result=supervisor(config,path).execute(action)
    assert result['status']=='ambiguous',result
    assert (config.workspaces['scratch']/'count.txt').read_text()=='x'


def test_real_worker_rejects_unknown_operation_before_first_write(tmp_path):
    config,path=make_config(tmp_path)
    action=job([{'type':'file.write','path':'bad.txt','text':'must not exist'},
                {'type':'windows.ui','desktop':True,'actions':[{'op':'click_typo'}]}])
    result=supervisor(config,path).execute(action)
    assert result['status']=='failed'
    assert not (config.workspaces['scratch']/'bad.txt').exists()


def test_real_worker_requires_goal_not_merely_successful_noop(tmp_path):
    config,path=make_config(tmp_path)
    action=job([{'type':'noop'}],goal={'description':'file exists','conditions':[{'type':'file.exists','workspace':'scratch','path':'not-created'}]})
    result=supervisor(config,path).execute(action)
    assert result['status']=='failed'
    assert not result['goal']['goal_achieved']


def test_external_cancel_stops_child_before_late_file_write(tmp_path):
    config,path=make_config(tmp_path)
    marker=config.workspaces['scratch']/'started'
    code='from pathlib import Path; import time; Path("started").write_text("1"); time.sleep(4); Path("late").write_text("BAD")'
    action=job([{'type':'process.exec','program':sys.executable,'args':['-c',code]}])
    def cancel():
        deadline=time.monotonic()+5
        while not marker.exists() and time.monotonic()<deadline:time.sleep(.01)
        Control(config).cancel('job')
    thread=threading.Thread(target=cancel);thread.start()
    result=supervisor(config,path).execute(action)
    thread.join(timeout=5)
    assert result['status'] in {'cancelled','ambiguous'}
    assert marker.exists()
    time.sleep(4.2)  # prove no delayed side effect after the killed worker returned
    assert not (config.workspaces['scratch']/'late').exists()
    assert 'cancellation' in result.get('error','')


def test_continue_on_error_cannot_override_unknown_side_effect(tmp_path):
    config,_=make_config(tmp_path)
    action=job([{'type':'process.exec','program':sys.executable,'args':['-c','raise RuntimeError("unknown")'],'continue_on_error':True},
                {'type':'file.write','path':'should-not-exist','text':'x'}])
    result=Executor(config).execute(action)
    assert result['status']=='ambiguous'
    assert not (config.workspaces['scratch']/'should-not-exist').exists()


def test_dependency_checks_payload_and_success(tmp_path):
    config,_=make_config(tmp_path)
    first=job([{'type':'noop'}],ident='first')
    result=Executor(config).execute(first)
    atomic_json(config.repo_path/'results/first.json',result)
    dependent=job([{'type':'file.write','path':'dependent','text':'yes'}],ident='second',
        depends_on=[{'action_id':'first','action_sha256':digest(first)}])
    assert Executor(config).execute(dependent)['status']=='succeeded'
    broken=job([{'type':'file.write','path':'broken','text':'no'}],ident='third',
        depends_on=[{'action_id':'first','action_sha256':'0'*64}])
    assert Executor(config).execute(broken)['status']=='blocked'
    assert not (config.workspaces['scratch']/'broken').exists()


def test_dependency_may_not_hide_failed_goal(tmp_path):
    config,_=make_config(tmp_path)
    atomic_json(config.repo_path/'results/prior.json',{'status':'succeeded','action_id':'prior','action_sha256':'a'*64,'goal':{'goal_achieved':False}})
    action=job([{'type':'noop'}],depends_on=[{'action_id':'prior','action_sha256':'a'*64}])
    assert Executor(config).execute(action)['status']=='blocked'


def test_output_bounds_use_real_two_stream_process(tmp_path):
    from agent_runtime.util import run_process
    result=run_process([sys.executable,'-c','import sys; sys.stdout.write("x"*5_000_000); sys.stderr.write("y"*5_000_000)'],timeout=10,max_output_bytes=4096)
    assert result['exit_code']==0
    assert len(result['stdout'])==len(result['stderr'])==4096
    assert result['stdout_truncated'] and result['stderr_truncated']
    assert result['stdout_bytes_seen']==result['stderr_bytes_seen']==5_000_000
    assert result['streams_closed']


def test_approval_required_does_not_consume_execution_slot(tmp_path):
    config,_=make_config(tmp_path)
    target=config.workspaces['scratch']/'file';target.write_text('original')
    action=job([{'type':'file.delete','path':'file'}])
    assert Executor(config).execute(action)['status']=='needs_user'
    ledger=Ledger(state_root(config)/'execution.sqlite3')
    assert ledger.action('job') is None
    ledger.approve('job',digest(action))
    assert Executor(config).execute(action)['status']=='succeeded'
    assert not target.exists()
