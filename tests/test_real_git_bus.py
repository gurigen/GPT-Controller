"""Git integration in temporary local bare repositories. Never contacts GitHub."""
import json
import subprocess
import sys
from dataclasses import replace
from pathlib import Path
import pytest
from test_real_runtime import make_config, job
from agent_runtime.git_bus import GitBus
from agent_runtime.resilient_bus import ResilientGitBus
from agent_runtime.executor import Executor
from agent_runtime.hardening.common import atomic_json, digest, state_root
from agent_runtime.hardening.control_poller import ControlPoller


def git(cwd,*args):
    result=subprocess.run(['git',*args],cwd=cwd,capture_output=True,check=True,timeout=15)
    return result.stdout.decode().strip()


def setup_bus(tmp_path):
    remote=tmp_path/'remote.git';git(tmp_path,'init','--bare',str(remote))
    seed=tmp_path/'seed';seed.mkdir();git(seed,'init')
    git(seed,'config','user.name','Test');git(seed,'config','user.email','test@example.invalid')
    for path in ['queue/pending','queue/running','queue/done','queue/ambiguous','queue/rejected','claims','results','rejections']:
        folder=seed/path;folder.mkdir(parents=True);(folder/'.gitkeep').touch()
    git(seed,'add','.');git(seed,'commit','-m','seed');git(seed,'branch','-M','gpt-controller-control')
    git(seed,'remote','add','origin',str(remote));git(seed,'push','-u','origin','gpt-controller-control')
    configs=[]
    for name in ['agent-a','agent-b']:
        config,path=make_config(tmp_path/name)
        config.repo_path.rmdir()
        git(tmp_path,'clone','--branch','gpt-controller-control',str(remote),str(config.repo_path))
        configs.append(config)
    return remote,seed,configs


def enqueue(seed,action):
    atomic_json(seed/f'queue/pending/{action["id"]}.json',action)
    git(seed,'add','.');git(seed,'commit','-m','enqueue');git(seed,'push')


def test_two_real_clones_cannot_claim_same_pending_action(tmp_path):
    _,seed,configs=setup_bus(tmp_path)
    action=job([{'type':'noop'}]);action['target']={'mode':'any'}
    enqueue(seed,action)
    buses=[GitBus(config) for config in configs]
    for bus in buses:bus.sync()
    first=buses[0].claim(buses[0].repo/'queue/pending/job.json')
    second=buses[1].claim(buses[1].repo/'queue/pending/job.json')
    assert first is not None and second is None
    git(seed,'pull','--ff-only')
    claim=json.loads((seed/'claims/job.json').read_text(encoding='utf-8'))
    assert claim['action_sha256']==digest(action)


def test_real_claim_rejects_reinserted_action_id_before_result(tmp_path):
    _,seed,configs=setup_bus(tmp_path)
    action=job([{'type':'noop'}]);enqueue(seed,action)
    first=GitBus(configs[0]);first.sync();assert first.claim(first.repo/'queue/pending/job.json')
    git(seed,'pull','--ff-only');enqueue(seed,action)
    second=GitBus(configs[1]);second.sync()
    with pytest.raises(ValueError,match='REPLAY_REJECTED'):
        second.claim(second.repo/'queue/pending/job.json')


def test_result_outbox_recovers_without_reexecuting_work(tmp_path,monkeypatch):
    _,seed,configs=setup_bus(tmp_path)
    action=job([{'type':'file.append','path':'counter','text':'x'}]);enqueue(seed,action)
    bus=ResilientGitBus(configs[0]);bus.sync();claimed,running=bus.claim(bus.repo/'queue/pending/job.json')
    result=Executor(configs[0]).execute(claimed)
    real_git=bus._git
    def disconnected(*args,**kwargs):
        if args[0] in {'push','pull'}:
            return {'exit_code':128,'stdout':'','stderr':'simulated disconnection'}
        return real_git(*args,**kwargs)
    monkeypatch.setattr(bus,'_git',disconnected)
    with pytest.raises(RuntimeError,match='outbox'):
        bus.finish(claimed,running,result)
    assert (state_root(configs[0])/'outbox/job.json').exists()
    recovered=ResilientGitBus(configs[0]);recovered.sync()
    assert not (state_root(configs[0])/'outbox/job.json').exists()
    git(seed,'pull','--ff-only')
    published=json.loads((seed/'results/job.json').read_text(encoding='utf-8'))
    assert published['status']=='succeeded' and published['action_sha256']==digest(action)
    assert (configs[0].workspaces['scratch']/'counter').read_text(encoding='utf-8')=='x'


def test_porcelain_repair_preserves_columns_and_refuses_unrelated_changes(tmp_path):
    _,_,configs=setup_bus(tmp_path)
    bus=ResilientGitBus(configs[0]);bus.sync()
    target=bus.repo/'results/.gitkeep';target.write_text('crash residue')
    assert bus.repair_control_repo() is True
    assert target.read_text(encoding='utf-8')==''
    private=bus.repo/'not-owned.txt';private.write_text('preserve')
    with pytest.raises(RuntimeError,match='unexpected'):
        bus.repair_control_repo()
    assert private.read_text(encoding='utf-8')=='preserve'


def test_independent_cancel_poller_and_manifest_publish(tmp_path):
    _,seed,configs=setup_bus(tmp_path)
    atomic_json(seed/'control/cancel/active.json',{'action_id':'active','cancel':True})
    git(seed,'add','.');git(seed,'commit','-m','cancel');git(seed,'push')
    poller=ControlPoller(configs[0],lambda:'active')
    original_head=git(configs[0].repo_path,'rev-parse','HEAD')
    poller.poll()
    assert (state_root(configs[0])/'cancel/active.json').exists()
    assert git(configs[0].repo_path,'rev-parse','HEAD')==original_head
    assert not git(configs[0].repo_path,'status','--porcelain')
    git(seed,'pull','--ff-only')
    manifest=json.loads((seed/'agents/test-agent/manifest.json').read_text(encoding='utf-8'))
    status=json.loads((seed/'agents/test-agent/status.json').read_text(encoding='utf-8'))
    assert manifest['agent_id']=='test-agent' and manifest['gui_ready'] is None
    assert status['state']=='executing' and status['action_id']=='active'
    assert 'valid_until' in status
    assert (seed/'control/cancel/active.json').exists()
