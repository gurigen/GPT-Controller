import hashlib
import sys
from pathlib import Path
import pytest
from conftest import action, FixtureExecutor
from agent_runtime.hardening.common import digest, state_root, load_json, atomic_json, ControlError
from agent_runtime.hardening.state import Ledger


def test_goal_requires_evidence_not_just_exit_zero(config):
    job=action([{'type':'noop'}],goal={'description':'CSV saved','conditions':[{'type':'file.exists','workspace':'scratch','path':'missing.csv'}]})
    result=FixtureExecutor(config).execute(job)
    assert result['status']=='failed'
    assert result['goal']['goal_achieved'] is False


def test_real_file_creation_and_goal_success(config):
    job=action([{'type':'file.write','path':'data.csv','text':'name,score\n日本語,10\n'}],goal={'description':'CSV saved','conditions':[{'type':'csv.columns','workspace':'scratch','path':'data.csv','columns':['name','score']}]})
    result=FixtureExecutor(config).execute(job)
    assert result['status']=='succeeded'
    assert result['goal']['goal_achieved'] is True
    assert (config.workspaces['scratch']/'data.csv').exists()


def test_same_action_returns_cached_result_without_side_effect(config):
    engine=FixtureExecutor(config)
    job=action([{'type':'file.append','path':'counter.txt','text':'x'}])
    assert engine.execute(job)['status']=='succeeded'
    again=engine.execute(job)
    assert again['cached_result'] is True
    assert (config.workspaces['scratch']/'counter.txt').read_text()=='x'


def test_same_id_different_payload_rejected(config):
    engine=FixtureExecutor(config)
    first=action([{'type':'file.append','path':'counter','text':'a'}])
    second=action([{'type':'file.append','path':'counter','text':'b'}])
    engine.execute(first)
    assert engine.execute(second)['status']=='blocked'
    assert (config.workspaces['scratch']/'counter').read_text()=='a'


def test_existing_started_action_becomes_ambiguous(config):
    job=action([{'type':'noop'}]);ledger=Ledger(state_root(config)/'execution.sqlite3')
    ledger.begin(job['id'],digest(job))
    result=FixtureExecutor(config).execute(job)
    assert result['status']=='ambiguous'


def test_real_process_side_effect_then_error_is_not_retried(config):
    marker=config.workspaces['scratch']/'counter'
    script='from pathlib import Path; p=Path("counter"); p.write_text((p.read_text() if p.exists() else "")+"x"); raise RuntimeError("reply failed")'
    job=action([{'type':'desktop.loop','session':'no-repeat','retry_delay_seconds':0,'steps':[{'type':'process.exec','program':sys.executable,'args':['-c',script]}]}])
    result=FixtureExecutor(config).execute(job)
    assert result['status']=='ambiguous'
    assert marker.read_text()=='x'


def test_read_only_retry_has_no_more_than_configured_attempts(config):
    calls=[]
    def handler(a,s):
        calls.append(1)
        raise RuntimeError('temporary read failure')
    # Existing agent.info is read-only; the adapter deliberately injects read errors.
    result=FixtureExecutor(config,handler).execute(action([{'type':'desktop.loop','session':'read-retry','retry_delay_seconds':0,'steps':[{'type':'agent.info'}]}]))
    assert len(calls)==3
    assert result['status']=='failed'


def test_until_failure_never_becomes_completed_on_resume(config):
    engine=FixtureExecutor(config)
    loop={'type':'desktop.loop','session':'until-test','max_cycles':1,'require_until':True,'until':{'source':0,'path':'result.ok','equals':False},'steps':[{'type':'noop'}]}
    first=engine.execute(action([loop],ident='one'))
    assert first['status']=='failed'
    checkpoint=load_json(state_root(config)/'workflows'/'until-test.json')
    assert checkpoint['status']=='exhausted'
    second=engine.execute(action([{**loop,'resume_from_action':'one'}],ident='two'))
    assert second['status']=='failed'


def test_checkpoint_requires_explicit_cross_action_reference(config):
    loop={'type':'desktop.loop','session':'same-session','steps':[{'type':'noop'}]}
    engine=FixtureExecutor(config)
    assert engine.execute(action([loop],ident='old'))['status']=='succeeded'
    assert engine.execute(action([loop],ident='new'))['status']=='blocked'


def test_checkpoint_rejects_changed_steps(config):
    engine=FixtureExecutor(config)
    loop={'type':'desktop.loop','session':'bound','steps':[{'type':'noop'}]}
    engine.execute(action([loop],ident='old'))
    changed={**loop,'resume_from_action':'old','steps':[{'type':'file.append','path':'x','text':'x'}]}
    assert engine.execute(action([changed],ident='new'))['status']=='blocked'
    assert not (config.workspaces['scratch']/'x').exists()


def test_checkpoint_correct_explicit_resume_does_not_repeat(config):
    engine=FixtureExecutor(config)
    loop={'type':'desktop.loop','session':'bound','steps':[{'type':'file.append','path':'x','text':'x'}]}
    assert engine.execute(action([loop],ident='old'))['status']=='succeeded'
    assert engine.execute(action([{**loop,'resume_from_action':'old'}],ident='new'))['status']=='succeeded'
    assert (config.workspaces['scratch']/'x').read_text()=='x'


def test_in_progress_side_effect_blocks_resume(config):
    engine=FixtureExecutor(config)
    loop={'type':'desktop.loop','session':'bound','steps':[{'type':'file.append','path':'x','text':'x'}]}
    engine.execute(action([loop],ident='old'))
    file=state_root(config)/'workflows'/'bound.json'; record=load_json(file)
    record.update(status='running',next_step=0,in_progress={'effect':'non_idempotent'})
    atomic_json(file,record)
    assert engine.execute(action([{**loop,'resume_from_action':'old'}],ident='new'))['status']=='ambiguous'
    assert (config.workspaces['scratch']/'x').read_text()=='x'


def test_workspace_inheritance_matches_execution(config,tmp_path):
    second=tmp_path/'second'; second.mkdir();config.workspaces['second']=second
    job=action([{'type':'desktop.loop','session':'workspace','workspace':'second','steps':[{'type':'file.write','path':'result','text':'right workspace'}]}])
    result=FixtureExecutor(config).execute(job)
    assert result['status']=='succeeded'
    assert (second/'result').exists()
    assert not (config.workspaces['scratch']/'result').exists()


def test_validation_happens_before_valid_initial_step(config):
    engine=FixtureExecutor(config)
    result=engine.execute(action([{'type':'file.append','path':'x','text':'x'},{'type':'windows.ui','desktop':True,'actions':[{'op':'unknown'}]}]))
    assert result['status']=='failed'
    assert not (config.workspaces['scratch']/'x').exists()


def test_restricted_shell_denied_before_execution(config):
    config.security={'mode':'restricted'}
    engine=FixtureExecutor(config)
    result=engine.execute(action([{'type':'process.exec','program':sys.executable,'args':['-c','print("x")']}]))
    assert result['status']=='blocked'
    assert engine.calls==0


def test_explicit_local_approval_is_bound_and_single_use(config):
    path=config.workspaces['scratch']/'x';path.write_text('x')
    engine=FixtureExecutor(config)
    job=action([{'type':'file.delete','path':'x'}])
    ledger=Ledger(state_root(config)/'execution.sqlite3')
    ledger.approve(job['id'],digest(job))
    result=engine.execute(job)
    assert result['status']=='succeeded'
    assert not path.exists()
    assert ledger.consume_approval(job['id'],digest(job)) is False
    assert Path(result['steps'][0]['result']['recovery_path']).read_text()=='x'


def test_unapproved_delete_has_no_side_effect(config):
    path=config.workspaces['scratch']/'x';path.write_text('x')
    result=FixtureExecutor(config).execute(action([{'type':'file.delete','path':'x'}]))
    assert result['status']=='needs_user';assert path.exists()


def test_wrong_agent_does_not_execute(config):
    job=action([{'type':'file.append','path':'x','text':'x'}]);job['target']['agent']='someone-else'
    assert FixtureExecutor(config).execute(job)['status']=='blocked'
    assert not (config.workspaces['scratch']/'x').exists()


def test_missing_capability_is_not_inferred_from_requires(config):
    config.capabilities=frozenset({'general'})
    job=action([{'type':'desktop.observe'}])
    assert FixtureExecutor(config).execute(job)['status']=='blocked'


def test_stale_destination_refuses_overwrite(config):
    path=config.workspaces['scratch']/'x';path.write_text('original')
    job=action([{'type':'file.write','path':'x','text':'new','overwrite':True,'expected_sha256':'0'*64}])
    assert FixtureExecutor(config).execute(job)['status']=='blocked'
    assert path.read_text()=='original'


def test_valid_destination_hash_allows_atomic_update(config):
    path=config.workspaces['scratch']/'x';path.write_text('original')
    job=action([{'type':'file.write','path':'x','text':'new','overwrite':True,'expected_sha256':hashlib.sha256(b'original').hexdigest()}])
    assert FixtureExecutor(config).execute(job)['status']=='succeeded'
    assert path.read_text()=='new'
