import json
import math
from datetime import datetime, timedelta, timezone
import pytest
from conftest import action
from agent_runtime.hardening.common import bounded_number, digest, identifier, load_json, atomic_json, timestamp
from agent_runtime.hardening.validation import validate_action_extra, finite_tree, condition_shape

@pytest.mark.parametrize('value',['../oops','/tmp/x','',None,'a/b','a\\b','a'*129])
def test_ids_reject_unsafe_values(value):
    with pytest.raises(ValueError):identifier(value)

@pytest.mark.parametrize('value',[False,True,'1',None,1.5,float('nan'),float('inf'),0,-1,86401])
def test_timeout_must_be_bounded_integer(value):
    with pytest.raises(ValueError):validate_action_extra(action([{'type':'noop'}],timeout_seconds=value))

@pytest.mark.parametrize('key',['non_interference','allow_physical_input','allow_absolute_paths','overwrite','continue_on_error','restore_clipboard'])
def test_boolean_strings_are_not_permissions(key):
    with pytest.raises(ValueError):finite_tree({key:'false'})

@pytest.mark.parametrize('op',['typo_click','think','run_script','CLICK'])
def test_unknown_suboperation_rejected_before_any_execution(op):
    with pytest.raises(ValueError):validate_action_extra(action([{'type':'windows.ui','desktop':True,'actions':[{'op':'click_at','coords':[1,2]},{'op':op}]}]))

@pytest.mark.parametrize('point',[[1],['1',2],[1,False],[float('nan'),1],[200000,1]])
def test_points_are_strict(point):
    with pytest.raises(ValueError):validate_action_extra(action([{'type':'windows.ui','desktop':True,'actions':[{'op':'click_at','coords':point}]}]))

def test_dict_key_order_does_not_change_hash():
    assert digest({'x':1,'a':'日本語'})==digest({'a':'日本語','x':1})

def test_content_change_changes_hash():
    assert digest({'x':1})!=digest({'x':2})

def test_load_rejects_duplicate_keys_and_nonfinite(tmp_path):
    file=tmp_path/'x.json'
    for content in ['{"x":1,"x":2}','{"x": NaN}']:
        file.write_text(content)
        with pytest.raises(ValueError):load_json(file)

def test_json_size_limit(tmp_path):
    file=tmp_path/'x.json';file.write_text('"'+'x'*100+'"')
    with pytest.raises(ValueError):load_json(file,max_bytes=50)

def test_atomic_write_roundtrip_unicode(tmp_path):
    file=tmp_path/'new'/'x.json';atomic_json(file,{'text':'こんにちは😀'})
    assert load_json(file)=={'text':'こんにちは😀'}
    assert list(file.parent.iterdir())==[file]

@pytest.mark.parametrize('condition',[{}, {'all':[]},{'any':[]},{'equals':1,'not_equals':2},{'matches':'(a+)+$'},{'truthy':'false'}])
def test_invalid_conditions_fail_closed(condition):
    with pytest.raises(ValueError):condition_shape(condition)

def test_no_timezone_is_rejected():
    with pytest.raises(ValueError):timestamp('2026-09-08T10:00:00')

def test_new_protocol_not_silently_selected():
    value=action([{'type':'noop'}]);value['protocol']='q-agent-v5'
    with pytest.raises(ValueError):validate_action_extra(value)

def test_cdp_requires_exact_agent():
    value=action([{'type':'browser.playwright','connection':'cdp','actions':[{'op':'title'}]}]);value['target']={'mode':'any'}
    with pytest.raises(ValueError):validate_action_extra(value)

def test_target_agent_id_typo_rejected():
    value=action([{'type':'desktop.observe'}]);value['target']={'mode':'agent','agent_id':'test-agent'}
    with pytest.raises(ValueError):validate_action_extra(value)

def test_nested_workspace_shape_is_valid():
    validate_action_extra(action([{'type':'desktop.loop','session':'job','workspace':'scratch','steps':[{'type':'file.write','path':'x','text':'y'}]}]))

def test_unknown_top_level_step_rejected():
    with pytest.raises(ValueError):validate_action_extra(action([{'type':'think'}]))
