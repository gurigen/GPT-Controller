"""Authenticated filesystem IPC tests with harmless fake UI callbacks.

Real request/host/locking/cancellation code is exercised; actual Windows UI is not.
"""
import json
import os
import multiprocessing as mp
import threading
import time
from pathlib import Path
from types import SimpleNamespace
import pytest
from agent_runtime.hardening.common import ControlError, atomic_json, load_json
from agent_runtime.hardening.ipc import request, sign
from agent_runtime.hardening.control import Control
from agent_runtime.hardening.host import serve, before_operation


def host_process(config, mode='normal'):
    def ui(config, step):
        before_operation(config,step,{'op':'sleep','seconds':0})
        if mode=='slow':time.sleep(.5)
        before_operation(config,step,{'op':'sleep','seconds':0})
        marker=config.repo_path.parent/'host-completed'
        marker.write_text('done')
        return {'outputs':[{'op':'sleep','ok':True}]}
    serve(config,ui)


def start_host(config, mode='normal'):
    process=mp.get_context('spawn').Process(target=host_process,args=(config,mode))
    process.start()
    deadline=time.monotonic()+5
    while not (config.interactive_spool/'host-heartbeat.json').exists() and time.monotonic()<deadline:time.sleep(.02)
    return process


def test_real_host_authenticated_roundtrip(config):
    process=start_host(config)
    try:
        client=SimpleNamespace(config=config,action_id='roundtrip',action_sha256='a'*64)
        result=request(client,{'type':'windows.ui','desktop':True,'actions':[{'op':'sleep','seconds':0}]},2)
        assert result['outputs'][0]['ok'] is True
        assert (config.repo_path.parent/'host-completed').exists()
        deadline=time.monotonic()+1
        while list((config.interactive_spool/'processing').glob('*.json')) and time.monotonic()<deadline:time.sleep(.02)
        assert not list((config.interactive_spool/'processing').glob('*.json'))
    finally:
        process.terminate();process.join(3)


def test_unclaimed_timeout_cancels_without_quarantine(config):
    client=SimpleNamespace(config=config,action_id='unclaimed',action_sha256='b'*64)
    with pytest.raises(ControlError,match='cancelled'):
        request(client,{'type':'windows.ui','desktop':True,'actions':[{'op':'sleep','seconds':0}]},.1)
    assert not list((config.interactive_spool/'requests').glob('*.json'))
    assert not list((config.interactive_spool/'quarantine').glob('*.json'))


def test_inflight_timeout_quarantines_until_authenticated_stop(config):
    process=start_host(config,'slow')
    try:
        client=SimpleNamespace(config=config,action_id='slow',action_sha256='c'*64)
        with pytest.raises(ControlError,match='ambiguous'):
            request(client,{'type':'windows.ui','desktop':True,'actions':[{'op':'sleep','seconds':0}]},.2)
        with pytest.raises(ControlError,match='quarantined'):
            Control(config).check(input_operation=True)
        time.sleep(.6)
        Control(config).check(input_operation=True)
        assert not (config.repo_path.parent/'host-completed').exists()
    finally:
        process.terminate();process.join(3)


def test_unsigned_ack_cannot_clear_input_quarantine(config):
    root=config.interactive_spool
    Control(config).quarantine('req-1','unconfirmed')
    atomic_json(root/'responses/req-1.json',{'protocol':'q-agent-v4-interactive-response','id':'req-1','execution_finished':True,'status':'succeeded'})
    with pytest.raises(ControlError,match='quarantined'):
        Control(config).check(input_operation=True)
    assert (root/'quarantine/req-1.json').exists()


def test_host_restart_marks_claim_ambiguous_without_replay(config):
    root=config.interactive_spool
    payload={'protocol':'q-agent-v4-interactive-request','id':'old-claim','action_id':'old','action_sha256':'d'*64,
             'step':{'type':'windows.ui','desktop':True,'actions':[{'op':'sleep','seconds':0}]}}
    atomic_json(root/'processing/old-claim.json',sign(root,payload))
    process=start_host(config)
    try:
        result=load_json(root/'responses/old-claim.json')
        assert result['status']=='ambiguous' and result['execution_finished'] is True
        assert not (config.repo_path.parent/'host-completed').exists()
        assert not (root/'processing/old-claim.json').exists()
    finally:
        process.terminate();process.join(3)
