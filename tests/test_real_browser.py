"""Real Chromium/CDP tests on a temporary, headless, isolated browser profile."""
import base64
import hashlib
import io
import json
import os
import shutil
import socket
import subprocess
import sys
import time
import urllib.request
from dataclasses import replace
from pathlib import Path
import pytest
from PIL import Image
from agent_runtime.process_supervisor import ActionSupervisor
from agent_runtime.hardening.artifacts import ArtifactStore
from test_real_runtime import make_config, job


@pytest.fixture
def chromium_session(tmp_path):
    executable=os.environ.get('GPT_TEST_CHROMIUM') or shutil.which('chromium') or shutil.which('google-chrome')
    from playwright.sync_api import sync_playwright
    if not executable:
        with sync_playwright() as probe:
            candidate = Path(probe.chromium.executable_path)
            if candidate.is_file():
                executable = str(candidate)
    if not executable:
        pytest.skip('Real Chromium executable not present; install browser and set GPT_TEST_CHROMIUM')
    sock=socket.socket();sock.bind(('127.0.0.1',0));port=sock.getsockname()[1];sock.close()
    test_flags = []  # Keep Chromium sandbox enabled on every platform.
    stderr_path = tmp_path / 'chromium-stderr.log'
    stderr_stream = stderr_path.open('wb')
    process=subprocess.Popen([executable, *test_flags, '--headless=new','--enable-automation','--disable-dev-shm-usage',
        '--remote-debugging-address=127.0.0.1',f'--remote-debugging-port={port}',
        f'--user-data-dir={tmp_path/"browser-profile"}','--no-first-run','about:blank'],
        stdout=subprocess.DEVNULL,stderr=stderr_stream)
    endpoint=f'http://127.0.0.1:{port}'
    try:
        deadline=time.monotonic()+10
        while True:
            try:
                with urllib.request.urlopen(endpoint+'/json/version',timeout=.5):break
            except Exception:
                if process.poll() is not None or time.monotonic()>deadline:
                    raise RuntimeError(f'test browser failed to start: exit={process.poll()}, stderr={stderr_path}')
                time.sleep(.05)
        with sync_playwright() as playwright:
            browser=playwright.chromium.connect_over_cdp(endpoint)
            context=browser.contexts[0]
            page=context.pages[0]
            page.set_content('<!doctype html><meta charset="utf-8"><title>Borrowed original</title><h1>Controller verification</h1><label>Name<input id="name"></label><p id="status">未入力</p><button onclick="document.getElementById(\'status\').textContent=document.getElementById(\'name\').value">Save</button>')
            config,_=make_config(tmp_path/'runtime',interaction_policy={'non_interference':False},browser={'headless_only':True,'cdp_endpoint':endpoint})
            yield config,page,context
            browser.close()
    finally:
        observed_exit = process.poll()
        process.terminate()
        try:process.wait(timeout=5)
        except subprocess.TimeoutExpired:process.kill();process.wait(5)
        stderr_stream.close()
        (tmp_path / 'chromium-exit.json').write_text(json.dumps({
            'executable': executable, 'observed_exit': observed_exit,
            'cleanup_exit': process.returncode, 'stderr': str(stderr_path),
            'args': process.args}), encoding='utf-8')


def test_real_cdp_owned_tab_cleanup_does_not_close_borrowed_tab(chromium_session):
    config,borrowed,context=chromium_session
    action=job([{'type':'browser.playwright','connection':'cdp','actions':[
        {'op':'switch_page','index':0},{'op':'fill','selector':'#name','text':'日本語😀'},
        {'op':'click','selector':'button'},{'op':'new_page'},{'op':'goto','url':'about:blank'},
        {'op':'switch_page','index':0},{'op':'text','selector':'#status'}]}])
    result=ActionSupervisor(config, config.repo_path.parent / "config.json").execute(action)
    assert result['status']=='succeeded',result
    assert not borrowed.is_closed()
    assert len(context.pages)==1
    assert borrowed.locator('#status').inner_text()=='日本語😀'


def test_real_cdp_missing_match_is_fail_closed(chromium_session):
    config,borrowed,context=chromium_session
    action=job([{'type':'browser.playwright','connection':'cdp','reuse_page':True,
        'page_match':{'title':'Nonexistent'},'actions':[{'op':'fill','selector':'#name','text':'WRONG'}]}])
    result=ActionSupervisor(config, config.repo_path.parent / "config.json").execute(action)
    assert result['status']!='succeeded'
    assert borrowed.locator('#name').input_value()==''
    assert not borrowed.is_closed()


def test_real_browser_png_reaches_decrypted_image(chromium_session,tmp_path):
    config,borrowed,context=chromium_session
    action=job([{'type':'browser.playwright','connection':'cdp','reuse_page':True,
        'page_match':{'title':'Borrowed original'},'actions':[{'op':'screenshot','path':'capture.png'}]}])
    result=ActionSupervisor(config, config.repo_path.parent / "config.json").execute(action)
    assert result['status']=='succeeded',result
    record=result['steps'][0]['result']['outputs'][0]['artifact']
    image_bytes=ArtifactStore(config).get(record['artifact_id'])[1]
    assert hashlib.sha256(image_bytes).hexdigest()==record['sha256']
    assert Image.open(io.BytesIO(image_bytes)).width>0
    exported=ArtifactStore(config).chunk(record['artifact_id'])
    assert base64.b64decode(exported['data'])==image_bytes
    assert not borrowed.is_closed()
    evidence=os.environ.get('GPT_VERIFICATION_IMAGE')
    if evidence:
        Path(evidence).write_bytes(image_bytes)


def test_real_browser_goal_checks_observed_state(chromium_session):
    config,borrowed,context=chromium_session
    action=job([{'type':'browser.playwright','connection':'cdp','reuse_page':True,
        'page_match':{'title':'Borrowed original'},'actions':[{'op':'fill','selector':'#name','text':'complete'},
        {'op':'click','selector':'button'},{'op':'text','selector':'#status'}]}],
        goal={'description':'UI saved text','conditions':[{'type':'output.matches','condition':{
            'source':0,'path':'result.outputs.2.text','equals':'complete'}}]})
    result=ActionSupervisor(config, config.repo_path.parent / "config.json").execute(action)
    assert result['status']=='succeeded' and result['goal']['goal_achieved']
