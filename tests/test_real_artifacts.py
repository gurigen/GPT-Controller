import base64
import hashlib
import io
import json
import secrets
import sqlite3
import threading
import urllib.error
import urllib.request
from pathlib import Path
from PIL import Image
import pytest
from agent_runtime.hardening.artifacts import ArtifactStore, create_http_server
from agent_runtime.hardening.common import state_root


def png():
    image=Image.new('RGB',(64,32),(20,30,40))
    stream=io.BytesIO();image.save(stream,format='PNG');return stream.getvalue()


def test_actual_png_encryption_export_and_reconstruction(config):
    store=ArtifactStore(config);data=png();meta=store.add_bytes(data,name='test.png',mime='image/png')
    restored=bytearray();offset=0
    while True:
        chunk=store.chunk(meta['artifact_id'],offset,23)
        part=base64.b64decode(chunk['data'],validate=True)
        assert hashlib.sha256(part).hexdigest()==chunk['chunk_sha256']
        restored.extend(part);offset=chunk['next_offset']
        if chunk['eof']:break
    assert bytes(restored)==data
    assert hashlib.sha256(restored).hexdigest()==meta['sha256']
    assert Image.open(io.BytesIO(restored)).size==(64,32)
    assert data not in store.path.read_bytes()
    assert store.key not in store.path.read_bytes()


def test_artifact_crypto_detects_metadata_and_ciphertext_changes(config):
    from cryptography.exceptions import InvalidTag
    store=ArtifactStore(config);meta=store.add_bytes(b'confidential test data',name='a',mime='text/plain')
    with store.connect() as db:
        db.execute('UPDATE artifacts SET meta=? WHERE id=?',(json.dumps({**meta,'name':'tampered'}),meta['artifact_id']))
    with pytest.raises(InvalidTag):store.get(meta['artifact_id'])


def test_expiration_is_enforced_even_before_cleanup(config):
    store=ArtifactStore(config);meta=store.add_bytes(b'a',name='a',mime='text/plain')
    with store.connect() as db:db.execute('UPDATE artifacts SET expires=0')
    with pytest.raises(FileNotFoundError):store.get(meta['artifact_id'])
    assert store.cleanup()==1


def test_quota_never_deletes_unexpired_evidence(config):
    config.security={'artifact_max_bytes':1024,'artifact_total_bytes':1024}
    store=ArtifactStore(config);meta=store.add_bytes(b'a'*1024,name='a',mime='text/plain')
    with pytest.raises(ValueError,match='full'):store.add_bytes(b'x',name='b',mime='text/plain')
    assert len(store.get(meta['artifact_id'])[1])==1024


def test_sensitive_state_never_uses_normal_export(config):
    store=ArtifactStore(config);meta=store.add_bytes(b'private state',name='state.json',mime='application/json',metadata={'sensitive':True})
    with pytest.raises(PermissionError):store.chunk(meta['artifact_id'])


def test_real_http_requires_auth_and_delivers_exact_image(config):
    data=png();meta=ArtifactStore(config).add_bytes(data,name='test.png',mime='image/png')
    token=secrets.token_urlsafe(48)
    server=create_http_server(config,token,0)
    thread=threading.Thread(target=server.serve_forever,daemon=True);thread.start()
    url=f'http://127.0.0.1:{server.server_port}/artifacts/{meta["artifact_id"]}'
    try:
        for authorization in [None,'Bearer wrong']:
            request=urllib.request.Request(url,headers={'Authorization':authorization} if authorization else {})
            with pytest.raises(urllib.error.HTTPError) as error:urllib.request.urlopen(request,timeout=2)
            assert error.value.code==401
        request=urllib.request.Request(url,headers={'Authorization':'Bearer '+token})
        with urllib.request.urlopen(request,timeout=2) as response:
            assert response.headers['Cache-Control']=='no-store'
            assert response.headers['X-Artifact-SHA256']==meta['sha256']
            assert response.read()==data
    finally:
        server.shutdown();server.server_close();thread.join(2)
