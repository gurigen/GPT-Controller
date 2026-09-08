"""Regression cases first demonstrated against rc1; no user repositories touched."""
import secrets
import threading
import urllib.error
import urllib.request
from types import SimpleNamespace

import pytest
from agent_runtime.hardening import artifacts, control_poller, discovery
from agent_runtime.hardening.artifacts import ArtifactStore, create_http_server
from agent_runtime.hardening.control_poller import ControlPoller
from test_real_git_bus import setup_bus, git


def test_first_manifest_publishes_during_first_minute_of_boot(tmp_path, monkeypatch):
    _, seed, configs = setup_bus(tmp_path)
    monkeypatch.setattr(control_poller, 'time', SimpleNamespace(monotonic=lambda: 45.0))
    poller = ControlPoller(configs[0], lambda: None)
    poller.poll()
    git(seed, 'pull', '--ff-only')
    assert (seed / 'agents/test-agent/manifest.json').is_file()
    assert poller.last_published == 45.0


def test_failed_first_publication_retries_then_respects_interval(tmp_path, monkeypatch):
    _, _, configs = setup_bus(tmp_path)
    clock = [45.0]
    monkeypatch.setattr(control_poller, 'time', SimpleNamespace(monotonic=lambda: clock[0]))
    calls = []
    outcomes = iter([False, True, True])
    def publish(*args):
        calls.append(clock[0])
        return next(outcomes)
    monkeypatch.setattr(discovery, 'publish', publish)
    poller = ControlPoller(configs[0], lambda: None)
    poller.poll()
    clock[0] = 46.0
    poller.poll()
    clock[0] = 47.0
    poller.poll()
    clock[0] = 346.0
    poller.poll()
    assert calls == [45.0, 46.0, 346.0]
    assert poller.last_published == 346.0


def test_artifact_index_cannot_extend_authenticated_expiry(config, monkeypatch):
    store = ArtifactStore(config)
    meta = store.add_bytes(b'secret image bytes', name='image', mime='application/octet-stream')
    with store.connect() as db:
        db.execute('UPDATE artifacts SET expires=expires+7200')
    monkeypatch.setattr(artifacts, 'time', SimpleNamespace(time=lambda: meta['expires_unix'] + 1))
    with pytest.raises((ValueError, FileNotFoundError)):
        store.get(meta['artifact_id'])


def test_artifact_row_identity_must_match_authenticated_identity(config):
    store = ArtifactStore(config)
    meta = store.add_bytes(b'original', name='image', mime='application/octet-stream')
    alias = 'artifact-alias'
    with store.connect() as db:
        db.execute('UPDATE artifacts SET id=? WHERE id=?', (alias, meta['artifact_id']))
    with pytest.raises(ValueError, match='integrity'):
        store.get(alias)


def test_artifact_size_index_must_match_authenticated_size(config):
    store = ArtifactStore(config)
    meta = store.add_bytes(b'original', name='image', mime='application/octet-stream')
    with store.connect() as db:
        db.execute('UPDATE artifacts SET size=0')
    with pytest.raises(ValueError, match='integrity'):
        store.get(meta['artifact_id'])


def test_http_tampered_ciphertext_is_rejected_without_connection_abort(config):
    store = ArtifactStore(config)
    meta = store.add_bytes(b'do not expose', name='image', mime='application/octet-stream')
    with store.connect() as db:
        row = db.execute('SELECT data FROM artifacts').fetchone()
        damaged = bytearray(row['data']); damaged[-1] ^= 1
        db.execute('UPDATE artifacts SET data=?', (bytes(damaged),))
    token = secrets.token_urlsafe(48)
    server = create_http_server(config, token, 0)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        request = urllib.request.Request(
            f'http://127.0.0.1:{server.server_port}/artifacts/{meta["artifact_id"]}',
            headers={'Authorization': 'Bearer ' + token})
        with pytest.raises(urllib.error.HTTPError) as result:
            urllib.request.urlopen(request, timeout=3)
        assert result.value.code == 404
    finally:
        server.shutdown(); server.server_close(); thread.join(3)
