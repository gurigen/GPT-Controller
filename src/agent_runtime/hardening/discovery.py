"""Publish bounded agent status using an isolated Git index and a fast-forward push.

No force pushes, no worktree edits, no queue modifications. Staleness is explicit;
this is recent reported state, not a guarantee the device remains connected.
"""
from __future__ import annotations
import os
import tempfile
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path
from . import VERSION
from .common import canonical, identifier, load_json, utc_now
from .policy import security
from .processes import run_process


def publish(config, mirror: Path, remote_url: str, current_action: str | None) -> bool:
    from .integration import doctor
    ident = identifier(config.agent_id)
    interval = security(config).get('agent_publish_seconds', 300)
    manifest = doctor(config, probe_git=False)
    manifest['protocol'] = 'q-agent-v4-agent-manifest'
    manifest['transport'] = 'private-git'
    manifest['published_at'] = utc_now()
    status = {'protocol':'q-agent-v4-agent-status', 'agent_id':ident, 'runtime_extension':VERSION,
              'reported_at':utc_now(), 'valid_until':(datetime.now(timezone.utc)+timedelta(seconds=interval*2)).isoformat(),
              'state':'executing' if current_action else 'idle', 'action_id':current_action,
              'status_is_lease_not_reexecution_authority':True}
    index_fd, index_name = tempfile.mkstemp(prefix='status-index-',dir=mirror)
    os.close(index_fd)
    os.unlink(index_name)
    env = os.environ.copy()
    env.update(GIT_INDEX_FILE=index_name, GIT_AUTHOR_NAME='GPT Controller Status',
               GIT_AUTHOR_EMAIL='gpt-controller@localhost', GIT_COMMITTER_NAME='GPT Controller Status',
               GIT_COMMITTER_EMAIL='gpt-controller@localhost')
    def git(*args):
        result = run_process([config.git,*args],mirror,15,env=env,max_output_bytes=65536)
        if result['exit_code'] != 0:
            raise RuntimeError('agent status publication failed; no force push or worktree reset')
        return result['stdout'].strip()
    try:
        parent = git('rev-parse','FETCH_HEAD')
        git('read-tree',parent)
        for name, value in [('manifest.json',manifest),('status.json',status)]:
            fd, data_name = tempfile.mkstemp(prefix='status-data-',dir=mirror)
            try:
                with os.fdopen(fd,'wb') as stream:
                    stream.write(canonical(value)+b'\n')
                blob = git('hash-object','-w',data_name)
                git('update-index','--add','--cacheinfo',f'100644,{blob},agents/{ident}/{name}')
            finally:
                Path(data_name).unlink(missing_ok=True)
        tree = git('write-tree')
        commit = git('commit-tree',tree,'-p',parent,'-m',f'gpt-controller status {ident}')
        git('push',remote_url,f'{commit}:refs/heads/{config.branch}')
        return True
    finally:
        Path(index_name).unlink(missing_ok=True)
