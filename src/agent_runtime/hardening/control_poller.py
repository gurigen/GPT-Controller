from __future__ import annotations

import json
import threading
import time
from pathlib import Path
from typing import Any, Callable
from .common import identifier, state_root
from .control import Control
from .processes import run_process


class ControlPoller:
    """Independent read-only control checkout; never changes the action worktree.

    The same authorized private Git remote is the only source. Expired ownership
    does NOT requeue Actions. Remote requests may pause/cancel, but cannot resume.
    """
    def __init__(self, config: Any, current_action: Callable[[], str | None]):
        self.config = config
        self.current_action = current_action
        self.root = state_root(config) / "control-mirror.git"
        self.stop_event = threading.Event()
        self.thread = None
        self.last_published: float | None = None

    def start(self):
        self.thread = threading.Thread(target=self.run, daemon=True, name="gpt-out-of-band-cancel")
        self.thread.start()

    def close(self):
        self.stop_event.set()
        if self.thread:
            self.thread.join(timeout=12)

    def run(self):
        while not self.stop_event.is_set():
            try:
                self.poll()
            except Exception:
                # Do not log remote URL or raw Git output, which may contain tokens.
                pass
            self.stop_event.wait(max(1, self.config.poll_seconds))

    def poll(self):
        c = self.config
        if not self.root.exists():
            result = run_process([c.git, "init", "--bare", str(self.root)], timeout=10, max_output_bytes=1024)
            if result["exit_code"]:
                return
        remote = run_process([c.git, "remote", "get-url", c.remote], c.repo_path, 10, max_output_bytes=8192)
        if remote["exit_code"]:
            return
        url = remote["stdout"].strip()
        if not url or url.startswith("-"):
            return
        fetched = run_process([c.git, "fetch", "--no-tags", "--depth=1", url, c.branch], self.root, 10, max_output_bytes=1024)
        if fetched["exit_code"]:
            return
        ident = self.current_action()
        if ident:
            identifier(ident)
            result = run_process([c.git, "show", f"FETCH_HEAD:control/cancel/{ident}.json"], self.root, 5, max_output_bytes=8192)
            if result["exit_code"] == 0:
                record = json.loads(result["stdout"])
                if record.get("action_id") == ident and record.get("cancel") is True:
                    Control(c).cancel(ident, "authenticated control repository cancellation")
        pause = run_process([c.git, "show", f"FETCH_HEAD:control/pause/{identifier(c.agent_id)}.json"], self.root, 5, max_output_bytes=8192)
        if pause["exit_code"] == 0 and json.loads(pause["stdout"]).get("paused") is True:
            Control(c).pause(True)
        from .policy import security
        # Monotonic time is host uptime, not time since this poller started.
        # Publish immediately even within the first interval after OS boot.
        now = time.monotonic()
        if self.last_published is None or now - self.last_published >= security(c).get('agent_publish_seconds', 300):
            from .discovery import publish
            if publish(c, self.root, url, ident):
                self.last_published = time.monotonic()

