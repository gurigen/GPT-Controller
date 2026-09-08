from __future__ import annotations

import time
import uuid
from typing import Any

from .config import Config
from .util import atomic_write_json, load_json, utc_now


class InteractiveClient:
    def __init__(self, config: Config):
        self.config = config
        self.root = config.interactive_spool
        self.requests = self.root / "requests"
        self.processing = self.root / "processing"
        self.responses = self.root / "responses"

    def request(self, step: dict[str, Any], timeout_seconds: int) -> dict[str, Any]:
        from .hardening.ipc import request
        return request(self, step, timeout_seconds)
