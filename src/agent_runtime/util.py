from __future__ import annotations

import json
import logging
import os
import signal
import subprocess
import tempfile
from datetime import datetime, timezone
from logging.handlers import RotatingFileHandler
from pathlib import Path
from typing import Any


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def parse_utc(value: str) -> datetime:
    if value.endswith("Z"):
        value = value[:-1] + "+00:00"
    dt = datetime.fromisoformat(value)
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


def configure_file_logging(log_path: Path, level: int = logging.INFO) -> None:
    log_path.parent.mkdir(parents=True, exist_ok=True)
    root = logging.getLogger()
    root.handlers.clear()
    root.setLevel(level)
    handler = RotatingFileHandler(log_path, maxBytes=2_000_000, backupCount=3, encoding="utf-8")
    handler.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(name)s %(message)s"))
    root.addHandler(handler)


def atomic_write_json(path: Path, value: Any) -> None:
    from .hardening.common import atomic_json
    atomic_json(path, value)


def load_json(path: Path) -> Any:
    from .hardening.common import load_json as bounded_json
    return bounded_json(path)


def terminate_process_tree(process: subprocess.Popen[bytes], *, wait_seconds: float = 10.0) -> None:
    """Best-effort process-tree termination used by all timeout paths.

    On Windows, taskkill /T handles console wrappers such as pwsh -> cmd -> node. Action
    workers additionally live in a KILL_ON_JOB_CLOSE Job Object, which is the stronger
    guarantee for descendants that intentionally outlive an intermediate parent.
    """
    if process.poll() is not None:
        return
    if os.name == "nt":
        try:
            subprocess.run(
                ["taskkill.exe", "/PID", str(process.pid), "/T", "/F"],
                stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                timeout=wait_seconds,
                check=False,
                creationflags=subprocess.CREATE_NO_WINDOW,
            )
        except Exception:
            try:
                process.kill()
            except Exception:
                pass
    else:
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        except Exception:
            try:
                process.kill()
            except Exception:
                pass
    try:
        process.wait(timeout=wait_seconds)
    except subprocess.TimeoutExpired:
        try:
            process.kill()
        except Exception:
            pass


def run_process(argv: list[str], cwd: Path | None = None, timeout: int = 300,
                env: dict[str, str] | None = None, max_output_bytes: int = 2_000_000) -> dict[str, Any]:
    from .hardening.processes import run_process as bounded_process
    return bounded_process(argv, cwd, timeout, env, max_output_bytes)
