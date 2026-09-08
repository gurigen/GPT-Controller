from __future__ import annotations

import os
import signal
import subprocess
import threading
import time
from pathlib import Path
from typing import Any

from .common import bounded_number


def run_process(argv: list[str], cwd: Path | None = None, timeout: int = 300,
                env: dict[str, str] | None = None, max_output_bytes: int = 2_000_000) -> dict[str, Any]:
    bounded_number(timeout, "timeout", 0.01, 86400)
    bounded_number(max_output_bytes, "max_output_bytes", 1, 10_000_000, True)
    if not isinstance(argv, list) or not argv or not all(isinstance(x, str) for x in argv):
        raise ValueError("argv must be a non-empty list of strings")
    flags = subprocess.CREATE_NO_WINDOW | subprocess.CREATE_NEW_PROCESS_GROUP if os.name == "nt" else 0
    process = subprocess.Popen(argv, cwd=str(cwd) if cwd else None, env=env,
                               stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                               shell=False, creationflags=flags, start_new_session=os.name != "nt")
    buffers = [bytearray(), bytearray()]
    totals = [0, 0]
    errors = []
    locks = [threading.Lock(), threading.Lock()]
    def pump(stream, index):
        try:
            while True:
                chunk = stream.read1(65536)
                if not chunk:
                    break
                with locks[index]:
                    totals[index] += len(chunk)
                    room = max_output_bytes - len(buffers[index])
                    if room > 0:
                        buffers[index].extend(chunk[:room])
        except (OSError, ValueError) as exc:
            errors.append(type(exc).__name__)
        finally:
            stream.close()
    threads = [threading.Thread(target=pump, args=(stream, index), daemon=True)
               for index, stream in enumerate((process.stdout, process.stderr))]
    for thread in threads:
        thread.start()
    deadline = time.monotonic() + timeout
    timed_out = False
    try:
        while process.poll() is None or any(thread.is_alive() for thread in threads):
            if time.monotonic() >= deadline:
                timed_out = True
                if os.name == "nt":
                    subprocess.run(["taskkill.exe", "/PID", str(process.pid), "/T", "/F"],
                                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=10,
                                   creationflags=subprocess.CREATE_NO_WINDOW, check=False)
                else:
                    try:
                        os.killpg(process.pid, signal.SIGKILL)
                    except ProcessLookupError:
                        pass
                if process.poll() is None:
                    process.kill()
                break
            time.sleep(0.01)
    finally:
        if process.poll() is None:
            process.kill()
        process.wait(timeout=10)
        for thread in threads:
            thread.join(timeout=1)
    with locks[0]:
        stdout = bytes(buffers[0]).decode("utf-8", errors="replace")
    with locks[1]:
        stderr = bytes(buffers[1]).decode("utf-8", errors="replace")
    if timed_out:
        stderr = (stderr[:max(0, max_output_bytes - 100)] + f"\nGPT Controller terminated process tree after {timeout}s timeout.")
    return {"exit_code": 124 if timed_out else process.returncode, "stdout": stdout, "stderr": stderr,
            "stdout_truncated": totals[0] > max_output_bytes, "stderr_truncated": totals[1] > max_output_bytes,
            "stdout_bytes_seen": totals[0], "stderr_bytes_seen": totals[1], "timed_out": timed_out,
            "stream_errors": errors, "streams_closed": not any(t.is_alive() for t in threads)}


def snapshot_descendants(process) -> list[tuple[int, float]]:
    """Best-effort POSIX test-host containment; Windows uses the upstream Job Object.

    PID plus creation time avoids terminating an unrelated process after PID reuse.
    This is not a security sandbox against deliberately escaping hostile programs.
    """
    import psutil
    try:
        return [(child.pid,child.create_time()) for child in psutil.Process(process.pid).children(recursive=True)]
    except (psutil.Error, OSError):
        return []


def terminate_snapshot(items: list[tuple[int, float]]) -> None:
    import psutil
    processes=[]
    for pid, created in reversed(items):
        try:
            child=psutil.Process(pid)
            if child.create_time()==created:
                child.kill();processes.append(child)
        except (psutil.Error, OSError):
            continue
    psutil.wait_procs(processes,timeout=1)


class CaptureLog:
    """Drain a worker's stderr continuously, retaining only a bounded tail."""
    def __init__(self, stream, maximum: int=65536):
        self.stream=stream;self.maximum=maximum;self.buffer=bytearray();self.lock=threading.Lock()
        self.thread=threading.Thread(target=self._drain,daemon=True,name='gpt-worker-stderr')
        self.thread.start()
    def _drain(self):
        try:
            while True:
                chunk=self.stream.read1(65536)
                if not chunk:break
                with self.lock:
                    self.buffer.extend(chunk)
                    if len(self.buffer)>self.maximum:del self.buffer[:-self.maximum]
        except (OSError,ValueError):
            pass
        finally:
            self.stream.close()
    def text(self):
        self.thread.join(timeout=.25)
        with self.lock:
            return bytes(self.buffer).decode('utf-8',errors='replace')
