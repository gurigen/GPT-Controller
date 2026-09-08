from __future__ import annotations

import hashlib
import os
import shutil
import tempfile
import uuid
from pathlib import Path
from typing import Any
from .common import ControlError, state_root
from .goals import resolve


def sha256(path: Path) -> str:
    result = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(65536), b""):
            result.update(chunk)
    return result.hexdigest()


def check_overwrite(path: Path, step: dict) -> None:
    if not path.exists():
        return
    if not step.get("overwrite") or not step.get("expected_sha256") or not path.is_file():
        raise ControlError("blocked", "existing destination requires overwrite=true and its expected_sha256")
    if sha256(path) != step["expected_sha256"]:
        raise ControlError("blocked", "destination changed since it was inspected")


def execute(config: Any, step: dict) -> dict:
    kind = step["type"]
    workspace = step["workspace"]
    root = config.workspaces[workspace].resolve()
    if kind in {"file.copy", "file.move"}:
        source = resolve(config, workspace, step["source"])
        destination = resolve(config, workspace, step["destination"])
        if source == destination or source in destination.parents:
            raise ControlError("blocked", "cannot copy/move an item onto itself or into its descendant")
        if source == root or destination == root:
            raise ControlError("blocked", "cannot replace or move workspace root")
        check_overwrite(destination, step)
        destination.parent.mkdir(parents=True, exist_ok=True)
        if kind == "file.move":
            shutil.move(str(source), str(destination))
        elif source.is_dir():
            shutil.copytree(source, destination, symlinks=True)
        else:
            fd, temp = tempfile.mkstemp(prefix=".gpt-copy-", dir=destination.parent)
            os.close(fd)
            try:
                shutil.copy2(source, temp)
                check_overwrite(destination, step)
                if step.get("overwrite"):
                    os.replace(temp, destination)
                else:
                    # Atomic no-clobber publication; a concurrent new destination wins.
                    os.link(temp, destination)
            finally:
                Path(temp).unlink(missing_ok=True)
        return {"source": str(source), "destination": str(destination)}
    path = resolve(config, workspace, step["path"])
    if kind == "file.mkdir":
        path.mkdir(parents=True, exist_ok=True)
        return {"path": str(path)}
    if kind in {"file.write", "file.append"}:
        text = step.get("text", "")
        if not isinstance(text, str):
            raise ValueError("file text must be a string")
        encoding = step.get("encoding", "utf-8")
        data = text.encode(encoding)
        if kind == "file.append":
            if path.exists() and step.get("expected_sha256") and sha256(path) != step["expected_sha256"]:
                raise ControlError("blocked", "append target changed since inspection")
            path.parent.mkdir(parents=True, exist_ok=True)
            with path.open("ab") as stream:
                stream.write(data)
                stream.flush()
                os.fsync(stream.fileno())
        else:
            check_overwrite(path, step)
            path.parent.mkdir(parents=True, exist_ok=True)
            fd, temp = tempfile.mkstemp(prefix=".gpt-write-", dir=path.parent)
            try:
                with os.fdopen(fd, "wb") as stream:
                    stream.write(data)
                    stream.flush()
                    os.fsync(stream.fileno())
                check_overwrite(path, step)
                if step.get("overwrite"):
                    os.replace(temp, path)
                else:
                    os.link(temp, path)
            finally:
                Path(temp).unlink(missing_ok=True)
        return {"path": str(path), "bytes": path.stat().st_size, "sha256": sha256(path)}
    if kind == "file.delete":
        if path == root or path == config.repo_path or path in config.repo_path.parents:
            raise ControlError("blocked", "cannot delete workspace or control roots")
        if not path.exists():
            return {"path": str(path), "deleted": False, "reason": "not_found"}
        if path.is_file() and step.get("expected_sha256") and sha256(path) != step["expected_sha256"]:
            raise ControlError("blocked", "delete target changed since inspection")
        if step.get("permanent", False):
            if path.is_dir():
                if not step.get("recursive", False):
                    raise ControlError("blocked", "permanent directory deletion requires recursive=true")
                shutil.rmtree(path)
            else:
                path.unlink()
            return {"path": str(path), "deleted": True, "permanent": True}
        trash = state_root(config) / "trash" / (uuid.uuid4().hex + "-" + path.name)
        trash.parent.mkdir(parents=True, exist_ok=True)
        shutil.move(str(path), str(trash))
        return {"path": str(path), "deleted": True, "permanent": False, "recovery_path": str(trash)}
    raise ValueError("unsupported filesystem operation")
