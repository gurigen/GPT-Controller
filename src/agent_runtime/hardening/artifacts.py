from __future__ import annotations

import base64
from contextlib import contextmanager
import hashlib
import json
import mimetypes
import os
import secrets
import sqlite3
import time
from pathlib import Path
from typing import Any

from .common import canonical, identifier, state_root, utc_now
from .policy import security
from .key_storage import load_or_create_key


class ArtifactStore:
    """Encrypted, quota-controlled local artifacts; no automatic remote upload.

    artifact.get is an explicit, locally authorized plaintext export to the private
    control bus. HTTP exports require a separate bearer token and are loopback-only.
    """
    def __init__(self, config: Any):
        self.config = config
        self.root = state_root(config) / "artifacts"
        self.root.mkdir(parents=True, exist_ok=True)
        self.path = self.root / "artifacts.sqlite3"
        settings = security(config)
        self.max_bytes = settings.get("artifact_max_bytes", 16_000_000)
        self.total_bytes = settings.get("artifact_total_bytes", 128_000_000)
        self.ttl = settings.get("artifact_ttl_seconds", 3600)
        self.key = load_or_create_key(state_root(config) / "keys" / "artifacts.key")
        with self.connect() as db:
            db.execute("CREATE TABLE IF NOT EXISTS artifacts (id TEXT PRIMARY KEY, meta TEXT NOT NULL, nonce BLOB NOT NULL, data BLOB NOT NULL, size INTEGER NOT NULL, expires REAL NOT NULL)")
        if os.name != "nt":
            os.chmod(self.root, 0o700)
            os.chmod(self.path, 0o600)

    @contextmanager
    def connect(self):
        db = sqlite3.connect(self.path, timeout=10)
        db.row_factory = sqlite3.Row
        db.execute("PRAGMA synchronous=FULL")
        try:
            yield db
            db.commit()
        except BaseException:
            db.rollback()
            raise
        finally:
            db.close()

    def add_bytes(self, data: bytes, *, name: str, mime: str, metadata: dict | None = None) -> dict:
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
        if len(data) > self.max_bytes:
            raise ValueError("artifact exceeds per-file quota")
        name = Path(name).name
        ident = "artifact-" + secrets.token_hex(16)
        expires = time.time() + self.ttl
        meta = {"artifact_id": ident, "name": name, "mime": mime, "bytes": len(data),
                "sha256": hashlib.sha256(data).hexdigest(), "created_at": utc_now(),
                "expires_unix": expires, "metadata": json.loads(canonical(metadata or {}))}
        aad = canonical(meta)
        with self.connect() as db:
            db.execute("BEGIN IMMEDIATE")
            db.execute("DELETE FROM artifacts WHERE expires<=?", (time.time(),))
            size = db.execute("SELECT COALESCE(SUM(size),0) FROM artifacts").fetchone()[0]
            if size + len(data) > self.total_bytes:
                raise ValueError("artifact store full; no unexpired evidence was deleted")
            nonce = secrets.token_bytes(12)
            encrypted = AESGCM(self.key).encrypt(nonce, data, aad)
            db.execute("INSERT INTO artifacts VALUES(?,?,?,?,?,?)", (ident, aad.decode(), nonce, encrypted, len(data), expires))
        return meta

    def add_file(self, path: Path, *, metadata: dict | None = None) -> dict:
        with path.open("rb") as stream:
            data = stream.read(self.max_bytes + 1)
        return self.add_bytes(data, name=path.name, mime=mimetypes.guess_type(path.name)[0] or "application/octet-stream", metadata=metadata)

    def get(self, ident: str, *, allow_sensitive: bool = False) -> tuple[dict, bytes]:
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
        identifier(ident, "artifact_id")
        with self.connect() as db:
            row = db.execute("SELECT * FROM artifacts WHERE id=?", (ident,)).fetchone()
            if row is None or row["expires"] <= time.time():
                raise FileNotFoundError("artifact absent or expired")
        # The indexed columns are not authenticated. They may reject early, but
        # must never authorize an export or extend the authenticated lifetime.
        data = AESGCM(self.key).decrypt(row["nonce"], row["data"], row["meta"].encode())
        meta = json.loads(row["meta"])
        if (meta.get("artifact_id") != ident or row["size"] != meta.get("bytes")
                or row["expires"] != meta.get("expires_unix")
                or len(data) != meta.get("bytes")
                or hashlib.sha256(data).hexdigest() != meta.get("sha256")):
            raise ValueError("artifact integrity mismatch")
        if meta["expires_unix"] <= time.time():
            raise FileNotFoundError("artifact absent or expired")
        if meta.get("metadata", {}).get("sensitive") and not allow_sensitive:
            raise PermissionError("sensitive artifacts are not exposed by normal artifact export")
        return meta, data

    def chunk(self, ident: str, offset: int = 0, max_bytes: int = 49152) -> dict:
        if type(offset) is not int or offset < 0 or type(max_bytes) is not int or not 1 <= max_bytes <= 49152:
            raise ValueError("invalid artifact range")
        meta, data = self.get(ident)
        if offset > len(data):
            raise ValueError("range starts beyond artifact")
        part = data[offset:offset + max_bytes]
        return {"artifact": meta, "offset": offset, "next_offset": offset + len(part),
                "eof": offset + len(part) == len(data), "chunk_sha256": hashlib.sha256(part).hexdigest(),
                "encoding": "base64", "data": base64.b64encode(part).decode("ascii"),
                "warning": "Explicit export: plaintext bytes may remain in private Git history"}

    def cleanup(self) -> int:
        with self.connect() as db:
            return db.execute("DELETE FROM artifacts WHERE expires<=?", (time.time(),)).rowcount


def create_http_server(config: Any, token: str, port: int = 8766):
    import hmac
    from cryptography.exceptions import InvalidTag
    from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
    if not isinstance(token, str) or len(token) < 32:
        raise ValueError("use an unpredictable token of at least 32 characters")
    store = ArtifactStore(config)
    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *_args):
            pass  # never log bearer tokens, URLs or artifact names
        def do_GET(self):
            expected = "Bearer " + token
            if not hmac.compare_digest(self.headers.get("Authorization", "").encode("utf-8"), expected.encode("utf-8")):
                self.send_error(401)
                return
            if not self.path.startswith("/artifacts/") or "?" in self.path:
                self.send_error(404)
                return
            try:
                meta, data = store.get(self.path[len("/artifacts/"):])
            except (ValueError, FileNotFoundError, PermissionError, InvalidTag):
                self.send_error(404)
                return
            self.send_response(200)
            self.send_header("Content-Type", meta["mime"])
            self.send_header("Content-Length", str(len(data)))
            self.send_header("Cache-Control", "no-store")
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("Content-Disposition", "attachment")
            self.send_header("X-Artifact-SHA256", meta["sha256"])
            self.end_headers()
            self.wfile.write(data)
    server = ThreadingHTTPServer(("127.0.0.1", port), Handler)
    server.daemon_threads = True
    return server


def serve_http(config: Any, token: str, port: int = 8766) -> None:
    with create_http_server(config, token, port) as server:
        server.serve_forever()
