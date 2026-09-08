from __future__ import annotations

import ctypes
import os
import secrets
import time
from pathlib import Path


def _dpapi(data: bytes, decrypt: bool = False) -> bytes:
    """Windows protects this key for the current logon identity (not machine-wide).

    A process running as that identity can still decrypt it. This is protection
    against copying an artifact database, not a sandbox against the account owner.
    """
    from ctypes import wintypes
    class BLOB(ctypes.Structure):
        _fields_ = [('size', wintypes.DWORD), ('data', ctypes.POINTER(ctypes.c_ubyte))]
    buffer = (ctypes.c_ubyte * len(data)).from_buffer_copy(data)
    source = BLOB(len(data), buffer)
    destination = BLOB()
    crypt32 = ctypes.WinDLL('crypt32', use_last_error=True)
    kernel32 = ctypes.WinDLL('kernel32', use_last_error=True)
    kernel32.LocalFree.argtypes = [ctypes.c_void_p]
    kernel32.LocalFree.restype = ctypes.c_void_p
    function = crypt32.CryptUnprotectData if decrypt else crypt32.CryptProtectData
    function.argtypes = [ctypes.POINTER(BLOB), ctypes.c_void_p, ctypes.POINTER(BLOB), ctypes.c_void_p,
                         ctypes.c_void_p, wintypes.DWORD, ctypes.POINTER(BLOB)]
    function.restype = wintypes.BOOL
    if not function(ctypes.byref(source), None, None, None, None, 1, ctypes.byref(destination)):
        raise OSError(ctypes.get_last_error(), 'Windows DPAPI key protection failed')
    try:
        return ctypes.string_at(destination.data, destination.size)
    finally:
        kernel32.LocalFree(destination.data)


def load_or_create_key(path: Path) -> bytes:
    path.parent.mkdir(parents=True, exist_ok=True)
    if os.name != 'nt':
        os.chmod(path.parent, 0o700)
    try:
        descriptor = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    except FileExistsError:
        payload = b''
        for _ in range(100):
            payload = path.read_bytes()
            if payload:
                break
            time.sleep(0.01)
    else:
        key = secrets.token_bytes(32)
        try:
            payload = b'DPAPI1' + _dpapi(key) if os.name == 'nt' else b'RAW1' + key
            with os.fdopen(descriptor, 'wb') as stream:
                stream.write(payload)
                stream.flush()
                os.fsync(stream.fileno())
        except BaseException:
            try:
                os.close(descriptor)
            except OSError:
                pass
            path.unlink(missing_ok=True)
            raise
    if os.name == 'nt':
        if not payload.startswith(b'DPAPI1'):
            raise ValueError('unprotected or corrupt key file on Windows; refusing to downgrade protection')
        key = _dpapi(payload[6:], decrypt=True)
    else:
        if not payload.startswith(b'RAW1'):
            raise ValueError('unsupported key file (Windows DPAPI keys are not portable)')
        key = payload[4:]
    if len(key) != 32:
        raise ValueError('invalid artifact key length')
    return key
