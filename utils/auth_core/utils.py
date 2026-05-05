"""Utility functions for auth_core."""
import base64
import json
import os
import random
import string
import time
import threading
from typing import Optional

from curl_cffi import requests as cffi_requests

_ssl_verify = False


def random_hex(n: int) -> str:
    return os.urandom(n).hex()


def random_int(min_val: int, max_val: int) -> int:
    return random.randint(min_val, max_val)


def web_print(*args, **kwargs):
    ts = time.strftime("%H:%M:%S")
    print(f"[{ts}]", *args, **kwargs)


def _ts() -> str:
    return time.strftime("%H:%M:%S")


# Session pool for isolation
_sessions: dict = {}
_sessions_lock = threading.Lock()


def get_session(identifier: str, proxies: Optional[dict] = None) -> cffi_requests.Session:
    with _sessions_lock:
        if identifier not in _sessions:
            _sessions[identifier] = cffi_requests.Session(
                impersonate="chrome110", proxies=proxies, timeout=30, verify=False
            )
        return _sessions[identifier]


def clear_session(identifier: str):
    with _sessions_lock:
        sess = _sessions.pop(identifier, None)
        if sess:
            try:
                sess.close()
            except Exception:
                pass


def email_jwt(acc_token: str) -> dict:
    """Extract the JWT payload from an access-token, returning the full dict."""
    try:
        payload = acc_token.split(".")[1]
        payload += "=" * (-len(payload) % 4)
        data = json.loads(base64.urlsafe_b64decode(payload))
        return data if isinstance(data, dict) else {}
    except Exception:
        return {}
