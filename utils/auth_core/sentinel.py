"""Sentinel API interaction and token management.

The OpenAI Sentinel system validates requests via a token obtained from
the sentinel API. This module fetches and caches those tokens.

Key discovery: the raw API token from sentinel.openai.com is accepted
directly by the auth API - no Fernet re-encryption, PoW solving, or
Turnstile VM execution required.
"""
import json
import time
import threading
from typing import Any, Dict, Optional, Tuple

from curl_cffi import requests as cffi_requests

from .models import Config, Token
from .utils import _ts

_SENTINEL_REQ_URL = "https://sentinel.openai.com/backend-api/sentinel/req"
_UA = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
       "AppleWebKit/537.36 (KHTML, like Gecko) "
       "Chrome/110.0.0.0 Safari/537.36")

# Token cache: (did) -> (token_str, expire_at)
_token_cache: Dict[str, Tuple[str, float]] = {}
_cache_lock = threading.Lock()


def _fetch_sentinel_token(
    did: str,
    proxy: Optional[str] = None,
    user_agent: Optional[str] = None,
    impersonate: str = "chrome110",
    timeout: float = 15.0,
) -> Optional[Dict[str, Any]]:
    """Fetch a fresh sentinel challenge from the API.

    Returns the full API response dict with keys: persona, token, expire_after,
    expire_at, turnstile, proofofwork.
    """
    ua = user_agent or _UA
    proxies = {"http": proxy, "https": proxy} if proxy else None
    headers = {
        "accept": "application/json",
        "accept-language": "en-US,en;q=0.9",
        "user-agent": ua,
        "oai-device-id": did or "",
        "referer": "https://chatgpt.com/",
        "content-type": "application/json",
    }
    try:
        sess = cffi_requests.Session(impersonate=impersonate, proxies=proxies, timeout=timeout, verify=False)
        resp = sess.post(_SENTINEL_REQ_URL, headers=headers, json={}, verify=False, timeout=timeout)
        if resp.status_code == 200:
            return resp.json()
        print(f"[{_ts()}] [WARNING] Sentinel API returned {resp.status_code}: {resp.text[:200]}")
        return None
    except Exception as e:
        print(f"[{_ts()}] [WARNING] Sentinel API request failed: {e}")
        return None
    finally:
        try:
            sess.close()
        except Exception:
            pass


def generate_payload(
    did: str,
    flow: str,
    proxy: Optional[str] = None,
    user_agent: Optional[str] = None,
    impersonate: str = "chrome110",
    ctx: Optional[dict] = None,
) -> str:
    """Generate a sentinel token for the given flow.

    Returns a JSON string containing the token. The raw API token is used
    directly without re-encryption.

    The token is cached per DID for ~8 minutes (API gives 540s TTL,
    we use 480s to be safe).
    """
    cache_key = did or "_anonymous"

    # Check cache
    with _cache_lock:
        if cache_key in _token_cache:
            cached_token, expire_at = _token_cache[cache_key]
            if time.time() < expire_at:
                return cached_token
            del _token_cache[cache_key]

    # Fetch fresh token from sentinel API
    api_resp = _fetch_sentinel_token(
        did=did, proxy=proxy, user_agent=user_agent,
        impersonate=impersonate,
    )

    if not api_resp or not api_resp.get("token"):
        # Fallback: return minimal token structure
        print(f"[{_ts()}] [WARNING] Failed to fetch sentinel token, using empty fallback")
        return json.dumps({"p": "", "t": "", "c": "", "id": did or "", "flow": flow})

    raw_token = api_resp["token"]
    expire_after = api_resp.get("expire_after", 540)

    # Build the token JSON in the format expected by the API consumers
    token_obj = {
        "p": "",
        "t": "",
        "c": raw_token,
        "id": did or "",
        "flow": flow,
    }
    token_json = json.dumps(token_obj)

    # Cache with safety margin (480s instead of 540s)
    with _cache_lock:
        _token_cache[cache_key] = (token_json, time.time() + min(expire_after - 60, 480))

    return token_json


def invalidate_cache(did: Optional[str] = None):
    """Clear cached tokens. If did is specified, clear only that entry."""
    with _cache_lock:
        if did:
            _token_cache.pop(did, None)
        else:
            _token_cache.clear()
