"""
Compatibility shim: adds v14.0.0 APIs to the v13.1.0 auth_core compiled binary.

Importing this module monkey-patches ``utils.auth_core`` so that code written
against v14.0.0 continues to work without the license-check machinery.

API details verified against:
- v14.0.0 Nuitka binary string table (function names, URL fragments, payload fields)
- https://github.com/loLollipop/team-manage-refresh (production ChatGPT API reference)

v14.4.36: added token refresh (session_token / refresh_token), ensure_access_token
          auto-refresh with fallback chain, error code detection (token_invalidated,
          account_deactivated), session isolation per identity, extended DB schema.
"""
import base64
import io
import json
import os
import sys
import time
import threading

# Suppress the auth_core binary's startup banner (hardcoded branding)
_prev_stdout, _prev_stderr = sys.stdout, sys.stderr
sys.stdout, sys.stderr = io.StringIO(), io.StringIO()
try:
    import utils.auth_core as _ac
finally:
    sys.stdout, sys.stderr = _prev_stdout, _prev_stderr

try:
    from curl_cffi import requests as cffi_requests
except ImportError:
    cffi_requests = None

_CHATGPT_BASE = "https://chatgpt.com"
_BACKEND_API = f"{_CHATGPT_BASE}/backend-api"
_UA = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
       "AppleWebKit/537.36 (KHTML, like Gecko) "
       "Chrome/110.0.0.0 Safari/537.36")
_REQ_KW = {"timeout": 30, "impersonate": "chrome110", "verify": False}

# Session pool: per-identity curl_cffi sessions for cookie isolation
_sessions: dict = {}
_sessions_lock = threading.Lock()


def _get_session(identifier: str, proxies: dict):
    """Get or create a curl_cffi session isolated by identifier."""
    if cffi_requests is None:
        return None
    with _sessions_lock:
        if identifier not in _sessions:
            session = cffi_requests.Session(impersonate="chrome110",
                                            proxies=proxies, timeout=30, verify=False)
            _sessions[identifier] = session
        return _sessions[identifier]


def _clear_session(identifier: str):
    """Close and remove a specific session."""
    with _sessions_lock:
        sess = _sessions.pop(identifier, None)
        if sess:
            try:
                sess.close()
            except Exception:
                pass


def _email_jwt(acc_token: str) -> dict:
    """Extract the JWT payload from an access-token, returning the full dict."""
    try:
        payload = acc_token.split(".")[1]
        payload += "=" * (-len(payload) % 4)
        data = json.loads(base64.urlsafe_b64decode(payload))
        return data if isinstance(data, dict) else {}
    except Exception:
        return {}


def _jwt_is_expired(acc_token: str) -> bool:
    """Check if a JWT access token is expired."""
    try:
        data = _email_jwt(acc_token)
        exp = data.get("exp", 0)
        return time.time() > exp
    except Exception:
        return True


def _extract_client_id(acc_token: str) -> str:
    """Extract client_id (aud or azp claim) from JWT."""
    try:
        data = _email_jwt(acc_token)
        return data.get("azp", data.get("aud", ""))
    except Exception:
        return ""


def _refresh_with_session_token(session_token: str, proxies: dict,
                                 account_id: str = "") -> dict:
    """Refresh AT using __Secure-next-auth.session-token cookie.

    Reference: chatgpt_service.refresh_access_token_with_session_token
    GET /api/auth/session?exchange_workspace_token=true&workspace_id={account_id}
    Cookie: __Secure-next-auth.session-token={session_token}
    """
    if cffi_requests is None or not session_token:
        return {}
    try:
        url = f"{_CHATGPT_BASE}/api/auth/session"
        if account_id:
            url += f"?exchange_workspace_token=true&workspace_id={account_id}&reason=setCurrentAccount"
        headers = {
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Cookie": f"__Secure-next-auth.session-token={session_token}",
            "Referer": f"{_CHATGPT_BASE}/",
            "Connection": "keep-alive",
        }
        sess = _get_session(f"st_{session_token[:8]}", proxies)
        if sess is None:
            return {}
        resp = sess.get(url, headers=headers, **_REQ_KW)
        if resp.status_code == 200:
            data = resp.json()
            at = data.get("accessToken")
            if at:
                return {
                    "access_token": at,
                    "session_token": data.get("sessionToken", ""),
                    "id_token": data.get("idToken") or data.get("id_token", ""),
                }
        return {}
    except Exception:
        return {}


def _refresh_with_refresh_token(refresh_token: str, client_id: str,
                                 proxies: dict) -> dict:
    """Refresh AT using refresh_token + client_id.

    Reference: chatgpt_service.refresh_access_token_with_refresh_token
    Primary:    POST auth.openai.com/oauth/token  (form-urlencoded, no redirect_uri)
    Fallback 1: POST auth.openai.com/oauth/token  (JSON, with Sora redirect_uri)
    Fallback 2: POST auth0.openai.com/oauth/token (form-urlencoded, legacy)
    """
    if cffi_requests is None or not refresh_token or not client_id:
        return {}

    def _parse_tokens(resp) -> dict:
        if 200 <= resp.status_code < 300:
            data = resp.json()
            return {
                "access_token": data.get("access_token", ""),
                "id_token": data.get("id_token", ""),
                "refresh_token": data.get("refresh_token", ""),
            }
        return {}

    try:
        # Primary (reference: codex_invitation_helper.refresh_access_token in the
        # bugteam reference repo): form-urlencoded POST to auth.openai.com/oauth/token
        # — proven working with the Codex Desktop client_id (app_EMoamEEZ73f0CkXaXp7hrann).
        resp = cffi_requests.post(
            "https://auth.openai.com/oauth/token",
            data={
                "grant_type": "refresh_token",
                "client_id": client_id,
                "refresh_token": refresh_token,
            },
            headers={
                "Content-Type": "application/x-www-form-urlencoded",
                "Accept": "application/json",
            },
            proxies=proxies, **_REQ_KW)
        parsed = _parse_tokens(resp)
        if parsed:
            return parsed

        # Fallback 1: JSON body to auth.openai.com (some clients require redirect_uri)
        resp = cffi_requests.post(
            "https://auth.openai.com/oauth/token",
            json={
                "client_id": client_id,
                "grant_type": "refresh_token",
                "redirect_uri": "com.openai.sora://auth.openai.com/android/com.openai.sora/callback",
                "refresh_token": refresh_token,
            },
            headers={"Content-Type": "application/json"},
            proxies=proxies, **_REQ_KW)
        parsed = _parse_tokens(resp)
        if parsed:
            return parsed

        # Fallback 2: legacy auth0.openai.com endpoint
        resp2 = cffi_requests.post(
            "https://auth0.openai.com/oauth/token",
            data={
                "grant_type": "refresh_token",
                "client_id": client_id,
                "refresh_token": refresh_token,
                "scope": "openid profile email offline_access",
            },
            headers={
                "Content-Type": "application/x-www-form-urlencoded",
                "Accept": "application/json",
            },
            proxies=proxies, **_REQ_KW)
        return _parse_tokens(resp2)
    except Exception:
        return {}


def _detect_error_code(resp) -> str:
    """Detect fatal error codes from API response (token_invalidated, account_deactivated, etc).

    Reference: team_service._handle_api_error
    """
    error_code = ""
    try:
        data = resp.json()
        if isinstance(data, dict):
            err_info = data.get("error", {})
            if isinstance(err_info, dict):
                error_code = err_info.get("code", "")
            if not error_code:
                error_code = data.get("code", "")
            detail = data.get("detail", "")
            error_msg = str(detail).lower() if detail else ""
    except Exception:
        error_msg = resp.text.lower() if hasattr(resp, 'text') else ""

    ban_codes = {
        "account_deactivated", "token_invalidated", "account_suspended",
        "account_not_found", "user_not_found", "deactivated_workspace",
    }
    ban_keywords = [
        "token has been invalidated", "account_deactivated",
        "account has been deactivated", "account is deactivated",
        "account_suspended", "account is suspended",
        "account was deleted", "user_not_found",
        "this account is deactivated", "deactivated_workspace",
    ]
    if error_code in ban_codes:
        return error_code
    # Check keywords in detail/error text
    msg = error_msg if 'error_msg' in dir() else ""
    if any(kw in msg for kw in ban_keywords):
        for kw in ban_keywords:
            if kw in msg:
                return kw.replace(" ", "_")
    return error_code


def _ensure_access_token(team_row: dict, proxies: dict, force: bool = False) -> str:
    """Ensure a valid access token, refreshing via ST/RT if the current AT is expired.

    Reference: team_service.ensure_access_token (fallback chain: AT -> RT -> ST)
    Returns a valid access_token, or empty string on failure.
    Updates team_row in-place and persists new tokens to DB on success.
    """
    access_token = team_row.get("access_token", "")
    session_token = team_row.get("session_token", "")
    refresh_token = team_row.get("refresh_token", "")
    client_id = team_row.get("client_id", "")
    account_id = team_row.get("account_id", "")
    team_id = team_row.get("id", 0)

    # 1. Check if current AT is still valid
    if access_token and not _jwt_is_expired(access_token) and not force:
        return access_token

    if force:
        print(f"[Team] 强制刷新 Team {team_id} Token")
    else:
        print(f"[Team] Team {team_id} Token 已过期, 尝试刷新")

    # 2. Try refresh_token first (more stable without ST)
    if refresh_token and client_id:
        result = _refresh_with_refresh_token(refresh_token, client_id, proxies)
        if result and result.get("access_token"):
            new_at = result["access_token"]
            print(f"[Team] Team {team_id} 通过 refresh_token 成功刷新 AT")
            team_row["access_token"] = new_at
            # Persist new tokens to DB
            try:
                from utils import db_manager
                new_rt = result.get("refresh_token", "")
                db_manager.update_team_account_tokens(
                    team_id,
                    access_token=new_at,
                    refresh_token=new_rt or None,
                )
            except Exception:
                pass
            # Reset status to active if was error
            try:
                from utils import db_manager
                db_manager.update_team_account_tokens(team_id, status=1)
            except Exception:
                pass
            return new_at

    # Auto-detect client_id from existing AT if we have RT but no client_id
    if refresh_token and not client_id and access_token:
        detected_cid = _extract_client_id(access_token)
        if detected_cid:
            client_id = detected_cid
            team_row["client_id"] = client_id
            result = _refresh_with_refresh_token(refresh_token, client_id, proxies)
            if result and result.get("access_token"):
                new_at = result["access_token"]
                print(f"[Team] Team {team_id} 通过 refresh_token (auto-detected client_id) 成功刷新 AT")
                team_row["access_token"] = new_at
                try:
                    from utils import db_manager
                    db_manager.update_team_account_tokens(
                        team_id,
                        access_token=new_at,
                        client_id=client_id,
                        refresh_token=result.get("refresh_token") or None,
                    )
                except Exception:
                    pass
                return new_at

    # 3. Fallback to session_token
    if session_token:
        result = _refresh_with_session_token(session_token, proxies, account_id)
        if result and result.get("access_token"):
            new_at = result["access_token"]
            print(f"[Team] Team {team_id} 通过 session_token 成功刷新 AT")
            team_row["access_token"] = new_at
            new_st = result.get("session_token", "")
            try:
                from utils import db_manager
                updates = {"access_token": new_at}
                if new_st and new_st != session_token:
                    updates["session_token"] = new_st
                db_manager.update_team_account_tokens(team_id, **updates)
            except Exception:
                pass
            return new_at

    # Force refresh failed but current AT still valid — use it
    if force and access_token and not _jwt_is_expired(access_token):
        print(f"[Team] Team {team_id} 强制刷新失败，但现有 AT 仍有效，回退使用当前 Token")
        return access_token

    # All refresh methods failed — mark as expired
    print(f"[Team] Team {team_id} Token 已过期且无法刷新，标记为失效")
    try:
        from utils import db_manager
        db_manager.update_team_account_tokens(team_id, status=0)
    except Exception:
        pass
    return ""


def _get_chatgpt_session(access_token: str, proxies: dict) -> dict:
    """Use an OpenAI access_token to sign into ChatGPT and return the session JSON."""
    if cffi_requests is None:
        return {}
    try:
        callback_resp = cffi_requests.get(
            f"{_CHATGPT_BASE}/api/auth/callback/openai",
            headers={
                "User-Agent": _UA,
                "Authorization": f"Bearer {access_token}",
                "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            },
            allow_redirects=True,
            proxies=proxies, **_REQ_KW)
        if callback_resp.status_code not in (200, 302):
            return {}

        session_resp = cffi_requests.get(
            f"{_CHATGPT_BASE}/api/auth/session",
            headers={"User-Agent": _UA},
            proxies=proxies, **_REQ_KW)
        if session_resp.status_code != 200:
            return {}
        return session_resp.json()
    except Exception:
        return {}


def _get_account_id(access_token: str, proxies: dict) -> str:
    """Get team chatgpt_account_id from the accounts check endpoint."""
    if cffi_requests is None:
        return ""
    headers = {
        "Authorization": f"Bearer {access_token}",
        "Accept": "application/json",
    }
    try:
        url = f"{_BACKEND_API}/accounts/check/v4-2023-04-27"
        resp = cffi_requests.get(url, headers=headers,
                                  proxies=proxies, **_REQ_KW)
        if resp.status_code == 200:
            data = resp.json()
            accounts = data.get("accounts", {})
            if isinstance(accounts, dict):
                for aid, info in accounts.items():
                    account = info.get("account", {})
                    if account.get("plan_type") == "team":
                        return aid
            for aid in accounts:
                return aid
    except Exception:
        pass
    try:
        resp = cffi_requests.get("https://api.openai.com/profile",
                                  headers=headers, proxies=proxies, **_REQ_KW)
        if resp.status_code == 200:
            data = resp.json()
            acc_id = data.get("chatgpt_account_id", "")
            if acc_id:
                return acc_id
    except Exception:
        pass
    return ""


def _get_team_admin_info(proxies: dict) -> tuple:
    """Get a random team account and ensure its AT is valid via refresh.

    Returns (admin_access_token, chatgpt_account_id, team_row) or (None, None, None).
    """
    try:
        from utils import db_manager
        team = db_manager.get_random_team_account()
        if not team:
            return None, None, None
        admin_at = team.get("access_token", "")
        if not admin_at:
            return None, None, None

        # Ensure access token is valid (refresh if needed)
        admin_at = _ensure_access_token(team, proxies)
        if not admin_at:
            return None, None, None

        account_id = team.get("account_id", "")
        if not account_id:
            account_id = _get_account_id(admin_at, proxies)
            if account_id:
                # Cache account_id in DB
                try:
                    db_manager.update_team_account_tokens(
                        team["id"], account_id=account_id)
                except Exception:
                    pass
        if not account_id:
            return None, None, None
        return admin_at, account_id, team
    except Exception:
        return None, None, None


def _make_chatgpt_headers(access_token: str, account_id: str = "") -> dict:
    """Build headers for ChatGPT backend-api requests."""
    h = {
        "Accept": "*/*",
        "Accept-Language": "en-US,en;q=0.9",
        "Authorization": f"Bearer {access_token}",
        "Content-Type": "application/json",
        "Origin": _CHATGPT_BASE,
        "Referer": f"{_CHATGPT_BASE}/",
        "Connection": "keep-alive",
    }
    if account_id:
        h["chatgpt-account-id"] = account_id
    return h


def _api_send_invite(admin_at: str, account_id: str,
                     email: str, proxies: dict) -> bool:
    """Send a team invite to the given email address."""
    if not cffi_requests or not admin_at or not account_id:
        return False
    try:
        url = f"{_BACKEND_API}/accounts/{account_id}/invites"
        headers = _make_chatgpt_headers(admin_at, account_id)
        payload = {
            "email_addresses": [email],
            "role": "standard-user",
            "resend_emails": True,
        }
        resp = cffi_requests.post(url, json=payload, headers=headers,
                                   proxies=proxies, **_REQ_KW)
        if resp.status_code in (200, 201):
            return True
        # Check for fatal errors
        error_code = _detect_error_code(resp)
        if error_code in ("account_deactivated", "token_invalidated"):
            print(f"[Team] 发送邀请检测到致命错误: {error_code}")
        return False
    except Exception:
        return False


def _api_get_invite_id(admin_at: str, account_id: str,
                       email_address: str, proxies: dict,
                       max_retries: int = 3) -> str:
    """Get the invite ID for a specific email from pending invites."""
    if not cffi_requests or not admin_at or not account_id:
        return ""
    for attempt in range(max_retries):
        try:
            url = f"{_BACKEND_API}/accounts/{account_id}/invites"
            headers = _make_chatgpt_headers(admin_at, account_id)
            resp = cffi_requests.get(url, headers=headers,
                                      proxies=proxies, **_REQ_KW)
            if resp.status_code != 200:
                if attempt < max_retries - 1:
                    time.sleep(2)
                    continue
                return ""
            data = resp.json()
            items = data.get("items", data) if isinstance(data, dict) else data
            if isinstance(items, list):
                for item in items:
                    inv_email = item.get("email_address", item.get("email", ""))
                    if inv_email.lower() == email_address.lower():
                        return str(item.get("id", ""))
            if attempt < max_retries - 1:
                time.sleep(2)
        except Exception:
            if attempt < max_retries - 1:
                time.sleep(2)
    return ""


def _api_accept_invite(user_at: str, account_id: str,
                       invite_id: str, proxies: dict) -> bool:
    """Accept a team invite using the new user's access token."""
    if not cffi_requests or not user_at or not invite_id:
        return False
    try:
        callback_resp = cffi_requests.get(
            f"{_CHATGPT_BASE}/api/auth/callback/openai",
            headers={
                "Authorization": f"Bearer {user_at}",
                "Accept": "*/*",
            },
            allow_redirects=True,
            proxies=proxies, **_REQ_KW)
    except Exception:
        pass

    headers = _make_chatgpt_headers(user_at, account_id)
    try:
        url = f"{_BACKEND_API}/accounts/{account_id}/invites/{invite_id}/accept"
        resp = cffi_requests.post(url, json={}, headers=headers,
                                   proxies=proxies, **_REQ_KW)
        if resp.status_code in (200, 201):
            return True
    except Exception:
        pass
    try:
        url = f"{_BACKEND_API}/invites/{invite_id}/accept"
        resp = cffi_requests.post(url, json={}, headers=headers,
                                   proxies=proxies, **_REQ_KW)
        return resp.status_code in (200, 201)
    except Exception:
        return False


def _api_remove_member(admin_at: str, account_id: str,
                       email: str, proxies: dict) -> bool:
    """Remove a member from the team by email."""
    if not cffi_requests or not admin_at or not account_id:
        return False
    try:
        headers = _make_chatgpt_headers(admin_at, account_id)
        offset = 0
        limit = 50
        while True:
            url = f"{_BACKEND_API}/accounts/{account_id}/users?limit={limit}&offset={offset}"
            resp = cffi_requests.get(url, headers=headers,
                                      proxies=proxies, **_REQ_KW)
            if resp.status_code != 200:
                error_code = _detect_error_code(resp)
                if error_code in ("account_deactivated", "token_invalidated"):
                    print(f"[Team] 移除成员检测到致命错误: {error_code}")
                return False
            data = resp.json()
            items = data.get("items", []) if isinstance(data, dict) else data
            total = data.get("total", 0) if isinstance(data, dict) else len(items)
            if not isinstance(items, list):
                return False
            for user in items:
                user_email = user.get("email", "").lower()
                if user_email == email.lower():
                    user_id = user.get("id", user.get("user_id", ""))
                    if not user_id:
                        return False
                    del_url = f"{_BACKEND_API}/accounts/{account_id}/users/{user_id}"
                    del_resp = cffi_requests.delete(del_url, headers=headers,
                                                    proxies=proxies, **_REQ_KW)
                    return del_resp.status_code in (200, 204)
            offset += limit
            if offset >= total:
                break
        return False
    except Exception:
        return False


def _api_delete_invite(admin_at: str, account_id: str,
                       email: str, proxies: dict) -> bool:
    """Revoke a pending invite."""
    if not cffi_requests or not admin_at or not account_id:
        return False
    try:
        url = f"{_BACKEND_API}/accounts/{account_id}/invites"
        headers = _make_chatgpt_headers(admin_at, account_id)
        payload = {"email_address": email}
        resp = cffi_requests.delete(url, json=payload, headers=headers,
                                     proxies=proxies, **_REQ_KW)
        return resp.status_code in (200, 204)
    except Exception:
        return False


_TEAM_STUB_WARNED = False


def _warn_team_stub(fn_name: str) -> None:
    """Emit a one-time notice that the invite-based Team functions are stubbed.

    v17's overspeed domain-verification path (sys_team_domain_verify) is fully
    implemented below. The invite-based allocation path (sys_node_allocate /
    sys_node_release) is intentionally left as a safe no-op stub — it is only
    used when team_mode.enable is on, and returns "not allocated" so normal /
    CPA / Sub2API / overspeed flows import and run cleanly. The legacy v14
    token-based invite helpers are kept dormant above for future wiring.
    """
    global _TEAM_STUB_WARNED
    if not _TEAM_STUB_WARNED:
        _TEAM_STUB_WARNED = True
        print(f"[Team] {fn_name} 为待接线桩（邀请制 Team）；超速妙域名验证模式可正常使用")


def _sys_node_allocate(s_reg, did, saved_temp_at, proxies) -> tuple:
    """v17 signature stub — Team seat allocation is deferred.

    Upstream v17 calls this as (session, device_id, temp_access_token, proxies)
    and expects a 4-tuple (is_allocated, handle_a, handle_b, handle_c). We return
    "not allocated" so the registration pipeline skips Team handling gracefully.
    """
    _warn_team_stub("sys_node_allocate")
    return False, "", "", ""


def _sys_node_release(saved_temp_at, handle_a="", handle_b="", handle_c="",
                      proxies=None, original_email=None) -> None:
    """v17 signature stub — seat release is a no-op while Team mode is deferred."""
    _warn_team_stub("sys_node_release")
    return None


# =====================================================================
# Overspeed Team domain verification (v17 「超速妙」)
# ---------------------------------------------------------------------
# Pure-Python reconstruction of the gated binary's sys_team_domain_verify
# flow. The binary stores its endpoints encrypted (see _decrypt_url /
# _get_url_key, entangled with the license machinery), so the exact OpenAI
# domains API paths/payloads below are a best-effort reconstruction from the
# binary string table (function decomposition, header names, payload keys,
# the /settings/auto_provision and /verify path fragments) plus the public
# Cloudflare DNS + DNS-over-HTTPS contracts. The Cloudflare / DoH halves are
# exact; the OpenAI-domains half is defensive (tries multiple field names)
# and verbosely logged so live responses can be validated and tuned.
#
# Flow: pick a Team admin (cookies model) -> add the email's domain to the
# Team -> write the verification TXT record on Cloudflare -> wait for DNS
# propagation via DoH -> verify the domain on OpenAI -> enable auto-provision
# so any @domain signup auto-joins the Team. Result is cached per domain.
# =====================================================================

_CF_API_BASE = "https://api.cloudflare.com/client/v4"
_DOH_ENDPOINTS = (
    "https://cloudflare-dns.com/dns-query",
    "https://dns.google/resolve",
    "https://dns.alidns.com/resolve",
)
_DOMAIN_VERIFY_TIMEOUT = 180        # seconds to wait for DNS propagation
_DOMAIN_VERIFY_POLL_INTERVAL = 6    # seconds between DoH polls

# domain -> (account_id, domain_id); guards against re-verifying the same domain
_verified_domains_cache: dict = {}
_domain_locks_guard = threading.Lock()
_domain_locks: dict = {}


def _domain_of(email: str) -> str:
    return email.rsplit("@", 1)[-1].strip().lower() if "@" in (email or "") else ""


def _get_domain_lock(domain: str) -> threading.Lock:
    """One lock per domain so concurrent workers don't double-verify it."""
    with _domain_locks_guard:
        lock = _domain_locks.get(domain)
        if lock is None:
            lock = threading.Lock()
            _domain_locks[domain] = lock
        return lock


def _parse_cookie(cookie_str: str, name: str) -> str:
    """Extract a single cookie value from a raw Cookie header string."""
    if not cookie_str:
        return ""
    for part in cookie_str.replace("\n", ";").split(";"):
        part = part.strip()
        if not part or "=" not in part:
            continue
        k, _, v = part.partition("=")
        if k.strip() == name:
            return v.strip()
    return ""


def _ensure_team_at_v17(team_row: dict, proxies: dict) -> str:
    """v17 cookies model: return a valid admin AT, refreshing from the stored
    session-token cookie if the AT is missing/expired."""
    at = team_row.get("access_token", "") or ""
    if at and not _jwt_is_expired(at):
        return at
    cookies = team_row.get("cookies", "") or ""
    session_token = (
        _parse_cookie(cookies, "__Secure-next-auth.session-token")
        or _parse_cookie(cookies, "next-auth.session-token")
    )
    if session_token:
        result = _refresh_with_session_token(
            session_token, proxies, team_row.get("account_id", "") or "")
        new_at = result.get("access_token", "") if result else ""
        if new_at:
            team_row["access_token"] = new_at
            return new_at
    return at  # last resort: hand back whatever we had


def _oai_admin_headers(admin_at: str, account_id: str, cookies: str) -> dict:
    """Headers for OpenAI Team admin (domains) operations — Bearer AT plus the
    admin's browser cookies, mirroring the binary's ADMIN_ORIGIN/IDENTITY use."""
    h = {
        "Accept": "*/*",
        "Accept-Language": "en-US,en;q=0.9",
        "Authorization": f"Bearer {admin_at}",
        "Content-Type": "application/json",
        "Origin": _CHATGPT_BASE,
        "Referer": f"{_CHATGPT_BASE}/admin",
        "User-Agent": _UA,
        "Connection": "keep-alive",
    }
    if account_id:
        h["chatgpt-account-id"] = account_id
    if cookies:
        h["Cookie"] = cookies
    return h


# ---- Cloudflare DNS ----

def _cf_headers() -> dict:
    from utils import config as cfg
    return {
        "X-Auth-Email": getattr(cfg, "CF_API_EMAIL", "") or "",
        "X-Auth-Key": getattr(cfg, "CF_API_KEY", "") or "",
        "Content-Type": "application/json",
    }


def _cf_get_zone_id(domain: str, proxies: dict) -> str:
    """Resolve the Cloudflare zone id for a domain, walking up to the
    registrable parent (e.g. a.b.example.com -> example.com)."""
    if cffi_requests is None:
        return ""
    headers = _cf_headers()
    if not headers.get("X-Auth-Email") or not headers.get("X-Auth-Key"):
        print(f"[Team][超速妙] 未配置 Cloudflare API 凭证 (cf_api_email / cf_api_key)")
        return ""
    labels = domain.split(".")
    candidates = [".".join(labels[i:]) for i in range(len(labels) - 1)]
    for cand in candidates:
        try:
            resp = cffi_requests.get(
                f"{_CF_API_BASE}/zones", params={"name": cand},
                headers=headers, proxies=proxies, **_REQ_KW)
            if resp.status_code == 200:
                result = resp.json().get("result", [])
                if result:
                    return result[0].get("id", "")
        except Exception:
            continue
    return ""


def _cf_set_txt(domain: str, record_name: str, content: str, proxies: dict) -> bool:
    """Create (or confirm) a TXT record on Cloudflare for domain verification."""
    if cffi_requests is None:
        return False
    zone_id = _cf_get_zone_id(domain, proxies)
    if not zone_id:
        print(f"[Team][超速妙] 未找到 {domain} 对应的 Cloudflare zone")
        return False
    headers = _cf_headers()
    payload = {"type": "TXT", "name": record_name, "content": content, "ttl": 120}
    try:
        resp = cffi_requests.post(
            f"{_CF_API_BASE}/zones/{zone_id}/dns_records",
            json=payload, headers=headers, proxies=proxies, **_REQ_KW)
        if resp.status_code in (200, 201):
            return True
        # Already-exists (CF error 81057/81058) is success for our purposes
        try:
            errors = resp.json().get("errors", [])
            codes = {str(e.get("code")) for e in errors if isinstance(e, dict)}
            blob = json.dumps(errors).lower()
        except Exception:
            codes, blob = set(), resp.text.lower() if hasattr(resp, "text") else ""
        if codes & {"81057", "81058", "81053"} or "already exists" in blob:
            return True
        print(f"[Team][超速妙] Cloudflare 写入 TXT 失败 ({resp.status_code}): {blob[:160]}")
    except Exception as e:
        print(f"[Team][超速妙] Cloudflare 写入 TXT 异常: {e}")
    return False


# ---- DNS-over-HTTPS verification ----

def _doh_txt_lookup(name: str, proxies: dict) -> list:
    """Query TXT records for `name` via several DoH providers; return values."""
    if cffi_requests is None:
        return []
    headers = {"Accept": "application/dns-json"}
    for endpoint in _DOH_ENDPOINTS:
        try:
            resp = cffi_requests.get(
                endpoint, params={"name": name, "type": "TXT"},
                headers=headers, proxies=proxies, **_REQ_KW)
            if resp.status_code != 200:
                continue
            answers = resp.json().get("Answer", []) or []
            values = []
            for ans in answers:
                if ans.get("type") in (16, "16", "TXT"):
                    values.append(str(ans.get("data", "")).strip().strip('"'))
            if values:
                return values
        except Exception:
            continue
    return []


def _wait_txt_propagation(name: str, expected: str, proxies: dict) -> bool:
    """Poll DoH until the expected TXT content is visible, or timeout."""
    deadline = time.time() + _DOMAIN_VERIFY_TIMEOUT
    needle = expected.strip().strip('"')
    while time.time() < deadline:
        for val in _doh_txt_lookup(name, proxies):
            if needle and needle in val:
                return True
        time.sleep(_DOMAIN_VERIFY_POLL_INTERVAL)
    return False


# ---- OpenAI Team verified-domains API ----

def _oai_add_domain(headers: dict, account_id: str, domain: str, proxies: dict) -> dict:
    """Register `domain` on the Team workspace. Returns a dict with the
    domain_id and the DNS record (name + token) to publish, parsed
    defensively across the field names seen in the binary string table."""
    if cffi_requests is None:
        return {}
    url = f"{_BACKEND_API}/accounts/{account_id}/domains"
    for body in ({"domain": domain}, {"domain_name": domain}, {"name": domain}):
        try:
            resp = cffi_requests.post(url, json=body, headers=headers,
                                      proxies=proxies, **_REQ_KW)
            if resp.status_code in (200, 201):
                data = resp.json() if resp.text else {}
                if isinstance(data, dict):
                    return data
            elif resp.status_code in (400, 409):
                # Domain may already be registered — fall through to GET lookup
                break
        except Exception:
            continue
    # Fallback: list existing domains and find this one
    try:
        resp = cffi_requests.get(url, headers=headers, proxies=proxies, **_REQ_KW)
        if resp.status_code == 200:
            data = resp.json()
            items = data.get("items", data) if isinstance(data, dict) else data
            if isinstance(items, list):
                for item in items:
                    dn = str(item.get("domain", item.get("name", ""))).lower()
                    if dn == domain.lower():
                        return item
    except Exception:
        pass
    return {}


def _extract_domain_fields(info: dict, domain: str) -> tuple:
    """Pull (domain_id, txt_record_name, txt_token) out of an add-domain
    response, tolerating the several shapes OpenAI/the binary may use."""
    domain_id = str(info.get("id", info.get("domain_id", "")))
    token = (info.get("dns_verification_token")
             or info.get("verification_token")
             or info.get("token") or "")
    record_name = (info.get("dns_record_name")
                   or info.get("record_name")
                   or info.get("host") or "")
    # Some shapes nest the record under a key
    rec = info.get("dns_record") or info.get("txt_record") or info.get("verification")
    if isinstance(rec, dict):
        token = token or rec.get("value") or rec.get("content") or rec.get("token") or ""
        record_name = record_name or rec.get("name") or rec.get("host") or ""
    if not record_name:
        record_name = domain  # default: TXT at the apex
    return domain_id, record_name, str(token)


def _oai_verify_domain(headers: dict, account_id: str, domain_id: str, proxies: dict) -> bool:
    if cffi_requests is None or not domain_id:
        return False
    url = f"{_BACKEND_API}/accounts/{account_id}/domains/{domain_id}/verify"
    try:
        resp = cffi_requests.post(url, json={}, headers=headers,
                                  proxies=proxies, **_REQ_KW)
        if resp.status_code in (200, 201, 204):
            return True
        try:
            blob = resp.text.lower()
        except Exception:
            blob = ""
        if "verified" in blob:
            return True
        print(f"[Team][超速妙] OpenAI 域名验证返回 {resp.status_code}: {blob[:160]}")
    except Exception as e:
        print(f"[Team][超速妙] OpenAI 域名验证异常: {e}")
    return False


def _oai_enable_auto_provision(headers: dict, account_id: str, proxies: dict) -> bool:
    """Enable domain-based auto provisioning so @domain signups auto-join."""
    if cffi_requests is None:
        return False
    url = f"{_BACKEND_API}/accounts/{account_id}/settings/auto_provision"
    for body in ({"enabled": True}, {"auto_provision": True}, {"value": True}):
        try:
            resp = cffi_requests.post(url, json=body, headers=headers,
                                      proxies=proxies, **_REQ_KW)
            if resp.status_code in (200, 201, 204):
                return True
        except Exception:
            continue
    return False


def _sys_team_domain_verify(email, proxies) -> tuple:
    """v17 「超速妙」: ensure the email's domain is verified + auto-provisioning
    on a Team workspace, so the account auto-joins on signup (no per-user
    invite). Returns (is_verified, account_id, domain, domain_id).
    """
    domain = _domain_of(email)
    if not domain:
        return False, "", "", ""

    lock = _get_domain_lock(domain)
    with lock:
        cached = _verified_domains_cache.get(domain)
        if cached:
            return True, cached[0], domain, cached[1]

        try:
            from utils import db_manager
            team = db_manager.get_random_team_account()
        except Exception:
            team = None
        if not team:
            print(f"[Team][超速妙] Team 库为空，无法验证域名 {domain}")
            return False, "", "", ""

        admin_at = _ensure_team_at_v17(team, proxies)
        cookies = team.get("cookies", "") or ""
        if not admin_at and not cookies:
            print(f"[Team][超速妙] Team 账号缺少有效凭证，无法验证域名 {domain}")
            return False, "", "", ""

        account_id = team.get("account_id", "") or _get_account_id(admin_at, proxies)
        if not account_id:
            print(f"[Team][超速妙] 无法获取 Team account_id")
            return False, "", "", ""

        headers = _oai_admin_headers(admin_at, account_id, cookies)

        # 1) Register the domain on the Team and read the verification record
        info = _oai_add_domain(headers, account_id, domain, proxies)
        if not info:
            print(f"[Team][超速妙] 在 Team 添加域名 {domain} 失败")
            return False, "", "", ""
        domain_id, record_name, token = _extract_domain_fields(info, domain)
        if not token:
            print(f"[Team][超速妙] 未取得域名 {domain} 的验证 TXT 值，响应: {json.dumps(info)[:200]}")
            return False, "", "", ""

        # 2) Publish the TXT record on Cloudflare
        if not _cf_set_txt(domain, record_name, token, proxies):
            return False, "", "", ""

        # 3) Wait for DNS propagation
        print(f"[Team][超速妙] 已写入 TXT，等待 DNS 传播 ({record_name})...")
        if not _wait_txt_propagation(record_name, token, proxies):
            print(f"[Team][超速妙] DNS 传播超时，域名 {domain} 验证失败")
            return False, "", "", ""

        # 4) Ask OpenAI to verify, then enable auto-provisioning
        if not _oai_verify_domain(headers, account_id, domain_id, proxies):
            return False, "", "", ""
        _oai_enable_auto_provision(headers, account_id, proxies)

        _verified_domains_cache[domain] = (account_id, domain_id)
        print(f"[Team][超速妙] 域名 {domain} 已验证并开启自动加入")
        return True, account_id, domain, domain_id


def _api_clear_all_seats_silent(admin_at: str, account_id: str, proxies: dict) -> int:
    """Remove all members and revoke all pending invites from a team.

    Uses ThreadPoolExecutor for concurrent deletion (v14.2.1 upstream pattern).
    Returns the number of cleared items (members + invites).
    """
    if not cffi_requests or not admin_at or not account_id:
        return 0
    total_cleared = 0
    headers = _make_chatgpt_headers(admin_at, account_id)

    def _do_delete(url, json_body=None):
        try:
            if json_body:
                r = cffi_requests.delete(url, json=json_body, headers=headers, proxies=proxies, **_REQ_KW)
            else:
                r = cffi_requests.delete(url, headers=headers, proxies=proxies, **_REQ_KW)
            return r.status_code in (200, 204)
        except Exception:
            return False

    # 1. Remove all members (paginate, concurrent delete)
    try:
        from concurrent.futures import ThreadPoolExecutor, as_completed
        offset = 0
        limit = 100
        while True:
            url = f"{_BACKEND_API}/accounts/{account_id}/users?limit={limit}&offset={offset}"
            resp = cffi_requests.get(url, headers=headers, proxies=proxies, **_REQ_KW)
            if resp.status_code != 200:
                break
            data = resp.json()
            items = data.get("items", []) if isinstance(data, dict) else data
            total = data.get("total", 0) if isinstance(data, dict) else len(items)
            if not isinstance(items, list) or not items:
                break
            delete_tasks = []
            for user in items:
                user_id = user.get("id", user.get("user_id", ""))
                if not user_id:
                    continue
                del_url = f"{_BACKEND_API}/accounts/{account_id}/users/{user_id}"
                delete_tasks.append(del_url)
            with ThreadPoolExecutor(max_workers=min(len(delete_tasks), 8)) as executor:
                futures = {executor.submit(_do_delete, u): u for u in delete_tasks}
                for f in as_completed(futures):
                    if f.result():
                        total_cleared += 1
            offset += limit
            if offset >= total:
                break
    except Exception:
        pass

    # 2. Revoke all pending invites (paginate, concurrent delete)
    try:
        offset = 0
        limit = 100
        while True:
            url = f"{_BACKEND_API}/accounts/{account_id}/invites?limit={limit}&offset={offset}"
            resp = cffi_requests.get(url, headers=headers, proxies=proxies, **_REQ_KW)
            if resp.status_code != 200:
                break
            data = resp.json()
            items = data.get("items", data) if isinstance(data, dict) else data
            if not isinstance(items, list) or not items:
                break
            delete_tasks = []
            for inv in items:
                inv_email = inv.get("email_address", inv.get("email", ""))
                if not inv_email:
                    continue
                delete_tasks.append(inv_email)
            del_url = f"{_BACKEND_API}/accounts/{account_id}/invites"
            with ThreadPoolExecutor(max_workers=min(len(delete_tasks), 8)) as executor:
                futures = {executor.submit(_do_delete, del_url, {"email_address": e}): e for e in delete_tasks}
                for f in as_completed(futures):
                    if f.result():
                        total_cleared += 1
            offset += limit
            if offset >= len(items):
                break
    except Exception:
        pass

    return total_cleared


def _sys_node_bulk_silent(proxies: dict = None, force_all: bool = False) -> None:
    """Bulk maintenance: iterate all team accounts, ensure tokens are valid,
    and optionally clean up stale seats.

    Uses ThreadPoolExecutor for concurrent processing (v14.2.1 upstream pattern).
    """
    try:
        from utils import db_manager
        from concurrent.futures import ThreadPoolExecutor, as_completed
        team_accounts = db_manager.get_all_team_accounts()
        if not team_accounts:
            return

        def _process_team(team):
            try:
                valid_at = _ensure_access_token(team, proxies, force=False)
                if not valid_at:
                    return
                account_id = team.get("account_id", "")
                if not account_id:
                    account_id = _get_account_id(valid_at, proxies)
                    if account_id:
                        try:
                            db_manager.update_team_account_tokens(
                                team["id"], account_id=account_id)
                        except Exception:
                            pass
                if not account_id:
                    return
                if force_all:
                    cleared = _api_clear_all_seats_silent(valid_at, account_id, proxies)
                    if cleared > 0:
                        print(f"[Team] Team {team['id']} 全局清洗完成，清理 {cleared} 个席位")
            except Exception:
                pass

        with ThreadPoolExecutor(max_workers=min(len(team_accounts), 4)) as executor:
            futures = [executor.submit(_process_team, t) for t in team_accounts]
            for f in as_completed(futures):
                try:
                    f.result()
                except Exception:
                    pass
    except Exception:
        pass


_ac.email_jwt = _email_jwt
_ac.sys_node_allocate = _sys_node_allocate
_ac.sys_node_release = _sys_node_release
_ac.sys_team_domain_verify = _sys_team_domain_verify
_ac.sys_node_bulk_silent = _sys_node_bulk_silent
