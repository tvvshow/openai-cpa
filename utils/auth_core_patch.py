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
    Primary: POST auth.openai.com/oauth/token (JSON)
    Fallback: POST auth0.openai.com/oauth/token (form-urlencoded)
    """
    if cffi_requests is None or not refresh_token or not client_id:
        return {}
    try:
        # Primary: JSON to auth.openai.com
        url = "https://auth.openai.com/oauth/token"
        payload = {
            "client_id": client_id,
            "grant_type": "refresh_token",
            "redirect_uri": "com.openai.sora://auth.openai.com/android/com.openai.sora/callback",
            "refresh_token": refresh_token,
        }
        headers = {"Content-Type": "application/json"}
        resp = cffi_requests.post(url, json=payload, headers=headers,
                                   proxies=proxies, **_REQ_KW)
        if 200 <= resp.status_code < 300:
            data = resp.json()
            return {
                "access_token": data.get("access_token", ""),
                "id_token": data.get("id_token", ""),
                "refresh_token": data.get("refresh_token", ""),
            }

        # Fallback: form-urlencoded to auth0.openai.com
        url2 = "https://auth0.openai.com/oauth/token"
        form_data = {
            "grant_type": "refresh_token",
            "client_id": client_id,
            "refresh_token": refresh_token,
            "scope": "openid profile email offline_access",
        }
        headers2 = {
            "Content-Type": "application/x-www-form-urlencoded",
            "Accept": "application/json",
        }
        resp2 = cffi_requests.post(url2, data=form_data, headers=headers2,
                                    proxies=proxies, **_REQ_KW)
        if 200 <= resp2.status_code < 300:
            data = resp2.json()
            return {
                "access_token": data.get("access_token", ""),
                "id_token": data.get("id_token", ""),
                "refresh_token": data.get("refresh_token", ""),
            }
        return {}
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


def _sys_node_allocate(data: str, proxies) -> tuple:
    """Allocate a team seat for the newly registered user.

    Flow (binary + reference):
    1. get_random_team_account() from DB (with token refresh)
    2. _get_account_id() to find admin's team account_id
    3. Extract email from new user's JWT
    4. _api_send_invite(admin_at, account_id, email)
    5. _api_get_invite_id(admin_at, account_id, email)
    6. _api_accept_invite(user_at=data, account_id, invite_id)
    7. Return (success, invite_id, chatgpt_account_id)
    """
    try:
        jwt_data = _email_jwt(data)
        email_address = jwt_data.get("email", "")
        if not email_address:
            return False, "", ""

        admin_at, account_id, _ = _get_team_admin_info(proxies)
        if not admin_at or not account_id:
            return False, "", ""

        if not _api_send_invite(admin_at, account_id, email_address, proxies):
            return False, "", ""

        time.sleep(2)

        invite_id = _api_get_invite_id(admin_at, account_id, email_address, proxies)
        if not invite_id:
            return False, "", ""

        if not _api_accept_invite(data, account_id, invite_id, proxies):
            return False, invite_id, account_id

        return True, invite_id, account_id
    except Exception:
        return False, "", ""


def _sys_node_release(temp_user_at: str, handle_a: str, handle_b: str, proxies) -> None:
    """Release a team seat by removing the user from the team.

    handle_a = invite_id (unused for removal)
    handle_b = chatgpt_account_id of the team
    """
    try:
        if not handle_b:
            return
        account_id = handle_b
        jwt_data = _email_jwt(temp_user_at)
        email = jwt_data.get("email", "")
        if not email:
            return
        # Use _get_team_admin_info which handles token refresh
        admin_at, _, _ = _get_team_admin_info(proxies)
        if not admin_at:
            return
        _api_remove_member(admin_at, account_id, email, proxies)
    except Exception:
        pass


_ac.email_jwt = _email_jwt
_ac.sys_node_allocate = _sys_node_allocate
_ac.sys_node_release = _sys_node_release
