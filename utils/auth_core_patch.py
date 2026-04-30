"""
Compatibility shim: adds v14.0.0 APIs to the v13.1.0 auth_core compiled binary.

Importing this module monkey-patches ``utils.auth_core`` so that code written
against v14.0.0 continues to work without the license-check machinery.

API details verified against:
- v14.0.0 Nuitka binary string table (function names, URL fragments, payload fields)
- https://github.com/loLollipop/team-manage-refresh (production ChatGPT API reference)
"""
import base64
import json
import time

import utils.auth_core as _ac

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


def _email_jwt(acc_token: str) -> dict:
    """Extract the JWT payload from an access-token, returning the full dict."""
    try:
        payload = acc_token.split(".")[1]
        payload += "=" * (-len(payload) % 4)
        data = json.loads(base64.urlsafe_b64decode(payload))
        return data if isinstance(data, dict) else {}
    except Exception:
        return {}


def _get_chatgpt_session(access_token: str, proxies: dict) -> dict:
    """Use an OpenAI access_token to sign into ChatGPT and return the session JSON.

    Binary: /api/auth/callback/openai -> /api/auth/session -> extract accessToken
    Reference: GET /api/auth/session with Cookie header for session_token refresh
    """
    if cffi_requests is None:
        return {}
    try:
        # Establish chatgpt.com session via OpenAI callback
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

        # Get session containing accessToken and account info
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
    """Get team chatgpt_account_id from the accounts check endpoint.

    Binary: calls api.openai.com/profile + api.openai.com/auth
    Reference (confirmed): GET /backend-api/accounts/check/v4-2023-04-27
    Response: {accounts: {id: {account: {plan_type: "team", ...}}}}
    """
    if cffi_requests is None:
        return ""
    headers = {
        "Authorization": f"Bearer {access_token}",
        "Accept": "application/json",
    }
    # Primary: backend-api accounts check (from reference repo)
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
                # Fallback: return first account id
                for aid in accounts:
                    return aid
    except Exception:
        pass
    # Fallback: api.openai.com (from binary strings)
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
    """Get a random team account and its chatgpt_account_id.

    Returns (admin_access_token, chatgpt_account_id) or (None, None).
    """
    try:
        from utils import db_manager
        team = db_manager.get_random_team_account()
        if not team:
            return None, None
        admin_at = team.get("access_token", "")
        if not admin_at:
            return None, None
        account_id = _get_account_id(admin_at, proxies)
        if not account_id:
            return None, None
        return admin_at, account_id
    except Exception:
        return None, None


def _make_chatgpt_headers(access_token: str, account_id: str = "") -> dict:
    """Build headers for ChatGPT backend-api requests.

    Binary: Authorization, Bearer, chatgpt-account-id, Content-Type
    Reference: adds Origin, Accept-Language, Connection
    """
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
    """Send a team invite to the given email address.

    Binary+Reference: POST /accounts/{account_id}/invites
    Body: {email_addresses: [email], role: "standard-user", resend_emails: true}
    """
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
        return resp.status_code in (200, 201)
    except Exception:
        return False


def _api_get_invite_id(admin_at: str, account_id: str,
                       email_address: str, proxies: dict,
                       max_retries: int = 3) -> str:
    """Get the invite ID for a specific email from pending invites.

    Binary: GET /accounts/{account_id}/invites, filter by email_address, extract id
    Reference: response uses {items: [{email_address, id, ...}]}
    """
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
    """Accept a team invite using the new user's access token.

    Binary: POST /accounts/{account_id}/invites/{invite_id}/accept (primary)
           /invites/{invite_id}/accept (alt_url fallback)
    The new user signs into chatgpt.com first, then accepts.
    """
    if not cffi_requests or not user_at or not invite_id:
        return False
    # Establish chatgpt session for the new user first
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
    # Primary URL
    try:
        url = f"{_BACKEND_API}/accounts/{account_id}/invites/{invite_id}/accept"
        resp = cffi_requests.post(url, json={}, headers=headers,
                                  proxies=proxies, **_REQ_KW)
        if resp.status_code in (200, 201):
            return True
    except Exception:
        pass
    # Fallback URL (from binary alt_url)
    try:
        url = f"{_BACKEND_API}/invites/{invite_id}/accept"
        resp = cffi_requests.post(url, json={}, headers=headers,
                                  proxies=proxies, **_REQ_KW)
        return resp.status_code in (200, 201)
    except Exception:
        return False


def _api_remove_member(admin_at: str, account_id: str,
                       email: str, proxies: dict) -> bool:
    """Remove a member from the team by email.

    Binary+Reference: GET /accounts/{id}/users?limit=N&offset=0
    Response: {items: [{email, id, ...}], total: N}
    Then: DELETE /accounts/{id}/users/{user_id}
    """
    if not cffi_requests or not admin_at or not account_id:
        return False
    try:
        headers = _make_chatgpt_headers(admin_at, account_id)
        # Paginate through all members
        offset = 0
        limit = 50
        while True:
            url = f"{_BACKEND_API}/accounts/{account_id}/users?limit={limit}&offset={offset}"
            resp = cffi_requests.get(url, headers=headers,
                                     proxies=proxies, **_REQ_KW)
            if resp.status_code != 200:
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
    """Revoke a pending invite.

    Reference: DELETE /accounts/{account_id}/invites
    Body: {email_address: email}
    """
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
    1. get_random_team_account() from DB
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

        admin_at, account_id = _get_team_admin_info(proxies)
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
        from utils import db_manager
        team = db_manager.get_random_team_account()
        if not team:
            return
        admin_at = team.get("access_token", "")
        if not admin_at:
            return
        _api_remove_member(admin_at, account_id, email, proxies)
    except Exception:
        pass


_ac.email_jwt = _email_jwt
_ac.sys_node_allocate = _sys_node_allocate
_ac.sys_node_release = _sys_node_release