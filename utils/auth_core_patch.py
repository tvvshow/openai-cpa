"""
Compatibility shim: adds v14.0.0 APIs to the v13.1.0 auth_core compiled binary.

Importing this module monkey-patches ``utils.auth_core`` so that code written
against v14.0.0 continues to work without the license-check machinery.

Reverse-engineered from v14.0.0 Nuitka-compiled binary (string table analysis).
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

    Flow (from binary): /api/auth/callback/openai -> /api/auth/session
    """
    if cffi_requests is None:
        return {}
    try:
        # Step 1: OpenAI callback to establish chatgpt.com session cookies
        callback_resp = cffi_requests.get(
            f"{_CHATGPT_BASE}/api/auth/callback/openai",
            headers={
                "User-Agent": _UA,
                "Authorization": f"Bearer {access_token}",
            },
            allow_redirects=True,
            proxies=proxies, **_REQ_KW)
        if callback_resp.status_code not in (200, 302):
            return {}

        # Step 2: Get session which contains accessToken and account info
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
    """Get chatgpt_account_id via api.openai.com/profile or /auth.

    From binary: calls api.openai.com/profile then api.openai.com/auth,
    extracts chatgpt_account_id from the response.
    """
    if cffi_requests is None:
        return ""
    headers = {
        "User-Agent": _UA,
        "Authorization": f"Bearer {access_token}",
        "Accept": "application/json",
    }
    try:
        resp = cffi_requests.get(
            "https://api.openai.com/profile",
            headers=headers, proxies=proxies, **_REQ_KW)
        if resp.status_code == 200:
            data = resp.json()
            # Try direct field
            acc_id = data.get("chatgpt_account_id", "")
            if acc_id:
                return acc_id
    except Exception:
        pass
    try:
        resp = cffi_requests.get(
            "https://api.openai.com/auth",
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

    From binary: Authorization, Bearer, chatgpt-account-id, Content-Type,
    Referer (admin/members page), impersonate chrome110.
    """
    h = {
        "User-Agent": _UA,
        "Authorization": f"Bearer {access_token}",
        "Content-Type": "application/json",
        "Accept": "application/json",
        "Referer": "https://chatgpt.com/admin/members?tab=members",
    }
    if account_id:
        h["chatgpt-account-id"] = account_id
    return h


def _api_send_invite(admin_at: str, account_id: str,
                     email: str, proxies: dict) -> bool:
    """Send a team invite to the given email address.

    From binary: POST /accounts/{account_id}/invites
    Body: {email_addresses: [email], role: "standard-user",
           seat_type: ..., usage_based: ..., resend_emails: ...}
    """
    if not cffi_requests or not admin_at or not account_id:
        return False
    try:
        url = f"{_BACKEND_API}/accounts/{account_id}/invites"
        headers = _make_chatgpt_headers(admin_at, account_id)
        payload = {
            "email_addresses": [email],
            "role": "standard-user",
            "seat_type": "standard-user",
            "usage_based": False,
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

    From binary: GET /accounts/{account_id}/invites, filter by email_address,
    extract 'id'. Has retry logic (max_retries, attempt).
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
            items = data if isinstance(data, list) else data.get("items", [])
            for item in items:
                inv_email = item.get("email_address", "")
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

    From binary: POST /accounts/{account_id}/invites/{invite_id}/accept
    Also tries /invites/{invite_id}/accept as alt_url fallback.
    """
    if not cffi_requests or not user_at or not invite_id:
        return False
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
    # Fallback URL
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

    From binary: GET /accounts/{account_id}/users?limit=100&offset=0
    then find user by email, DELETE /accounts/{account_id}/users/{user_id}
    """
    if not cffi_requests or not admin_at or not account_id:
        return False
    try:
        # List users
        headers = _make_chatgpt_headers(admin_at, account_id)
        url = f"{_BACKEND_API}/accounts/{account_id}/users?limit=100&offset=0"
        resp = cffi_requests.get(url, headers=headers,
                                 proxies=proxies, **_REQ_KW)
        if resp.status_code != 200:
            return False
        data = resp.json()
        items = data.get("items", data) if isinstance(data, dict) else data
        if not isinstance(items, list):
            return False
        # Find target user
        for user in items:
            user_email = user.get("email", "").lower()
            if user_email == email.lower():
                user_id = user.get("id", user.get("user_id", ""))
                if not user_id:
                    continue
                # Delete the user
                del_url = f"{_BACKEND_API}/accounts/{account_id}/users/{user_id}"
                del_resp = cffi_requests.delete(del_url, headers=headers,
                                                proxies=proxies, **_REQ_KW)
                return del_resp.status_code in (200, 204)
        return False
    except Exception:
        return False


def _sys_node_allocate(data: str, proxies) -> tuple:
    """Allocate a team seat for the newly registered user.

    Reverse-engineered flow from v14.0.0 binary:
    1. Pick a random team admin from team_accounts table
    2. Get admin's chatgpt_account_id via api.openai.com/profile
    3. Extract email from the new user's JWT
    4. _api_send_invite(admin_at, account_id, email, proxies)
    5. _api_get_invite_id(admin_at, account_id, email, proxies)
    6. _api_accept_invite(user_at= data, account_id, invite_id, proxies)
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

    Reverse-engineered from v14.0.0 binary:
    1. Get admin's access_token from team_accounts
    2. Use handle_b as chatgpt_account_id
    3. Extract email from the user's JWT
    4. _api_remove_member(admin_at, account_id, email, proxies)
    """
    try:
        if not handle_b:
            return
        account_id = handle_b
        jwt_data = _email_jwt(temp_user_at)
        email = jwt_data.get("email", "")
        if not email:
            return
        # Get admin token from DB
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