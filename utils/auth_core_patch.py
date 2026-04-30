"""
Compatibility shim: adds v14.0.0 APIs to the v13.1.0 auth_core compiled binary.

Importing this module monkey-patches ``utils.auth_core`` so that code written
against v14.0.0 continues to work without the license-check machinery.
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
    """Use an OpenAI access_token to sign into ChatGPT and return the session JSON."""
    if cffi_requests is None:
        return {}
    try:
        # Step 1: Get CSRF token
        csrf_resp = cffi_requests.get(
            f"{_CHATGPT_BASE}/api/auth/csrf",
            headers={"User-Agent": _UA},
            proxies=proxies, **_REQ_KW)
        if csrf_resp.status_code != 200:
            return {}
        csrf_token = csrf_resp.json().get("csrfToken", "")

        # Step 2: Sign in with OpenAI token
        signin_resp = cffi_requests.get(
            f"{_CHATGPT_BASE}/api/auth/signin/openai?",
            headers={
                "User-Agent": _UA,
                "Authorization": f"Bearer {access_token}",
            },
            proxies=proxies, **_REQ_KW)
        if signin_resp.status_code not in (200, 302):
            return {}

        # Step 3: Get session info
        session_resp = cffi_requests.get(
            f"{_CHATGPT_BASE}/api/auth/session",
            headers={"User-Agent": _UA},
            proxies=proxies, **_REQ_KW)
        if session_resp.status_code != 200:
            return {}
        return session_resp.json()
    except Exception:
        return {}


def _get_team_admin_session(proxies: dict) -> tuple:
    """Get a random team account and its ChatGPT session info.
    Returns (admin_access_token, chatgpt_account_id, admin_user_id) or (None, None, None).
    """
    try:
        from utils import db_manager
        team = db_manager.get_random_team_account()
        if not team:
            return None, None, None
        admin_at = team.get("access_token", "")
        if not admin_at:
            return None, None, None
        session = _get_chatgpt_session(admin_at, proxies)
        if not session:
            return None, None, None
        # Extract account_id from session
        account_id = ""
        user_id = session.get("user", {}).get("id", "")
        # The chatgpt-account-id is typically in the accounts list
        accounts = session.get("accounts", {}).get("accounts", [])
        for acc in accounts:
            account = acc.get("account", {})
            if account.get("account", {}).get("is_deactivated", False):
                continue
            acc_id = account.get("account_id", "")
            if acc_id:
                account_id = acc_id
                break
        if not account_id:
            # Fallback: try the first non-deactivated account
            for acc in accounts:
                acc_id = acc.get("account", {}).get("account_id", "")
                if acc_id:
                    account_id = acc_id
                    break
        return admin_at, account_id, user_id
    except Exception:
        return None, None, None


def _make_chatgpt_headers(access_token: str, account_id: str = "") -> dict:
    """Build headers for ChatGPT backend-api requests."""
    h = {
        "User-Agent": _UA,
        "Authorization": f"Bearer {access_token}",
        "Content-Type": "application/json",
        "Accept": "application/json",
    }
    if account_id:
        h["chatgpt-account-id"] = account_id
    return h


def _api_send_invite(admin_at: str, chatgpt_account_id: str,
                     email_address: str, proxies: dict) -> bool:
    """Send a team invite to the given email address."""
    if not cffi_requests or not admin_at or not chatgpt_account_id:
        return False
    try:
        url = f"{_BACKEND_API}/accounts/{chatgpt_account_id}/invites"
        headers = _make_chatgpt_headers(admin_at, chatgpt_account_id)
        payload = {
            "email_address": email_address,
            "role": "standard-user",
        }
        resp = cffi_requests.post(url, json=payload, headers=headers,
                                  proxies=proxies, **_REQ_KW)
        return resp.status_code in (200, 201)
    except Exception:
        return False


def _api_get_invite_id(admin_at: str, chatgpt_account_id: str,
                       email_address: str, proxies: dict) -> str:
    """Get the invite ID for a specific email from pending invites."""
    if not cffi_requests or not admin_at or not chatgpt_account_id:
        return ""
    try:
        url = f"{_BACKEND_API}/accounts/{chatgpt_account_id}/invites"
        headers = _make_chatgpt_headers(admin_at, chatgpt_account_id)
        resp = cffi_requests.get(url, headers=headers,
                                 proxies=proxies, **_REQ_KW)
        if resp.status_code != 200:
            return ""
        invites = resp.json()
        if isinstance(invites, dict):
            invites = invites.get("items", invites.get("invites", []))
        if isinstance(invites, list):
            for inv in invites:
                inv_email = inv.get("email_address", inv.get("email", ""))
                if inv_email.lower() == email_address.lower():
                    return str(inv.get("id", inv.get("invite_id", "")))
        return ""
    except Exception:
        return ""


def _api_accept_invite(user_at: str, invite_id: str, proxies: dict) -> bool:
    """Accept a team invite using the new user's access token."""
    if not cffi_requests or not user_at or not invite_id:
        return False
    try:
        url = f"{_BACKEND_API}/invites/{invite_id}/accept"
        headers = _make_chatgpt_headers(user_at)
        resp = cffi_requests.post(url, json={}, headers=headers,
                                  proxies=proxies, **_REQ_KW)
        return resp.status_code in (200, 201)
    except Exception:
        return False


def _api_remove_member(admin_at: str, chatgpt_account_id: str,
                       user_id: str, proxies: dict) -> bool:
    """Remove a member from the team."""
    if not cffi_requests or not admin_at or not chatgpt_account_id or not user_id:
        return False
    try:
        url = f"{_BACKEND_API}/accounts/{chatgpt_account_id}/users/{user_id}"
        headers = _make_chatgpt_headers(admin_at, chatgpt_account_id)
        resp = cffi_requests.delete(url, headers=headers,
                                    proxies=proxies, **_REQ_KW)
        return resp.status_code in (200, 204)
    except Exception:
        return False


def _sys_node_allocate(data: str, proxies) -> tuple:
    """Allocate a team seat for the newly registered user.

    Flow:
    1. Pick a random team admin from team_accounts table
    2. Use admin token to sign into ChatGPT, get account_id
    3. Send invite to the new user's email (extracted from JWT)
    4. Get the invite_id
    5. New user accepts the invite
    6. Return (success, invite_id, chatgpt_account_id)
    """
    try:
        # Extract email from the new user's access token
        jwt_data = _email_jwt(data)
        email_address = jwt_data.get("email", "")
        if not email_address:
            return False, "", ""

        # Get a team admin session
        admin_at, chatgpt_account_id, admin_user_id = _get_team_admin_session(proxies)
        if not admin_at or not chatgpt_account_id:
            return False, "", ""

        # Send invite
        if not _api_send_invite(admin_at, chatgpt_account_id, email_address, proxies):
            return False, "", ""

        time.sleep(2)  # Wait for invite to be processed

        # Get invite ID
        invite_id = _api_get_invite_id(admin_at, chatgpt_account_id, email_address, proxies)
        if not invite_id:
            return False, "", ""

        # Accept invite
        if not _api_accept_invite(data, invite_id, proxies):
            return False, invite_id, chatgpt_account_id

        return True, invite_id, chatgpt_account_id
    except Exception:
        return False, "", ""


def _sys_node_release(temp_user_at: str, handle_a: str, handle_b: str, proxies) -> None:
    """Release a team seat by removing the user from the team.

    Args:
        temp_user_at: The user's access_token
        handle_a: invite_id (unused for removal)
        handle_b: chatgpt_account_id of the team admin
    """
    try:
        if not handle_b:
            return
        # Get admin session to remove the user
        admin_at, admin_account_id, _ = _get_team_admin_session(proxies)
        if not admin_at:
            return
        # Use handle_b (chatgpt_account_id) to find and remove the user
        # Get user list to find the user's ID
        chatgpt_account_id = handle_b
        headers = _make_chatgpt_headers(admin_at, chatgpt_account_id)
        url = f"{_BACKEND_API}/accounts/{chatgpt_account_id}/users?limit=100&offset=0"
        resp = cffi_requests.get(url, headers=headers, proxies=proxies, **_REQ_KW)
        if resp.status_code != 200:
            return
        users_data = resp.json()
        users = users_data if isinstance(users_data, list) else users_data.get("items", [])
        # Find the user by their email from the JWT
        jwt_data = _email_jwt(temp_user_at)
        target_email = jwt_data.get("email", "").lower()
        for user in users:
            user_email = user.get("email", "").lower()
            if user_email == target_email:
                user_id = user.get("id", user.get("user_id", ""))
                if user_id:
                    _api_remove_member(admin_at, chatgpt_account_id, user_id, proxies)
                break
    except Exception:
        pass


_ac.email_jwt = _email_jwt
_ac.sys_node_allocate = _sys_node_allocate
_ac.sys_node_release = _sys_node_release