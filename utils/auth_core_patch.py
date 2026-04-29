"""
Compatibility shim: adds v14.0.0 APIs to the v13.1.0 auth_core compiled binary.

Importing this module monkey-patches ``utils.auth_core`` so that code written
against v14.0.0 continues to work without the license-check machinery.
"""
import base64
import json

import utils.auth_core as _ac


def _email_jwt(acc_token: str) -> str:
    """Extract the email address from a JWT access-token payload."""
    try:
        payload = acc_token.split(".")[1]
        payload += "=" * (-len(payload) % 4)
        data = json.loads(base64.urlsafe_b64decode(payload))
        return data.get("email") or data.get("preferred_username") or data.get("upn") or ""
    except Exception:
        return ""


def _sys_node_allocate(data, proxies):
    """Stub: team-mode node allocation (no-op without license server)."""
    return True, "", ""


def _sys_node_release(temp_user_at, handle_a, handle_b, proxies):
    """Stub: team-mode node release (no-op without license server)."""
    pass


_ac.email_jwt = _email_jwt
_ac.sys_node_allocate = _sys_node_allocate
_ac.sys_node_release = _sys_node_release
