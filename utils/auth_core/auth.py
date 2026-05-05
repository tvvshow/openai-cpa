"""Authentication initialization and token exchange.

init_auth: Obtains a device ID (oai-did) and User-Agent from chatgpt.com.
image2api_data: Follows OAuth redirect chain to extract access_token.
"""
import json
import time
import urllib.parse
from typing import Optional, Tuple

from curl_cffi import requests as cffi_requests

from .utils import _ts

_CHATGPT_BASE = "https://chatgpt.com"
_UA = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
       "AppleWebKit/537.36 (KHTML, like Gecko) "
       "Chrome/110.0.0.0 Safari/537.36")


def init_auth(
    session: cffi_requests.Session,
    email: str,
    masked_email: str,
    proxies: Optional[dict] = None,
    verify: bool = True,
) -> Tuple[str, str]:
    """Get device ID and User-Agent from chatgpt.com.

    Flow:
    1. GET /api/auth/csrf -> extract csrfToken
    2. POST /api/auth/signin/openai -> extract oai-did from cookies/headers
    3. GET /api/auth/session -> confirm session

    Returns (device_id, user_agent). device_id may be empty if extraction fails.
    """
    ua = _UA
    did = ""
    ssl_verify = verify if verify is not None else False

    try:
        # Step 1: Get CSRF token
        csrf_resp = session.get(
            f"{_CHATGPT_BASE}/api/auth/csrf",
            headers={"User-Agent": ua, "Accept": "application/json"},
            proxies=proxies, verify=ssl_verify, timeout=15,
        )
        csrf_data = csrf_resp.json() if csrf_resp.status_code == 200 else {}
        csrf_token = csrf_data.get("csrfToken", "")

        # Step 2: Sign in to get redirect URL
        signin_url = f"{_CHATGPT_BASE}/api/auth/signin/openai?"
        headers = {
            "User-Agent": ua,
            "Content-Type": "application/x-www-form-urlencoded",
            "Accept": "application/json",
            "Referer": f"{_CHATGPT_BASE}/",
        }
        form_data = f"csrfToken={csrf_token}&callbackUrl={_CHATGPT_BASE}/&json=true"

        signin_resp = session.post(
            signin_url, data=form_data, headers=headers,
            proxies=proxies, verify=ssl_verify, timeout=15,
            allow_redirects=False,
        )

        # Step 3: Follow redirect to auth.openai.com (this sets oai-did cookie)
        redirect_url = ""
        if signin_resp.status_code == 200:
            try:
                body = signin_resp.json()
                redirect_url = body.get("url", "")
            except Exception:
                pass
        if not redirect_url:
            redirect_url = signin_resp.headers.get("Location", "")

        if redirect_url:
            try:
                session.get(
                    redirect_url,
                    headers={"User-Agent": ua, "Accept": "text/html"},
                    proxies=proxies, verify=ssl_verify, timeout=15,
                    allow_redirects=True,
                )
            except Exception:
                pass

        # Step 4: Extract device ID from cookies
        try:
            cookies_dict = session.cookies if hasattr(session.cookies, 'get') else {}
            for cookie_name in ("oai-did", "ext-oai-did"):
                val = cookies_dict.get(cookie_name, "")
                if val:
                    did = val
                    break
        except Exception:
            pass

        # Check response headers as fallback
        if not did:
            for header_name in ("oai-device-id", "ext-oai-did", "oai-did"):
                did = signin_resp.headers.get(header_name, "")
                if did:
                    break

    except Exception as e:
        print(f"[{_ts()}] [WARNING] init_auth failed: {e}")

    return did, ua


def image2api_data(
    session: cffi_requests.Session,
    url: str,
    proxies: Optional[dict] = None,
) -> str:
    """Follow OAuth redirect chain from continue_url to extract access_token.

    The continue_url is obtained after successful OAuth authorization.
    This function follows the redirect chain and extracts the access_token
    from the final URL fragment or response.
    """
    if not url:
        return ""

    ssl_verify = False
    current_url = url
    max_redirects = 12

    try:
        for _ in range(max_redirects):
            resp = session.get(
                current_url, headers={"User-Agent": _UA},
                proxies=proxies, verify=ssl_verify, timeout=15,
                allow_redirects=False,
            )

            if resp.status_code in (301, 302, 303, 307, 308):
                location = resp.headers.get("Location", "")
                if not location:
                    break
                current_url = urllib.parse.urljoin(current_url, location)

                # Check if this URL contains the access token
                if "access_token=" in current_url or "code=" in current_url:
                    parsed = urllib.parse.urlparse(current_url)
                    params = urllib.parse.parse_qs(parsed.query)
                    fragment_params = urllib.parse.parse_qs(parsed.fragment)

                    # Check query params
                    if "access_token" in params:
                        return params["access_token"][0]
                    if "code" in params:
                        return params["code"][0]

                    # Check fragment params
                    if "access_token" in fragment_params:
                        return fragment_params["access_token"][0]
                    if "code" in fragment_params:
                        return fragment_params["code"][0]
            else:
                # Try to extract token from response body
                try:
                    data = resp.json()
                    if isinstance(data, dict):
                        for key in ("access_token", "token", "id_token"):
                            if key in data:
                                return data[key]
                except Exception:
                    pass
                break

    except Exception as e:
        print(f"[{_ts()}] [WARNING] image2api_data failed: {e}")

    return ""
