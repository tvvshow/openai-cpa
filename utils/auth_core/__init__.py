"""Pure Python reimplementation of auth_core.

Replaces the Nuitka-compiled binary with transparent Python code.
All public APIs are preserved for backward compatibility.

Key discovery: the sentinel API token is accepted directly by the auth API
without re-encryption, eliminating the need for Fernet, PoW, and Turnstile VM.
"""
from .auth import init_auth, image2api_data
from .models import Config, Token, Persona, Session, DEVICE_PROFILES, LANGUAGES
from .sentinel import generate_payload, invalidate_cache
from .utils import random_hex, random_int, web_print, email_jwt
from .webhook import router, code_pool, cache_lock, EmailWebhookReq, receive_email_webhook

# Re-export commonly used external types for compatibility
from fastapi import APIRouter, Header, HTTPException
from pydantic import BaseModel
from cachetools import TTLCache
from typing import Optional

# Stubs for functions added by auth_core_patch.py
# These will be replaced when auth_core_patch is imported
def sys_node_allocate(data, proxies):
    """Stub: patched by auth_core_patch.py"""
    return False, "", ""

def sys_node_release(temp_user_at, handle_a, handle_b, proxies):
    """Stub: patched by auth_core_patch.py"""
    pass

def sys_node_bulk_silent(proxies=None, force_all=False):
    """Stub: patched by auth_core_patch.py"""
    pass

__all__ = [
    # Core API
    "generate_payload",
    "init_auth",
    "image2api_data",
    "sys_node_allocate",
    "sys_node_release",
    "sys_node_bulk_silent",
    # Models
    "Config",
    "Token",
    "Persona",
    "Session",
    "DEVICE_PROFILES",
    "LANGUAGES",
    # Webhook
    "router",
    "code_pool",
    "cache_lock",
    "EmailWebhookReq",
    "receive_email_webhook",
    # Utilities
    "random_hex",
    "random_int",
    "web_print",
    "email_jwt",
    "invalidate_cache",
    # Re-exports for compatibility
    "APIRouter",
    "BaseModel",
    "Header",
    "HTTPException",
    "Optional",
    "TTLCache",
]
