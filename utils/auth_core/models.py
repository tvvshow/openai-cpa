"""Data models for auth_core."""
import uuid
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional


@dataclass
class Config:
    sentinel_base_url: str = "https://sentinel.openai.com"
    sentinel_timeout: float = 15.0
    sentinel_max_attempts: int = 3
    sentinel_direct_fallback: bool = False
    turnstile_static_token: str = ""


@dataclass
class Token:
    p: str = ""
    t: str = ""
    c: str = ""
    id: str = ""
    flow: str = ""


@dataclass
class Persona:
    platform: str = "Win32"
    vendor: str = "Google Inc."
    timezone_offset_min: int = 0
    session_id: str = ""
    time_origin: float = 0.0
    window_flags: List[int] = field(default_factory=list)
    window_flags_set: bool = False
    entropy_a: float = 0.0
    entropy_b: float = 0.0
    date_string: str = ""
    requirements_script_url: str = ""
    navigator_probe: str = ""
    document_probe: str = ""
    window_probe: str = ""
    performance_now: float = 0.0
    requirements_elapsed: float = 0.0


@dataclass
class Session:
    client: Any = None
    device_id: str = ""
    user_agent: str = ""
    screen_width: int = 1920
    screen_height: int = 1080
    heap_limit: int = 0
    hardware_concurrency: int = 8
    language: str = "en-US"
    languages_join: str = "en-US,en"
    persona: Persona = field(default_factory=Persona)


DEVICE_PROFILES: List[Dict[str, Any]] = [
    {
        "platform": "Win32",
        "vendor": "Google Inc. (NVIDIA)",
        "renderer": "ANGLE (NVIDIA, NVIDIA GeForce RTX 5080 Laptop GPU Direct3D11 vs_5_0 ps_5_0, D3D11)",
        "screen_width": 1920,
        "screen_height": 1080,
    },
]

LANGUAGES: List[str] = ["en-US", "en"]
