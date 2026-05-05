"""Email webhook endpoint for receiving verification codes.

The binary exposes a FastAPI router with POST /api/webhook/email
that receives email content and stores verification codes in a shared pool.
"""
import asyncio
import time
from typing import Optional

from cachetools import TTLCache
from fastapi import APIRouter, Header, HTTPException
from pydantic import BaseModel

# Shared code pool: email address -> raw email content
code_pool: TTLCache = TTLCache(maxsize=20000, ttl=600)
cache_lock = asyncio.Lock()

router = APIRouter()


class EmailWebhookReq(BaseModel):
    message_id: str
    to_addr: str
    raw_content: str
    from_addr: Optional[str] = None


@router.post("/api/webhook/email")
async def receive_email_webhook(req: EmailWebhookReq, x_webhook_secret: str = Header(None)):
    """Receive email webhook and store content in code_pool.

    The webhook secret is validated against configured secrets from the environment.
    """
    import os

    # Validate webhook secret
    valid_secrets = set()
    for env_key in ("OPENAI_CPA_WEBHOOK_SECRET", "CM_WEBHOOK_SECRET", "FREEMAIL_WEBHOOK_SECRET"):
        val = os.environ.get(env_key, "").strip()
        if val:
            valid_secrets.add(val)

    if valid_secrets and (not x_webhook_secret or x_webhook_secret not in valid_secrets):
        raise HTTPException(status_code=401, detail="Unauthorized: Secret mismatch")

    # Store email content in the shared pool
    async with cache_lock:
        code_pool[req.to_addr.lower()] = req.raw_content

    return {"status": "ok", "message_id": req.message_id}
