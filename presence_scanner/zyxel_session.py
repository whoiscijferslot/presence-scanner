"""Cached Zyxel session management.

The router allows only a handful of concurrent login slots, so logging in on
every scan quickly exhausts them ("Maximum number of login account has
reached"). Instead we log in once, persist the session to the database, and
reuse it until it nears the router's ~60-minute expiry, then re-login.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

from loguru import logger

from .config import settings
from .database import (
    ZyxelSessionRecord,
    clear_zyxel_session,
    get_zyxel_session,
    save_zyxel_session,
)
from .zyxel_client import Zyxel

# Re-login a couple of minutes before the router's ~60-minute hard expiry.
SESSION_TTL = timedelta(minutes=58)


def _now_iso() -> str:
    return datetime.now(UTC).isoformat()


def fresh_login() -> Zyxel:
    """Log in, persist the new session, and return the client."""
    zyxel = Zyxel(base_url=settings.zyxel.base_url)
    zyxel.login(settings.zyxel.username, settings.zyxel.password)
    cookie, aes_key, session_key = zyxel.export_session()
    save_zyxel_session(
        ZyxelSessionRecord(
            cookie=cookie,
            aes_key=aes_key,
            session_key=session_key,
            created_at=_now_iso(),
        ),
    )
    logger.info("Zyxel: established and cached a new session")
    return zyxel


def _record_age(record: ZyxelSessionRecord) -> timedelta:
    try:
        return datetime.now(UTC) - datetime.fromisoformat(record.created_at)
    except ValueError:
        return SESSION_TTL  # unparseable -> treat as expired


def get_session() -> Zyxel:
    """Return a ready client, reusing the cached session when still valid.

    A cached session past :data:`SESSION_TTL` is logged out (best-effort) and
    replaced with a fresh login.
    """
    record = get_zyxel_session()
    if record is None:
        return fresh_login()

    if _record_age(record) < SESSION_TTL:
        zyxel = Zyxel(base_url=settings.zyxel.base_url)
        zyxel.restore_session(
            cookie=record.cookie,
            aes_key_b64=record.aes_key,
            session_key=record.session_key,
        )
        return zyxel

    # Cached session is near/at expiry: free the slot, then log in fresh.
    logger.info("Zyxel: cached session near expiry, re-logging in")
    stale = Zyxel(base_url=settings.zyxel.base_url)
    stale.restore_session(
        cookie=record.cookie,
        aes_key_b64=record.aes_key,
        session_key=record.session_key,
    )
    stale.logout()
    clear_zyxel_session()
    return fresh_login()
