"""Real-time detection and logging of new devices joining the network.

Polls the router's connected-hosts list (``Zyxel.lan_hosts``) on a short
interval and compares every *active* host against every MAC address this
monitor has ever seen before (kept in the ``known_devices`` table). Any
active host whose MAC has never been recorded is logged as a new-device
connection event and then recorded, so it is never reported as "new" again.

Note this is scoped to what *this monitor* has seen, not the router's own
DHCP-lease history -- the first poll after a fresh database will report
every currently-active device as new (a one-time baseline).

Standalone usage::

    uv run python -m presence_scanner.new_device_monitor

Or, once installed, via the ``presence-watch-new-devices`` console script.
Events are logged to stderr and appended to ``new_devices.log`` inside
``DATA_DIR``. When run as part of the FastAPI app instead (see ``app.py``),
it runs as a background task alongside the regular presence scanner and
recent events are also available via ``GET /api/new-devices``.
"""

from __future__ import annotations

import asyncio
import sys
from datetime import UTC, datetime

import requests
from loguru import logger

from .config import settings
from .database import get_known_macs, init_db, record_seen_device
from .zyxel_client import LanHost, ZyxelError
from .zyxel_session import fresh_login, get_session

# Exceptions that mean "could not reach / parse the router" (transient), which
# also covers talking to the router with a stale/expired cached session.
_ROUTER_ERRORS = (
    ZyxelError,
    requests.RequestException,
    ValueError,
    KeyError,
    IndexError,
    OSError,
)


def _fetch_lan_hosts() -> list[LanHost]:
    """Fetch the LAN host list, reusing the cached router session.

    If the cached session is stale (or the query otherwise fails), log in
    fresh once and retry; a second failure propagates to the caller.
    """
    try:
        return get_session().lan_hosts()
    except _ROUTER_ERRORS as exc:
        logger.info(f"Zyxel query failed ({exc}); retrying with a fresh login")
        return fresh_login().lan_hosts()


def check_for_new_devices() -> list[LanHost]:
    """Poll the router once and return newly-seen *active* devices.

    Every currently active host is recorded (first-seen/last-seen) in the
    ``known_devices`` table regardless of whether it is new, so subsequent
    polls only report devices that have genuinely never connected before.
    """
    hosts = _fetch_lan_hosts()
    now = datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")

    new_devices: list[LanHost] = []
    for host in hosts:
        if not host.active:
            continue
        is_new = record_seen_device(
            mac=host.mac,
            ip=host.ip,
            name=host.name,
            connection=host.connection,
            seen_time=now,
        )
        if is_new:
            new_devices.append(host)
    return new_devices


def _log_new_device(host: LanHost) -> None:
    """Emit a prominent log line for a first-time device connection."""
    logger.warning(
        f"NEW DEVICE CONNECTED: {host.name!r} ip={host.ip} mac={host.mac} "
        f"conn={host.connection or 'unknown'}",
    )


async def run_new_device_watch(poll_interval: int | None = None) -> None:
    """Poll for new devices forever, logging each first-time connection."""
    interval = poll_interval or settings.new_device_poll_interval
    known = len(get_known_macs())
    logger.info(
        f"New-device watch started (interval: {interval}s, "
        f"{known} device(s) already known)",
    )
    while True:
        try:
            for host in await asyncio.to_thread(check_for_new_devices):
                _log_new_device(host)
        except asyncio.CancelledError:
            raise
        except _ROUTER_ERRORS as exc:
            logger.warning(f"New-device check failed: {exc}")
        await asyncio.sleep(interval)


def _configure_standalone_logging() -> None:
    """Add a rotating file sink so events persist when run as a script."""
    settings.data_dir.mkdir(parents=True, exist_ok=True)
    logger.add(settings.new_device_log_file, rotation="5 MB", retention=10)


def main() -> None:
    """Run the new-device watcher as a standalone, long-running process."""
    init_db()
    _configure_standalone_logging()
    try:
        asyncio.run(run_new_device_watch())
    except KeyboardInterrupt:
        sys.exit(0)


if __name__ == "__main__":
    main()
