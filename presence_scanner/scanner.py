"""Presence detection via the Zyxel router API.

The host is no longer on the home LAN, so ping / ARP / nmap are gone. Presence
is derived entirely from the router's own view of the network, obtained through
the bundled :mod:`presence_scanner.zyxel_client`:

* ``lanhosts`` -- devices the router considers connected (with an ``Active`` flag).
* the live ARP / neighbour table -- MACs currently resolved on the LAN bridge.

A device counts as present if its MAC is an active LAN host or appears in the
live ARP table.
"""

import asyncio
from datetime import UTC, datetime

import requests
from loguru import logger

from .config import settings
from .database import DeviceUpdate, get_device_state, update_device_state
from .models import DeviceState
from .zyxel_client import Zyxel, ZyxelError
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


def _arp_ipv4_macs(zyxel: Zyxel) -> set[str]:
    """Lowercased MACs currently in the router's IPv4 ARP table.

    IPv4 only, on purpose: IPv6 neighbour entries linger for a long time after
    a device leaves, and the ``lanhosts`` ``Active`` flag follows the DHCP lease
    rather than live connectivity. The IPv4 ARP table ages out promptly, so it
    is the reliable signal for "is this device actually on the network now".
    """
    return {entry.mac.lower() for entry in zyxel.arp_table().ipv4}


def _present_macs() -> set[str]:
    """Present MACs from the IPv4 ARP table, reusing the cached session.

    If the cached session is stale (or the query otherwise fails), log in fresh
    once and retry; a second failure propagates to the caller.
    """
    try:
        return _arp_ipv4_macs(get_session())
    except _ROUTER_ERRORS as exc:
        logger.info(f"Zyxel query failed ({exc}); retrying with a fresh login")
        return _arp_ipv4_macs(fresh_login())


def detect_presence() -> dict[str, tuple[bool, str]] | None:
    """Detect presence for all tracked devices via the Zyxel router.

    Returns ``device_id -> (is_present, method)``, or ``None`` if the router
    could not be reached so the caller can preserve the previous state.
    """
    if not settings.zyxel.enabled:
        logger.warning("Zyxel detection disabled; no data source available")
        return None

    try:
        present = _present_macs()
    except _ROUTER_ERRORS as exc:
        logger.warning(f"Zyxel query failed: {exc}")
        return None

    results: dict[str, tuple[bool, str]] = {}
    for device_id, device in settings.devices.items():
        is_present = device.mac.lower() in present
        results[device_id] = (is_present, "arp" if is_present else "none")
    return results


async def run_scan() -> dict[str, bool]:
    """Run a presence scan with debouncing.

    Returns ``device_id -> is_present``.
    """
    default_state = DeviceState(present=False, last_online=None)
    previous_state: dict[str, DeviceState] = {
        device_id: get_device_state(device_id) or default_state
        for device_id in settings.devices
    }

    logger.info("Running presence scan (Zyxel router)...")
    results = await asyncio.to_thread(detect_presence)

    if results is None:
        logger.warning("Router unreachable; keeping previous presence state")
        return {d: previous_state[d].present for d in settings.devices}

    presence: dict[str, bool] = {d: r[0] for d, r in results.items()}
    for device_id, (is_present, method) in results.items():
        name = settings.devices[device_id].name
        status = f"present ({method})" if is_present else "away"
        logger.debug(f"  {name}: {status}")

    # Debounce: confirm any state change with a second query.
    needs_confirmation: list[tuple[str, bool, str]] = []
    for device_id, is_present in presence.items():
        if is_present != previous_state[device_id].present:
            transition = "appeared" if is_present else "disappeared"
            needs_confirmation.append((device_id, is_present, transition))
            name = settings.devices[device_id].name
            logger.info(f"  {name} {transition} - confirming")

    if needs_confirmation:
        logger.info(f"Waiting {settings.debounce_delay}s for confirmation...")
        await asyncio.sleep(settings.debounce_delay)
        confirm = await asyncio.to_thread(detect_presence)

        for device_id, expected, transition in needs_confirmation:
            name = settings.devices[device_id].name
            prev = previous_state[device_id].present
            if confirm is not None and confirm[device_id][0] == expected:
                logger.info(f"  {name} {transition} CONFIRMED")
                presence[device_id] = expected
            else:
                logger.info(
                    f"  {name} {transition} NOT confirmed (fluke), keeping state"
                )
                presence[device_id] = prev

    now = datetime.now(UTC)
    scan_time_iso = now.strftime("%Y-%m-%dT%H:%M:%SZ")

    for device_id, device in settings.devices.items():
        is_present = presence[device_id]
        last_online = (
            scan_time_iso if is_present else previous_state[device_id].last_online
        )
        update_device_state(
            DeviceUpdate(
                device_id=device_id,
                name=device.name,
                ip=device.ip,
                mac=device.mac,
                present=is_present,
                last_online=last_online,
                scan_time=scan_time_iso,
            ),
        )

    status_str = ", ".join(
        f"{settings.devices[d].name}={'ON' if p else 'OFF'}"
        for d, p in presence.items()
    )
    logger.info(f"Scan complete: {status_str}")
    return presence
