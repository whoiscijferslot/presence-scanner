"""Network scanning using ping and nmap."""

import asyncio
import subprocess
from datetime import UTC, datetime

from loguru import logger

from .config import settings
from .database import DeviceUpdate, get_device_state, update_device_state
from .models import DeviceState

# Full paths for security
PING_PATH = "/usr/bin/ping"


def ping_host(ip: str) -> bool:
    """
    Ping a single host using standard ICMP ping.

    iPhones respond to regular ping but often block nmap's probes.
    """
    try:
        result = subprocess.run(  # noqa: S603
            [PING_PATH, "-c", "2", "-W", "2", ip],
            capture_output=True,
            timeout=10,
            check=False,
        )
    except subprocess.TimeoutExpired:
        return False
    except FileNotFoundError:
        logger.error("ping not found")
        return False
    else:
        return result.returncode == 0


def run_ping_scan(ips: list[str]) -> dict[str, bool]:
    """
    Ping multiple IPs using standard ICMP ping.

    Returns dict of ip -> is_present.
    More reliable for iPhones than nmap ICMP probes.
    """
    if not ips:
        return {}

    return {ip: ping_host(ip) for ip in ips}


def detect_presence_ping() -> dict[str, bool]:
    """Check device presence using standard ICMP ping (reliable for iPhones)."""
    ips = [device.ip for device in settings.devices.values()]
    ip_results = run_ping_scan(ips)

    return {
        device_id: ip_results.get(device.ip, False)
        for device_id, device in settings.devices.items()
    }


async def run_scan() -> dict[str, bool]:
    """
    Run a presence scan with debouncing.

    Returns dict of device_id -> is_present.
    """
    default_state = DeviceState(present=False, last_online=None)
    previous_state: dict[str, DeviceState] = {
        device_id: get_device_state(device_id) or default_state
        for device_id in settings.devices
    }

    logger.info("Running ping scan...")
    presence = await asyncio.to_thread(detect_presence_ping)

    for device_id, is_present in presence.items():
        status = "responds" if is_present else "no response"
        logger.debug(f"  {settings.devices[device_id].name}: {status}")

    needs_confirmation: list[tuple[str, bool, str]] = []
    for device_id, is_present in presence.items():
        was_present = previous_state[device_id].present

        if is_present != was_present:
            transition = "appeared" if is_present else "disappeared"
            needs_confirmation.append((device_id, is_present, transition))
            device_name = settings.devices[device_id].name
            logger.info(f"  {device_name} {transition} - needs confirmation")

    if needs_confirmation:
        logger.info(f"Waiting {settings.debounce_delay}s for confirmation...")
        await asyncio.sleep(settings.debounce_delay)

        logger.info("Running confirmation ping scan...")
        confirm_presence = await asyncio.to_thread(detect_presence_ping)

        for device_id, expected_present, transition in needs_confirmation:
            confirmed = confirm_presence[device_id]
            device_name = settings.devices[device_id].name
            if confirmed == expected_present:
                logger.info(f"  {device_name} {transition} CONFIRMED")
                presence[device_id] = expected_present
            else:
                prev_present = previous_state[device_id].present
                state_str = "ONLINE" if prev_present else "OFFLINE"
                logger.info(
                    f"  {device_name} {transition} NOT confirmed (fluke), "
                    f"keeping {state_str}"
                )
                presence[device_id] = prev_present

    now = datetime.now(UTC)
    scan_time_iso = now.strftime("%Y-%m-%dT%H:%M:%SZ")

    for device_id, device in settings.devices.items():
        is_present = presence[device_id]
        last_online = previous_state[device_id].last_online

        if is_present:
            last_online = scan_time_iso

        update_device_state(
            DeviceUpdate(
                device_id=device_id,
                name=device.name,
                ip=device.ip,
                mac=device.mac,
                present=is_present,
                last_online=last_online,
                scan_time=scan_time_iso,
            )
        )

    status_str = ", ".join(
        f"{settings.devices[d].name}={'ON' if p else 'OFF'}"
        for d, p in presence.items()
    )
    logger.info(f"Scan complete: {status_str}")

    return presence
