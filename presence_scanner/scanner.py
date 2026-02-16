"""Network scanning using nmap."""

import asyncio
import subprocess
from datetime import UTC, datetime

from loguru import logger

from .config import settings
from .database import DeviceUpdate, get_device_state, update_device_state

# Full paths for security
SUDO_PATH = "/usr/bin/sudo"
NMAP_PATH = "/usr/bin/nmap"


def run_nmap_icmp(ips: list[str]) -> dict[str, bool]:
    """
    Run nmap ICMP ping scan on specific IPs.

    Returns dict of ip -> is_present.
    Uses sudo for raw socket access.
    """
    if not ips:
        return {}

    results: dict[str, bool] = {}
    try:
        result = subprocess.run(  # noqa: S603
            [SUDO_PATH, NMAP_PATH, "-sn", "-PE", "--host-timeout", "3s", *ips],
            capture_output=True,
            text=True,
            timeout=20,
            check=False,
        )
        output = result.stdout

        for ip in ips:
            results[ip] = ip in output and "Host is up" in output

    except subprocess.TimeoutExpired:
        logger.error("nmap ICMP scan timed out")
        return dict.fromkeys(ips, False)
    except FileNotFoundError:
        logger.error("nmap not found")
        return dict.fromkeys(ips, False)

    return results


def run_nmap_arp(network: str) -> str:
    """
    Run nmap ARP scan on network.

    Returns raw output for MAC address matching.
    Uses sudo for ARP access.
    """
    try:
        result = subprocess.run(  # noqa: S603
            [SUDO_PATH, NMAP_PATH, "-sn", "-PR", network],
            capture_output=True,
            text=True,
            timeout=120,
            check=False,
        )
        return result.stdout.lower()
    except subprocess.TimeoutExpired:
        logger.error("nmap ARP scan timed out")
        return ""
    except FileNotFoundError:
        logger.error("nmap not found")
        return ""


def detect_presence_icmp() -> dict[str, bool]:
    """Check device presence using ICMP ping (fast)."""
    ips = [device.ip for device in settings.devices.values()]
    ip_results = run_nmap_icmp(ips)

    return {
        device_id: ip_results.get(device.ip, False)
        for device_id, device in settings.devices.items()
    }


def detect_presence_arp(scan_output: str) -> dict[str, bool]:
    """Check device presence using ARP/MAC detection (definitive)."""
    return {
        device_id: device.mac.lower() in scan_output
        for device_id, device in settings.devices.items()
    }


async def run_scan() -> dict[str, bool]:
    """
    Run a presence scan with debouncing.

    Returns dict of device_id -> is_present.
    """
    previous_state = {
        device_id: get_device_state(device_id)
        or {"present": False, "last_online": None}
        for device_id in settings.devices
    }

    logger.info("Running ICMP ping scan...")
    presence = await asyncio.to_thread(detect_presence_icmp)

    for device_id, is_present in presence.items():
        status = "responds" if is_present else "no response"
        logger.debug(f"  {settings.devices[device_id].name}: {status}")

    needs_confirmation: list[tuple[str, bool, str]] = []
    for device_id, is_present in presence.items():
        was_present = bool(previous_state[device_id]["present"])

        if is_present != was_present:
            transition = "appeared" if is_present else "disappeared"
            needs_confirmation.append((device_id, is_present, transition))
            device_name = settings.devices[device_id].name
            logger.info(f"  {device_name} {transition} - needs ARP confirmation")

    if needs_confirmation:
        logger.info(f"Waiting {settings.debounce_delay}s for confirmation...")
        await asyncio.sleep(settings.debounce_delay)

        logger.info("Running ARP confirmation scan (MAC-based)...")
        confirm_output = await asyncio.to_thread(run_nmap_arp, settings.network)
        confirm_presence = detect_presence_arp(confirm_output)

        for device_id, expected_present, transition in needs_confirmation:
            confirmed = confirm_presence[device_id]
            device_name = settings.devices[device_id].name
            if confirmed == expected_present:
                logger.info(f"  {device_name} {transition} CONFIRMED by MAC")
                presence[device_id] = expected_present
            else:
                prev_present = bool(previous_state[device_id]["present"])
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
        last_online = str(previous_state[device_id]["last_online"] or "")

        if is_present:
            last_online = scan_time_iso

        update_device_state(
            DeviceUpdate(
                device_id=device_id,
                name=device.name,
                ip=device.ip,
                mac=device.mac,
                present=is_present,
                last_online=last_online or None,
                scan_time=scan_time_iso,
            )
        )

    status_str = ", ".join(
        f"{settings.devices[d].name}={'ON' if p else 'OFF'}"
        for d, p in presence.items()
    )
    logger.info(f"Scan complete: {status_str}")

    return presence
