"""Network scanning using ping, ARP, and Zyxel router API fallback.

Detection priority:
1. ICMP Ping - Fastest, works when device is awake
2. ARP Cache - Fallback for sleeping iPhones that don't respond to ping
3. Zyxel Router API - Most reliable but slowest (requires login + encryption)
"""

import asyncio
import re
import subprocess
from datetime import UTC, datetime

from loguru import logger

from .config import settings
from .database import DeviceUpdate, get_device_state, update_device_state
from .models import DeviceState
from .zyxel import ZyxelConfig, check_device_presence

# Full paths for security
PING_PATH = "/usr/bin/ping"
IP_PATH = "/usr/sbin/ip"

# ARP neighbor states that indicate presence
ARP_PRESENT_STATES = {"REACHABLE", "STALE", "DELAY", "PROBE"}


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


def check_arp_cache(ip: str, expected_mac: str) -> bool:
    """
    Check if device is present in ARP cache with matching MAC.

    This works even when iPhones don't respond to ICMP ping because:
    - The ping attempt triggers ARP resolution
    - iPhones MUST respond to ARP to maintain their IP lease
    - The wifi chip handles ARP at hardware level even in deep sleep

    Args:
        ip: IP address to check
        expected_mac: Expected MAC address (lowercase, colon-separated)

    Returns:
        True if device is in ARP cache with matching MAC and valid state
    """
    try:
        result = subprocess.run(  # noqa: S603
            [IP_PATH, "neigh", "show", ip],
            capture_output=True,
            text=True,
            timeout=5,
            check=False,
        )
    except (subprocess.TimeoutExpired, FileNotFoundError) as e:
        logger.warning(f"ARP check failed for {ip}: {e}")
        return False

    output = result.stdout.strip()
    if not output:
        return False

    # Check for FAILED or INCOMPLETE states (device not present)
    if any(absent_state in output for absent_state in ("FAILED", "INCOMPLETE")):
        return False

    # Extract and verify MAC address
    mac_match = re.search(r"lladdr\s+([0-9a-f:]+)", output.lower())
    if not mac_match:
        return False

    found_mac = mac_match.group(1)
    if found_mac != expected_mac.lower():
        logger.debug(f"MAC mismatch for {ip}: expected {expected_mac}, got {found_mac}")
        return False

    # Check state is one of the "present" states
    return any(state in output for state in ARP_PRESENT_STATES)


def detect_presence_single(ip: str, mac: str) -> tuple[bool, str]:
    """
    Detect presence for a single device using ping + ARP fallback.

    Args:
        ip: Device IP address
        mac: Device MAC address

    Returns:
        Tuple of (is_present, detection_method)
    """
    # First try ICMP ping
    if ping_host(ip):
        return True, "ping"

    # Ping failed - check ARP cache (ping attempt triggers ARP resolution)
    if check_arp_cache(ip, mac):
        return True, "arp"

    return False, "none"


def detect_via_zyxel() -> dict[str, tuple[bool, str]] | None:
    """
    Detect presence via Zyxel router API.

    Returns:
        Dict of device_id -> (is_present, "router") or None if failed
    """
    if not settings.zyxel.enabled:
        return None

    try:
        config = ZyxelConfig(
            router_ip=settings.zyxel.router_ip,
            username=settings.zyxel.username,
            password=settings.zyxel.password,
            timeout=settings.zyxel.timeout,
        )

        mac_addresses = {
            device_id: device.mac for device_id, device in settings.devices.items()
        }

        results = check_device_presence(config, mac_addresses)

        return {
            device_id: (is_present, "router" if is_present else "none")
            for device_id, is_present in results.items()
        }

    except (OSError, ValueError, KeyError) as e:
        logger.warning(f"Zyxel detection failed: {e}")
        return None


def detect_via_ping_arp() -> dict[str, tuple[bool, str]]:
    """
    Detect presence via ping with ARP fallback.

    Returns:
        Dict of device_id -> (is_present, detection_method)
    """
    return {
        device_id: detect_presence_single(device.ip, device.mac)
        for device_id, device in settings.devices.items()
    }


def detect_presence() -> dict[str, tuple[bool, str]]:
    """
    Detect presence using all available methods.

    Priority: Ping > ARP > Zyxel router API

    Returns:
        Dict of device_id -> (is_present, detection_method)
    """
    # Try ping/ARP first (fastest)
    results = detect_via_ping_arp()

    # Check if any device wasn't detected - try router API as fallback
    undetected = [
        device_id for device_id, (present, _) in results.items() if not present
    ]

    if undetected:
        # Try Zyxel router for undetected devices
        zyxel_results = detect_via_zyxel()
        if zyxel_results is not None:
            for device_id in undetected:
                zyxel_present, _ = zyxel_results.get(device_id, (False, "none"))
                if zyxel_present:
                    results[device_id] = (True, "router")

    return results


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

    logger.info("Running presence scan...")
    presence_results = await asyncio.to_thread(detect_presence)

    # Extract just the presence bool for main logic
    presence: dict[str, bool] = {
        device_id: result[0] for device_id, result in presence_results.items()
    }

    for device_id, (is_present, method) in presence_results.items():
        device_name = settings.devices[device_id].name
        status = f"responds ({method})" if is_present else "no response"
        logger.debug(f"  {device_name}: {status}")

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

        logger.info("Running confirmation scan...")
        confirm_results = await asyncio.to_thread(detect_presence)

        for device_id, expected_present, transition in needs_confirmation:
            confirmed, method = confirm_results[device_id]
            device_name = settings.devices[device_id].name
            if confirmed == expected_present:
                method_str = f" via {method}" if confirmed else ""
                logger.info(f"  {device_name} {transition} CONFIRMED{method_str}")
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
