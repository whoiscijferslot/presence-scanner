"""Network scanning using nmap."""

import asyncio
import subprocess
import time
from datetime import datetime, timezone
from typing import Literal

from loguru import logger

from .config import DEBOUNCE_DELAY, DEVICES, NETWORK
from .database import get_device_state, update_device_state


def run_nmap_icmp(ips: list[str]) -> dict[str, bool]:
    """
    Run nmap ICMP ping scan on specific IPs.
    Fast check using ICMP echo requests.
    """
    if not ips:
        return {}
    
    try:
        result = subprocess.run(
            ["nmap", "-sn", "-PE", "--host-timeout", "2s", *ips],
            capture_output=True,
            text=True,
            timeout=15,
        )
        output = result.stdout.lower()
        
        return {ip: ip in output and "host is up" in output.split(ip)[0].split("\n")[-1:][0] if ip in output else False
                for ip in ips}
    except (subprocess.TimeoutExpired, FileNotFoundError) as e:
        logger.error(f"nmap ICMP scan failed: {e}")
        return {ip: False for ip in ips}


def run_nmap_icmp_simple(ips: list[str]) -> dict[str, bool]:
    """
    Run nmap ICMP ping scan on specific IPs.
    Returns dict of ip -> is_present.
    Uses sudo for raw socket access.
    """
    if not ips:
        return {}
    
    results = {}
    try:
        result = subprocess.run(
            ["sudo", "nmap", "-sn", "-PE", "--host-timeout", "3s", *ips],
            capture_output=True,
            text=True,
            timeout=20,
        )
        output = result.stdout
        
        # Parse output - look for "Host is up" after each IP
        for ip in ips:
            # Check if IP appears with "Host is up" nearby
            results[ip] = ip in output and "Host is up" in output
            
    except (subprocess.TimeoutExpired, FileNotFoundError) as e:
        logger.error(f"nmap ICMP scan failed: {e}")
        return {ip: False for ip in ips}
    
    return results


def run_nmap_arp(network: str) -> str:
    """
    Run nmap ARP scan on network.
    Returns raw output for MAC address matching.
    Uses sudo for ARP access.
    """
    try:
        result = subprocess.run(
            ["sudo", "nmap", "-sn", "-PR", network],
            capture_output=True,
            text=True,
            timeout=120,
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
    ips = [info["ip"] for info in DEVICES.values()]
    ip_results = run_nmap_icmp_simple(ips)
    
    return {
        device_id: ip_results.get(info["ip"], False)
        for device_id, info in DEVICES.items()
    }


def detect_presence_arp(scan_output: str) -> dict[str, bool]:
    """Check device presence using ARP/MAC detection (definitive)."""
    return {
        device_id: info["mac"].lower() in scan_output
        for device_id, info in DEVICES.items()
    }


async def run_scan() -> dict[str, bool]:
    """
    Run a presence scan with debouncing.
    
    Returns dict of device_id -> is_present.
    """
    # Get previous state from database
    previous_state = {
        device_id: get_device_state(device_id) or {"present": False, "last_online": None}
        for device_id in DEVICES
    }

    # Run fast ICMP ping check
    logger.info("Running ICMP ping scan...")
    presence = await asyncio.to_thread(detect_presence_icmp)
    
    for device_id, is_present in presence.items():
        logger.debug(f"  {DEVICES[device_id]['name']}: {'responds' if is_present else 'no response'}")

    # Check for state transitions that need confirmation
    needs_confirmation = []
    for device_id, is_present in presence.items():
        was_present = previous_state[device_id]["present"]
        
        if is_present != was_present:
            transition = "appeared" if is_present else "disappeared"
            needs_confirmation.append((device_id, is_present, transition))
            logger.info(f"  {DEVICES[device_id]['name']} {transition} - needs ARP confirmation")

    # If there are state changes, wait and confirm with ARP/MAC scan
    if needs_confirmation:
        logger.info(f"Waiting {DEBOUNCE_DELAY}s for confirmation...")
        await asyncio.sleep(DEBOUNCE_DELAY)
        
        logger.info("Running ARP confirmation scan (MAC-based)...")
        confirm_output = await asyncio.to_thread(run_nmap_arp, NETWORK)
        confirm_presence = detect_presence_arp(confirm_output)
        
        # Check which transitions are confirmed
        for device_id, expected_present, transition in needs_confirmation:
            confirmed = confirm_presence[device_id]
            if confirmed == expected_present:
                logger.info(f"  {DEVICES[device_id]['name']} {transition} CONFIRMED by MAC")
                presence[device_id] = expected_present
            else:
                # Transition not confirmed - keep old state
                prev_present = previous_state[device_id]["present"]
                logger.info(f"  {DEVICES[device_id]['name']} {transition} NOT confirmed (fluke), keeping {'ONLINE' if prev_present else 'OFFLINE'}")
                presence[device_id] = prev_present

    # Get current time
    now = datetime.now(timezone.utc)
    scan_time_iso = now.strftime("%Y-%m-%dT%H:%M:%SZ")

    # Update database
    for device_id, device_info in DEVICES.items():
        is_present = presence[device_id]
        
        # Get previous last_online time
        last_online = previous_state[device_id]["last_online"]
        
        # Update last_online if device is currently present
        if is_present:
            last_online = scan_time_iso

        update_device_state(
            device_id=device_id,
            name=device_info["name"],
            ip=device_info["ip"],
            mac=device_info["mac"],
            present=is_present,
            last_online=last_online,
            scan_time=scan_time_iso
        )

    logger.info(f"Scan complete: " + ", ".join(
        f"{DEVICES[d]['name']}={'ON' if p else 'OFF'}" for d, p in presence.items()
    ))
    
    return presence
