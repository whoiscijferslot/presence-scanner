#!/usr/bin/env -S uv run --python 3.14
# /// script
# requires-python = ">=3.14"
# ///
"""
Presence Scanner - Detects phone presence on the network.

Primary method: ICMP ping to fixed IP addresses (fast, ~1 second)
Debounce method: nmap MAC address scan (slower but definitive)

When a state change is detected via ping, we wait 5 seconds and
confirm with a full nmap scan to prevent false transitions.
"""

import json
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

# Configuration
OUTPUT_FILE = Path("/home/sam1902/projects/presence-scanner/www/status.json")
NETWORK = "192.168.1.0/24"
DEBOUNCE_DELAY = 5  # seconds to wait before confirmation scan
PING_COUNT = 5  # number of ICMP packets to send

# Devices to track
DEVICES = {
    "alex": {
        "name": "Alex",
        "ip": "192.168.1.101",
        "mac": "aa:bb:cc:dd:ee:01",
    },
    "roomie": {
        "name": "Roomie",
        "ip": "192.168.1.102",
        "mac": "aa:bb:cc:dd:ee:02",
    },
}


def ping_device(ip: str) -> bool:
    """Ping an IP address. Returns True if device responds."""
    try:
        result = subprocess.run(
            ["ping", "-c", str(PING_COUNT), "-W", "1", ip],
            capture_output=True,
            timeout=PING_COUNT + 5,
        )
        return result.returncode == 0
    except (subprocess.TimeoutExpired, FileNotFoundError):
        return False


def run_nmap_scan(network: str) -> str:
    """Run nmap ping scan and return output (for MAC-based confirmation)."""
    try:
        result = subprocess.run(
            ["nmap", "-sn", "-PR", network],
            capture_output=True,
            text=True,
            timeout=120,
        )
        return result.stdout.lower()
    except subprocess.TimeoutExpired:
        print("nmap scan timed out", file=sys.stderr)
        return ""
    except FileNotFoundError:
        print("nmap not found", file=sys.stderr)
        return ""


def load_previous_state() -> dict:
    """Load previous state from JSON file if it exists."""
    if OUTPUT_FILE.exists():
        try:
            with OUTPUT_FILE.open() as f:
                return json.load(f)
        except (json.JSONDecodeError, IOError):
            pass
    return {}


def detect_presence_ping() -> dict[str, bool]:
    """Check device presence using ICMP ping (fast)."""
    return {
        device_id: ping_device(device_info["ip"])
        for device_id, device_info in DEVICES.items()
    }


def detect_presence_nmap(scan_output: str) -> dict[str, bool]:
    """Check device presence using nmap MAC detection (definitive)."""
    return {
        device_id: device_info["mac"].lower() in scan_output
        for device_id, device_info in DEVICES.items()
    }


def main():
    # Load previous state to compare
    previous_state = load_previous_state()
    previous_devices = previous_state.get("devices", {})

    # Run fast ping check
    print("Pinging devices...")
    presence = detect_presence_ping()
    
    for device_id, is_present in presence.items():
        print(f"  {DEVICES[device_id]['name']}: {'responds' if is_present else 'no response'}")

    # Check for state transitions that need confirmation
    needs_confirmation = []
    for device_id, is_present in presence.items():
        prev_device = previous_devices.get(device_id, {})
        was_present = prev_device.get("present", False)
        
        if is_present != was_present:
            transition = "appeared" if is_present else "disappeared"
            needs_confirmation.append((device_id, is_present, transition))
            print(f"  {DEVICES[device_id]['name']} {transition} - needs nmap confirmation")

    # If there are state changes, wait and confirm with nmap MAC scan
    if needs_confirmation:
        print(f"Waiting {DEBOUNCE_DELAY}s for confirmation...")
        time.sleep(DEBOUNCE_DELAY)
        
        print("Running nmap confirmation scan (MAC-based)...")
        confirm_output = run_nmap_scan(NETWORK)
        confirm_presence = detect_presence_nmap(confirm_output)
        
        # Check which transitions are confirmed
        for device_id, expected_present, transition in needs_confirmation:
            confirmed = confirm_presence[device_id]
            if confirmed == expected_present:
                print(f"  {DEVICES[device_id]['name']} {transition} CONFIRMED by MAC")
                presence[device_id] = expected_present
            else:
                # Transition not confirmed - keep old state
                prev_present = previous_devices.get(device_id, {}).get("present", False)
                print(f"  {DEVICES[device_id]['name']} {transition} NOT confirmed (fluke), keeping {'ONLINE' if prev_present else 'OFFLINE'}")
                presence[device_id] = prev_present

    # Get current time for output
    now = datetime.now(timezone.utc)
    scan_time_iso = now.strftime("%Y-%m-%dT%H:%M:%SZ")
    scan_time_human = now.strftime("%Y-%m-%d %H:%M:%S UTC")

    # Build device status
    devices_status = {}
    for device_id, device_info in DEVICES.items():
        is_present = presence[device_id]

        # Get previous last_online time
        prev_device = previous_devices.get(device_id, {})
        last_online = prev_device.get("last_online")
        last_online_human = prev_device.get("last_online_human")

        # Update last_online if device is currently present
        if is_present:
            last_online = scan_time_iso
            last_online_human = scan_time_human

        devices_status[device_id] = {
            "name": device_info["name"],
            "present": is_present,
            "last_online": last_online,
            "last_online_human": last_online_human,
        }

    # Build output
    output = {
        "scan_time": scan_time_iso,
        "scan_time_human": scan_time_human,
        "devices": devices_status,
    }

    # Write JSON output
    OUTPUT_FILE.parent.mkdir(parents=True, exist_ok=True)
    with OUTPUT_FILE.open("w") as f:
        json.dump(output, f, indent=2)

    # Set permissions
    OUTPUT_FILE.chmod(0o644)

    print(f"Scan complete at {scan_time_human}")
    for device_id, status in devices_status.items():
        state = "ONLINE" if status["present"] else "OFFLINE"
        print(f"  {status['name']}: {state}")


if __name__ == "__main__":
    main()
