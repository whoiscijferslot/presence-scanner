#!/usr/bin/env -S uv run --python 3.14
# /// script
# requires-python = ">=3.14"
# ///
"""
Presence Scanner - Scans network for specific MAC addresses using nmap.
Tracks current presence and last online time for each device.
"""

import json
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

# Configuration
OUTPUT_FILE = Path("/home/sam1902/projects/presence-scanner/www/status.json")
NETWORK = "192.168.1.0/24"

# Devices to track (MAC addresses in lowercase)
DEVICES = {
    "alex": {
        "name": "Alex",
        "mac": "aa:bb:cc:dd:ee:01",
    },
    "roomie": {
        "name": "Roomie",
        "mac": "aa:bb:cc:dd:ee:02",
    },
}


def run_nmap_scan(network: str) -> str:
    """Run nmap ping scan and return output."""
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


def main():
    # Get current time
    now = datetime.now(timezone.utc)
    scan_time_iso = now.strftime("%Y-%m-%dT%H:%M:%SZ")
    scan_time_human = now.strftime("%Y-%m-%d %H:%M:%S UTC")

    # Run the scan
    scan_output = run_nmap_scan(NETWORK)

    # Load previous state to preserve last_online times
    previous_state = load_previous_state()
    previous_devices = previous_state.get("devices", {})

    # Check each device
    devices_status = {}
    for device_id, device_info in DEVICES.items():
        mac = device_info["mac"].lower()
        is_present = mac in scan_output

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
