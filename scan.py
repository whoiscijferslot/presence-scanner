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

Data is stored in SQLite for reliability and easy querying.
"""

import sqlite3
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

# Configuration
DB_FILE = Path("/home/sam1902/projects/presence-scanner/presence.db")
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


def init_db(conn: sqlite3.Connection) -> None:
    """Initialize database schema."""
    conn.execute("""
        CREATE TABLE IF NOT EXISTS devices (
            device_id TEXT PRIMARY KEY,
            name TEXT NOT NULL,
            ip TEXT,
            mac TEXT,
            present INTEGER NOT NULL DEFAULT 0,
            last_online TEXT,
            updated_at TEXT NOT NULL
        )
    """)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS scans (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            scan_time TEXT NOT NULL,
            device_id TEXT NOT NULL,
            present INTEGER NOT NULL,
            FOREIGN KEY (device_id) REFERENCES devices(device_id)
        )
    """)
    # Keep only last 1000 scans per device
    conn.execute("""
        CREATE TRIGGER IF NOT EXISTS limit_scan_history
        AFTER INSERT ON scans
        BEGIN
            DELETE FROM scans WHERE id IN (
                SELECT id FROM scans 
                WHERE device_id = NEW.device_id 
                ORDER BY id DESC 
                LIMIT -1 OFFSET 1000
            );
        END
    """)
    conn.commit()


def get_device_state(conn: sqlite3.Connection, device_id: str) -> dict | None:
    """Get current state of a device from database."""
    row = conn.execute(
        "SELECT present, last_online FROM devices WHERE device_id = ?",
        (device_id,)
    ).fetchone()
    if row:
        return {"present": bool(row[0]), "last_online": row[1]}
    return None


def update_device_state(
    conn: sqlite3.Connection,
    device_id: str,
    name: str,
    ip: str,
    mac: str,
    present: bool,
    last_online: str | None,
    scan_time: str
) -> None:
    """Update device state in database."""
    conn.execute("""
        INSERT INTO devices (device_id, name, ip, mac, present, last_online, updated_at)
        VALUES (?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(device_id) DO UPDATE SET
            name = excluded.name,
            ip = excluded.ip,
            mac = excluded.mac,
            present = excluded.present,
            last_online = excluded.last_online,
            updated_at = excluded.updated_at
    """, (device_id, name, ip, mac, int(present), last_online, scan_time))
    
    # Record in scan history
    conn.execute(
        "INSERT INTO scans (scan_time, device_id, present) VALUES (?, ?, ?)",
        (scan_time, device_id, int(present))
    )
    conn.commit()


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
    # Connect to database
    conn = sqlite3.connect(DB_FILE)
    init_db(conn)

    # Load previous state from database
    previous_state = {
        device_id: get_device_state(conn, device_id) or {"present": False, "last_online": None}
        for device_id in DEVICES
    }

    # Run fast ping check
    print("Pinging devices...")
    presence = detect_presence_ping()
    
    for device_id, is_present in presence.items():
        print(f"  {DEVICES[device_id]['name']}: {'responds' if is_present else 'no response'}")

    # Check for state transitions that need confirmation
    needs_confirmation = []
    for device_id, is_present in presence.items():
        was_present = previous_state[device_id]["present"]
        
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
                prev_present = previous_state[device_id]["present"]
                print(f"  {DEVICES[device_id]['name']} {transition} NOT confirmed (fluke), keeping {'ONLINE' if prev_present else 'OFFLINE'}")
                presence[device_id] = prev_present

    # Get current time
    now = datetime.now(timezone.utc)
    scan_time_iso = now.strftime("%Y-%m-%dT%H:%M:%SZ")
    scan_time_human = now.strftime("%Y-%m-%d %H:%M:%S UTC")

    # Update database
    for device_id, device_info in DEVICES.items():
        is_present = presence[device_id]
        
        # Get previous last_online time
        last_online = previous_state[device_id]["last_online"]
        
        # Update last_online if device is currently present
        if is_present:
            last_online = scan_time_iso

        update_device_state(
            conn,
            device_id=device_id,
            name=device_info["name"],
            ip=device_info["ip"],
            mac=device_info["mac"],
            present=is_present,
            last_online=last_online,
            scan_time=scan_time_iso
        )

    conn.close()

    print(f"Scan complete at {scan_time_human}")
    for device_id, device_info in DEVICES.items():
        state = "ONLINE" if presence[device_id] else "OFFLINE"
        print(f"  {device_info['name']}: {state}")


if __name__ == "__main__":
    main()
