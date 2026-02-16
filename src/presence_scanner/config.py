"""Configuration for presence scanner."""

from pathlib import Path
from typing import TypedDict


class DeviceConfig(TypedDict):
    name: str
    ip: str
    mac: str


# Paths
DATA_DIR = Path("/var/lib/presence-scanner")
DB_FILE = DATA_DIR / "presence.db"

# Network
NETWORK = "192.168.1.0/24"
DEBOUNCE_DELAY = 5  # seconds to wait before confirmation scan

# Devices to track
DEVICES: dict[str, DeviceConfig] = {
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

# Hue integration
HUE_BRIDGE_IP = "192.168.1.103"
HUE_TOKENS_FILE = Path.home() / ".config/bedwolf/hue-tokens.json"
LIVING_ROOM_GROUP = "81"
VALOU_ROOM_GROUP = "84"

# Scan interval (seconds)
SCAN_INTERVAL = 60
