"""Configuration for presence scanner."""

from pathlib import Path

from pydantic import BaseModel


class DeviceConfig(BaseModel):
    """Configuration for a tracked device."""

    name: str
    ip: str
    mac: str


class Settings(BaseModel):
    """Application settings."""

    # Paths
    data_dir: Path = Path("/var/lib/presence-scanner")
    db_file: Path = Path("/var/lib/presence-scanner/presence.db")

    # Network
    network: str = "192.168.1.0/24"
    debounce_delay: int = 5  # seconds to wait before confirmation scan

    # Devices to track
    devices: dict[str, DeviceConfig] = {
        "alex": DeviceConfig(
            name="Alex",
            ip="192.168.1.101",
            mac="aa:bb:cc:dd:ee:01",
        ),
        "roomie": DeviceConfig(
            name="Roomie",
            ip="192.168.1.102",
            mac="aa:bb:cc:dd:ee:02",
        ),
    }

    # Hue integration
    hue_bridge_ip: str = "192.168.1.103"
    hue_tokens_file: Path = Path("/home/sam1902/.config/bedwolf/hue-tokens.json")
    living_room_group: str = "81"
    valou_room_group: str = "84"

    # Scan interval (seconds)
    scan_interval: int = 60


settings = Settings()
