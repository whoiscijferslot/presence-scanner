"""Configuration for presence scanner.

The host running this app is *not* on the home LAN anymore. All information is
obtained remotely through two endpoints exposed on the router's WAN IP:

1. The Zyxel router API (HTTPS) -- connected devices + live ARP table.
2. The Philips Hue bridge HTTP API, port-forwarded on the router.
"""

from pathlib import Path

from pydantic import BaseModel


class DeviceConfig(BaseModel):
    """Configuration for a tracked device."""

    name: str
    ip: str
    mac: str


class ZyxelConfig(BaseModel):
    """Zyxel router API configuration (remote, over the WAN IP)."""

    enabled: bool = True
    base_url: str = "https://203.0.113.1"
    username: str = "admin"
    password: str = "ZYXEL_PASSWORD_REDACTED"  # noqa: S105
    timeout: int = 15


class HueConfig(BaseModel):
    """Philips Hue bridge configuration (port-forwarded on the router).

    The bridge lives at 192.168.1.103 on the LAN and is exposed on the router's
    WAN IP at port 25875, so the v1 API base is ``http://<wan-ip>:25875``.
    """

    base_url: str = "http://203.0.113.1:25875"
    username: str = "HUE_USERNAME_REDACTED"
    living_room_group: str = "81"
    valou_room_group: str = "84"
    timeout: int = 5


class Settings(BaseModel):
    """Application settings."""

    # Paths
    data_dir: Path = Path("/var/lib/presence-scanner")
    db_file: Path = Path("/var/lib/presence-scanner/presence.db")

    # Debounce before confirming a presence state change
    debounce_delay: int = 5

    # Devices to track (MAC addresses are the source of truth for presence)
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

    # Remote data sources
    zyxel: ZyxelConfig = ZyxelConfig()
    hue: HueConfig = HueConfig()

    # Scan interval (seconds)
    scan_interval: int = 60


settings = Settings()
