"""Configuration for presence scanner.

The host running this app is *not* on the home LAN anymore. All information is
obtained remotely through two endpoints exposed on the router's WAN IP:

1. The Zyxel router API (HTTPS) -- connected devices + live ARP table.
2. The Philips Hue bridge HTTP API, port-forwarded on the router.

No credentials, hostnames, or personal data are hardcoded here. Everything is
read from environment variables at startup -- see ``.envrc.example`` for the
full list of variables and example values. Secrets default to an empty string
(never a real value) so a missing/misconfigured value fails loudly instead of
silently reusing someone else's credentials.
"""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Literal

from pydantic import BaseModel, Field


def _env_bool(name: str, default: bool) -> bool:  # noqa: FBT001
    """Parse a boolean environment variable (``1/true/yes/on``, case-insensitive)."""
    value = os.environ.get(name)
    if value is None:
        return default
    return value.strip().lower() in {"1", "true", "yes", "on"}


def _env_int(name: str, default: int) -> int:
    """Parse an integer environment variable, falling back to ``default``."""
    value = os.environ.get(name)
    return int(value) if value else default


def _env_optional_int(name: str) -> int | None:
    """Parse an optional integer environment variable (``None`` if unset)."""
    value = os.environ.get(name)
    return int(value) if value else None


def _default_hue_backend() -> str:
    """Default to the "mock" backend unless a real Hue username is set.

    This means the app is fully demoable -- including the light-based
    Downstairs/Around/Awake/Sleeping/Away states -- with zero configuration
    and no real smart-home hardware.
    """
    explicit = os.environ.get("HUE_BACKEND")
    if explicit:
        return explicit
    return "live" if os.environ.get("HUE_USERNAME") else "mock"


class DeviceConfig(BaseModel):
    """Configuration for a tracked device."""

    name: str
    ip: str
    mac: str


def _load_devices() -> dict[str, DeviceConfig]:
    """Load tracked devices from the ``DEVICES`` env var (a JSON object).

    Example::

        export DEVICES='{"alice": {"name": "Alice", "ip": "192.168.1.50",
                                    "mac": "aa:bb:cc:dd:ee:ff"}}'

    Falls back to a single placeholder device so the app is runnable out of
    the box without embedding anyone's real IP/MAC/name in source control.
    """
    raw = os.environ.get("DEVICES")
    if not raw:
        return {
            "example": DeviceConfig(
                name="Example Device",
                ip="192.168.1.100",
                mac="aa:bb:cc:dd:ee:ff",
            ),
        }
    data = json.loads(raw)
    return {device_id: DeviceConfig(**fields) for device_id, fields in data.items()}


class ZyxelConfig(BaseModel):
    """Zyxel router API configuration (remote, over the WAN IP).

    Set ``ZYXEL_URL``, ``ZYXEL_USER`` and ``ZYXEL_PASS`` in the environment.
    There is deliberately no default password.
    """

    enabled: bool = Field(
        default_factory=lambda: _env_bool("ZYXEL_ENABLED", default=True),
    )
    base_url: str = Field(
        default_factory=lambda: os.environ.get("ZYXEL_URL", "https://192.168.1.1"),
    )
    username: str = Field(
        default_factory=lambda: os.environ.get("ZYXEL_USER", "admin"),
    )
    password: str = Field(default_factory=lambda: os.environ.get("ZYXEL_PASS", ""))  # noqa: S105
    timeout: int = Field(default_factory=lambda: _env_int("ZYXEL_TIMEOUT", 15))


class HueConfig(BaseModel):
    """Philips Hue bridge configuration (port-forwarded on the router).

    Set ``HUE_BASE_URL`` and ``HUE_USERNAME`` in the environment for a real
    bridge. With no Hue config at all, a deterministic *mock* backend is used
    instead (see ``hue.MockHueClient``), so the light-based enhanced status
    can be demoed and tested without any real smart-home hardware.
    """

    backend: Literal["live", "mock"] = Field(default_factory=_default_hue_backend)
    base_url: str = Field(
        default_factory=lambda: os.environ.get("HUE_BASE_URL", "http://192.168.1.2:80"),
    )
    username: str | None = Field(
        default_factory=lambda: os.environ.get("HUE_USERNAME") or None,
    )
    living_room_group: str = Field(
        default_factory=lambda: os.environ.get("HUE_LIVING_ROOM_GROUP", "1"),
    )
    secondary_room_group: str = Field(
        default_factory=lambda: os.environ.get("HUE_SECONDARY_ROOM_GROUP", "2"),
    )
    timeout: int = Field(default_factory=lambda: _env_int("HUE_TIMEOUT", 5))
    # Which tracked device (a key in `devices`) gets light-based enhanced
    # status. Defaults to the "example" placeholder device (see
    # `_load_devices`) so the feature is visible out of the box; set to ""
    # explicitly to disable it.
    enhanced_device_id: str = Field(
        default_factory=lambda: os.environ.get("HUE_ENHANCED_DEVICE_ID", "example"),
    )
    # Only used by the mock backend: pin the simulated hour (0-23) instead of
    # using the current time, for reproducible demos/screenshots.
    mock_force_hour: int | None = Field(
        default_factory=lambda: _env_optional_int("HUE_MOCK_FORCE_HOUR"),
    )


class Settings(BaseModel):
    """Application settings, sourced entirely from the environment."""

    # Paths
    data_dir: Path = Field(
        default_factory=lambda: Path(
            os.environ.get("DATA_DIR", "/var/lib/presence-scanner"),
        ),
    )

    # Debounce before confirming a presence state change
    debounce_delay: int = Field(default_factory=lambda: _env_int("DEBOUNCE_DELAY", 5))

    # Devices to track (MAC addresses are the source of truth for presence)
    devices: dict[str, DeviceConfig] = Field(default_factory=_load_devices)

    # Remote data sources
    zyxel: ZyxelConfig = Field(default_factory=ZyxelConfig)
    hue: HueConfig = Field(default_factory=HueConfig)

    # Scan interval (seconds)
    scan_interval: int = Field(default_factory=lambda: _env_int("SCAN_INTERVAL", 60))

    # How often to poll for devices never seen before (seconds)
    new_device_poll_interval: int = Field(
        default_factory=lambda: _env_int("NEW_DEVICE_POLL_INTERVAL", 30),
    )

    @property
    def db_file(self) -> Path:
        """Path to the SQLite database file, inside ``data_dir``."""
        return self.data_dir / "presence.db"

    @property
    def new_device_log_file(self) -> Path:
        """Path to the dedicated new-device-connections log file."""
        return self.data_dir / "new_devices.log"


settings = Settings()
