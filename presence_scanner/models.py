"""Pydantic models for API responses and internal data."""

from typing import Literal

from pydantic import BaseModel

# =============================================================================
# Internal models (used within the application)
# =============================================================================


class DeviceState(BaseModel):
    """Internal state of a device from database."""

    present: bool
    last_online: str | None


class DeviceData(BaseModel):
    """Full device data from database."""

    name: str
    present: bool
    last_online: str | None
    last_online_human: str | None


class PresenceData(BaseModel):
    """All device states from database."""

    scan_time: str | None
    scan_time_human: str | None
    devices: dict[str, DeviceData]


class ValouStatusHistory(BaseModel):
    """Roomie status history from database."""

    status: str | None
    since: str | None


class RoomStates(BaseModel):
    """State of room lights from Hue."""

    living_room_on: bool
    valou_room_on: bool


class EnhancedValouData(BaseModel):
    """Enhanced Roomie status with Hue integration."""

    enhanced_status: Literal["downstairs", "around", "awake", "sleeping", "away"]
    enhanced_label: str
    living_room_on: bool
    valou_room_on: bool
    since: str | None
    since_minutes: int | None
    since_human: str | None
    minutes_away: float | None


# =============================================================================
# API response models
# =============================================================================


class DeviceStatus(BaseModel):
    """Status of a single device (API response)."""

    name: str
    present: bool
    last_online: str | None
    last_online_human: str | None


class ValouEnhancedStatus(BaseModel):
    """Enhanced status for Roomie with Hue integration (API response)."""

    name: str
    present: bool
    last_online: str | None
    last_online_human: str | None
    enhanced_status: Literal["downstairs", "around", "awake", "sleeping", "away"]
    enhanced_label: str
    living_room_on: bool
    valou_room_on: bool
    since: str | None
    since_minutes: int | None
    since_human: str | None


class PresenceResponse(BaseModel):
    """Full presence status response."""

    scan_time: str | None
    scan_time_human: str | None
    devices: dict[str, DeviceStatus | ValouEnhancedStatus]


class ValouStatusResponse(BaseModel):
    """Roomie-only status response."""

    status: Literal["downstairs", "around", "awake", "sleeping", "away"]
    label: str
    present: bool
    last_online: str | None
    minutes_away: float | None
    living_room_on: bool
    valou_room_on: bool
    since: str | None
    since_minutes: int | None
    since_human: str | None


class HealthResponse(BaseModel):
    """Health check response."""

    status: str
    timestamp: str


class ScanTriggerResponse(BaseModel):
    """Response for scan trigger endpoint."""

    status: str
    retry_after: float | None = None
