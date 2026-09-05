"""SQLite database operations for presence scanner."""

import sqlite3
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from zoneinfo import ZoneInfo

from loguru import logger

from .config import settings
from .models import (
    DeviceData,
    DeviceState,
    EnhancedStatusHistory,
    NewDeviceEvent,
    PresenceData,
)

DISPLAY_TZ = ZoneInfo("Europe/Amsterdam")
_WEEKDAYS = ("Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun")
_MONTHS = (
    "January",
    "February",
    "March",
    "April",
    "May",
    "June",
    "July",
    "August",
    "September",
    "October",
    "November",
    "December",
)


@dataclass
class DeviceUpdate:
    """Data for updating a device state."""

    device_id: str
    name: str
    ip: str
    mac: str
    present: bool
    last_online: str | None
    scan_time: str


@dataclass
class ZyxelSessionRecord:
    """A cached Zyxel router session (reused until it expires, ~60 min).

    Reusing a session avoids exhausting the router's small pool of concurrent
    login slots. All three values are needed to talk to the router without a
    fresh login: ``cookie`` authenticates, ``aes_key`` decrypts responses, and
    ``session_key`` is the CSRF token for any state-changing call.
    """

    cookie: str
    aes_key: str
    session_key: str
    created_at: str  # ISO-8601, UTC


def get_connection() -> sqlite3.Connection:
    """Get a database connection with row factory."""
    settings.data_dir.mkdir(parents=True, exist_ok=True)

    conn = sqlite3.connect(settings.db_file)
    conn.row_factory = sqlite3.Row
    return conn


def init_db() -> None:
    """Initialize database schema."""
    conn = get_connection()
    try:
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
        conn.execute("""
            CREATE TABLE IF NOT EXISTS enhanced_status (
                id INTEGER PRIMARY KEY CHECK (id = 1),
                status TEXT,
                since TEXT
            )
        """)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS zyxel_session (
                id INTEGER PRIMARY KEY CHECK (id = 1),
                cookie TEXT NOT NULL,
                aes_key TEXT NOT NULL,
                session_key TEXT NOT NULL,
                created_at TEXT NOT NULL
            )
        """)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS known_devices (
                mac TEXT PRIMARY KEY,
                ip TEXT NOT NULL,
                name TEXT NOT NULL,
                connection TEXT NOT NULL,
                first_seen TEXT NOT NULL,
                last_seen TEXT NOT NULL
            )
        """)
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
        logger.debug("Database schema initialized")
    finally:
        conn.close()


def get_device_state(device_id: str) -> DeviceState | None:
    """Get current state of a device from database."""
    conn = get_connection()
    try:
        row = conn.execute(
            "SELECT present, last_online FROM devices WHERE device_id = ?",
            (device_id,),
        ).fetchone()
        if row:
            return DeviceState(
                present=bool(row["present"]),
                last_online=row["last_online"],
            )
        return None
    finally:
        conn.close()


def get_all_device_states() -> PresenceData:
    """Get current state of all *currently configured* devices.

    Filtered against ``settings.devices`` so a device that's been removed or
    renamed in config (e.g. ``DEVICES`` changed) stops appearing in API
    responses immediately, instead of lingering forever just because old rows
    still exist in the database.
    """
    configured_ids = list(settings.devices.keys())
    if not configured_ids:
        return PresenceData(scan_time=None, scan_time_human=None, devices={})

    conn = get_connection()
    try:
        placeholders = ",".join("?" for _ in configured_ids)
        row = conn.execute(
            f"SELECT MAX(updated_at) as scan_time FROM devices "
            f"WHERE device_id IN ({placeholders})",
            configured_ids,
        ).fetchone()
        scan_time: str | None = row["scan_time"] if row else None

        devices: dict[str, DeviceData] = {}
        query = f"SELECT * FROM devices WHERE device_id IN ({placeholders})"
        for row in conn.execute(query, configured_ids):
            device_id: str = row["device_id"]
            devices[device_id] = DeviceData(
                name=row["name"],
                present=bool(row["present"]),
                last_online=row["last_online"],
                last_online_human=format_time_human(row["last_online"]),
            )

        return PresenceData(
            scan_time=scan_time,
            scan_time_human=format_time_human(scan_time),
            devices=devices,
        )
    finally:
        conn.close()


def update_device_state(update: DeviceUpdate) -> None:
    """Update device state in database."""
    conn = get_connection()
    try:
        conn.execute(
            """
            INSERT INTO devices
                (device_id, name, ip, mac, present, last_online, updated_at)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(device_id) DO UPDATE SET
                name = excluded.name,
                ip = excluded.ip,
                mac = excluded.mac,
                present = excluded.present,
                last_online = excluded.last_online,
                updated_at = excluded.updated_at
            """,
            (
                update.device_id,
                update.name,
                update.ip,
                update.mac,
                int(update.present),
                update.last_online,
                update.scan_time,
            ),
        )

        conn.execute(
            "INSERT INTO scans (scan_time, device_id, present) VALUES (?, ?, ?)",
            (update.scan_time, update.device_id, int(update.present)),
        )
        conn.commit()
    finally:
        conn.close()


def get_enhanced_status_history() -> EnhancedStatusHistory:
    """Get the last known enhanced (light-based) status."""
    conn = get_connection()
    try:
        row = conn.execute(
            "SELECT status, since FROM enhanced_status WHERE id = 1"
        ).fetchone()
        if row:
            return EnhancedStatusHistory(status=row["status"], since=row["since"])
        return EnhancedStatusHistory(status=None, since=None)
    finally:
        conn.close()


def save_enhanced_status_history(status: str, since: str) -> None:
    """Save the current enhanced (light-based) status."""
    conn = get_connection()
    try:
        conn.execute(
            """
            INSERT INTO enhanced_status (id, status, since) VALUES (1, ?, ?)
            ON CONFLICT(id) DO UPDATE SET
                status = excluded.status,
                since = excluded.since
            """,
            (status, since),
        )
        conn.commit()
    finally:
        conn.close()


def get_zyxel_session() -> ZyxelSessionRecord | None:
    """Load the cached Zyxel session, or None if none is stored."""
    conn = get_connection()
    try:
        row = conn.execute(
            "SELECT cookie, aes_key, session_key, created_at "
            "FROM zyxel_session WHERE id = 1",
        ).fetchone()
        if row:
            return ZyxelSessionRecord(
                cookie=row["cookie"],
                aes_key=row["aes_key"],
                session_key=row["session_key"],
                created_at=row["created_at"],
            )
        return None
    finally:
        conn.close()


def save_zyxel_session(record: ZyxelSessionRecord) -> None:
    """Persist (replace) the cached Zyxel session."""
    conn = get_connection()
    try:
        conn.execute(
            """
            INSERT INTO zyxel_session (id, cookie, aes_key, session_key, created_at)
            VALUES (1, ?, ?, ?, ?)
            ON CONFLICT(id) DO UPDATE SET
                cookie = excluded.cookie,
                aes_key = excluded.aes_key,
                session_key = excluded.session_key,
                created_at = excluded.created_at
            """,
            (record.cookie, record.aes_key, record.session_key, record.created_at),
        )
        conn.commit()
    finally:
        conn.close()


def clear_zyxel_session() -> None:
    """Drop the cached Zyxel session (forces a fresh login next time)."""
    conn = get_connection()
    try:
        conn.execute("DELETE FROM zyxel_session WHERE id = 1")
        conn.commit()
    finally:
        conn.close()


def get_known_macs() -> set[str]:
    """Every MAC address ever recorded as an active device (lowercased).

    This is scoped to devices seen by the new-device monitor -- it is *not*
    the same as the router's own DHCP-lease history, which can predate this
    feature entirely.
    """
    conn = get_connection()
    try:
        rows = conn.execute("SELECT mac FROM known_devices").fetchall()
        return {row["mac"] for row in rows}
    finally:
        conn.close()


def record_seen_device(
    *,
    mac: str,
    ip: str,
    name: str,
    connection: str,
    seen_time: str,
) -> bool:
    """Record that ``mac`` was seen active at ``seen_time``.

    Returns ``True`` if this MAC has never been recorded before, i.e. it is
    a genuinely new device connecting for the first time since this monitor
    started running.
    """
    mac = mac.lower()
    conn = get_connection()
    try:
        existing = conn.execute(
            "SELECT 1 FROM known_devices WHERE mac = ?",
            (mac,),
        ).fetchone()
        conn.execute(
            """
            INSERT INTO known_devices
                (mac, ip, name, connection, first_seen, last_seen)
            VALUES (?, ?, ?, ?, ?, ?)
            ON CONFLICT(mac) DO UPDATE SET
                ip = excluded.ip,
                name = excluded.name,
                connection = excluded.connection,
                last_seen = excluded.last_seen
            """,
            (mac, ip, name, connection, seen_time, seen_time),
        )
        conn.commit()
        return existing is None
    finally:
        conn.close()


def get_recent_new_devices(limit: int = 50) -> list[NewDeviceEvent]:
    """Most recently first-seen devices, newest first."""
    conn = get_connection()
    try:
        rows = conn.execute(
            "SELECT mac, ip, name, connection, first_seen, last_seen "
            "FROM known_devices ORDER BY first_seen DESC LIMIT ?",
            (limit,),
        ).fetchall()
        return [
            NewDeviceEvent(
                mac=row["mac"],
                ip=row["ip"],
                name=row["name"],
                connection=row["connection"],
                first_seen=row["first_seen"],
                first_seen_human=format_time_human(row["first_seen"]),
                last_seen=row["last_seen"],
                last_seen_human=format_time_human(row["last_seen"]),
            )
            for row in rows
        ]
    finally:
        conn.close()


def _ordinal_suffix(day: int) -> str:
    """Return the English ordinal suffix for a day of the month (st/nd/rd/th)."""
    if 11 <= day % 100 <= 13:  # noqa: PLR2004 -- 11th/12th/13th are all "th"
        return "th"
    return {1: "st", 2: "nd", 3: "rd"}.get(day % 10, "th")


def _utc_offset_label(dt: datetime) -> str:
    """Format a datetime's UTC offset as e.g. ``UTC+2`` or ``UTC+5:30``."""
    offset = dt.utcoffset() or timedelta(0)
    total_minutes = int(offset.total_seconds()) // 60
    sign = "+" if total_minutes >= 0 else "-"
    hours, minutes = divmod(abs(total_minutes), 60)
    return f"UTC{sign}{hours}" if minutes == 0 else f"UTC{sign}{hours}:{minutes:02d}"


def format_time_human(iso_time: str | None) -> str | None:
    """Format a UTC ISO timestamp for display in Amsterdam local time.

    Example: ``Tue 26th June 19:53:12 UTC+2`` — abbreviated weekday, ordinal
    day, full month, 24-hour time, and the local UTC offset.
    """
    if not iso_time:
        return None
    try:
        dt = datetime.fromisoformat(iso_time)
    except ValueError:
        return iso_time
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=UTC)
    local = dt.astimezone(DISPLAY_TZ)
    weekday = _WEEKDAYS[local.weekday()]
    day = f"{local.day}{_ordinal_suffix(local.day)}"
    month = _MONTHS[local.month - 1]
    return f"{weekday} {day} {month} {local:%H:%M:%S} {_utc_offset_label(local)}"
