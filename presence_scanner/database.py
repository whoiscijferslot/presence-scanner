"""SQLite database operations for presence scanner."""

import sqlite3
from dataclasses import dataclass
from datetime import datetime

from loguru import logger

from .config import settings
from .models import DeviceData, DeviceState, PresenceData, ValouStatusHistory


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
            CREATE TABLE IF NOT EXISTS valou_status (
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
    """Get current state of all devices."""
    conn = get_connection()
    try:
        row = conn.execute(
            "SELECT MAX(updated_at) as scan_time FROM devices"
        ).fetchone()
        scan_time: str | None = row["scan_time"] if row else None

        devices: dict[str, DeviceData] = {}
        for row in conn.execute("SELECT * FROM devices"):
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


def get_valou_status_history() -> ValouStatusHistory:
    """Get the last known Roomie status."""
    conn = get_connection()
    try:
        row = conn.execute(
            "SELECT status, since FROM valou_status WHERE id = 1"
        ).fetchone()
        if row:
            return ValouStatusHistory(status=row["status"], since=row["since"])
        return ValouStatusHistory(status=None, since=None)
    finally:
        conn.close()


def save_valou_status_history(status: str, since: str) -> None:
    """Save the current Roomie status."""
    conn = get_connection()
    try:
        conn.execute(
            """
            INSERT INTO valou_status (id, status, since) VALUES (1, ?, ?)
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


def format_time_human(iso_time: str | None) -> str | None:
    """Convert ISO time to human readable format."""
    if not iso_time:
        return None
    try:
        dt = datetime.fromisoformat(iso_time)
        return dt.strftime("%Y-%m-%d %H:%M:%S UTC")
    except ValueError:
        return iso_time
