import sqlite3
from pathlib import Path
from datetime import datetime, timedelta, timezone

ROOT = Path(__file__).resolve().parent.parent
DB_PATH = ROOT / "data" / "netwatch.db"


def utc_now():
    return (
        datetime.now(timezone.utc)
        .isoformat(timespec="seconds")
        .replace("+00:00", "Z")
    )


def connect():
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)

    db = sqlite3.connect(DB_PATH)
    db.row_factory = sqlite3.Row
    db.execute("PRAGMA journal_mode=WAL")
    db.execute("PRAGMA foreign_keys=ON")
    return db


def initialize():
    with connect() as db:
        db.executescript("""
            CREATE TABLE IF NOT EXISTS devices (
                mac TEXT PRIMARY KEY,
                last_ip TEXT NOT NULL,
                hostname TEXT,
                vendor TEXT,
                first_seen TEXT NOT NULL,
                last_seen TEXT NOT NULL,
                last_interface TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS device_observations (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                mac TEXT NOT NULL,
                ip_address TEXT NOT NULL,
                observed_at TEXT NOT NULL,
                interface TEXT NOT NULL,
                source TEXT NOT NULL,
                FOREIGN KEY(mac) REFERENCES devices(mac)
            );

            CREATE INDEX IF NOT EXISTS idx_observations_mac
            ON device_observations(mac);

            CREATE INDEX IF NOT EXISTS idx_observations_time
            ON device_observations(observed_at);

            CREATE TABLE IF NOT EXISTS packet_observations (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL,
                interface TEXT NOT NULL,
                src_mac TEXT,
                dst_mac TEXT,
                src_ip TEXT,
                dst_ip TEXT,
                protocol TEXT NOT NULL,
                src_port INTEGER,
                dst_port INTEGER,
                packet_length INTEGER NOT NULL,
                tcp_flags TEXT
            );

            CREATE INDEX IF NOT EXISTS idx_packet_timestamp
            ON packet_observations(timestamp);

            CREATE INDEX IF NOT EXISTS idx_packet_src_ip
            ON packet_observations(src_ip);

            CREATE INDEX IF NOT EXISTS idx_packet_dst_ip
            ON packet_observations(dst_ip);

            CREATE TABLE IF NOT EXISTS flow_summaries (
                flow_key TEXT PRIMARY KEY,
                window_start TEXT NOT NULL,
                interface TEXT NOT NULL,
                protocol TEXT NOT NULL,
                endpoint_a_ip TEXT NOT NULL,
                endpoint_a_port INTEGER,
                endpoint_b_ip TEXT NOT NULL,
                endpoint_b_port INTEGER,
                first_seen TEXT NOT NULL,
                last_seen TEXT NOT NULL,
                packets INTEGER NOT NULL,
                bytes INTEGER NOT NULL,
                a_to_b_packets INTEGER NOT NULL,
                b_to_a_packets INTEGER NOT NULL,
                a_to_b_bytes INTEGER NOT NULL,
                b_to_a_bytes INTEGER NOT NULL
            );

            CREATE INDEX IF NOT EXISTS idx_flows_window
            ON flow_summaries(window_start);

            CREATE TABLE IF NOT EXISTS device_traffic (
                window_start TEXT NOT NULL,
                interface TEXT NOT NULL,
                device_ip TEXT NOT NULL,
                tx_packets INTEGER NOT NULL DEFAULT 0,
                rx_packets INTEGER NOT NULL DEFAULT 0,
                tx_bytes INTEGER NOT NULL DEFAULT 0,
                rx_bytes INTEGER NOT NULL DEFAULT 0,
                PRIMARY KEY(window_start, interface, device_ip)
            );

            CREATE TABLE IF NOT EXISTS device_ip_history (
                mac TEXT NOT NULL,
                ip_address TEXT NOT NULL,
                first_seen TEXT NOT NULL,
                last_seen TEXT NOT NULL,
                last_interface TEXT NOT NULL,
                observations INTEGER NOT NULL DEFAULT 1,
                PRIMARY KEY(mac, ip_address),
                FOREIGN KEY(mac) REFERENCES devices(mac)
            );

            CREATE INDEX IF NOT EXISTS idx_ip_history_mac
            ON device_ip_history(mac);

            CREATE TABLE IF NOT EXISTS scan_runs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                interface TEXT NOT NULL,
                subnet TEXT NOT NULL,
                started_at TEXT NOT NULL,
                completed_at TEXT,
                discovered_count INTEGER NOT NULL DEFAULT 0,
                status TEXT NOT NULL DEFAULT 'running'
            );

            CREATE INDEX IF NOT EXISTS idx_scan_runs_started
            ON scan_runs(started_at);
        """)

        # Migrate existing devices tables without deleting old records.
        columns = {
            row["name"]
            for row in db.execute("PRAGMA table_info(devices)")
        }

        migrations = {
            "status": "TEXT NOT NULL DEFAULT 'unknown'",
            "mac_type": "TEXT NOT NULL DEFAULT 'unknown'",
            "trust_status": "TEXT NOT NULL DEFAULT 'unknown'",
            "hostname_source": "TEXT",
            "vendor_source": "TEXT",
            "last_scan_id": "INTEGER",
        }

        for column, definition in migrations.items():
            if column not in columns:
                db.execute(
                    f"ALTER TABLE devices ADD COLUMN {column} {definition}"
                )


def start_scan(interface, subnet, started_at=None):
    started_at = started_at or utc_now()

    with connect() as db:
        cursor = db.execute("""
            INSERT INTO scan_runs (
                interface, subnet, started_at, status
            )
            VALUES (?, ?, ?, 'running')
        """, (interface, subnet, started_at))

        return cursor.lastrowid


def finish_scan(
    scan_id,
    interface,
    discovered_count,
    offline_after_seconds=300,
):
    completed_at = utc_now()

    cutoff = (
        datetime.now(timezone.utc)
        - timedelta(seconds=offline_after_seconds)
    ).isoformat(timespec="seconds").replace("+00:00", "Z")

    with connect() as db:
        db.execute("""
            UPDATE scan_runs
            SET completed_at = ?,
                discovered_count = ?,
                status = 'completed'
            WHERE id = ?
        """, (completed_at, discovered_count, scan_id))

        # Do not mark a device offline after one missed ARP response.
        # Status is based on its most recent successful observation.
        db.execute("""
            UPDATE devices
            SET status = CASE
                WHEN last_seen >= ? THEN 'online'
                ELSE 'offline'
            END
            WHERE last_interface = ?
        """, (cutoff, interface))


def record_device(
    mac,
    ip_address,
    observed_at,
    interface,
    source="arp",
    hostname=None,
    vendor=None,
    mac_type="unknown",
    scan_id=None,
    hostname_source=None,
    vendor_source=None,
):
    mac = mac.lower()

    with connect() as db:
        db.execute("""
            INSERT INTO devices (
                mac, last_ip, hostname, vendor,
                first_seen, last_seen, last_interface,
                status, mac_type, trust_status,
                hostname_source, vendor_source, last_scan_id
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, 'online', ?, 'unknown', ?, ?, ?)

            ON CONFLICT(mac) DO UPDATE SET
                last_ip = excluded.last_ip,
                hostname = COALESCE(excluded.hostname, devices.hostname),
                vendor = COALESCE(excluded.vendor, devices.vendor),
                last_seen = excluded.last_seen,
                last_interface = excluded.last_interface,
                status = 'online',
                mac_type = excluded.mac_type,
                hostname_source = COALESCE(
                    excluded.hostname_source,
                    devices.hostname_source
                ),
                vendor_source = COALESCE(
                    excluded.vendor_source,
                    devices.vendor_source
                ),
                last_scan_id = excluded.last_scan_id
        """, (
            mac,
            ip_address,
            hostname,
            vendor,
            observed_at,
            observed_at,
            interface,
            mac_type,
            hostname_source,
            vendor_source,
            scan_id,
        ))

        db.execute("""
            INSERT INTO device_ip_history (
                mac, ip_address, first_seen, last_seen,
                last_interface, observations
            )
            VALUES (?, ?, ?, ?, ?, 1)

            ON CONFLICT(mac, ip_address) DO UPDATE SET
                last_seen = excluded.last_seen,
                last_interface = excluded.last_interface,
                observations = device_ip_history.observations + 1
        """, (
            mac,
            ip_address,
            observed_at,
            observed_at,
            interface,
        ))

        db.execute("""
            INSERT INTO device_observations (
                mac, ip_address, observed_at, interface, source
            )
            VALUES (?, ?, ?, ?, ?)
        """, (
            mac,
            ip_address,
            observed_at,
            interface,
            source,
        ))


def get_devices():
    with connect() as db:
        rows = db.execute("""
            SELECT *
            FROM devices
            ORDER BY last_seen DESC
        """).fetchall()

    return [dict(row) for row in rows]


def set_device_trust(mac, trust_status):
    if trust_status not in {"trusted", "untrusted", "unknown"}:
        raise ValueError("Trust status must be trusted, untrusted or unknown.")

    with connect() as db:
        cursor = db.execute("""
            UPDATE devices
            SET trust_status = ?
            WHERE mac = ?
        """, (trust_status, mac.lower()))

        return cursor.rowcount
