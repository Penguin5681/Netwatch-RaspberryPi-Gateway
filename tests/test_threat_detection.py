import ipaddress
import sqlite3
from datetime import datetime, timedelta, timezone

from agent.threat_detection import (
    detect_network_scans,
    detect_unknown_devices,
    ensure_schema,
)


INTERFACE = "wlan1"
NETWORK = ipaddress.ip_network("10.42.0.0/24")
SOURCE = "10.42.0.57"


def timestamp(minutes_ago=0):
    value = datetime.now(timezone.utc) - timedelta(minutes=minutes_ago)
    return value.isoformat(timespec="seconds").replace("+00:00", "Z")


def make_db():
    db = sqlite3.connect(":memory:")
    db.row_factory = sqlite3.Row

    ensure_schema(db)

    db.execute("""
        CREATE TABLE packet_observations (
            timestamp TEXT NOT NULL,
            interface TEXT NOT NULL,
            protocol TEXT NOT NULL,
            src_ip TEXT,
            dst_ip TEXT,
            dst_port INTEGER,
            tcp_flags TEXT
        )
    """)

    db.execute("""
        CREATE TABLE devices (
            mac TEXT NOT NULL,
            last_ip TEXT,
            hostname TEXT,
            vendor TEXT,
            first_seen TEXT NOT NULL,
            mac_type TEXT,
            trust_status TEXT NOT NULL,
            last_interface TEXT NOT NULL,
            status TEXT NOT NULL
        )
    """)

    return db


def add_packet(db, src, dst, port, flags="S"):
    db.execute("""
        INSERT INTO packet_observations (
            timestamp,
            interface,
            protocol,
            src_ip,
            dst_ip,
            dst_port,
            tcp_flags
        )
        VALUES (?, ?, 'TCP', ?, ?, ?, ?)
    """, (
        timestamp(),
        INTERFACE,
        src,
        dst,
        port,
        flags,
    ))


def detect(db):
    return detect_network_scans(
        db=db,
        interface=INTERFACE,
        network=NETWORK,
        lookback_minutes=5,
        bucket_seconds=60,
        port_threshold=10,
        horizontal_threshold=10,
        burst_threshold=25,
    )


def event_types(db):
    return [
        row["detection_type"]
        for row in db.execute("""
            SELECT detection_type
            FROM security_events
            ORDER BY id
        """)
    ]


def test_vertical_tcp_scan_detected_at_threshold():
    db = make_db()

    for port in range(1, 11):
        add_packet(db, SOURCE, "10.42.0.1", port)

    examined, generated = detect(db)

    assert examined == 10
    assert generated == 1
    assert event_types(db) == ["tcp_port_scan"]

    db.close()


def test_horizontal_tcp_scan_detected_at_threshold():
    db = make_db()

    for host in range(10, 20):
        add_packet(db, SOURCE, f"10.42.0.{host}", 80)

    examined, generated = detect(db)

    assert examined == 10
    assert generated == 1
    assert event_types(db) == ["tcp_horizontal_scan"]

    db.close()


def test_tcp_syn_burst_detected_at_threshold():
    db = make_db()

    for _ in range(25):
        add_packet(db, SOURCE, "10.42.0.1", 443)

    examined, generated = detect(db)

    assert examined == 25
    assert generated == 1
    assert event_types(db) == ["tcp_connection_burst"]

    db.close()


def test_below_threshold_does_not_generate_scan_event():
    db = make_db()

    for port in range(1, 10):
        add_packet(db, SOURCE, "10.42.0.1", port)

    examined, generated = detect(db)

    assert examined == 9
    assert generated == 0
    assert event_types(db) == []

    db.close()


def test_syn_ack_and_public_destination_are_out_of_scope():
    db = make_db()

    # Ten initial SYNs to a public destination.
    for port in range(1, 11):
        add_packet(db, SOURCE, "49.44.89.225", port, "S")

    # Ten SYN-ACK responses involving a local destination.
    for port in range(1, 11):
        add_packet(db, SOURCE, "10.42.0.1", port, "SA")

    examined, generated = detect(db)

    assert examined == 20
    assert generated == 0
    assert event_types(db) == []

    db.close()


def test_only_new_online_unknown_device_generates_event():
    db = make_db()

    recent = timestamp(minutes_ago=1)
    old = timestamp(minutes_ago=20)

    db.executemany("""
        INSERT INTO devices (
            mac,
            last_ip,
            hostname,
            vendor,
            first_seen,
            mac_type,
            trust_status,
            last_interface,
            status
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, [
        (
            "02:00:00:00:00:01",
            "10.42.0.80",
            "unknown-device",
            None,
            recent,
            "locally_administered",
            "unknown",
            INTERFACE,
            "online",
        ),
        (
            "02:00:00:00:00:02",
            "10.42.0.81",
            "trusted-device",
            None,
            recent,
            "locally_administered",
            "trusted",
            INTERFACE,
            "online",
        ),
        (
            "02:00:00:00:00:03",
            "10.42.0.82",
            "offline-device",
            None,
            recent,
            "locally_administered",
            "unknown",
            INTERFACE,
            "offline",
        ),
        (
            "02:00:00:00:00:04",
            "10.42.0.83",
            "old-device",
            None,
            old,
            "locally_administered",
            "unknown",
            INTERFACE,
            "online",
        ),
    ])

    generated = detect_unknown_devices(
        db,
        INTERFACE,
        lookback_minutes=5,
    )

    assert generated == 1
    assert event_types(db) == ["new_unknown_device"]

    event = db.execute("""
        SELECT source_ip, severity, confidence
        FROM security_events
    """).fetchone()

    assert event["source_ip"] == "10.42.0.80"
    assert event["severity"] == "medium"
    assert event["confidence"] == 0.95

    db.close()


def test_repeated_scan_detection_does_not_duplicate_event():
    db = make_db()

    for port in range(1, 11):
        add_packet(db, SOURCE, "10.42.0.1", port)

    detect(db)
    detect(db)

    count = db.execute("""
        SELECT COUNT(*)
        FROM security_events
        WHERE detection_type = 'tcp_port_scan'
    """).fetchone()[0]

    assert count == 1

    db.close()


def test_repeated_baseline_anomaly_import_does_not_duplicate_event():
    from agent.threat_detection import import_baseline_anomalies

    db = make_db()

    db.execute("""
        CREATE TABLE anomaly_events (
            id INTEGER PRIMARY KEY,
            window_start TEXT,
            interface TEXT,
            device_ip TEXT,
            metric_name TEXT,
            observed_value REAL,
            baseline_mean REAL,
            baseline_stddev REAL,
            z_score REAL,
            severity TEXT,
            explanation TEXT
        )
    """)

    db.execute("""
        INSERT INTO anomaly_events (
            window_start,
            interface,
            device_ip,
            metric_name,
            observed_value,
            baseline_mean,
            baseline_stddev,
            z_score,
            severity,
            explanation
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (
        timestamp(),
        INTERFACE,
        SOURCE,
        "tcp_syn_packets",
        30,
        5,
        5,
        5,
        "high",
        "Synthetic baseline deviation for isolated testing.",
    ))

    first_import = import_baseline_anomalies(
        db, INTERFACE, lookback_minutes=5
    )
    second_import = import_baseline_anomalies(
        db, INTERFACE, lookback_minutes=5
    )

    count = db.execute("""
        SELECT COUNT(*)
        FROM security_events
        WHERE detection_type = 'behavioral_deviation'
    """).fetchone()[0]

    assert first_import == 1
    assert second_import == 1
    assert count == 1

    db.close()
