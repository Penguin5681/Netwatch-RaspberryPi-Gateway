import argparse
import hashlib
import ipaddress
import json

from collections import defaultdict
from datetime import datetime, timedelta, timezone

from agent.database import connect, initialize
from agent.interfaces import get_interface_network


def utc_now():
    return (
        datetime.now(timezone.utc)
        .isoformat(timespec="seconds")
        .replace("+00:00", "Z")
    )


def parse_time(value):
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


def bucket_start(timestamp, seconds):
    epoch = int(timestamp.timestamp())
    aligned = epoch - (epoch % seconds)

    return datetime.fromtimestamp(
        aligned,
        timezone.utc,
    ).isoformat(timespec="seconds").replace("+00:00", "Z")


def is_local_ipv4(address, network):
    try:
        parsed = ipaddress.ip_address(address)
        return (
            isinstance(parsed, ipaddress.IPv4Address)
            and parsed in network
            and parsed != network.network_address
            and parsed != network.broadcast_address
            and not parsed.is_multicast
        )
    except ValueError:
        return False


def ensure_schema(db):
    db.executescript("""
        CREATE TABLE IF NOT EXISTS security_events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            event_key TEXT NOT NULL UNIQUE,
            window_start TEXT NOT NULL,
            interface TEXT NOT NULL,
            detection_type TEXT NOT NULL,
            source_ip TEXT,
            destination_ip TEXT,
            destination_port INTEGER,
            severity TEXT NOT NULL,
            confidence REAL NOT NULL,
            evidence_json TEXT NOT NULL,
            explanation TEXT NOT NULL,
            created_at TEXT NOT NULL,
            status TEXT NOT NULL DEFAULT 'open'
        );

        CREATE INDEX IF NOT EXISTS idx_security_events_time
        ON security_events(window_start);

        CREATE INDEX IF NOT EXISTS idx_security_events_source
        ON security_events(source_ip);

        CREATE INDEX IF NOT EXISTS idx_security_events_severity
        ON security_events(severity);

        CREATE INDEX IF NOT EXISTS idx_security_events_status
        ON security_events(status);
    """)


def make_event_key(
    window_start,
    interface,
    detection_type,
    source_ip,
    destination_ip,
    destination_port,
    discriminator=None,
):
    payload = json.dumps(
        [
            window_start,
            interface,
            detection_type,
            source_ip,
            destination_ip,
            destination_port,
            discriminator,
        ],
        sort_keys=True,
        separators=(",", ":"),
    )

    return hashlib.sha256(payload.encode()).hexdigest()


def store_event(
    db,
    window_start,
    interface,
    detection_type,
    source_ip,
    destination_ip,
    destination_port,
    severity,
    confidence,
    evidence,
    explanation,
):
    event_key = make_event_key(
        window_start,
        interface,
        detection_type,
        source_ip,
        destination_ip,
        destination_port,
        evidence.get("discriminator"),
    )

    db.execute("""
        INSERT INTO security_events (
            event_key,
            window_start,
            interface,
            detection_type,
            source_ip,
            destination_ip,
            destination_port,
            severity,
            confidence,
            evidence_json,
            explanation,
            created_at,
            status
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'open')

        ON CONFLICT(event_key) DO UPDATE SET
            severity = excluded.severity,
            confidence = excluded.confidence,
            evidence_json = excluded.evidence_json,
            explanation = excluded.explanation
    """, (
        event_key,
        window_start,
        interface,
        detection_type,
        source_ip,
        destination_ip,
        destination_port,
        severity,
        confidence,
        json.dumps(evidence, sort_keys=True),
        explanation,
        utc_now(),
    ))


def detect_network_scans(
    db,
    interface,
    network,
    lookback_minutes,
    bucket_seconds,
    port_threshold,
    horizontal_threshold,
    burst_threshold,
):
    cutoff = datetime.now(timezone.utc) - timedelta(
        minutes=lookback_minutes
    )

    rows = db.execute("""
        SELECT
            timestamp,
            src_ip,
            dst_ip,
            dst_port,
            tcp_flags
        FROM packet_observations
        WHERE julianday(timestamp) >= julianday(?)
          AND interface = ?
          AND protocol = 'TCP'
          AND src_ip IS NOT NULL
          AND dst_ip IS NOT NULL
          AND dst_port IS NOT NULL
        ORDER BY timestamp
    """, (
        cutoff.isoformat(timespec="seconds").replace("+00:00", "Z"),
        interface,
    )).fetchall()

    vertical = defaultdict(set)
    horizontal = defaultdict(set)
    bursts = defaultdict(int)

    for row in rows:
        src_ip = row["src_ip"]
        dst_ip = row["dst_ip"]

        if not is_local_ipv4(src_ip, network):
            continue

        if not is_local_ipv4(dst_ip, network):
            continue

        if src_ip == dst_ip:
            continue

        flags = row["tcp_flags"] or ""

        # Only count initial SYN packets, not SYN-ACK responses.
        if "S" not in flags or "A" in flags:
            continue

        timestamp = parse_time(row["timestamp"])
        bucket = bucket_start(timestamp, bucket_seconds)
        port = int(row["dst_port"])

        vertical[(bucket, src_ip, dst_ip)].add(port)
        horizontal[(bucket, src_ip, port)].add(dst_ip)
        bursts[(bucket, src_ip, dst_ip, port)] += 1

    generated = 0

    for (bucket, src, dst), ports in vertical.items():
        if len(ports) < port_threshold:
            continue

        sorted_ports = sorted(ports)

        store_event(
            db,
            bucket,
            interface,
            "tcp_port_scan",
            src,
            dst,
            None,
            "high",
            0.90,
            {
                "distinct_destination_ports": len(ports),
                "ports": sorted_ports[:100],
                "threshold": port_threshold,
                "discriminator": sorted_ports,
            },
            (
                f"{src} attempted TCP connections to "
                f"{len(ports)} distinct ports on {dst} "
                f"within {bucket_seconds} seconds."
            ),
        )
        generated += 1

    for (bucket, src, port), destinations in horizontal.items():
        if len(destinations) < horizontal_threshold:
            continue

        sorted_destinations = sorted(destinations)

        store_event(
            db,
            bucket,
            interface,
            "tcp_horizontal_scan",
            src,
            None,
            port,
            "high",
            0.90,
            {
                "distinct_destination_ips": len(destinations),
                "destinations": sorted_destinations[:100],
                "destination_port": port,
                "threshold": horizontal_threshold,
                "discriminator": sorted_destinations,
            },
            (
                f"{src} attempted connections to "
                f"{len(destinations)} local devices "
                f"on TCP port {port} within {bucket_seconds} seconds."
            ),
        )
        generated += 1

    for (bucket, src, dst, port), count in bursts.items():
        if count < burst_threshold:
            continue

        store_event(
            db,
            bucket,
            interface,
            "tcp_connection_burst",
            src,
            dst,
            port,
            "medium",
            0.75,
            {
                "initial_syn_packets": count,
                "threshold": burst_threshold,
                "destination_port": port,
            },
            (
                f"{src} generated {count} initial TCP SYN packets "
                f"toward {dst}:{port} within {bucket_seconds} seconds."
            ),
        )
        generated += 1

    return len(rows), generated


def detect_unknown_devices(
    db,
    interface,
    lookback_minutes,
):
    cutoff = datetime.now(timezone.utc) - timedelta(
        minutes=lookback_minutes
    )

    cutoff_string = (
        cutoff.isoformat(timespec="seconds")
        .replace("+00:00", "Z")
    )

    rows = db.execute("""
        SELECT
            mac,
            last_ip,
            hostname,
            vendor,
            first_seen,
            mac_type,
            trust_status
        FROM devices
        WHERE last_interface = ?
          AND status = 'online'
          AND trust_status = 'unknown'
          AND first_seen >= ?
    """, (
        interface,
        cutoff_string,
    )).fetchall()

    generated = 0

    for row in rows:
        event_window = row["first_seen"]

        store_event(
            db,
            event_window,
            interface,
            "new_unknown_device",
            row["last_ip"],
            None,
            None,
            "medium",
            0.95,
            {
                "mac": row["mac"],
                "hostname": row["hostname"],
                "vendor": row["vendor"],
                "mac_type": row["mac_type"],
                "trust_status": row["trust_status"],
                "discriminator": row["mac"],
            },
            (
                f"New device {row['last_ip']} "
                f"with MAC {row['mac']} was discovered "
                "but has not been classified as trusted."
            ),
        )

        generated += 1

    return generated


def import_baseline_anomalies(db, interface, lookback_minutes):
    tables = {
        row["name"]
        for row in db.execute("""
            SELECT name
            FROM sqlite_master
            WHERE type = 'table'
        """)
    }

    if "anomaly_events" not in tables:
        return 0

    cutoff = datetime.now(timezone.utc) - timedelta(
        minutes=lookback_minutes
    )
    

    cutoff_string = (
        cutoff.isoformat(timespec="seconds")
        .replace("+00:00", "Z")
    )

    rows = db.execute("""
        SELECT *
        FROM anomaly_events
        WHERE interface = ?
          AND window_start >= ?
    """, (
        interface,
        cutoff_string,
    )).fetchall()

    generated = 0

    for row in rows:
        evidence = {
            "metric_name": row["metric_name"],
            "observed_value": row["observed_value"],
            "baseline_mean": row["baseline_mean"],
            "baseline_stddev": row["baseline_stddev"],
            "z_score": row["z_score"],
            "original_explanation": row["explanation"],
            "discriminator": row["metric_name"],
        }

        store_event(
            db,
            row["window_start"],
            interface,
            "behavioral_deviation",
            row["device_ip"],
            None,
            None,
            row["severity"],
            0.80,
            evidence,
            row["explanation"],
        )

        generated += 1

    return generated

def run_detection(
    interface="wlan0",
    lookback_minutes=5,
    bucket_seconds=60,
    port_threshold=10,
    horizontal_threshold=10,
    burst_threshold=25,
):
    initialize()

    db = connect()
    ensure_schema(db)

    info = get_interface_network(interface)

    network = ipaddress.ip_network(
        info["network"],
        strict=False,
    )

    print("\n===== NETWATCH THREAT DETECTION =====")
    print(f"Interface : {interface}")
    print(f"Local net : {network}")
    print(f"Lookback  : {lookback_minutes} minutes")

    packet_rows, scan_events = detect_network_scans(
        db,
        interface,
        network,
        lookback_minutes,
        bucket_seconds,
        port_threshold,
        horizontal_threshold,
        burst_threshold,
    )

    unknown_events = detect_unknown_devices(
        db,
        interface,
        lookback_minutes,
    )

    baseline_events = import_baseline_anomalies(
        db,
        interface,
        lookback_minutes,
    )

    db.commit()

    total = db.execute("""
        SELECT COUNT(*)
        FROM security_events
        WHERE interface = ?
    """, (interface,)).fetchone()[0]

    recent = db.execute("""
        SELECT COUNT(*)
        FROM security_events
        WHERE interface = ?
          AND created_at >= ?
    """, (
        interface,
        utc_now()[:19],
    )).fetchone()[0]

    print(f"\nTCP packet rows examined : {packet_rows}")
    print(f"Scan/burst events        : {scan_events}")
    print(f"Unknown-device events    : {unknown_events}")
    print(f"Baseline anomaly imports : {baseline_events}")
    print(f"Total stored events      : {total}")
    print(f"Events created/refreshed : {recent}")

    db.close()


def list_events(limit=30, status=None):
    initialize()

    db = connect()

    query = """
        SELECT *
        FROM security_events
    """
    params = []

    if status:
        query += " WHERE status = ?"
        params.append(status)

    query += " ORDER BY created_at DESC, id DESC LIMIT ?"
    params.append(limit)

    rows = db.execute(query, params).fetchall()

    print("\n===== NETWATCH SECURITY EVENTS =====")

    if not rows:
        print("No security events recorded.")
        db.close()
        return

    for row in rows:
        print("\n----------------------------------------")
        print(f"ID          : {row['id']}")
        print(f"Type        : {row['detection_type']}")
        print(f"Severity    : {row['severity']}")
        print(f"Confidence  : {row['confidence']:.2f}")
        print(f"Source      : {row['source_ip']}")
        print(f"Destination : {row['destination_ip']}")
        print(f"Port        : {row['destination_port']}")
        print(f"Window      : {row['window_start']}")
        print(f"Status      : {row['status']}")
        print(f"Explanation : {row['explanation']}")
        print(f"Evidence    : {row['evidence_json']}")

    db.close()


def main():
    parser = argparse.ArgumentParser(
        description="NetWatch rule-based threat detection"
    )

    subparsers = parser.add_subparsers(
        dest="command",
        required=True,
    )

    run_parser = subparsers.add_parser(
        "run",
        help="Run network threat detection",
    )

    run_parser.add_argument("--interface", default="wlan0")
    run_parser.add_argument("--lookback", type=int, default=5)
    run_parser.add_argument("--bucket", type=int, default=60)
    run_parser.add_argument("--port-threshold", type=int, default=10)
    run_parser.add_argument(
        "--horizontal-threshold",
        type=int,
        default=10,
    )
    run_parser.add_argument("--burst-threshold", type=int, default=25)

    list_parser = subparsers.add_parser(
        "list",
        help="List stored security events",
    )

    list_parser.add_argument("--limit", type=int, default=30)
    list_parser.add_argument(
        "--status",
        choices=["open", "acknowledged", "resolved", "false_positive"],
    )

    args = parser.parse_args()

    if args.command == "run":
        values = [
            args.lookback,
            args.bucket,
            args.port_threshold,
            args.horizontal_threshold,
            args.burst_threshold,
        ]

        if min(values) < 1:
            parser.error("All thresholds and time values must be positive.")

        run_detection(
            interface=args.interface,
            lookback_minutes=args.lookback,
            bucket_seconds=args.bucket,
            port_threshold=args.port_threshold,
            horizontal_threshold=args.horizontal_threshold,
            burst_threshold=args.burst_threshold,
        )

    elif args.command == "list":
        if args.limit < 1:
            parser.error("--limit must be positive.")

        list_events(args.limit, args.status)


if __name__ == "__main__":
    main()
