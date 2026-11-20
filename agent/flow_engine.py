import argparse
import hashlib
import ipaddress
import json

from collections import Counter, defaultdict
from datetime import datetime, timedelta, timezone

from agent.database import connect, initialize
from agent.interfaces import get_interface_network


def parse_time(value):
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


def format_time(value):
    return (
        value.astimezone(timezone.utc)
        .isoformat(timespec="seconds")
        .replace("+00:00", "Z")
    )


def get_bucket(timestamp, seconds):
    epoch = int(timestamp.timestamp())
    bucket_epoch = epoch - (epoch % seconds)

    return datetime.fromtimestamp(bucket_epoch, timezone.utc)


def endpoint(ip, port):
    return (ip, int(port) if port is not None else -1)


def make_flow_key(bucket, interface, protocol, a, b):
    raw = json.dumps(
        [bucket, interface, protocol, a, b],
        separators=(",", ":"),
    )

    return hashlib.sha256(raw.encode()).hexdigest()


def ensure_schema(db):
    db.executescript("""
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

        CREATE TABLE IF NOT EXISTS device_window_metrics (
            window_start TEXT NOT NULL,
            interface TEXT NOT NULL,
            device_ip TEXT NOT NULL,
            flow_count INTEGER NOT NULL,
            unique_destinations INTEGER NOT NULL,
            unique_destination_ports INTEGER NOT NULL,
            tcp_syn_packets INTEGER NOT NULL,
            tcp_rst_packets INTEGER NOT NULL,
            protocol_distribution TEXT NOT NULL,
            PRIMARY KEY(window_start, interface, device_ip)
        );

        CREATE INDEX IF NOT EXISTS idx_device_metrics_ip
        ON device_window_metrics(device_ip);
    """)


def get_local_network(interface):
    info = get_interface_network(interface)

    network = ipaddress.ip_network(
        info["network"],
        strict=False,
    )

    return info, network


def is_local_address(address, network, known_ips):
    if not address:
        return False

    try:
        parsed = ipaddress.ip_address(address)
    except ValueError:
        return False

    # Exclude addresses that cannot represent individual devices.
    if (
        parsed.is_multicast
        or parsed.is_unspecified
        or parsed.is_loopback
    ):
        return False

    if isinstance(parsed, ipaddress.IPv4Address):
        if parsed == network.network_address:
            return False
        if parsed == network.broadcast_address:
            return False

    return parsed in network or address in known_ips


def aggregate(window_minutes=15, bucket_seconds=60, interface="wlan0"):
    initialize()

    db = connect()
    ensure_schema(db)

    info, local_network = get_local_network(interface)

    known_ips = {info["ip"]}

    for row in db.execute("""
        SELECT last_ip AS ip FROM devices
        UNION
        SELECT ip_address AS ip FROM device_ip_history
    """):
        if row["ip"]:
            known_ips.add(row["ip"])

    cutoff = datetime.now(timezone.utc) - timedelta(
        minutes=window_minutes
    )

    # Expand the cutoff to the beginning of its aggregation bucket.
    # This prevents partial minute summaries from overwriting complete ones.
    cutoff_epoch = int(cutoff.timestamp())
    aligned_epoch = cutoff_epoch - (cutoff_epoch % bucket_seconds)

    cutoff = datetime.fromtimestamp(
        aligned_epoch,
        timezone.utc,
    )

    cursor = db.execute("""
        SELECT
            timestamp,
            interface,
            src_ip,
            dst_ip,
            protocol,
            src_port,
            dst_port,
            packet_length,
            tcp_flags
        FROM packet_observations
        WHERE julianday(timestamp) >= julianday(?)
          AND interface = ?
          AND src_ip IS NOT NULL
          AND dst_ip IS NOT NULL
        ORDER BY timestamp
    """, (format_time(cutoff), interface))

    flows = {}
    traffic = defaultdict(lambda: {
        "tx_packets": 0,
        "rx_packets": 0,
        "tx_bytes": 0,
        "rx_bytes": 0,
    })

    metrics = defaultdict(lambda: {
        "flows": set(),
        "destinations": set(),
        "ports": set(),
        "syn": 0,
        "rst": 0,
        "protocols": Counter(),
    })

    processed = 0
    buckets = set()

    for row in cursor:
        timestamp = parse_time(row["timestamp"])
        bucket = format_time(
            get_bucket(timestamp, bucket_seconds)
        )

        buckets.add(bucket)

        src_ip = row["src_ip"]
        dst_ip = row["dst_ip"]
        protocol = row["protocol"]

        src_port = row["src_port"]
        dst_port = row["dst_port"]

        packet_size = row["packet_length"]

        src_local = is_local_address(
            src_ip, local_network, known_ips
        )
        dst_local = is_local_address(
            dst_ip, local_network, known_ips
        )

        src = endpoint(src_ip, src_port)
        dst = endpoint(dst_ip, dst_port)

        if src <= dst:
            a, b = src, dst
            direction = "a_to_b"
        else:
            a, b = dst, src
            direction = "b_to_a"

        key = make_flow_key(
            bucket,
            interface,
            protocol,
            a,
            b,
        )

        if key not in flows:
            flows[key] = {
                "flow_key": key,
                "window_start": bucket,
                "interface": interface,
                "protocol": protocol,
                "endpoint_a_ip": a[0],
                "endpoint_a_port": None if a[1] == -1 else a[1],
                "endpoint_b_ip": b[0],
                "endpoint_b_port": None if b[1] == -1 else b[1],
                "first_seen": timestamp,
                "last_seen": timestamp,
                "packets": 0,
                "bytes": 0,
                "a_to_b_packets": 0,
                "b_to_a_packets": 0,
                "a_to_b_bytes": 0,
                "b_to_a_bytes": 0,
            }

        flow = flows[key]

        flow["first_seen"] = min(
            flow["first_seen"], timestamp
        )
        flow["last_seen"] = max(
            flow["last_seen"], timestamp
        )

        flow["packets"] += 1
        flow["bytes"] += packet_size
        flow[f"{direction}_packets"] += 1
        flow[f"{direction}_bytes"] += packet_size

        if src_local:
            stats = traffic[(bucket, interface, src_ip)]
            stats["tx_packets"] += 1
            stats["tx_bytes"] += packet_size

            metric = metrics[(bucket, interface, src_ip)]
            metric["flows"].add(key)
            metric["destinations"].add(dst_ip)
            metric["protocols"][protocol] += 1

            if dst_port is not None:
                metric["ports"].add(int(dst_port))

            flags = row["tcp_flags"] or ""

            if protocol == "TCP":
                if "S" in flags and "A" not in flags:
                    metric["syn"] += 1

                if "R" in flags:
                    metric["rst"] += 1

        if dst_local:
            stats = traffic[(bucket, interface, dst_ip)]
            stats["rx_packets"] += 1
            stats["rx_bytes"] += packet_size

            metrics[(bucket, interface, dst_ip)]["flows"].add(key)

        processed += 1

    flow_rows = []

    for flow in flows.values():
        flow_rows.append((
            flow["flow_key"],
            flow["window_start"],
            flow["interface"],
            flow["protocol"],
            flow["endpoint_a_ip"],
            flow["endpoint_a_port"],
            flow["endpoint_b_ip"],
            flow["endpoint_b_port"],
            format_time(flow["first_seen"]),
            format_time(flow["last_seen"]),
            flow["packets"],
            flow["bytes"],
            flow["a_to_b_packets"],
            flow["b_to_a_packets"],
            flow["a_to_b_bytes"],
            flow["b_to_a_bytes"],
        ))

    traffic_rows = [
        (
            bucket, iface, ip,
            values["tx_packets"],
            values["rx_packets"],
            values["tx_bytes"],
            values["rx_bytes"],
        )
        for (bucket, iface, ip), values in traffic.items()
    ]

    metric_rows = [
        (
            bucket,
            iface,
            ip,
            len(values["flows"]),
            len(values["destinations"]),
            len(values["ports"]),
            values["syn"],
            values["rst"],
            json.dumps(dict(values["protocols"]), sort_keys=True),
        )
        for (bucket, iface, ip), values in metrics.items()
    ]

    # Rebuild only the buckets represented in this query.
    # Older buckets remain untouched.
    with db:
        for bucket in buckets:
            db.execute("""
                DELETE FROM flow_summaries
                WHERE window_start = ? AND interface = ?
            """, (bucket, interface))

            db.execute("""
                DELETE FROM device_traffic
                WHERE window_start = ? AND interface = ?
            """, (bucket, interface))

            db.execute("""
                DELETE FROM device_window_metrics
                WHERE window_start = ? AND interface = ?
            """, (bucket, interface))

        db.executemany("""
            INSERT INTO flow_summaries VALUES (
                ?, ?, ?, ?, ?, ?, ?, ?,
                ?, ?, ?, ?, ?, ?, ?, ?
            )
        """, flow_rows)

        db.executemany("""
            INSERT INTO device_traffic VALUES (
                ?, ?, ?, ?, ?, ?, ?
            )
        """, traffic_rows)

        db.executemany("""
            INSERT INTO device_window_metrics VALUES (
                ?, ?, ?, ?, ?, ?, ?, ?, ?
            )
        """, metric_rows)

    db.close()

    print("\n===== NETWATCH TRAFFIC INTELLIGENCE =====")
    print(f"Interface           : {interface}")
    print(f"Local IPv4 network  : {local_network}")
    print(f"Local interface IP  : {info['ip']}")
    print(f"Packets processed   : {processed}")
    print(f"Unique flows        : {len(flows)}")
    print(f"Device metric rows  : {len(metric_rows)}")
    print(f"Historical buckets  : {len(buckets)}")
    print(f"Analysis window     : {window_minutes} minutes")
    print(f"Bucket duration     : {bucket_seconds} seconds")

    print("\n===== TOP OBSERVED FLOWS =====")

    for flow in sorted(
        flows.values(),
        key=lambda value: value["bytes"],
        reverse=True,
    )[:10]:
        print(
            f"{flow['protocol']:<8} "
            f"{flow['endpoint_a_ip']}:{flow['endpoint_a_port']} "
            f"<-> "
            f"{flow['endpoint_b_ip']}:{flow['endpoint_b_port']} "
            f"| {flow['packets']} packets "
            f"| {flow['bytes']} bytes"
        )

    print("\n===== LOCAL DEVICE TRAFFIC =====")

    for row in sorted(
        traffic_rows,
        key=lambda value: value[5] + value[6],
        reverse=True,
    )[:15]:
        bucket, iface, ip, txp, rxp, txb, rxb = row

        print(
            f"{ip:<40} "
            f"TX {txb:>10} bytes "
            f"RX {rxb:>10} bytes"
        )


def main():
    parser = argparse.ArgumentParser(
        description="NetWatch persistent traffic intelligence"
    )

    parser.add_argument("--window", type=int, default=15)
    parser.add_argument("--bucket", type=int, default=60)
    parser.add_argument("--interface", default="wlan0")

    args = parser.parse_args()

    if args.window < 1 or args.bucket < 1:
        parser.error("Window and bucket must be positive.")

    try:
        aggregate(
            window_minutes=args.window,
            bucket_seconds=args.bucket,
            interface=args.interface,
        )
    except Exception as error:
        print(f"[ERROR] Traffic aggregation failed: {error}")
        raise SystemExit(1)


if __name__ == "__main__":
    main()
