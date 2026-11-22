import argparse
import json

from collections import defaultdict
from datetime import datetime, timedelta, timezone
from pathlib import Path

from agent.database import connect, initialize


ROOT = Path(__file__).resolve().parent.parent
CONFIG_PATH = ROOT / "config" / "risk_weights.json"


def utc_now():
    return (
        datetime.now(timezone.utc)
        .isoformat(timespec="seconds")
        .replace("+00:00", "Z")
    )


def load_config():
    if not CONFIG_PATH.exists():
        raise FileNotFoundError(
            f"Risk configuration not found: {CONFIG_PATH}"
        )

    with CONFIG_PATH.open("r", encoding="utf-8") as file:
        config = json.load(file)

    required = [
        "weights",
        "behavioral_severity_weights",
        "repeat_bonus",
        "maximum_repeat_bonus",
        "type_caps",
        "risk_levels",
    ]

    for key in required:
        if key not in config:
            raise ValueError(f"Missing configuration field: {key}")

    return config


def ensure_schema(db):
    db.executescript("""
        CREATE TABLE IF NOT EXISTS risk_assessments (
            device_ip TEXT PRIMARY KEY,
            mac TEXT,
            hostname TEXT,
            vendor TEXT,
            risk_score INTEGER NOT NULL,
            risk_level TEXT NOT NULL,
            event_count INTEGER NOT NULL,
            lookback_hours INTEGER NOT NULL,
            factors_json TEXT NOT NULL,
            assessed_at TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS risk_assessment_history (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            device_ip TEXT NOT NULL,
            mac TEXT,
            hostname TEXT,
            vendor TEXT,
            risk_score INTEGER NOT NULL,
            risk_level TEXT NOT NULL,
            event_count INTEGER NOT NULL,
            lookback_hours INTEGER NOT NULL,
            factors_json TEXT NOT NULL,
            assessed_at TEXT NOT NULL
        );

        CREATE INDEX IF NOT EXISTS idx_risk_history_device
        ON risk_assessment_history(device_ip, assessed_at);

        CREATE INDEX IF NOT EXISTS idx_risk_history_time
        ON risk_assessment_history(assessed_at);
    """)


def classify_risk(score, config):
    for level in config["risk_levels"]:
        if level["minimum"] <= score <= level["maximum"]:
            return level["label"]

    return "Unclassified"


def get_event_weight(event, config):
    detection_type = event["detection_type"]

    if detection_type == "behavioral_deviation":
        severity = event["severity"].lower()

        return config["behavioral_severity_weights"].get(
            severity, 0
        )

    return config["weights"].get(detection_type, 0)


def calculate_factors(events, config):
    grouped = defaultdict(list)

    for event in events:
        weight = get_event_weight(event, config)

        if weight <= 0:
            continue

        grouped[event["detection_type"]].append({
            "id": event["id"],
            "weight": weight,
            "severity": event["severity"],
            "destination_ip": event["destination_ip"],
            "destination_port": event["destination_port"],
            "explanation": event["explanation"],
            "window_start": event["window_start"],
        })

    factors = []
    total_score = 0

    for detection_type, evidence in sorted(grouped.items()):
        base_points = sum(item["weight"] for item in evidence)

        repeat_count = max(0, len(evidence) - 1)

        repeat_bonus = min(
            repeat_count * config["repeat_bonus"],
            config["maximum_repeat_bonus"],
        )

        subtotal = base_points + repeat_bonus

        type_cap = config["type_caps"].get(
            detection_type, 100
        )

        points = min(subtotal, type_cap)

        total_score += points

        factors.append({
            "detection_type": detection_type,
            "event_count": len(evidence),
            "base_points": base_points,
            "repeat_bonus": repeat_bonus,
            "type_cap": type_cap,
            "awarded_points": points,
            "evidence": evidence,
        })

    return min(100, total_score), factors


def assess_risks(lookback_hours=24, device_filter=None):
    if lookback_hours < 1:
        raise ValueError("Lookback period must be positive.")

    config = load_config()

    initialize()

    db = connect()
    ensure_schema(db)

    tables = {
        row["name"]
        for row in db.execute("""
            SELECT name
            FROM sqlite_master
            WHERE type = 'table'
        """)
    }

    if "security_events" not in tables:
        db.close()
        raise RuntimeError(
            "security_events table is missing. "
            "Run the threat detector first."
        )

    cutoff = (
        datetime.now(timezone.utc)
        - timedelta(hours=lookback_hours)
    ).isoformat(timespec="seconds").replace("+00:00", "Z")

    events = db.execute("""
        SELECT *
        FROM security_events
        WHERE created_at >= ?
          AND status IN ('open', 'acknowledged')
          AND source_ip IS NOT NULL
        ORDER BY created_at
    """, (cutoff,)).fetchall()

    grouped_events = defaultdict(list)

    for event in events:
        grouped_events[event["source_ip"]].append(event)

    known_devices = {}

    for device in db.execute("""
        SELECT last_ip, mac, hostname, vendor
        FROM devices
        WHERE status = 'online'
    """):
        known_devices[device["last_ip"]] = {
            "mac": device["mac"],
            "hostname": device["hostname"],
            "vendor": device["vendor"],
        }

    # Include devices with events even when they are not in ARP inventory.
    device_ips = set(known_devices)
    device_ips.update(grouped_events)

    if device_filter:
        device_ips = {
            ip for ip in device_ips
            if ip == device_filter
        }

    assessed_at = utc_now()

    print("\n===== NETWATCH RISK ASSESSMENT =====")
    print(f"Lookback period: {lookback_hours} hours")
    print(f"Devices assessed: {len(device_ips)}")

    with db:
        for device_ip in sorted(device_ips):
            device_events = grouped_events.get(device_ip, [])

            score, factors = calculate_factors(
                device_events,
                config,
            )

            level = classify_risk(score, config)
            identity = known_devices.get(device_ip, {})

            payload = json.dumps(
                factors,
                sort_keys=True,
            )

            db.execute("""
                INSERT INTO risk_assessments (
                    device_ip,
                    mac,
                    hostname,
                    vendor,
                    risk_score,
                    risk_level,
                    event_count,
                    lookback_hours,
                    factors_json,
                    assessed_at
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)

                ON CONFLICT(device_ip) DO UPDATE SET
                    mac = excluded.mac,
                    hostname = excluded.hostname,
                    vendor = excluded.vendor,
                    risk_score = excluded.risk_score,
                    risk_level = excluded.risk_level,
                    event_count = excluded.event_count,
                    lookback_hours = excluded.lookback_hours,
                    factors_json = excluded.factors_json,
                    assessed_at = excluded.assessed_at
            """, (
                device_ip,
                identity.get("mac"),
                identity.get("hostname"),
                identity.get("vendor"),
                score,
                level,
                len(device_events),
                lookback_hours,
                payload,
                assessed_at,
            ))

            db.execute("""
                INSERT INTO risk_assessment_history (
                    device_ip,
                    mac,
                    hostname,
                    vendor,
                    risk_score,
                    risk_level,
                    event_count,
                    lookback_hours,
                    factors_json,
                    assessed_at
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                device_ip,
                identity.get("mac"),
                identity.get("hostname"),
                identity.get("vendor"),
                score,
                level,
                len(device_events),
                lookback_hours,
                payload,
                assessed_at,
            ))

            print(
                f"\n{device_ip:<18} "
                f"{score:>3}/100 "
                f"{level.upper()}"
            )

            if identity.get("hostname"):
                print(f"  Hostname: {identity['hostname']}")

            if identity.get("vendor"):
                print(f"  Vendor: {identity['vendor']}")

            print(f"  Active evidence events: {len(device_events)}")

            if not factors:
                print("  No active risk indicators.")
                continue

            for factor in factors:
                print(
                    f"  + {factor['awarded_points']} points: "
                    f"{factor['detection_type']} "
                    f"({factor['event_count']} event(s))"
                )

                for evidence in factor["evidence"]:
                    print(
                        f"      Event #{evidence['id']}: "
                        f"{evidence['explanation']}"
                    )

    db.close()

    print("\nRisk scores represent investigation priority,")
    print("not probability of device compromise.")


def show_risks():
    initialize()

    db = connect()
    ensure_schema(db)

    rows = db.execute("""
        SELECT *
        FROM risk_assessments
        ORDER BY risk_score DESC, assessed_at DESC
    """).fetchall()

    print("\n===== NETWATCH DEVICE RISK TABLE =====")

    if not rows:
        print("No risk assessments found. Run the risk engine first.")
        db.close()
        return

    print(
        f"{'DEVICE IP':<19} "
        f"{'SCORE':<10} "
        f"{'LEVEL':<12} "
        f"{'EVENTS':<8} "
        f"{'HOSTNAME'}"
    )

    print("-" * 85)

    for row in rows:
        print(
            f"{row['device_ip']:<19} "
            f"{row['risk_score']:<10} "
            f"{row['risk_level']:<12} "
            f"{row['event_count']:<8} "
            f"{row['hostname'] or 'Unknown'}"
        )

    db.close()


def show_device(device_ip):
    initialize()

    db = connect()
    ensure_schema(db)

    row = db.execute("""
        SELECT *
        FROM risk_assessments
        WHERE device_ip = ?
    """, (device_ip,)).fetchone()

    if row is None:
        print(f"No assessment found for {device_ip}.")
        db.close()
        return

    print("\n===== DEVICE RISK PROFILE =====")
    print(f"IP Address : {row['device_ip']}")
    print(f"MAC        : {row['mac'] or 'Unknown'}")
    print(f"Hostname   : {row['hostname'] or 'Unknown'}")
    print(f"Vendor     : {row['vendor'] or 'Unknown'}")
    print(f"Risk Score : {row['risk_score']}/100")
    print(f"Risk Level : {row['risk_level']}")
    print(f"Events     : {row['event_count']}")
    print(f"Assessed   : {row['assessed_at']}")

    print("\n===== CONTRIBUTING FACTORS =====")

    for factor in json.loads(row["factors_json"]):
        print(f"\n{factor['detection_type']}")
        print(f"Points: {factor['awarded_points']}")
        print(f"Evidence count: {factor['event_count']}")

        for evidence in factor["evidence"]:
            print(f"  - {evidence['explanation']}")

    db.close()


def show_history(device_ip, limit=20):
    initialize()

    db = connect()
    ensure_schema(db)

    rows = db.execute("""
        SELECT
            assessed_at,
            risk_score,
            risk_level,
            event_count
        FROM risk_assessment_history
        WHERE device_ip = ?
        ORDER BY assessed_at DESC
        LIMIT ?
    """, (device_ip, limit)).fetchall()

    print(f"\n===== RISK HISTORY: {device_ip} =====")

    if not rows:
        print("No assessment history.")
        db.close()
        return

    for row in rows:
        print(
            f"{row['assessed_at']} | "
            f"{row['risk_score']:>3}/100 | "
            f"{row['risk_level']:<10} | "
            f"Events: {row['event_count']}"
        )

    db.close()


def main():
    parser = argparse.ArgumentParser(
        description="NetWatch explainable contextual risk engine"
    )

    subparsers = parser.add_subparsers(
        dest="command",
        required=True,
    )

    run_parser = subparsers.add_parser(
        "run",
        help="Calculate device risk scores",
    )

    run_parser.add_argument(
        "--lookback-hours",
        type=int,
        default=24,
    )

    run_parser.add_argument(
        "--device-ip",
        help="Assess a single device",
    )

    subparsers.add_parser(
        "list",
        help="List latest risk assessments",
    )

    show_parser = subparsers.add_parser(
        "show",
        help="Show one device risk profile",
    )

    show_parser.add_argument("device_ip")

    history_parser = subparsers.add_parser(
        "history",
        help="Show assessment history",
    )

    history_parser.add_argument("device_ip")
    history_parser.add_argument("--limit", type=int, default=20)

    args = parser.parse_args()

    if args.command == "run":
        assess_risks(
            lookback_hours=args.lookback_hours,
            device_filter=args.device_ip,
        )

    elif args.command == "list":
        show_risks()

    elif args.command == "show":
        show_device(args.device_ip)

    elif args.command == "history":
        if args.limit < 1:
            parser.error("--limit must be positive.")

        show_history(args.device_ip, args.limit)


if __name__ == "__main__":
    main()
