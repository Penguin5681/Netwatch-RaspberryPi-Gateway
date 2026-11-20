import argparse
import json
import statistics

from datetime import datetime, timedelta, timezone

from agent.database import connect, initialize


METRIC_LABELS = {
    "total_bytes": "Total traffic volume",
    "tx_bytes": "Transmitted bytes",
    "rx_bytes": "Received bytes",
    "flow_count": "Connection/flow count",
    "unique_destinations": "Unique destination addresses",
    "unique_destination_ports": "Unique destination ports",
    "tcp_syn_packets": "TCP SYN packets",
    "tcp_rst_packets": "TCP RST packets",
    "protocol_count": "Distinct observed protocols",
}

BYTE_METRICS = {
    "total_bytes",
    "tx_bytes",
    "rx_bytes",
}

DEFAULT_MEDIUM_THRESHOLD = 2.5
DEFAULT_HIGH_THRESHOLD = 3.5


def utc_now():
    return (
        datetime.now(timezone.utc)
        .isoformat(timespec="seconds")
        .replace("+00:00", "Z")
    )



def parse_timestamp(value):
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


def ensure_schema(db):
    db.executescript("""
        CREATE TABLE IF NOT EXISTS device_baselines (
            interface TEXT NOT NULL,
            device_ip TEXT NOT NULL,
            metric_name TEXT NOT NULL,
            sample_count INTEGER NOT NULL,
            mean REAL NOT NULL,
            stddev REAL NOT NULL,
            minimum REAL NOT NULL,
            maximum REAL NOT NULL,
            baseline_start TEXT NOT NULL,
            baseline_end TEXT NOT NULL,
            reference_window TEXT NOT NULL,
            updated_at TEXT NOT NULL,
            PRIMARY KEY(interface, device_ip, metric_name)
        );

        CREATE TABLE IF NOT EXISTS device_baseline_status (
            interface TEXT NOT NULL,
            device_ip TEXT NOT NULL,
            metric_name TEXT NOT NULL,
            status TEXT NOT NULL,
            sample_count INTEGER NOT NULL,
            evaluated_window TEXT NOT NULL,
            updated_at TEXT NOT NULL,
            PRIMARY KEY(interface, device_ip, metric_name)
        );

        CREATE TABLE IF NOT EXISTS anomaly_events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            window_start TEXT NOT NULL,
            interface TEXT NOT NULL,
            device_ip TEXT NOT NULL,
            metric_name TEXT NOT NULL,
            observed_value REAL NOT NULL,
            baseline_mean REAL NOT NULL,
            baseline_stddev REAL NOT NULL,
            z_score REAL NOT NULL,
            severity TEXT NOT NULL,
            direction TEXT NOT NULL,
            explanation TEXT NOT NULL,
            created_at TEXT NOT NULL,
            status TEXT NOT NULL DEFAULT 'open',
            UNIQUE(window_start, interface, device_ip, metric_name)
        );

        CREATE INDEX IF NOT EXISTS idx_anomaly_device
        ON anomaly_events(device_ip);

        CREATE INDEX IF NOT EXISTS idx_anomaly_severity
        ON anomaly_events(severity);

        CREATE INDEX IF NOT EXISTS idx_anomaly_time
        ON anomaly_events(window_start);
    """)


def metric_values(row):
    protocols = json.loads(
        row["protocol_distribution"] or "{}"
    )

    tx_bytes = int(row["tx_bytes"] or 0)
    rx_bytes = int(row["rx_bytes"] or 0)

    return {
        "total_bytes": tx_bytes + rx_bytes,
        "tx_bytes": tx_bytes,
        "rx_bytes": rx_bytes,
        "flow_count": int(row["flow_count"] or 0),
        "unique_destinations": int(
            row["unique_destinations"] or 0
        ),
        "unique_destination_ports": int(
            row["unique_destination_ports"] or 0
        ),
        "tcp_syn_packets": int(
            row["tcp_syn_packets"] or 0
        ),
        "tcp_rst_packets": int(
            row["tcp_rst_packets"] or 0
        ),
        "protocol_count": len(protocols),
    }


def get_observations(db, interface):
    return db.execute("""
        SELECT
            m.window_start,
            m.interface,
            m.device_ip,
            m.flow_count,
            m.unique_destinations,
            m.unique_destination_ports,
            m.tcp_syn_packets,
            m.tcp_rst_packets,
            m.protocol_distribution,
            COALESCE(t.tx_bytes, 0) AS tx_bytes,
            COALESCE(t.rx_bytes, 0) AS rx_bytes
        FROM device_window_metrics AS m
        LEFT JOIN device_traffic AS t
            ON t.window_start = m.window_start
            AND t.interface = m.interface
            AND t.device_ip = m.device_ip
        WHERE m.interface = ?
        ORDER BY m.window_start ASC
    """, (interface,)).fetchall()


def scale_floor(metric_name, mean):
    if metric_name in BYTE_METRICS:
        return max(1024.0, abs(mean) * 0.05)

    return max(1.0, abs(mean) * 0.10)


def calculate_baseline(values):
    mean = statistics.mean(values)

    stddev = (
        statistics.stdev(values)
        if len(values) >= 2
        else 0.0
    )

    return {
        "sample_count": len(values),
        "mean": mean,
        "stddev": stddev,
        "minimum": min(values),
        "maximum": max(values),
    }


def calculate_severity(z_score, medium, high):
    magnitude = abs(z_score)

    if magnitude >= high:
        return "high"

    if magnitude >= medium:
        return "medium"

    return None


def store_baseline(
    db,
    interface,
    device_ip,
    metric_name,
    baseline,
    samples,
    reference_window,
    updated_at,
):
    db.execute("""
        INSERT INTO device_baselines (
            interface,
            device_ip,
            metric_name,
            sample_count,
            mean,
            stddev,
            minimum,
            maximum,
            baseline_start,
            baseline_end,
            reference_window,
            updated_at
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)

        ON CONFLICT(interface, device_ip, metric_name)
        DO UPDATE SET
            sample_count = excluded.sample_count,
            mean = excluded.mean,
            stddev = excluded.stddev,
            minimum = excluded.minimum,
            maximum = excluded.maximum,
            baseline_start = excluded.baseline_start,
            baseline_end = excluded.baseline_end,
            reference_window = excluded.reference_window,
            updated_at = excluded.updated_at
    """, (
        interface,
        device_ip,
        metric_name,
        baseline["sample_count"],
        baseline["mean"],
        baseline["stddev"],
        baseline["minimum"],
        baseline["maximum"],
        samples[0]["window_start"],
        samples[-1]["window_start"],
        reference_window,
        updated_at,
    ))


def store_status(
    db,
    interface,
    device_ip,
    metric_name,
    status,
    sample_count,
    evaluated_window,
    updated_at,
):
    db.execute("""
        INSERT INTO device_baseline_status (
            interface,
            device_ip,
            metric_name,
            status,
            sample_count,
            evaluated_window,
            updated_at
        )
        VALUES (?, ?, ?, ?, ?, ?, ?)

        ON CONFLICT(interface, device_ip, metric_name)
        DO UPDATE SET
            status = excluded.status,
            sample_count = excluded.sample_count,
            evaluated_window = excluded.evaluated_window,
            updated_at = excluded.updated_at
    """, (
        interface,
        device_ip,
        metric_name,
        status,
        sample_count,
        evaluated_window,
        updated_at,
    ))


def store_anomaly(
    db,
    window_start,
    interface,
    device_ip,
    metric_name,
    observed,
    baseline,
    z_score,
    severity,
    now,
):
    direction = "above" if z_score > 0 else "below"

    label = METRIC_LABELS.get(metric_name, metric_name)

    explanation = (
        f"{label} is {direction} its historical baseline. "
        f"Observed={observed:.2f}, "
        f"mean={baseline['mean']:.2f}, "
        f"stddev={baseline['stddev']:.2f}, "
        f"z_score={z_score:.2f}, "
        f"samples={baseline['sample_count']}."
    )

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
            direction,
            explanation,
            created_at
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)

        ON CONFLICT(
            window_start,
            interface,
            device_ip,
            metric_name
        )
        DO UPDATE SET
            observed_value = excluded.observed_value,
            baseline_mean = excluded.baseline_mean,
            baseline_stddev = excluded.baseline_stddev,
            z_score = excluded.z_score,
            severity = excluded.severity,
            direction = excluded.direction,
            explanation = excluded.explanation
    """, (
        window_start,
        interface,
        device_ip,
        metric_name,
        observed,
        baseline["mean"],
        baseline["stddev"],
        z_score,
        severity,
        direction,
        explanation,
        now,
    ))

    return explanation


def run_baseline(
    interface="wlan0",
    minimum_samples=10,
    history_limit=30,
    medium_threshold=DEFAULT_MEDIUM_THRESHOLD,
    high_threshold=DEFAULT_HIGH_THRESHOLD,
    device_filter=None,
    bucket_seconds=60,
):
    initialize()

    db = connect()
    ensure_schema(db)

    observations = get_observations(db, interface)

    if not observations:
        print("[NETWATCH] No device-window metrics available.")
        db.close()
        return

    # Only use buckets whose complete duration has elapsed.
    now_dt = datetime.now(timezone.utc)

    eligible_observations = [
        row for row in observations
        if parse_timestamp(row["window_start"])
        + timedelta(seconds=bucket_seconds) <= now_dt
    ]

    if not eligible_observations:
        print("[NETWATCH] No completed time windows available.")
        db.close()
        return

    latest_window = max(
        row["window_start"] for row in eligible_observations
    )

    target_rows = [
        row for row in eligible_observations
        if row["window_start"] == latest_window
    ]

    grouped = {}

    for row in eligible_observations:
        grouped.setdefault(row["device_ip"], []).append(row)

    now = utc_now()
    evaluated = 0
    established = 0
    anomaly_count = 0

    print("\n===== NETWATCH BEHAVIOURAL BASELINES =====")
    print(f"Interface          : {interface}")
    print(f"Evaluation window  : {latest_window}")
    print(f"Minimum samples    : {minimum_samples}")
    print(f"History limit      : {history_limit}")\n    print(f"Bucket duration    : {bucket_seconds}s")

    with db:
        for current_row in target_rows:
            device_ip = current_row["device_ip"]

            if device_filter and device_ip != device_filter:
                continue

            evaluated += 1
            current_values = metric_values(current_row)

            historical_rows = [
                row
                for row in grouped.get(device_ip, [])
                if row["window_start"] < latest_window
            ][-history_limit:]

            print(f"\nDEVICE: {device_ip}")

            for metric_name, observed in current_values.items():
                samples = [
                    metric_values(row)[metric_name]
                    for row in historical_rows
                ]

                sample_count = len(samples)

                if sample_count < minimum_samples:
                    store_status(
                        db,
                        interface,
                        device_ip,
                        metric_name,
                        "insufficient_history",
                        sample_count,
                        latest_window,
                        now,
                    )

                    print(
                        f"  {metric_name:<28} "
                        f"INSUFFICIENT HISTORY "
                        f"({sample_count}/{minimum_samples})"
                    )
                    continue

                baseline = calculate_baseline(samples)

                store_baseline(
                    db,
                    interface,
                    device_ip,
                    metric_name,
                    baseline,
                    historical_rows,
                    latest_window,
                    now,
                )

                store_status(
                    db,
                    interface,
                    device_ip,
                    metric_name,
                    "established",
                    sample_count,
                    latest_window,
                    now,
                )

                established += 1

                floor = scale_floor(
                    metric_name,
                    baseline["mean"],
                )

                denominator = max(
                    baseline["stddev"],
                    floor,
                )

                z_score = (
                    observed - baseline["mean"]
                ) / denominator

                severity = calculate_severity(
                    z_score,
                    medium_threshold,
                    high_threshold,
                )

                print(
                    f"  {metric_name:<28} "
                    f"observed={observed:<12.2f} "
                    f"mean={baseline['mean']:<12.2f} "
                    f"z={z_score:>7.2f}"
                )

                if severity:
                    explanation = store_anomaly(
                        db,
                        latest_window,
                        interface,
                        device_ip,
                        metric_name,
                        observed,
                        baseline,
                        z_score,
                        severity,
                        now,
                    )

                    anomaly_count += 1

                    print(
                        f"    [{severity.upper()}] "
                        f"{explanation}"
                    )

    db.close()

    print("\n===== BASELINE SUMMARY =====")
    print(f"Devices evaluated       : {evaluated}")
    print(f"Established metric models: {established}")
    print(f"Anomaly observations    : {anomaly_count}")


def show_baselines(device_ip=None):
    with connect() as db:
        query = """
            SELECT *
            FROM device_baselines
        """
        params = ()

        if device_ip:
            query += " WHERE device_ip = ?"
            params = (device_ip,)

        query += " ORDER BY device_ip, metric_name"

        rows = db.execute(query, params).fetchall()

    print("\n===== STORED DEVICE BASELINES =====")

    if not rows:
        print("No established baselines yet.")
        return

    for row in rows:
        print(
            f"{row['device_ip']:<18} "
            f"{row['metric_name']:<28} "
            f"samples={row['sample_count']:<3} "
            f"mean={row['mean']:.2f} "
            f"stddev={row['stddev']:.2f}"
        )


def show_anomalies(limit=30):
    with connect() as db:
        rows = db.execute("""
            SELECT *
            FROM anomaly_events
            ORDER BY window_start DESC, id DESC
            LIMIT ?
        """, (limit,)).fetchall()

    print("\n===== NETWATCH ANOMALY EVENTS =====")

    if not rows:
        print("No anomaly events recorded.")
        return

    for row in rows:
        print("\n----------------------------------------")
        print(f"Device   : {row['device_ip']}")
        print(f"Metric   : {row['metric_name']}")
        print(f"Severity : {row['severity']}")
        print(f"Z-score  : {row['z_score']:.2f}")
        print(f"Window   : {row['window_start']}")
        print(f"Status   : {row['status']}")
        print(f"Reason   : {row['explanation']}")


def main():
    parser = argparse.ArgumentParser(
        description="NetWatch behavioural baseline engine"
    )

    subparsers = parser.add_subparsers(
        dest="command",
        required=True,
    )

    run_parser = subparsers.add_parser(
        "run",
        help="Evaluate latest completed traffic window",
    )

    run_parser.add_argument("--interface", default="wlan0")
    run_parser.add_argument("--min-samples", type=int, default=10)
    run_parser.add_argument("--history", type=int, default=30)\n    run_parser.add_argument("--bucket-seconds", type=int, default=60)
    run_parser.add_argument(
        "--medium-threshold",
        type=float,
        default=DEFAULT_MEDIUM_THRESHOLD,
    )
    run_parser.add_argument(
        "--high-threshold",
        type=float,
        default=DEFAULT_HIGH_THRESHOLD,
    )
    run_parser.add_argument("--device-ip")

    baseline_parser = subparsers.add_parser(
        "show",
        help="Show stored baselines",
    )
    baseline_parser.add_argument("--device-ip")

    anomaly_parser = subparsers.add_parser(
        "anomalies",
        help="Show recorded anomaly events",
    )
    anomaly_parser.add_argument("--limit", type=int, default=30)

    args = parser.parse_args()

    if args.command == "run":
        if args.min_samples < 2 or args.history < args.min_samples:
            parser.error(
                "--history must be greater than or equal to "
                "--min-samples, and --min-samples must be at least 2."
            )

        if args.bucket_seconds < 1:\n            parser.error("--bucket-seconds must be positive.")\n\n        if args.medium_threshold <= 0:
            parser.error("--medium-threshold must be positive.")

        if args.high_threshold <= args.medium_threshold:
            parser.error(
                "--high-threshold must exceed --medium-threshold."
            )

        run_baseline(
            interface=args.interface,
            minimum_samples=args.min_samples,
            history_limit=args.history,
            medium_threshold=args.medium_threshold,
            high_threshold=args.high_threshold,
            device_filter=args.device_ip,
        )

    elif args.command == "show":
        initialize()
        show_baselines(args.device_ip)

    elif args.command == "anomalies":
        if args.limit < 1:
            parser.error("--limit must be positive.")

        initialize()
        show_anomalies(args.limit)


if __name__ == "__main__":
    main()
