import argparse
from agent.database import connect, initialize


def list_devices():
    with connect() as db:
        rows = db.execute("""
            SELECT
                last_ip, mac, hostname, vendor,
                mac_type, status, trust_status,
                first_seen, last_seen
            FROM devices
            ORDER BY last_seen DESC
        """).fetchall()

    print("\n===== NETWATCH DEVICE INVENTORY =====")

    if not rows:
        print("No devices found.")
        return

    print(
        f"{'IP':<18} {'MAC':<20} {'STATUS':<9} "
        f"{'TRUST':<12} {'VENDOR'}"
    )
    print("-" * 95)

    for row in rows:
        print(
            f"{row['last_ip']:<18} "
            f"{row['mac']:<20} "
            f"{row['status']:<9} "
            f"{row['trust_status']:<12} "
            f"{row['vendor'] or 'Unknown'}"
        )

    print(f"\nTotal devices: {len(rows)}")


def find_device(identifier):
    with connect() as db:
        return db.execute("""
            SELECT *
            FROM devices
            WHERE lower(mac) = lower(?)
               OR last_ip = ?
            LIMIT 1
        """, (identifier, identifier)).fetchone()


def show_device(identifier):
    device = find_device(identifier)

    if device is None:
        print(f"Device not found: {identifier}")
        return

    print("\n===== DEVICE PROFILE =====")

    fields = [
        ("MAC Address", "mac"),
        ("Current IP", "last_ip"),
        ("Hostname", "hostname"),
        ("Manufacturer", "vendor"),
        ("MAC Classification", "mac_type"),
        ("Online Status", "status"),
        ("Trust Status", "trust_status"),
        ("First Seen", "first_seen"),
        ("Last Seen", "last_seen"),
        ("Last Interface", "last_interface"),
        ("Hostname Source", "hostname_source"),
        ("Vendor Source", "vendor_source"),
        ("Last Scan ID", "last_scan_id"),
    ]

    for label, key in fields:
        print(f"{label:<22}: {device[key] or 'Unknown'}")

    with connect() as db:
        history = db.execute("""
            SELECT
                ip_address,
                first_seen,
                last_seen,
                last_interface,
                observations
            FROM device_ip_history
            WHERE mac = ?
            ORDER BY last_seen DESC
        """, (device["mac"],)).fetchall()

    print("\n===== IP ADDRESS HISTORY =====")

    for entry in history:
        print(
            f"{entry['ip_address']:<18} "
            f"First: {entry['first_seen']} "
            f"Last: {entry['last_seen']} "
            f"Observations: {entry['observations']}"
        )

    with connect() as db:
        observations = db.execute("""
            SELECT COUNT(*)
            FROM device_observations
            WHERE mac = ?
        """, (device["mac"],)).fetchone()[0]

    print(f"\nTotal recorded observations: {observations}")


def set_trust(identifier, status):
    device = find_device(identifier)

    if device is None:
        print(f"Device not found: {identifier}")
        return

    with connect() as db:
        db.execute("""
            UPDATE devices
            SET trust_status = ?
            WHERE mac = ?
        """, (status, device["mac"]))

    print(
        f"Updated {device['mac']}: "
        f"trust status = {status}"
    )


def show_scans():
    with connect() as db:
        scans = db.execute("""
            SELECT *
            FROM scan_runs
            ORDER BY id DESC
            LIMIT 20
        """).fetchall()

    print("\n===== DISCOVERY SCAN HISTORY =====")

    for scan in scans:
        print(
            f"ID: {scan['id']} | "
            f"Interface: {scan['interface']} | "
            f"Subnet: {scan['subnet']} | "
            f"Devices: {scan['discovered_count']} | "
            f"Status: {scan['status']} | "
            f"Started: {scan['started_at']}"
        )


def main():
    initialize()

    parser = argparse.ArgumentParser(
        description="NetWatch Device Intelligence CLI"
    )

    subparsers = parser.add_subparsers(
        dest="command",
        required=True,
    )

    subparsers.add_parser("list", help="List all known devices")

    show_parser = subparsers.add_parser(
        "show",
        help="Inspect a device by IP or MAC",
    )
    show_parser.add_argument("identifier")

    trust_parser = subparsers.add_parser(
        "trust",
        help="Change a device's trust classification",
    )
    trust_parser.add_argument("identifier")
    trust_parser.add_argument(
        "status",
        choices=["trusted", "untrusted", "unknown"],
    )

    subparsers.add_parser(
        "scans",
        help="Show discovery scan history",
    )

    args = parser.parse_args()

    if args.command == "list":
        list_devices()

    elif args.command == "show":
        show_device(args.identifier)

    elif args.command == "trust":
        set_trust(args.identifier, args.status)

    elif args.command == "scans":
        show_scans()


if __name__ == "__main__":
    main()
