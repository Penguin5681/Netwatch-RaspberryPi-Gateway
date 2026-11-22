import argparse
import json

from agent.database import connect, initialize


def show_device(ip, limit, interface="wlan1"):
    with connect() as db:
        rows = db.execute("""
            SELECT
                window_start,
                interface,
                flow_count,
                unique_destinations,
                unique_destination_ports,
                tcp_syn_packets,
                tcp_rst_packets,
                protocol_distribution
            FROM device_window_metrics
            WHERE device_ip = ?
              AND interface = ?
            ORDER BY window_start DESC
            LIMIT ?
        """, (ip, interface, limit)).fetchall()

        totals = db.execute("""
            SELECT
                SUM(tx_packets) AS tx_packets,
                SUM(rx_packets) AS rx_packets,
                SUM(tx_bytes) AS tx_bytes,
                SUM(rx_bytes) AS rx_bytes
            FROM device_traffic
            WHERE device_ip = ?
              AND interface = ?
        """, (ip, interface)).fetchone()

    print(f"\n===== TRAFFIC PROFILE: {ip} =====")
    print(f"Interface: {interface}")

    if not rows:
        print(f"No traffic metrics recorded for {ip} on {interface}.")
        print("Capture traffic and run the flow engine first.")
        return

    print("\nCumulative retained observations:")
    print(f"TX packets: {totals['tx_packets'] or 0}")
    print(f"RX packets: {totals['rx_packets'] or 0}")
    print(f"TX bytes  : {totals['tx_bytes'] or 0}")
    print(f"RX bytes  : {totals['rx_bytes'] or 0}")

    print("\nRecent time windows:")

    for row in rows:
        print(f"\nWindow: {row['window_start']}")
        print(f"Flows: {row['flow_count']}")
        print(f"Unique destinations: {row['unique_destinations']}")
        print(f"Unique destination ports: {row['unique_destination_ports']}")
        print(f"TCP SYN packets: {row['tcp_syn_packets']}")
        print(f"TCP RST packets: {row['tcp_rst_packets']}")

        try:
            protocols = json.loads(row["protocol_distribution"])
        except (TypeError, json.JSONDecodeError):
            protocols = {}

        print(f"Outgoing protocol distribution: {protocols}")


def top_devices(limit, interface="wlan1"):
    with connect() as db:
        rows = db.execute("""
            SELECT
                device_ip,
                SUM(tx_packets) AS tx_packets,
                SUM(rx_packets) AS rx_packets,
                SUM(tx_bytes) AS tx_bytes,
                SUM(rx_bytes) AS rx_bytes
            FROM device_traffic
            WHERE interface = ?
            GROUP BY device_ip
            ORDER BY SUM(tx_bytes + rx_bytes) DESC
            LIMIT ?
        """, (interface, limit)).fetchall()

    print(
        f"\n===== TOP LOCAL IP ADDRESSES BY OBSERVED TRAFFIC "
        f"({interface}) ====="
    )

    if not rows:
        print("No device traffic summaries available.")
        return

    for row in rows:
        print(
            f"{row['device_ip']:<18} "
            f"TX {row['tx_bytes'] or 0:>10} bytes "
            f"RX {row['rx_bytes'] or 0:>10} bytes "
            f"Packets {row['tx_packets'] or 0}/{row['rx_packets'] or 0}"
        )


def main():
    initialize()

    parser = argparse.ArgumentParser(
        description="NetWatch device traffic profiles"
    )

    subparsers = parser.add_subparsers(
        dest="command",
        required=True,
    )

    profile = subparsers.add_parser(
        "show",
        help="Show traffic profile for a local IP",
    )
    profile.add_argument("ip")
    profile.add_argument("--limit", type=int, default=20)
    profile.add_argument("--interface", default="wlan1")

    top = subparsers.add_parser(
        "top",
        help="Show top local IP addresses",
    )
    top.add_argument("--limit", type=int, default=15)
    top.add_argument("--interface", default="wlan1")

    args = parser.parse_args()

    if args.command == "show":
        if args.limit < 1:
            parser.error("--limit must be positive.")

        show_device(args.ip, args.limit, args.interface)

    elif args.command == "top":
        if args.limit < 1:
            parser.error("--limit must be positive.")

        top_devices(args.limit, args.interface)


if __name__ == "__main__":
    main()
