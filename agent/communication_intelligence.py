import argparse
import ipaddress
from collections import Counter, defaultdict
from datetime import datetime, timedelta, timezone

from agent.database import connect, initialize
from agent.interfaces import get_interface_network


def get_network(interface):
    info = get_interface_network(interface)
    return ipaddress.ip_network(info["network"], strict=False)


def is_local(address, network):
    try:
        parsed = ipaddress.ip_address(address)
        return parsed.version == network.version and parsed in network
    except (ValueError, TypeError):
        return False


def make_cutoff(hours):
    return (
        datetime.now(timezone.utc) - timedelta(hours=hours)
    ).isoformat(timespec="seconds").replace("+00:00", "Z")


def get_flow_cursor(db, interface, cutoff=None):
    columns = """
        SELECT
            window_start,
            first_seen,
            protocol,
            endpoint_a_ip,
            endpoint_a_port,
            endpoint_b_ip,
            endpoint_b_port,
            packets,
            bytes,
            a_to_b_packets,
            b_to_a_packets,
            a_to_b_bytes,
            b_to_a_bytes
        FROM flow_summaries
        WHERE interface = ?
    """

    params = [interface]

    if cutoff is not None:
        columns += " AND julianday(window_start) >= julianday(?)"
        params.append(cutoff)

    columns += " ORDER BY first_seen"

    return db.execute(columns, params)


def validate_device_ip(device_ip, network):
    try:
        address = ipaddress.ip_address(device_ip)
    except ValueError as error:
        raise ValueError(f"Invalid IP address: {device_ip}") from error

    if address.version != network.version or address not in network:
        raise ValueError(
            f"{device_ip} is outside the monitored subnet {network}."
        )


def get_device_flows(db, interface, device_ip, cutoff):
    cursor = get_flow_cursor(db, interface, cutoff)

    for row in cursor:
        if (
            row["endpoint_a_ip"] == device_ip
            or row["endpoint_b_ip"] == device_ip
        ):
            yield row


def aggregate_device_communication(rows, device_ip):
    peers = defaultdict(lambda: {
        "flows": 0,
        "packets": 0,
        "tx_bytes": 0,
        "rx_bytes": 0,
    })

    protocols = Counter()
    ports = Counter()
    total_flows = 0
    total_packets = 0
    total_tx_bytes = 0
    total_rx_bytes = 0
    destinations = set()

    for row in rows:
        a_ip = row["endpoint_a_ip"]
        b_ip = row["endpoint_b_ip"]

        if a_ip == device_ip:
            peer_ip = b_ip
            peer_port = row["endpoint_b_port"]
            tx_bytes = row["a_to_b_bytes"]
            rx_bytes = row["b_to_a_bytes"]
            tx_packets = row["a_to_b_packets"]
            rx_packets = row["b_to_a_packets"]

        elif b_ip == device_ip:
            peer_ip = a_ip
            peer_port = row["endpoint_a_port"]
            tx_bytes = row["b_to_a_bytes"]
            rx_bytes = row["a_to_b_bytes"]
            tx_packets = row["b_to_a_packets"]
            rx_packets = row["a_to_b_packets"]

        else:
            continue

        protocol = row["protocol"]
        key = (peer_ip, protocol, peer_port)

        item = peers[key]
        item["flows"] += 1
        item["packets"] += row["packets"]
        item["tx_bytes"] += tx_bytes
        item["rx_bytes"] += rx_bytes

        total_flows += 1
        total_packets += row["packets"]
        total_tx_bytes += tx_bytes
        total_rx_bytes += rx_bytes

        protocols[protocol] += 1
        if peer_port is not None:
            ports[peer_port] += 1

        destinations.add(peer_ip)

    return {
        "peers": peers,
        "protocols": protocols,
        "ports": ports,
        "flows": total_flows,
        "packets": total_packets,
        "tx_bytes": total_tx_bytes,
        "rx_bytes": total_rx_bytes,
        "destinations": destinations,
    }


def print_peers(peers, limit):
    print("\n===== COMMUNICATION PEERS =====")

    ordered = sorted(
        peers.items(),
        key=lambda item: (
            item[1]["tx_bytes"] + item[1]["rx_bytes"]
        ),
        reverse=True,
    )

    if not ordered:
        print("No peer communication recorded.")
        return

    print(
        f"{'PEER IP':<18} {'PROTO':<8} {'PEER PORT':>10} "
        f"{'FLOWS':>7} {'TX BYTES':>12} {'RX BYTES':>12}"
    )
    print("-" * 85)

    for (peer_ip, protocol, peer_port), item in ordered[:limit]:
        print(
            f"{peer_ip:<18} "
            f"{protocol:<8} "
            f"{str(peer_port or '-'):>10} "
            f"{item['flows']:>7} "
            f"{item['tx_bytes']:>12} "
            f"{item['rx_bytes']:>12}"
        )


def show_device(device_ip, interface, since_hours, limit):
    network = get_network(interface)
    validate_device_ip(device_ip, network)
    cutoff = make_cutoff(since_hours)

    db = connect()

    try:
        rows = get_device_flows(
            db, interface, device_ip, cutoff
        )
        profile = aggregate_device_communication(rows, device_ip)
    finally:
        db.close()

    print(f"\n===== COMMUNICATION PROFILE: {device_ip} =====")
    print(f"Interface          : {interface}")
    print(f"Monitored subnet   : {network}")
    print(f"Lookback           : {since_hours:g} hours")
    print(f"Flows observed     : {profile['flows']}")
    print(f"Packets observed   : {profile['packets']}")
    print(f"Unique peers       : {len(profile['destinations'])}")
    print(f"Transmitted bytes  : {profile['tx_bytes']}")
    print(f"Received bytes     : {profile['rx_bytes']}")

    print("\nProtocol distribution:")
    if profile["protocols"]:
        for protocol, count in profile["protocols"].most_common():
            print(f"  {protocol:<10} {count}")
    else:
        print("  No protocol data.")

    print("\nMost contacted peer ports:")
    if profile["ports"]:
        for port, count in profile["ports"].most_common(10):
            print(f"  {port:<10} {count} flow records")
    else:
        print("  No peer port data.")

    print_peers(profile["peers"], limit)


def show_peers(device_ip, interface, since_hours, limit):
    network = get_network(interface)
    validate_device_ip(device_ip, network)
    cutoff = make_cutoff(since_hours)

    db = connect()
    try:
        rows = get_device_flows(
            db, interface, device_ip, cutoff
        )
        profile = aggregate_device_communication(rows, device_ip)
    finally:
        db.close()

    print(f"\nDevice: {device_ip}")
    print(f"Interface: {interface}")
    print(f"Lookback: {since_hours:g} hours")
    print_peers(profile["peers"], limit)


def show_top(interface, since_hours, limit):
    network = get_network(interface)
    cutoff = make_cutoff(since_hours)

    devices = defaultdict(lambda: {
        "flows": 0,
        "packets": 0,
        "tx_bytes": 0,
        "rx_bytes": 0,
        "peers": set(),
    })

    db = connect()
    try:
        for row in get_flow_cursor(db, interface, cutoff):
            a_ip = row["endpoint_a_ip"]
            b_ip = row["endpoint_b_ip"]

            a_local = is_local(a_ip, network)
            b_local = is_local(b_ip, network)

            if a_local:
                item = devices[a_ip]
                item["flows"] += 1
                item["packets"] += row["packets"]
                item["tx_bytes"] += row["a_to_b_bytes"]
                item["rx_bytes"] += row["b_to_a_bytes"]
                item["peers"].add(b_ip)

            if b_local:
                item = devices[b_ip]
                item["flows"] += 1
                item["packets"] += row["packets"]
                item["tx_bytes"] += row["b_to_a_bytes"]
                item["rx_bytes"] += row["a_to_b_bytes"]
                item["peers"].add(a_ip)
    finally:
        db.close()

    print(f"\n===== MOST ACTIVE DEVICES: {interface} =====")
    print(f"Subnet: {network}")
    print(f"Lookback: {since_hours:g} hours")

    ordered = sorted(
        devices.items(),
        key=lambda item: (
            item[1]["tx_bytes"] + item[1]["rx_bytes"]
        ),
        reverse=True,
    )

    if not ordered:
        print("No local device communication recorded.")
        return

    print(
        f"{'DEVICE IP':<18} {'FLOWS':>8} {'PEERS':>8} "
        f"{'TX BYTES':>13} {'RX BYTES':>13}"
    )
    print("-" * 68)

    for device_ip, item in ordered[:limit]:
        print(
            f"{device_ip:<18} "
            f"{item['flows']:>8} "
            f"{len(item['peers']):>8} "
            f"{item['tx_bytes']:>13} "
            f"{item['rx_bytes']:>13}"
        )


def show_new_destinations(interface, since_hours, limit):
    network = get_network(interface)
    cutoff = make_cutoff(since_hours)

    first_seen = {}

    db = connect()
    try:
        # Read retained interface history so an older contact is not
        # incorrectly reported as new merely because it is outside
        # the requested reporting window.
        for row in get_flow_cursor(db, interface):
            a_ip = row["endpoint_a_ip"]
            b_ip = row["endpoint_b_ip"]

            a_local = is_local(a_ip, network)
            b_local = is_local(b_ip, network)

            if a_local == b_local:
                continue

            device_ip = a_ip if a_local else b_ip
            destination_ip = b_ip if a_local else a_ip

            key = (device_ip, destination_ip)
            item = first_seen.setdefault(key, {
                "first_seen": row["first_seen"],
                "protocols": set(),
                "ports": set(),
            })

            if row["first_seen"] < item["first_seen"]:
                item["first_seen"] = row["first_seen"]

            item["protocols"].add(row["protocol"])

            destination_port = (
                row["endpoint_b_port"]
                if a_local
                else row["endpoint_a_port"]
            )

            if destination_port is not None:
                item["ports"].add(destination_port)
    finally:
        db.close()

    cutoff_dt = datetime.fromisoformat(cutoff.replace("Z", "+00:00"))

    recent = []
    for (device_ip, destination_ip), item in first_seen.items():
        observed = datetime.fromisoformat(
            item["first_seen"].replace("Z", "+00:00")
        )
        if observed >= cutoff_dt:
            recent.append((
                device_ip,
                destination_ip,
                item,
            ))

    recent.sort(
        key=lambda value: value[2]["first_seen"],
        reverse=True,
    )

    print(f"\n===== NEWLY OBSERVED DESTINATIONS: {interface} =====")
    print(f"Subnet: {network}")
    print(f"Lookback: {since_hours:g} hours")
    print("New means first observed in retained flow history.")

    if not recent:
        print("No newly observed external destinations.")
        return

    print(
        f"{'DEVICE IP':<16} {'DESTINATION':<18} "
        f"{'FIRST OBSERVED':<22} {'PROTOCOLS':<15} PORTS"
    )
    print("-" * 100)

    for device_ip, destination_ip, item in recent[:limit]:
        protocols = ",".join(sorted(item["protocols"]))
        ports = ",".join(
            str(port) for port in sorted(item["ports"])
        ) or "-"

        print(
            f"{device_ip:<16} "
            f"{destination_ip:<18} "
            f"{item['first_seen']:<22} "
            f"{protocols:<15} "
            f"{ports}"
        )


def main():
    initialize()

    parser = argparse.ArgumentParser(
        description="NetWatch communication intelligence"
    )

    subparsers = parser.add_subparsers(
        dest="command",
        required=True,
    )

    def add_common_options(command_parser):
        command_parser.add_argument(
            "--interface",
            default="wlan1",
        )
        command_parser.add_argument(
            "--since-hours",
            type=float,
            default=24,
        )
        command_parser.add_argument(
            "--limit",
            type=int,
            default=20,
        )

    show = subparsers.add_parser(
        "show",
        help="Show a device communication profile",
    )
    show.add_argument("device_ip")
    add_common_options(show)

    peers = subparsers.add_parser(
        "peers",
        help="Show peers contacted by a device",
    )
    peers.add_argument("device_ip")
    add_common_options(peers)

    top = subparsers.add_parser(
        "top",
        help="Rank devices by observed traffic",
    )
    add_common_options(top)

    new = subparsers.add_parser(
        "new",
        help="Show destinations first seen in the lookback period",
    )
    add_common_options(new)

    args = parser.parse_args()

    if args.since_hours <= 0:
        parser.error("--since-hours must be positive.")

    if args.limit < 1:
        parser.error("--limit must be positive.")

    try:
        if args.command == "show":
            show_device(
                args.device_ip,
                args.interface,
                args.since_hours,
                args.limit,
            )

        elif args.command == "peers":
            show_peers(
                args.device_ip,
                args.interface,
                args.since_hours,
                args.limit,
            )

        elif args.command == "top":
            show_top(
                args.interface,
                args.since_hours,
                args.limit,
            )

        elif args.command == "new":
            show_new_destinations(
                args.interface,
                args.since_hours,
                args.limit,
            )

    except (ValueError, OSError) as error:
        parser.error(str(error))


if __name__ == "__main__":
    main()
