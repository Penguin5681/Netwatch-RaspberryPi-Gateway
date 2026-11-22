import argparse
import ipaddress
import json
import re
import sqlite3
from collections import Counter, defaultdict
from datetime import datetime, timedelta, timezone

from agent.database import connect, initialize
from agent.flow_engine import ensure_schema as ensure_flow_schema
from agent.interfaces import get_interface_network


CONFIDENCE_THRESHOLD = 0.65
MINIMUM_MARGIN = 0.15

# Hostnames are stronger than vendor names, but remain fallible:
# hostnames can be user-configured and are not authenticated.
HOSTNAME_RULES = {
    "smartphone": (
        "iphone", "android", "pixel", "galaxy", "redmi",
        "realme", "poco", "oneplus", "oppo", "vivo",
        "moto", "xperia", "honor",
    ),
    "computer": (
        "desktop", "laptop", "macbook", "imac", "thinkpad",
        "ideapad", "latitude", "precision", "workstation",
        "surface pro", "vivobook", "zenbook",
    ),
    "network_infrastructure": (
        "router", "gateway", "access point", "accesspoint",
        "switch", "firewall", "mesh", "unifi", "mikrotik",
        "omada", "deco",
    ),
    "printer": (
        "printer", "printing", "print server", "laserjet",
        "deskjet", "pixma", "ecotank", "workforce", "mfp",
    ),
    "server": (
        "server", "nas", "synology", "qnap", "truenas",
        "freenas", "proxmox", "pve",
    ),
    "iot": (
        "esp32", "esp8266", "espressif", "arduino",
        "sensor", "smart bulb", "smart plug", "smartplug",
        "tasmota", "shelly", "tuya",
    ),
    "media_device": (
        "chromecast", "roku", "fire tv", "apple tv",
        "android tv", "smart tv", "shield", "xbox",
        "playstation", "ps4", "ps5", "sonos",
        "soundbar", "speaker", "receiver",
    ),
}

# Vendor attribution is intentionally weaker. Manufacturers such as
# Apple, Samsung, HP, and Sony produce multiple device categories.
VENDOR_RULES = {
    "smartphone": {
        "apple": 0.20,
        "samsung": 0.25,
        "xiaomi": 0.25,
        "oppo": 0.25,
        "vivo": 0.25,
        "oneplus": 0.25,
        "google": 0.20,
        "motorola": 0.25,
        "huawei": 0.25,
        "realme": 0.25,
    },
    "computer": {
        "dell": 0.22,
        "lenovo": 0.22,
        "hewlett packard": 0.22,
        "acer": 0.22,
        "asus": 0.22,
        "intel": 0.15,
        "microsoft": 0.20,
        "apple": 0.20,
    },
    "network_infrastructure": {
        "cisco": 0.38,
        "mikrotik": 0.38,
        "ubiquiti": 0.38,
        "tp link": 0.38,
        "netgear": 0.35,
        "juniper": 0.38,
        "aruba": 0.35,
        "zyxel": 0.35,
    },
    "printer": {
        "brother": 0.32,
        "epson": 0.32,
        "canon": 0.25,
        "lexmark": 0.32,
        "ricoh": 0.32,
        "xerox": 0.32,
        "kyocera": 0.32,
    },
    "server": {
        "synology": 0.52,
        "qnap": 0.52,
        "supermicro": 0.45,
    },
    "iot": {
        "espressif": 0.52,
    },
    "media_device": {
        "roku": 0.48,
        "sonos": 0.48,
        "nvidia": 0.20,
    },
}

HOSTNAME_WEIGHT = 0.78


def utc_now():
    return (
        datetime.now(timezone.utc)
        .isoformat(timespec="seconds")
        .replace("+00:00", "Z")
    )


def normalize(value):
    return re.sub(
        r"[^a-z0-9]+",
        " ",
        str(value or "").casefold(),
    ).strip()


def contains_term(value, term):
    normalized_value = f" {normalize(value)} "
    normalized_term = f" {normalize(term)} "

    return bool(normalize(term)) and normalized_term in normalized_value


def combine_evidence(items):
    # Each source contributes at most once to a category.
    remaining = 1.0

    for item in items:
        remaining *= 1.0 - item["weight"]

    return round(1.0 - remaining, 4)


def classify_identity(hostname=None, vendor=None, mac_type=None):
    evidence_by_category = defaultdict(list)

    normalized_hostname = normalize(hostname)
    normalized_vendor = normalize(vendor)

    for category, terms in HOSTNAME_RULES.items():
        matched = [
            term for term in terms
            if contains_term(normalized_hostname, term)
        ]

        if matched:
            # Keep the most specific matching hostname signal.
            term = max(matched, key=len)
            evidence_by_category[category].append({
                "source": "hostname",
                "signal": "hostname_keyword",
                "value": term,
                "weight": HOSTNAME_WEIGHT,
            })

    for category, rules in VENDOR_RULES.items():
        matched = [
            (term, weight)
            for term, weight in rules.items()
            if contains_term(normalized_vendor, term)
        ]

        if matched:
            term, weight = max(
                matched,
                key=lambda item: item[1],
            )
            evidence_by_category[category].append({
                "source": "manufacturer",
                "signal": "manufacturer_match",
                "value": term,
                "weight": weight,
            })

    scores = {
        category: combine_evidence(items)
        for category, items in evidence_by_category.items()
    }

    ordered = sorted(
        scores.items(),
        key=lambda item: item[1],
        reverse=True,
    )

    if not ordered:
        return {
            "category": "unknown",
            "candidate_category": None,
            "confidence": 0.0,
            "evidence": [],
            "candidates": [],
            "explanation": (
                "No sufficiently informative identity evidence "
                "was available."
            ),
        }

    best_category, best_score = ordered[0]
    second_score = ordered[1][1] if len(ordered) > 1 else 0.0
    margin = best_score - second_score

    accepted = (
        best_score >= CONFIDENCE_THRESHOLD
        and margin >= MINIMUM_MARGIN
    )

    category = best_category if accepted else "unknown"

    if accepted:
        explanation = (
            f"Classified as {best_category} using "
            f"{len(evidence_by_category[best_category])} "
            f"independent identity signal(s)."
        )
    elif best_score < CONFIDENCE_THRESHOLD:
        explanation = (
            f"Best candidate is {best_category}, but confidence "
            f"{best_score:.2f} is below the "
            f"{CONFIDENCE_THRESHOLD:.2f} threshold."
        )
    else:
        explanation = (
            f"Classification is ambiguous: the leading candidates "
            f"are separated by only {margin:.2f}."
        )

    candidates = [
        {
            "category": candidate,
            "confidence": score,
        }
        for candidate, score in ordered
    ]

    return {
        "category": category,
        "candidate_category": best_category,
        "confidence": best_score,
        "evidence": evidence_by_category[best_category],
        "candidates": candidates,
        "explanation": explanation,
    }


def ensure_schema(db):
    db.executescript("""
        CREATE TABLE IF NOT EXISTS device_classifications (
            interface TEXT NOT NULL,
            mac TEXT NOT NULL,
            device_ip TEXT NOT NULL,
            category TEXT NOT NULL,
            candidate_category TEXT,
            confidence REAL NOT NULL,
            evidence_json TEXT NOT NULL,
            candidates_json TEXT NOT NULL,
            flow_context_json TEXT NOT NULL,
            explanation TEXT NOT NULL,
            classified_at TEXT NOT NULL,
            PRIMARY KEY(interface, mac)
        );

        CREATE TABLE IF NOT EXISTS device_classification_history (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            interface TEXT NOT NULL,
            mac TEXT NOT NULL,
            device_ip TEXT NOT NULL,
            category TEXT NOT NULL,
            candidate_category TEXT,
            confidence REAL NOT NULL,
            evidence_json TEXT NOT NULL,
            explanation TEXT NOT NULL,
            classified_at TEXT NOT NULL
        );

        CREATE INDEX IF NOT EXISTS idx_device_classification_category
        ON device_classifications(interface, category);

        CREATE INDEX IF NOT EXISTS idx_device_classification_history
        ON device_classification_history(interface, mac, classified_at);
    """)


def get_interface_subnet(interface):
    info = get_interface_network(interface)
    network = ipaddress.ip_network(
        info["network"],
        strict=False,
    )
    return info, network


def address_in_network(address, network):
    try:
        parsed = ipaddress.ip_address(address)
        return parsed.version == network.version and parsed in network
    except (ValueError, TypeError):
        return False


def get_flow_contexts(db, interface, network, lookback_hours):
    cutoff = (
        datetime.now(timezone.utc)
        - timedelta(hours=lookback_hours)
    ).isoformat(timespec="seconds").replace("+00:00", "Z")

    contexts = defaultdict(lambda: {
        "flow_count": 0,
        "packets": 0,
        "tx_bytes": 0,
        "rx_bytes": 0,
        "peers": set(),
        "protocols": Counter(),
        "peer_ports": Counter(),
    })

    rows = db.execute("""
        SELECT
            protocol,
            endpoint_a_ip,
            endpoint_a_port,
            endpoint_b_ip,
            endpoint_b_port,
            packets,
            a_to_b_bytes,
            b_to_a_bytes
        FROM flow_summaries
        WHERE interface = ?
          AND julianday(window_start) >= julianday(?)
    """, (interface, cutoff))

    for row in rows:
        a_ip = row["endpoint_a_ip"]
        b_ip = row["endpoint_b_ip"]

        a_local = address_in_network(a_ip, network)
        b_local = address_in_network(b_ip, network)

        if a_local:
            item = contexts[a_ip]
            item["flow_count"] += 1
            item["packets"] += row["packets"]
            item["tx_bytes"] += row["a_to_b_bytes"]
            item["rx_bytes"] += row["b_to_a_bytes"]
            item["peers"].add(b_ip)
            item["protocols"][row["protocol"]] += 1

            if row["endpoint_b_port"] is not None:
                item["peer_ports"][row["endpoint_b_port"]] += 1

        if b_local:
            item = contexts[b_ip]
            item["flow_count"] += 1
            item["packets"] += row["packets"]
            item["tx_bytes"] += row["b_to_a_bytes"]
            item["rx_bytes"] += row["a_to_b_bytes"]
            item["peers"].add(a_ip)
            item["protocols"][row["protocol"]] += 1

            if row["endpoint_a_port"] is not None:
                item["peer_ports"][row["endpoint_a_port"]] += 1

    result = {}

    for device_ip, item in contexts.items():
        result[device_ip] = {
            "flow_count": item["flow_count"],
            "packets": item["packets"],
            "tx_bytes": item["tx_bytes"],
            "rx_bytes": item["rx_bytes"],
            "unique_peers": len(item["peers"]),
            "protocols": dict(item["protocols"]),
            "frequent_peer_ports": {
                str(port): count
                for port, count in item["peer_ports"].most_common(10)
            },
        }

    return result


def record_classification(db, interface, device, result, flow_context):
    mac = device["mac"].lower()
    device_ip = device["last_ip"]
    classified_at = utc_now()

    evidence_json = json.dumps(
        result["evidence"],
        sort_keys=True,
    )
    candidates_json = json.dumps(
        result["candidates"],
        sort_keys=True,
    )
    flow_context_json = json.dumps(
        flow_context,
        sort_keys=True,
    )

    previous = db.execute("""
        SELECT category, candidate_category, confidence
        FROM device_classifications
        WHERE interface = ? AND mac = ?
    """, (interface, mac)).fetchone()

    changed = (
        previous is None
        or previous["category"] != result["category"]
        or previous["candidate_category"] != result["candidate_category"]
        or abs(previous["confidence"] - result["confidence"]) >= 0.10
    )

    db.execute("""
        INSERT INTO device_classifications (
            interface,
            mac,
            device_ip,
            category,
            candidate_category,
            confidence,
            evidence_json,
            candidates_json,
            flow_context_json,
            explanation,
            classified_at
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)

        ON CONFLICT(interface, mac) DO UPDATE SET
            device_ip = excluded.device_ip,
            category = excluded.category,
            candidate_category = excluded.candidate_category,
            confidence = excluded.confidence,
            evidence_json = excluded.evidence_json,
            candidates_json = excluded.candidates_json,
            flow_context_json = excluded.flow_context_json,
            explanation = excluded.explanation,
            classified_at = excluded.classified_at
    """, (
        interface,
        mac,
        device_ip,
        result["category"],
        result["candidate_category"],
        result["confidence"],
        evidence_json,
        candidates_json,
        flow_context_json,
        result["explanation"],
        classified_at,
    ))

    if changed:
        db.execute("""
            INSERT INTO device_classification_history (
                interface,
                mac,
                device_ip,
                category,
                candidate_category,
                confidence,
                evidence_json,
                explanation,
                classified_at
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            interface,
            mac,
            device_ip,
            result["category"],
            result["candidate_category"],
            result["confidence"],
            evidence_json,
            result["explanation"],
            classified_at,
        ))

    return changed


def classify_devices(
    interface="wlan1",
    lookback_hours=168,
    device_filter=None,
):
    if lookback_hours <= 0:
        raise ValueError("Lookback hours must be positive.")

    initialize()

    info, network = get_interface_subnet(interface)

    db = connect()

    try:
        ensure_flow_schema(db)
        ensure_schema(db)

        devices = db.execute("""
            SELECT
                mac,
                last_ip,
                hostname,
                vendor,
                mac_type,
                status,
                last_seen
            FROM devices
            WHERE last_interface = ?
            ORDER BY last_seen DESC
        """, (interface,)).fetchall()

        devices = [
            device for device in devices
            if address_in_network(device["last_ip"], network)
            and (
                device_filter is None
                or device["last_ip"] == device_filter
            )
        ]

        if device_filter and not devices:
            raise ValueError(
                f"Device {device_filter} was not found on "
                f"{interface} in {network}."
            )

        flow_contexts = get_flow_contexts(
            db,
            interface,
            network,
            lookback_hours,
        )

        classified = 0
        unknown = 0
        changed = 0

        with db:
            for device in devices:
                result = classify_identity(
                    hostname=device["hostname"],
                    vendor=device["vendor"],
                    mac_type=device["mac_type"],
                )

                context = flow_contexts.get(
                    device["last_ip"],
                    {
                        "flow_count": 0,
                        "packets": 0,
                        "tx_bytes": 0,
                        "rx_bytes": 0,
                        "unique_peers": 0,
                        "protocols": {},
                        "frequent_peer_ports": {},
                    },
                )

                changed_now = record_classification(
                    db,
                    interface,
                    device,
                    result,
                    context,
                )

                classified += 1
                unknown += result["category"] == "unknown"
                changed += changed_now

                print(
                    f"{device['last_ip']:<16} "
                    f"{device['mac']:<18} "
                    f"{result['category']:<24} "
                    f"{result['confidence']:.2f} "
                    f"{'*' if changed_now else ''}"
                )

        print("\n===== DEVICE CLASSIFICATION SUMMARY =====")
        print(f"Interface             : {interface}")
        print(f"Monitored subnet      : {network}")
        print(f"Interface IPv4        : {info['ip']}")
        print(f"Lookback              : {lookback_hours} hours")
        print(f"Devices classified    : {classified}")
        print(f"Unknown classifications: {unknown}")
        print(f"History entries added : {changed}")
        print("* Classification history updated")

    finally:
        db.close()


def list_classifications(interface):
    initialize()
    db = connect()

    try:
        ensure_schema(db)

        rows = db.execute("""
            SELECT
                device_ip,
                mac,
                category,
                candidate_category,
                confidence,
                explanation,
                classified_at
            FROM device_classifications
            WHERE interface = ?
            ORDER BY confidence DESC, device_ip
        """, (interface,)).fetchall()
    finally:
        db.close()

    print(f"\n===== DEVICE CLASSIFICATIONS: {interface} =====")

    if not rows:
        print("No classifications found. Run the classifier first.")
        return

    print(
        f"{'IP':<16} {'CATEGORY':<24} "
        f"{'CANDIDATE':<24} {'CONFIDENCE':>10}"
    )
    print("-" * 80)

    for row in rows:
        print(
            f"{row['device_ip']:<16} "
            f"{row['category']:<24} "
            f"{(row['candidate_category'] or '-'): <24} "
            f"{row['confidence']:>10.2f}"
        )


def show_classification(device_ip, interface):
    initialize()
    db = connect()

    try:
        ensure_schema(db)

        row = db.execute("""
            SELECT *
            FROM device_classifications
            WHERE interface = ? AND device_ip = ?
        """, (interface, device_ip)).fetchone()

        if row is None:
            raise ValueError(
                f"No classification found for {device_ip} on {interface}."
            )

        history = db.execute("""
            SELECT
                category,
                candidate_category,
                confidence,
                explanation,
                classified_at
            FROM device_classification_history
            WHERE interface = ? AND mac = ?
            ORDER BY classified_at DESC
            LIMIT 20
        """, (interface, row["mac"])).fetchall()
    finally:
        db.close()

    print(f"\n===== DEVICE CLASSIFICATION: {device_ip} =====")
    print(f"Interface          : {interface}")
    print(f"MAC                : {row['mac']}")
    print(f"Category           : {row['category']}")
    print(f"Best candidate     : {row['candidate_category'] or 'None'}")
    print(f"Confidence         : {row['confidence']:.2f}")
    print(f"Classified at      : {row['classified_at']}")
    print(f"Explanation        : {row['explanation']}")

    print("\nIdentity evidence:")
    for item in json.loads(row["evidence_json"]):
        print(
            f"  {item['source']}: {item['value']} "
            f"(weight {item['weight']:.2f})"
        )

    print("\nCandidate scores:")
    for item in json.loads(row["candidates_json"]):
        print(
            f"  {item['category']:<24} "
            f"{item['confidence']:.2f}"
        )

    print("\nObserved communication context:")
    print(
        json.dumps(
            json.loads(row["flow_context_json"]),
            indent=2,
            sort_keys=True,
        )
    )

    print("\nClassification history:")
    for item in history:
        print(
            f"  {item['classified_at']} | "
            f"{item['category']} | "
            f"{item['confidence']:.2f} | "
            f"{item['explanation']}"
        )


def main():
    parser = argparse.ArgumentParser(
        description="NetWatch explainable device classifier"
    )

    subparsers = parser.add_subparsers(
        dest="command",
        required=True,
    )

    run = subparsers.add_parser(
        "run",
        help="Classify devices on an interface",
    )
    run.add_argument("--interface", default="wlan1")
    run.add_argument("--lookback-hours", type=int, default=168)
    run.add_argument("--device-ip")

    listing = subparsers.add_parser(
        "list",
        help="List stored classifications",
    )
    listing.add_argument("--interface", default="wlan1")

    show = subparsers.add_parser(
        "show",
        help="Show classification evidence and history",
    )
    show.add_argument("device_ip")
    show.add_argument("--interface", default="wlan1")

    args = parser.parse_args()

    try:
        if args.command == "run":
            classify_devices(
                interface=args.interface,
                lookback_hours=args.lookback_hours,
                device_filter=args.device_ip,
            )

        elif args.command == "list":
            list_classifications(args.interface)

        elif args.command == "show":
            show_classification(
                args.device_ip,
                args.interface,
            )

    except (ValueError, OSError, sqlite3.Error) as error:
        parser.error(str(error))


if __name__ == "__main__":
    main()
