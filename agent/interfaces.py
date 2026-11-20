import ipaddress
import json
import subprocess


def get_interface_network(interface):
    result = subprocess.run(
        ["ip", "-j", "-4", "addr", "show", "dev", interface],
        capture_output=True,
        text=True,
        check=True,
    )

    interfaces = json.loads(result.stdout)

    if not interfaces:
        raise RuntimeError(f"Interface not found: {interface}")

    for address in interfaces[0].get("addr_info", []):
        if address.get("family") != "inet":
            continue

        if address.get("scope") != "global":
            continue

        ip_interface = ipaddress.ip_interface(
            f"{address['local']}/{address['prefixlen']}"
        )

        return {
            "interface": interface,
            "ip": str(ip_interface.ip),
            "network": str(ip_interface.network),
            "prefix_length": ip_interface.network.prefixlen,
        }

    raise RuntimeError(
        f"No global IPv4 address found on {interface}"
    )
