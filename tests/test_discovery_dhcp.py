from agent.discovery import parse_dhcp_lease_lines


def test_matching_dhcp_lease():
    lines = [
        "1795361339 3a:1a:ae:f4:61:4b 10.42.0.57 realme-13-5G client"
    ]
    assert parse_dhcp_lease_lines(
        lines,
        "3a:1a:ae:f4:61:4b",
        "10.42.0.57",
        now_epoch=1795360000,
    ) == "realme-13-5G"


def test_rejects_mac_or_ip_mismatch():
    lines = [
        "1795361339 3a:1a:ae:f4:61:4b 10.42.0.57 realme-13-5G client"
    ]
    assert parse_dhcp_lease_lines(
        lines, "00:11:22:33:44:55", "10.42.0.57", 1795360000
    ) is None
    assert parse_dhcp_lease_lines(
        lines, "3a:1a:ae:f4:61:4b", "10.42.0.58", 1795360000
    ) is None


def test_rejects_expired_lease():
    lines = ["100 3a:1a:ae:f4:61:4b 10.42.0.57 realme-13-5G client"]
    assert parse_dhcp_lease_lines(
        lines, "3a:1a:ae:f4:61:4b", "10.42.0.57", 101
    ) is None


def test_accepts_non_expiring_lease():
    lines = ["0 3a:1a:ae:f4:61:4b 10.42.0.57 realme-13-5G client"]
    assert parse_dhcp_lease_lines(
        lines, "3a:1a:ae:f4:61:4b", "10.42.0.57", 200
    ) == "realme-13-5G"


def test_rejects_unknown_hostname():
    lines = ["0 3a:1a:ae:f4:61:4b 10.42.0.57 * client"]
    assert parse_dhcp_lease_lines(
        lines, "3a:1a:ae:f4:61:4b", "10.42.0.57", 200
    ) is None
