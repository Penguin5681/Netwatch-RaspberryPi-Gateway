from agent.baseline_engine import (
    metric_values,
    select_historical_samples,
)


def make_row(
    window_start="2026-11-22T14:00:00Z",
    tx_packets=0,
    rx_packets=0,
    tx_bytes=0,
    rx_bytes=0,
    flow_count=0,
    unique_destinations=0,
    unique_destination_ports=0,
    tcp_syn_packets=0,
    tcp_rst_packets=0,
    protocol_distribution="{}",
):
    return {
        "window_start": window_start,
        "tx_packets": tx_packets,
        "rx_packets": rx_packets,
        "tx_bytes": tx_bytes,
        "rx_bytes": rx_bytes,
        "flow_count": flow_count,
        "unique_destinations": unique_destinations,
        "unique_destination_ports": unique_destination_ports,
        "tcp_syn_packets": tcp_syn_packets,
        "tcp_rst_packets": tcp_rst_packets,
        "protocol_distribution": protocol_distribution,
    }


def test_inbound_only_window_does_not_create_outbound_zeros():
    values = metric_values(make_row(
        rx_packets=4,
        rx_bytes=3903,
        flow_count=2,
    ))

    assert values["total_bytes"] == 3903
    assert values["flow_count"] == 2
    assert values["rx_bytes"] == 3903

    assert values["tx_bytes"] is None
    assert values["unique_destinations"] is None
    assert values["unique_destination_ports"] is None
    assert values["tcp_syn_packets"] is None
    assert values["tcp_rst_packets"] is None
    assert values["protocol_count"] is None


def test_outbound_only_window_does_not_create_inbound_zero():
    values = metric_values(make_row(
        tx_packets=5,
        tx_bytes=1200,
        flow_count=3,
        unique_destinations=2,
        unique_destination_ports=2,
        tcp_syn_packets=1,
        tcp_rst_packets=0,
        protocol_distribution='{"TCP": 5}',
    ))

    assert values["total_bytes"] == 1200
    assert values["flow_count"] == 3
    assert values["tx_bytes"] == 1200
    assert values["unique_destinations"] == 2
    assert values["unique_destination_ports"] == 2
    assert values["tcp_syn_packets"] == 1
    assert values["tcp_rst_packets"] == 0
    assert values["protocol_count"] == 1

    assert values["rx_bytes"] is None


def test_mixed_direction_window_populates_both_directions():
    values = metric_values(make_row(
        tx_packets=3,
        rx_packets=4,
        tx_bytes=500,
        rx_bytes=900,
        flow_count=4,
        unique_destinations=3,
        unique_destination_ports=2,
        protocol_distribution='{"TCP": 3, "UDP": 1}',
    ))

    assert values["total_bytes"] == 1400
    assert values["tx_bytes"] == 500
    assert values["rx_bytes"] == 900
    assert values["flow_count"] == 4
    assert values["protocol_count"] == 2


def test_window_without_packets_has_no_active_metric_values():
    values = metric_values(make_row())

    assert all(value is None for value in values.values())


def test_history_limit_counts_active_samples_per_metric():
    rows = [
        make_row(
            window_start="2026-11-22T14:00:00Z",
            tx_packets=1,
            tx_bytes=100,
        ),
        make_row(
            window_start="2026-11-22T14:01:00Z",
            rx_packets=1,
            rx_bytes=200,
        ),
        make_row(
            window_start="2026-11-22T14:02:00Z",
            tx_packets=1,
            tx_bytes=300,
        ),
        make_row(
            window_start="2026-11-22T14:03:00Z",
            rx_packets=1,
            rx_bytes=400,
        ),
        make_row(
            window_start="2026-11-22T14:04:00Z",
            tx_packets=1,
            tx_bytes=500,
        ),
    ]

    sample_rows, samples = select_historical_samples(
        rows,
        "tx_bytes",
        2,
    )

    assert samples == [300, 500]
    assert [
        row["window_start"] for row in sample_rows
    ] == [
        "2026-11-22T14:02:00Z",
        "2026-11-22T14:04:00Z",
    ]


def test_history_limit_rejects_zero():
    try:
        select_historical_samples([], "tx_bytes", 0)
    except ValueError as exc:
        assert "positive" in str(exc)
    else:
        raise AssertionError("Expected ValueError for zero history limit.")
