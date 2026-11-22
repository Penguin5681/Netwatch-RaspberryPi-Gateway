import pytest

from agent.risk_engine import (
    calculate_factors,
    classify_risk,
    get_event_weight,
    load_config,
)


@pytest.fixture
def config():
    return load_config()


def make_event(
    detection_type,
    event_id=1,
    severity="high",
):
    return {
        "id": event_id,
        "detection_type": detection_type,
        "severity": severity,
        "destination_ip": "10.42.0.1",
        "destination_port": 443,
        "explanation": "Synthetic event for isolated risk-engine testing.",
        "window_start": "2026-11-22T16:00:00Z",
    }


def test_configured_event_weights(config):
    assert get_event_weight(
        make_event("tcp_port_scan"), config
    ) == 40

    assert get_event_weight(
        make_event("tcp_horizontal_scan"), config
    ) == 40

    assert get_event_weight(
        make_event("tcp_connection_burst"), config
    ) == 20

    assert get_event_weight(
        make_event("new_unknown_device"), config
    ) == 15


def test_behavioral_weights_depend_on_severity(config):
    assert get_event_weight(
        make_event("behavioral_deviation", severity="medium"), config
    ) == 10

    assert get_event_weight(
        make_event("behavioral_deviation", severity="high"), config
    ) == 20

    assert get_event_weight(
        make_event("behavioral_deviation", severity="critical"), config
    ) == 25

    assert get_event_weight(
        make_event("behavioral_deviation", severity="unknown"), config
    ) == 0


def test_single_port_scan_scores_40(config):
    score, factors = calculate_factors(
        [make_event("tcp_port_scan")],
        config,
    )

    assert score == 40
    assert len(factors) == 1
    assert factors[0]["base_points"] == 40
    assert factors[0]["repeat_bonus"] == 0
    assert factors[0]["awarded_points"] == 40


def test_repeat_bonus_is_applied_and_capped(config):
    events = [
        make_event("tcp_port_scan", event_id=index)
        for index in range(1, 6)
    ]

    score, factors = calculate_factors(events, config)

    assert score == 55
    assert factors[0]["event_count"] == 5
    assert factors[0]["base_points"] == 200
    assert factors[0]["repeat_bonus"] == 15
    assert factors[0]["type_cap"] == 55
    assert factors[0]["awarded_points"] == 55


def test_connection_burst_type_cap_is_enforced(config):
    events = [
        make_event("tcp_connection_burst", event_id=index)
        for index in range(1, 5)
    ]

    score, factors = calculate_factors(events, config)

    assert score == 35
    assert factors[0]["base_points"] == 80
    assert factors[0]["repeat_bonus"] == 15
    assert factors[0]["type_cap"] == 35
    assert factors[0]["awarded_points"] == 35


def test_behavioral_deviation_type_cap_is_enforced(config):
    events = [
        make_event(
            "behavioral_deviation",
            event_id=index,
            severity="critical",
        )
        for index in range(1, 4)
    ]

    score, factors = calculate_factors(events, config)

    assert score == 40
    assert factors[0]["base_points"] == 75
    assert factors[0]["repeat_bonus"] == 10
    assert factors[0]["type_cap"] == 40
    assert factors[0]["awarded_points"] == 40


def test_unknown_detection_types_do_not_add_points(config):
    score, factors = calculate_factors(
        [make_event("unrecognized_detection")],
        config,
    )

    assert score == 0
    assert factors == []


def test_combined_detection_types_are_capped_at_100(config):
    events = [
        make_event("tcp_port_scan", 1),
        make_event("tcp_port_scan", 2),
        make_event("tcp_horizontal_scan", 3),
        make_event("tcp_horizontal_scan", 4),
        make_event("tcp_connection_burst", 5),
        make_event("tcp_connection_burst", 6),
        make_event("new_unknown_device", 7),
        make_event("behavioral_deviation", 8, "critical"),
        make_event("behavioral_deviation", 9, "critical"),
    ]

    score, factors = calculate_factors(events, config)

    assert score == 100
    assert sum(f["awarded_points"] for f in factors) > 100


@pytest.mark.parametrize(
    ("score", "expected"),
    [
        (0, "Normal"),
        (1, "Low"),
        (24, "Low"),
        (25, "Moderate"),
        (49, "Moderate"),
        (50, "High"),
        (74, "High"),
        (75, "Critical"),
        (100, "Critical"),
        (101, "Unclassified"),
        (-1, "Unclassified"),
    ],
)
def test_risk_level_boundaries(config, score, expected):
    assert classify_risk(score, config) == expected


def test_no_events_produces_normal_risk(config):
    score, factors = calculate_factors([], config)

    assert score == 0
    assert factors == []
    assert classify_risk(score, config) == "Normal"
