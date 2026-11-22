from agent.device_classifier import classify_identity


def test_specific_smartphone_hostname():
    result = classify_identity(
        hostname="realme-13-5g",
        vendor=None,
        mac_type="locally_administered",
    )

    assert result["category"] == "smartphone"
    assert result["confidence"] >= 0.65


def test_vendor_alone_does_not_force_device_type():
    result = classify_identity(
        hostname=None,
        vendor="Samsung Electronics",
        mac_type="globally_administered",
    )

    assert result["category"] == "unknown"


def test_esp_device_uses_independent_evidence():
    result = classify_identity(
        hostname="esp32-sensor",
        vendor="Espressif Inc.",
        mac_type="globally_administered",
    )

    assert result["category"] == "iot"
    assert result["confidence"] >= 0.80
    assert len(result["evidence"]) == 2


def test_generic_hostname_remains_unknown():
    result = classify_identity(
        hostname="android-tv",
        vendor=None,
        mac_type="locally_administered",
    )

    assert result["category"] == "unknown"
    assert result["candidate_category"] is not None


def test_network_gateway_hostname():
    result = classify_identity(
        hostname="home-gateway",
        vendor=None,
        mac_type="globally_administered",
    )

    assert result["category"] == "network_infrastructure"


def test_no_identity_evidence():
    result = classify_identity(
        hostname=None,
        vendor=None,
        mac_type="locally_administered",
    )

    assert result["category"] == "unknown"
    assert result["confidence"] == 0.0
    assert result["evidence"] == []
