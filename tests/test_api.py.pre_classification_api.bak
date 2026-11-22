import json
import pytest
from fastapi.testclient import TestClient

import agent.database as database
from api import main as api_main


@pytest.fixture
def client(tmp_path, monkeypatch):
    """Run the API against a fresh, isolated SQLite database."""
    test_db = tmp_path / "netwatch-test.db"

    # connect() reads DB_PATH from the agent.database module.
    monkeypatch.setattr(database, "DB_PATH", test_db)

    # The health endpoint reports this separate module-level path.
    monkeypatch.setattr(api_main, "DB_PATH", test_db)

    # Configure a disposable token for this test client.
    test_token = "pytest-only-netwatch-token"
    monkeypatch.setenv("NETWATCH_API_TOKEN", test_token)

    with TestClient(
        api_main.app,
        headers={"Authorization": f"Bearer {test_token}"},
    ) as test_client:
        yield test_client


def test_health(client):
    response = client.get("/health")

    assert response.status_code == 200
    body = response.json()
    assert body["status"] == "healthy"
    assert body["database"] == "connected"
    assert body["service"] == "NetWatch API"
    assert body["known_devices"] == 0
    assert body["security_events"] == 0


def test_empty_collection_endpoints(client):
    """Every collection endpoint should handle an empty database."""
    cases = [
        ("/api/v1/devices", "devices"),
        ("/api/v1/traffic/flows", "flows"),
        ("/api/v1/anomalies", "anomalies"),
        ("/api/v1/security/events", "events"),
        ("/api/v1/risks", "assessments"),
        ("/api/v1/incidents", "incidents"),
        ("/api/v1/scans", "scans"),
    ]

    for path, collection_key in cases:
        response = client.get(path)

        assert response.status_code == 200, (
            f"{path} returned {response.status_code}: {response.text}"
        )
        body = response.json()
        assert body["count"] == 0
        assert body["total"] == 0
        assert body["offset"] == 0
        assert body["limit"] >= 1
        assert body[collection_key] == []


def test_empty_traffic_summary(client):
    response = client.get("/api/v1/traffic/summary")

    assert response.status_code == 200
    body = response.json()
    assert body["devices"] == []
    assert body["protocols"] == []
    assert body["observed_device_count"] == 0


def test_empty_device_traffic(client):
    response = client.get("/api/v1/traffic/devices/192.0.2.10")

    assert response.status_code == 200
    body = response.json()
    assert body["device_ip"] == "192.0.2.10"
    assert body["windows"] == []
    assert body["totals"]["tx_packets"] is None
    assert body["totals"]["rx_packets"] is None


def test_missing_resources_return_404(client):
    cases = [
        "/api/v1/devices/192.0.2.99",
        "/api/v1/risks/192.0.2.99",
        "/api/v1/incidents/999999",
    ]

    for path in cases:
        response = client.get(path)
        assert response.status_code == 404, (
            f"{path} returned {response.status_code}: {response.text}"
        )


@pytest.mark.parametrize(
    "path",
    [
        "/api/v1/devices?limit=0",
        "/api/v1/devices?status=compromised",
        "/api/v1/traffic/summary?window_minutes=0",
        "/api/v1/traffic/flows?limit=1001",
        "/api/v1/anomalies?severity=urgent",
        "/api/v1/security/events?severity=urgent",
        "/api/v1/security/events?lookback_hours=0",
        "/api/v1/risks?minimum_score=101",
        "/api/v1/scans?limit=0",
    ],
)
def test_invalid_query_parameters_return_422(client, path):
    response = client.get(path)
    assert response.status_code == 422


def test_invalid_incident_status_returns_422(client):
    response = client.patch(
        "/api/v1/incidents/1",
        json={"status": "closed"},
    )
    assert response.status_code == 422


def test_missing_incident_update_returns_404(client):
    response = client.patch(
        "/api/v1/incidents/999999",
        json={"status": "acknowledged"},
    )
    assert response.status_code == 404


def test_missing_incident_note_returns_404(client):
    response = client.post(
        "/api/v1/incidents/999999/notes",
        json={"note": "Test note", "author": "pytest"},
    )
    assert response.status_code == 404


@pytest.mark.parametrize(
    "payload",
    [
        {"note": ""},
        {"note": "   "},
        {"note": "x" * 4001},
    ],
)
def test_invalid_incident_notes_return_422(client, payload):
    response = client.post(
        "/api/v1/incidents/1/notes",
        json=payload,
    )
    assert response.status_code == 422


def test_openapi_documentation_is_available(client):
    response = client.get("/openapi.json")

    assert response.status_code == 200
    schema = response.json()
    assert schema["info"]["title"] == "NetWatch API"
    assert "/api/v1/devices" in schema["paths"]
    assert "/api/v1/incidents/{incident_id}" in schema["paths"]


def test_incident_lifecycle_and_note_persistence(client):
    """Verify incident reads, status propagation, and note persistence."""
    from datetime import datetime, timezone

    now = (
        datetime.now(timezone.utc)
        .isoformat(timespec="seconds")
        .replace("+00:00", "Z")
    )

    db = database.connect()

    try:
        event_cursor = db.execute(
            """
            INSERT INTO security_events (
                event_key,
                window_start,
                interface,
                detection_type,
                source_ip,
                destination_ip,
                destination_port,
                severity,
                confidence,
                evidence_json,
                explanation,
                created_at,
                status
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                "pytest-event-001",
                now,
                "wlan0",
                "tcp_port_scan",
                "192.0.2.10",
                "192.0.2.1",
                22,
                "high",
                0.90,
                '{"distinct_ports": 30, "packets": 90}',
                "Synthetic port scan for API integration testing.",
                now,
                "open",
            ),
        )

        event_id = event_cursor.lastrowid

        incident_cursor = db.execute(
            """
            INSERT INTO incidents (
                incident_key,
                subject_ip,
                title,
                severity,
                status,
                first_seen,
                last_seen,
                event_count,
                risk_score,
                summary,
                created_at,
                updated_at
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                "pytest-incident-001",
                "192.0.2.10",
                "Synthetic port scan incident",
                "high",
                "open",
                now,
                now,
                1,
                40,
                "Synthetic incident for API integration testing.",
                now,
                now,
            ),
        )

        incident_id = incident_cursor.lastrowid

        db.execute(
            """
            INSERT INTO incident_events (
                event_id,
                incident_id,
                relationship,
                linked_at
            )
            VALUES (?, ?, ?, ?)
            """,
            (event_id, incident_id, "related_evidence", now),
        )

        db.commit()
    finally:
        db.close()

    # 1. Read incident and its linked security event.
    response = client.get(f"/api/v1/incidents/{incident_id}")

    assert response.status_code == 200
    body = response.json()

    assert body["incident"]["status"] == "open"
    assert body["incident"]["subject_ip"] == "192.0.2.10"
    assert len(body["events"]) == 1
    assert body["events"][0]["id"] == event_id
    assert body["events"][0]["evidence_json"]["distinct_ports"] == 30
    assert body["events"][0]["status"] == "open"
    assert body["notes"] == []

    # 2. Acknowledge the incident.
    response = client.patch(
        f"/api/v1/incidents/{incident_id}",
        json={"status": "acknowledged"},
    )

    assert response.status_code == 200
    assert response.json()["status"] == "acknowledged"

    response = client.get(f"/api/v1/incidents/{incident_id}")
    assert response.json()["incident"]["status"] == "acknowledged"
    assert response.json()["events"][0]["status"] == "acknowledged"

    # 3. Add an incident note.
    response = client.post(
        f"/api/v1/incidents/{incident_id}/notes",
        json={
            "note": "  Reviewed scan evidence. No service disruption observed.  ",
            "author": "pytest",
        },
    )

    assert response.status_code == 200
    note = response.json()

    assert note["incident_id"] == incident_id
    assert note["author"] == "pytest"
    assert note["note"] == "Reviewed scan evidence. No service disruption observed."
    assert note["note_id"] > 0

    # 4. Verify the note persisted.
    response = client.get(f"/api/v1/incidents/{incident_id}")

    assert response.status_code == 200
    notes = response.json()["notes"]

    assert len(notes) == 1
    assert notes[0]["id"] == note["note_id"]
    assert notes[0]["author"] == "pytest"
    assert notes[0]["note"] == note["note"]

    # 5. Resolve the incident.
    response = client.patch(
        f"/api/v1/incidents/{incident_id}",
        json={"status": "resolved"},
    )

    assert response.status_code == 200
    assert response.json()["status"] == "resolved"

    # 6. Verify both incident and linked event were updated.
    response = client.get(f"/api/v1/incidents/{incident_id}")

    assert response.status_code == 200
    body = response.json()

    assert body["incident"]["status"] == "resolved"
    assert body["events"][0]["status"] == "resolved"
    assert len(body["notes"]) == 1

    # 7. Verify incident status filtering.
    response = client.get("/api/v1/incidents?status=resolved")

    assert response.status_code == 200
    assert response.json()["count"] == 1
    assert response.json()["incidents"][0]["id"] == incident_id


def test_device_pagination_returns_correct_metadata(client):
    db = database.connect()

    try:
        for number in range(1, 4):
            timestamp = f"2026-01-0{number}T00:00:00Z"
            db.execute(
                """
                INSERT INTO devices (
                    mac,
                    last_ip,
                    hostname,
                    vendor,
                    first_seen,
                    last_seen,
                    last_interface,
                    status,
                    trust_status
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    f"02:00:00:00:00:{number:02x}",
                    f"192.0.2.{number}",
                    f"test-device-{number}",
                    "Test Vendor",
                    timestamp,
                    timestamp,
                    "wlan0",
                    "online",
                    "trusted",
                ),
            )

        db.commit()
    finally:
        db.close()

    # Page 1: newest two records.
    response = client.get("/api/v1/devices?limit=2&offset=0")

    assert response.status_code == 200
    body = response.json()

    assert body["count"] == 2
    assert body["total"] == 3
    assert body["limit"] == 2
    assert body["offset"] == 0
    assert [item["last_ip"] for item in body["devices"]] == [
        "192.0.2.3",
        "192.0.2.2",
    ]

    # Page 2: remaining record.
    response = client.get("/api/v1/devices?limit=2&offset=2")
    body = response.json()

    assert body["count"] == 1
    assert body["total"] == 3
    assert body["devices"][0]["last_ip"] == "192.0.2.1"

    # Offset beyond available records returns an empty page,
    # but preserves the actual filtered total.
    response = client.get("/api/v1/devices?limit=2&offset=99")
    body = response.json()

    assert body["count"] == 0
    assert body["total"] == 3
    assert body["devices"] == []


def test_device_traffic_pagination(client):
    db = database.connect()

    try:
        for number in range(1, 4):
            db.execute(
                """
                INSERT INTO device_traffic (
                    window_start,
                    interface,
                    device_ip,
                    tx_packets,
                    rx_packets,
                    tx_bytes,
                    rx_bytes
                )
                VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    f"2026-01-0{number}T00:00:00Z",
                    "wlan0",
                    "192.0.2.50",
                    number * 10,
                    number * 20,
                    number * 100,
                    number * 200,
                ),
            )

        db.commit()
    finally:
        db.close()

    response = client.get(
        "/api/v1/traffic/devices/192.0.2.50?limit=1&offset=1"
    )

    assert response.status_code == 200
    body = response.json()

    assert body["count"] == 1
    assert body["total"] == 3
    assert body["limit"] == 1
    assert body["offset"] == 1
    assert body["windows"][0]["tx_packets"] == 20

    # Totals remain independent of pagination.
    assert body["totals"]["tx_packets"] == 60
    assert body["totals"]["rx_packets"] == 120


@pytest.mark.parametrize(
    "path",
    [
        "/api/v1/devices?offset=-1",
        "/api/v1/traffic/flows?offset=-1",
        "/api/v1/anomalies?offset=-1",
        "/api/v1/security/events?offset=-1",
        "/api/v1/risks?offset=-1",
        "/api/v1/incidents?offset=-1",
        "/api/v1/scans?offset=-1",
        "/api/v1/risks?limit=0",
    ],
)
def test_invalid_pagination_parameters_return_422(client, path):
    response = client.get(path)
    assert response.status_code == 422


def test_api_rejects_missing_bearer_token(client):
    # Use a client with no default Authorization header.
    with TestClient(api_main.app) as unauthenticated:
        response = unauthenticated.get("/health")

    assert response.status_code == 401
    assert response.headers["www-authenticate"] == "Bearer"


def test_api_rejects_invalid_bearer_token(client):
    response = client.get(
        "/health",
        headers={"Authorization": "Bearer incorrect-token"},
    )

    assert response.status_code == 401
    assert response.headers["www-authenticate"] == "Bearer"


def test_api_fails_startup_without_configured_token(tmp_path, monkeypatch):
    monkeypatch.setattr(database, "DB_PATH", tmp_path / "startup-test.db")
    monkeypatch.setattr(api_main, "DB_PATH", tmp_path / "startup-test.db")
    monkeypatch.delenv("NETWATCH_API_TOKEN", raising=False)

    with pytest.raises(RuntimeError, match="NETWATCH_API_TOKEN is required"):
        with TestClient(api_main.app):
            pass


def test_openapi_declares_bearer_authentication(client):
    response = client.get("/openapi.json")

    assert response.status_code == 200
    schema = response.json()

    security_schemes = schema["components"]["securitySchemes"]
    assert "HTTPBearer" in security_schemes
    assert security_schemes["HTTPBearer"]["scheme"] == "bearer"

    health_security = schema["paths"]["/health"]["get"]["security"]
    assert {"HTTPBearer": []} in health_security


def test_swagger_docs_remain_accessible_without_authentication(client):
    with TestClient(api_main.app) as unauthenticated:
        response = unauthenticated.get("/docs")

    assert response.status_code == 200


def test_audit_log_records_status_changes_and_note_creation(client):
    from datetime import datetime, timezone

    now = (
        datetime.now(timezone.utc)
        .isoformat(timespec="seconds")
        .replace("+00:00", "Z")
    )

    db = database.connect()
    try:
        cursor = db.execute(
            """
            INSERT INTO incidents (
                incident_key,
                subject_ip,
                title,
                severity,
                status,
                first_seen,
                last_seen,
                event_count,
                risk_score,
                summary,
                created_at,
                updated_at
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                "pytest-audit-incident",
                "192.0.2.30",
                "Audit test incident",
                "high",
                "open",
                now,
                now,
                0,
                25,
                "Synthetic audit test incident.",
                now,
                now,
            ),
        )
        incident_id = cursor.lastrowid
        db.commit()
    finally:
        db.close()

    # Change status from open to acknowledged.
    response = client.patch(
        f"/api/v1/incidents/{incident_id}",
        json={"status": "acknowledged"},
    )
    assert response.status_code == 200

    # Repeating the same status must not create another audit entry.
    response = client.patch(
        f"/api/v1/incidents/{incident_id}",
        json={"status": "acknowledged"},
    )
    assert response.status_code == 200

    # Create an incident note.
    response = client.post(
        f"/api/v1/incidents/{incident_id}/notes",
        json={
            "note": "Reviewed the evidence.",
            "author": "pytest",
        },
    )
    assert response.status_code == 200
    note_id = response.json()["note_id"]

    # Fetch audit entries for this incident.
    response = client.get(
        f"/api/v1/audit?resource_type=incident&resource_id={incident_id}"
    )
    assert response.status_code == 200

    body = response.json()
    assert body["count"] == 2
    assert body["total"] == 2
    assert body["limit"] == 100
    assert body["offset"] == 0

    # Newest first.
    entries = body["entries"]
    assert entries[0]["action"] == "incident.note_created"
    assert entries[1]["action"] == "incident.status_changed"

    note_details = entries[0]["details_json"]
    assert note_details["note_id"] == note_id
    assert note_details["note_author"] == "pytest"
    assert note_details["note_length"] == len("Reviewed the evidence.")
    assert "note" not in note_details

    status_details = entries[1]["details_json"]
    assert status_details["previous_status"] == "open"
    assert status_details["new_status"] == "acknowledged"

    for entry in entries:
        assert entry["actor"] == "shared-api-token"
        assert entry["resource_type"] == "incident"
        assert entry["resource_id"] == str(incident_id)
        assert entry["created_at"]

    # Verify action filtering.
    response = client.get(
        "/api/v1/audit?action=incident.status_changed"
    )
    assert response.status_code == 200
    assert response.json()["total"] == 1

    # Verify pagination.
    response = client.get("/api/v1/audit?limit=1&offset=0")
    assert response.status_code == 200
    page = response.json()
    assert page["count"] == 1
    assert page["total"] == 2
    assert page["entries"][0]["action"] == "incident.note_created"

    response = client.get("/api/v1/audit?limit=1&offset=1")
    assert response.status_code == 200
    assert response.json()["entries"][0]["action"] == (
        "incident.status_changed"
    )


def test_audit_log_is_append_only(client):
    import sqlite3

    # Generate one audit entry through the API.
    from datetime import datetime, timezone

    now = (
        datetime.now(timezone.utc)
        .isoformat(timespec="seconds")
        .replace("+00:00", "Z")
    )

    db = database.connect()
    try:
        cursor = db.execute(
            """
            INSERT INTO incidents (
                incident_key, subject_ip, title, severity, status,
                first_seen, last_seen, event_count, risk_score,
                summary, created_at, updated_at
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                "pytest-append-only-incident",
                "192.0.2.31",
                "Append-only test",
                "low",
                "open",
                now,
                now,
                0,
                0,
                "Append-only audit test.",
                now,
                now,
            ),
        )
        incident_id = cursor.lastrowid
        db.commit()
    finally:
        db.close()

    response = client.patch(
        f"/api/v1/incidents/{incident_id}",
        json={"status": "resolved"},
    )
    assert response.status_code == 200

    # Direct SQL updates and deletes must be rejected by SQLite triggers.
    db = database.connect()
    try:
        audit_id = db.execute(
            "SELECT id FROM api_audit_log LIMIT 1"
        ).fetchone()["id"]

        with pytest.raises(sqlite3.IntegrityError):
            db.execute(
                "UPDATE api_audit_log SET actor = 'tampered' WHERE id = ?",
                (audit_id,),
            )
        db.rollback()

        with pytest.raises(sqlite3.IntegrityError):
            db.execute(
                "DELETE FROM api_audit_log WHERE id = ?",
                (audit_id,),
            )
        db.rollback()
    finally:
        db.close()


@pytest.mark.parametrize(
    "path",
    [
        "/api/v1/audit?limit=0",
        "/api/v1/audit?limit=501",
        "/api/v1/audit?offset=-1",
        "/api/v1/audit?action=",
        "/api/v1/audit?resource_type=",
    ],
)
def test_invalid_audit_query_parameters_return_422(client, path):
    response = client.get(path)
    assert response.status_code == 422


def test_websocket_ticket_is_single_use(client):
    response = client.post("/api/v1/ws-ticket")

    assert response.status_code == 200
    body = response.json()

    assert body["ticket"]
    assert body["expires_in_seconds"] == 30
    assert body["websocket_path"] == "/ws/events"

    ticket = body["ticket"]

    assert api_main.consume_websocket_ticket(ticket) is True
    assert api_main.consume_websocket_ticket(ticket) is False


def test_websocket_ticket_endpoint_requires_authentication(client):
    with TestClient(api_main.app) as unauthenticated:
        response = unauthenticated.post("/api/v1/ws-ticket")

    assert response.status_code == 401


def test_websocket_stream_replays_and_delivers_new_events(client):
    # Insert one device before connecting. after_id=0 should replay it.
    db = database.connect()
    try:
        db.execute(
            """
            INSERT INTO devices (
                mac, last_ip, hostname, vendor,
                first_seen, last_seen, last_interface,
                status, trust_status
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                "02:00:00:00:10:01",
                "192.0.2.101",
                "replay-device",
                "Test Vendor",
                "2026-11-22T10:00:00Z",
                "2026-11-22T10:00:00Z",
                "wlan0",
                "online",
                "unknown",
            ),
        )
        db.commit()
    finally:
        db.close()

    ticket_response = client.post("/api/v1/ws-ticket")
    assert ticket_response.status_code == 200
    ticket = ticket_response.json()["ticket"]

    with client.websocket_connect(
        f"/ws/events?ticket={ticket}&after_id=0"
    ) as websocket:
        ready = websocket.receive_json()

        assert ready["type"] == "connection.ready"
        assert ready["last_event_id"] == 0
        assert ready["poll_interval_seconds"] == 1

        replayed = websocket.receive_json()

        assert replayed["type"] == "device.discovered"
        assert replayed["resource"]["type"] == "device"
        assert replayed["resource"]["id"] == "02:00:00:00:10:01"
        assert replayed["data"]["ip_address"] == "192.0.2.101"

        first_event_id = replayed["id"]

        # Insert a second device while the WebSocket is connected.
        db = database.connect()
        try:
            db.execute(
                """
                INSERT INTO devices (
                    mac, last_ip, hostname, vendor,
                    first_seen, last_seen, last_interface,
                    status, trust_status
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    "02:00:00:00:10:02",
                    "192.0.2.102",
                    "live-device",
                    "Test Vendor",
                    "2026-11-22T10:01:00Z",
                    "2026-11-22T10:01:00Z",
                    "wlan0",
                    "online",
                    "unknown",
                ),
            )
            db.commit()
        finally:
            db.close()

        live_event = websocket.receive_json()

        assert live_event["type"] == "device.discovered"
        assert live_event["resource"]["id"] == "02:00:00:00:10:02"
        assert live_event["id"] > first_event_id


def test_realtime_triggers_capture_security_risk_and_incident(client):
    from datetime import datetime, timezone

    now = (
        datetime.now(timezone.utc)
        .isoformat(timespec="seconds")
        .replace("+00:00", "Z")
    )

    db = database.connect()
    try:
        db.execute(
            """
            INSERT INTO security_events (
                event_key, window_start, interface, detection_type,
                source_ip, destination_ip, destination_port,
                severity, confidence, evidence_json, explanation,
                created_at, status
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                "pytest-realtime-security",
                now,
                "wlan0",
                "tcp_port_scan",
                "192.0.2.110",
                "192.0.2.1",
                22,
                "high",
                0.90,
                '{"distinct_ports": 15}',
                "Synthetic real-time event test.",
                now,
                "open",
            ),
        )

        db.execute(
            """
            INSERT INTO risk_assessments (
                device_ip, mac, hostname, vendor,
                risk_score, risk_level, event_count,
                lookback_hours, factors_json, assessed_at
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                "192.0.2.110",
                None,
                "realtime-test",
                "Test Vendor",
                60,
                "high",
                1,
                24,
                '{"tcp_port_scan": 40}',
                now,
            ),
        )

        db.execute(
            """
            INSERT INTO incidents (
                incident_key, subject_ip, title, severity, status,
                first_seen, last_seen, event_count, risk_score,
                summary, created_at, updated_at
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                "pytest-realtime-incident",
                "192.0.2.110",
                "Realtime test incident",
                "high",
                "open",
                now,
                now,
                1,
                60,
                "Synthetic incident.",
                now,
                now,
            ),
        )

        db.commit()

        event_types = {
            row["event_type"]
            for row in db.execute(
                "SELECT event_type FROM api_realtime_events"
            ).fetchall()
        }
    finally:
        db.close()

    assert "security.event_created" in event_types
    assert "risk.updated" in event_types
    assert "incident.created" in event_types


def test_realtime_risk_update_trigger(client):
    from datetime import datetime, timezone

    now = (
        datetime.now(timezone.utc)
        .isoformat(timespec="seconds")
        .replace("+00:00", "Z")
    )

    db = database.connect()
    try:
        db.execute(
            """
            INSERT INTO risk_assessments (
                device_ip, mac, hostname, vendor,
                risk_score, risk_level, event_count,
                lookback_hours, factors_json, assessed_at
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                "192.0.2.120", None, None, None,
                10, "low", 1, 24, "{}", now,
            ),
        )

        db.execute(
            """
            UPDATE risk_assessments
            SET risk_score = ?, risk_level = ?, assessed_at = ?
            WHERE device_ip = ?
            """,
            (75, "critical", now, "192.0.2.120"),
        )

        db.commit()

        events = db.execute("""
            SELECT event_type, payload_json
            FROM api_realtime_events
            WHERE resource_id = ?
            ORDER BY id
        """, ("192.0.2.120",)).fetchall()
    finally:
        db.close()

    assert len(events) == 2
    assert events[0]["event_type"] == "risk.updated"
    assert events[1]["event_type"] == "risk.updated"

    updated_payload = json.loads(events[1]["payload_json"])
    assert updated_payload["previous_risk_score"] == 10
    assert updated_payload["risk_score"] == 75
    assert updated_payload["risk_level"] == "critical"
