import asyncio
import hashlib
import json
import os
import secrets
from contextlib import asynccontextmanager, contextmanager
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Literal

from fastapi import (
    Depends,
    FastAPI,
    HTTPException,
    Query,
    WebSocket,
    WebSocketDisconnect,
)
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from pydantic import BaseModel, Field, field_validator
from starlette.routing import WebSocketRoute

from agent.database import connect, initialize
from agent.flow_engine import ensure_schema as ensure_flow_schema
from agent.baseline_engine import ensure_schema as ensure_baseline_schema
from agent.threat_detection import ensure_schema as ensure_threat_schema
from agent.risk_engine import ensure_schema as ensure_risk_schema
from agent.incident_engine import ensure_schema as ensure_incident_schema


PROJECT_ROOT = Path(__file__).resolve().parent.parent
DB_PATH = PROJECT_ROOT / "data" / "netwatch.db"


def utc_now():
    return (
        datetime.now(timezone.utc)
        .isoformat(timespec="seconds")
        .replace("+00:00", "Z")
    )


def cutoff_time(minutes=None, hours=None):
    now = datetime.now(timezone.utc)

    if minutes is not None:
        now -= timedelta(minutes=minutes)

    if hours is not None:
        now -= timedelta(hours=hours)

    return (
        now.isoformat(timespec="seconds")
        .replace("+00:00", "Z")
    )


def row_dict(row):
    return dict(row) if row is not None else None



@contextmanager
def db_session():
    db = connect()
    try:
        yield db
        db.commit()
    except Exception:
        db.rollback()
        raise
    finally:
        db.close()



def page_metadata(rows, total, limit, offset):
    return {
        "count": len(rows),
        "total": total,
        "limit": limit,
        "offset": offset,
    }


def decode_json_field(item, field):
    if not item or not item.get(field):
        return item

    try:
        item[field] = json.loads(item[field])
    except (TypeError, json.JSONDecodeError):
        pass

    return item


def ensure_audit_schema(db):
    db.executescript("""
        CREATE TABLE IF NOT EXISTS api_audit_log (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            actor TEXT NOT NULL,
            action TEXT NOT NULL,
            resource_type TEXT NOT NULL,
            resource_id TEXT NOT NULL,
            details_json TEXT NOT NULL,
            created_at TEXT NOT NULL
        );

        CREATE INDEX IF NOT EXISTS idx_api_audit_created
        ON api_audit_log(created_at);

        CREATE INDEX IF NOT EXISTS idx_api_audit_resource
        ON api_audit_log(resource_type, resource_id);

        CREATE INDEX IF NOT EXISTS idx_api_audit_action
        ON api_audit_log(action);

        CREATE TRIGGER IF NOT EXISTS prevent_api_audit_update
        BEFORE UPDATE ON api_audit_log
        BEGIN
            SELECT RAISE(ABORT, 'Audit log is append-only');
        END;

        CREATE TRIGGER IF NOT EXISTS prevent_api_audit_delete
        BEFORE DELETE ON api_audit_log
        BEGIN
            SELECT RAISE(ABORT, 'Audit log is append-only');
        END;
    """)


def write_audit_log(
    db,
    action,
    resource_type,
    resource_id,
    details,
    actor="shared-api-token",
):
    db.execute("""
        INSERT INTO api_audit_log (
            actor,
            action,
            resource_type,
            resource_id,
            details_json,
            created_at
        )
        VALUES (?, ?, ?, ?, ?, ?)
    """, (
        actor,
        action,
        resource_type,
        str(resource_id),
        json.dumps(details, sort_keys=True),
        utc_now(),
    ))



def ensure_realtime_schema(db):
    db.executescript("""
        CREATE TABLE IF NOT EXISTS api_realtime_events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            event_type TEXT NOT NULL,
            resource_type TEXT NOT NULL,
            resource_id TEXT NOT NULL,
            payload_json TEXT NOT NULL,
            created_at TEXT NOT NULL
        );

        CREATE INDEX IF NOT EXISTS idx_realtime_events_type_id
        ON api_realtime_events(event_type, id);

        CREATE INDEX IF NOT EXISTS idx_realtime_events_created
        ON api_realtime_events(created_at);

        CREATE TABLE IF NOT EXISTS api_ws_tickets (
            token_hash TEXT PRIMARY KEY,
            created_at TEXT NOT NULL,
            expires_at TEXT NOT NULL
        );

        CREATE INDEX IF NOT EXISTS idx_ws_tickets_expiry
        ON api_ws_tickets(expires_at);

        -- A genuinely new inventory record.
        CREATE TRIGGER IF NOT EXISTS realtime_device_discovered
        AFTER INSERT ON devices
        BEGIN
            INSERT INTO api_realtime_events (
                event_type, resource_type, resource_id,
                payload_json, created_at
            )
            VALUES (
                'device.discovered',
                'device',
                NEW.mac,
                json_object(
                    'mac', NEW.mac,
                    'ip_address', NEW.last_ip,
                    'hostname', NEW.hostname,
                    'vendor', NEW.vendor,
                    'interface', NEW.last_interface,
                    'status', NEW.status,
                    'trust_status', NEW.trust_status
                ),
                strftime('%Y-%m-%dT%H:%M:%SZ', 'now')
            );
        END;

        -- Newly inserted security detections.
        CREATE TRIGGER IF NOT EXISTS realtime_security_event_created
        AFTER INSERT ON security_events
        BEGIN
            INSERT INTO api_realtime_events (
                event_type, resource_type, resource_id,
                payload_json, created_at
            )
            VALUES (
                'security.event_created',
                'security_event',
                CAST(NEW.id AS TEXT),
                json_object(
                    'event_id', NEW.id,
                    'detection_type', NEW.detection_type,
                    'source_ip', NEW.source_ip,
                    'destination_ip', NEW.destination_ip,
                    'destination_port', NEW.destination_port,
                    'severity', NEW.severity,
                    'confidence', NEW.confidence,
                    'status', NEW.status,
                    'explanation', NEW.explanation,
                    'evidence_json', NEW.evidence_json
                ),
                strftime('%Y-%m-%dT%H:%M:%SZ', 'now')
            );
        END;

        -- Existing security detections materially changed.
        CREATE TRIGGER IF NOT EXISTS realtime_security_event_updated
        AFTER UPDATE ON security_events
        WHEN OLD.severity IS NOT NEW.severity
          OR OLD.status IS NOT NEW.status
          OR OLD.evidence_json IS NOT NEW.evidence_json
        BEGIN
            INSERT INTO api_realtime_events (
                event_type, resource_type, resource_id,
                payload_json, created_at
            )
            VALUES (
                'security.event_updated',
                'security_event',
                CAST(NEW.id AS TEXT),
                json_object(
                    'event_id', NEW.id,
                    'detection_type', NEW.detection_type,
                    'source_ip', NEW.source_ip,
                    'destination_ip', NEW.destination_ip,
                    'severity', NEW.severity,
                    'status', NEW.status
                ),
                strftime('%Y-%m-%dT%H:%M:%SZ', 'now')
            );
        END;

        -- First risk assessment for a device.
        CREATE TRIGGER IF NOT EXISTS realtime_risk_inserted
        AFTER INSERT ON risk_assessments
        BEGIN
            INSERT INTO api_realtime_events (
                event_type, resource_type, resource_id,
                payload_json, created_at
            )
            VALUES (
                'risk.updated',
                'device',
                NEW.device_ip,
                json_object(
                    'device_ip', NEW.device_ip,
                    'risk_score', NEW.risk_score,
                    'risk_level', NEW.risk_level,
                    'event_count', NEW.event_count,
                    'assessed_at', NEW.assessed_at
                ),
                strftime('%Y-%m-%dT%H:%M:%SZ', 'now')
            );
        END;

        -- Changed risk assessment for an existing device.
        CREATE TRIGGER IF NOT EXISTS realtime_risk_updated
        AFTER UPDATE ON risk_assessments
        WHEN OLD.risk_score IS NOT NEW.risk_score
          OR OLD.risk_level IS NOT NEW.risk_level
          OR OLD.event_count IS NOT NEW.event_count
          OR OLD.factors_json IS NOT NEW.factors_json
        BEGIN
            INSERT INTO api_realtime_events (
                event_type, resource_type, resource_id,
                payload_json, created_at
            )
            VALUES (
                'risk.updated',
                'device',
                NEW.device_ip,
                json_object(
                    'device_ip', NEW.device_ip,
                    'previous_risk_score', OLD.risk_score,
                    'risk_score', NEW.risk_score,
                    'previous_risk_level', OLD.risk_level,
                    'risk_level', NEW.risk_level,
                    'event_count', NEW.event_count,
                    'assessed_at', NEW.assessed_at
                ),
                strftime('%Y-%m-%dT%H:%M:%SZ', 'now')
            );
        END;

        -- Newly correlated incident.
        CREATE TRIGGER IF NOT EXISTS realtime_incident_created
        AFTER INSERT ON incidents
        BEGIN
            INSERT INTO api_realtime_events (
                event_type, resource_type, resource_id,
                payload_json, created_at
            )
            VALUES (
                'incident.created',
                'incident',
                CAST(NEW.id AS TEXT),
                json_object(
                    'incident_id', NEW.id,
                    'subject_ip', NEW.subject_ip,
                    'title', NEW.title,
                    'severity', NEW.severity,
                    'status', NEW.status,
                    'event_count', NEW.event_count,
                    'risk_score', NEW.risk_score,
                    'summary', NEW.summary
                ),
                strftime('%Y-%m-%dT%H:%M:%SZ', 'now')
            );
        END;

        -- Material incident changes.
        CREATE TRIGGER IF NOT EXISTS realtime_incident_updated
        AFTER UPDATE ON incidents
        WHEN OLD.status IS NOT NEW.status
          OR OLD.severity IS NOT NEW.severity
          OR OLD.event_count IS NOT NEW.event_count
          OR OLD.risk_score IS NOT NEW.risk_score
        BEGIN
            INSERT INTO api_realtime_events (
                event_type, resource_type, resource_id,
                payload_json, created_at
            )
            VALUES (
                'incident.updated',
                'incident',
                CAST(NEW.id AS TEXT),
                json_object(
                    'incident_id', NEW.id,
                    'subject_ip', NEW.subject_ip,
                    'previous_status', OLD.status,
                    'status', NEW.status,
                    'previous_severity', OLD.severity,
                    'severity', NEW.severity,
                    'event_count', NEW.event_count,
                    'risk_score', NEW.risk_score,
                    'summary', NEW.summary
                ),
                strftime('%Y-%m-%dT%H:%M:%SZ', 'now')
            );
        END;
    """)


def hash_websocket_ticket(ticket):
    return hashlib.sha256(ticket.encode("utf-8")).hexdigest()


def consume_websocket_ticket(ticket):
    if not ticket or len(ticket) > 200:
        return False

    token_hash = hash_websocket_ticket(ticket)
    now = utc_now()

    with db_session() as db:
        # Serialize ticket consumption so two connections cannot
        # successfully consume the same ticket concurrently.
        db.execute("BEGIN IMMEDIATE")

        row = db.execute("""
            SELECT expires_at
            FROM api_ws_tickets
            WHERE token_hash = ?
        """, (token_hash,)).fetchone()

        if row is None:
            return False

        db.execute("""
            DELETE FROM api_ws_tickets
            WHERE token_hash = ?
        """, (token_hash,))

        return row["expires_at"] > now


def initialize_api_database():
    initialize()

    with db_session() as db:
        ensure_flow_schema(db)
        ensure_baseline_schema(db)
        ensure_threat_schema(db)
        ensure_risk_schema(db)
        ensure_incident_schema(db)
        ensure_audit_schema(db)
        ensure_realtime_schema(db)


@asynccontextmanager
async def lifespan(app: FastAPI):
    if not os.getenv("NETWATCH_API_TOKEN"):
        raise RuntimeError(
            "NETWATCH_API_TOKEN is required. Configure the API token "
            "before starting NetWatch API."
        )

    initialize_api_database()
    yield


bearer_scheme = HTTPBearer(auto_error=False)


def require_api_token(
    credentials: HTTPAuthorizationCredentials | None = Depends(bearer_scheme),
):
    expected_token = os.getenv("NETWATCH_API_TOKEN")

    if not expected_token:
        raise HTTPException(
            status_code=503,
            detail="API authentication is not configured.",
        )

    if (
        credentials is None
        or not secrets.compare_digest(
            credentials.credentials,
            expected_token,
        )
    ):
        raise HTTPException(
            status_code=401,
            detail="Missing or invalid bearer token.",
            headers={"WWW-Authenticate": "Bearer"},
        )


app = FastAPI(
    title="NetWatch API",
    description=(
        "Local network security monitoring API for device discovery, "
        "traffic intelligence, behavioural analysis, threat detection, "
        "risk assessment and incident management."
    ),
    version="0.1.0",
    lifespan=lifespan,
    dependencies=[Depends(require_api_token)],
)


# ---------------------------------------------------------
# REQUEST MODELS
# ---------------------------------------------------------

class IncidentStatusUpdate(BaseModel):
    status: Literal[
        "open",
        "acknowledged",
        "resolved",
        "false_positive",
    ]


class IncidentNoteCreate(BaseModel):
    note: str = Field(min_length=1, max_length=4000)
    author: str = Field(default="operator", min_length=1, max_length=100)

    @field_validator("note")
    @classmethod
    def validate_note_content(cls, value: str) -> str:
        value = value.strip()
        if not value:
            raise ValueError("Note cannot contain only whitespace.")
        return value


# ---------------------------------------------------------
# HEALTH
# ---------------------------------------------------------

@app.get("/health", tags=["System"])
def health():
    try:
        with db_session() as db:
            db.execute("SELECT 1")

            device_count = db.execute(
                "SELECT COUNT(*) FROM devices"
            ).fetchone()[0]

            event_count = db.execute(
                "SELECT COUNT(*) FROM security_events"
            ).fetchone()[0]

    except Exception as error:
        raise HTTPException(
            status_code=503,
            detail=f"Database unavailable: {error}",
        )

    return {
        "status": "healthy",
        "service": "NetWatch API",
        "version": app.version,
        "database": "connected",
        "database_path": str(DB_PATH),
        "known_devices": device_count,
        "security_events": event_count,
        "timestamp": utc_now(),
    }


# ---------------------------------------------------------
# DEVICE INVENTORY
# ---------------------------------------------------------

@app.get("/api/v1/devices", tags=["Devices"])
def list_devices(
    status: Literal["online", "offline", "unknown"] | None = None,
    trust_status: Literal["trusted", "untrusted", "unknown"] | None = None,
    limit: int = Query(100, ge=1, le=500),
    offset: int = Query(0, ge=0),
):
    query = "SELECT * FROM devices WHERE 1=1"
    params = []

    if status:
        query += " AND status = ?"
        params.append(status)

    if trust_status:
        query += " AND trust_status = ?"
        params.append(trust_status)

    count_query = query.replace("SELECT *", "SELECT COUNT(*)", 1)
    query += " ORDER BY last_seen DESC LIMIT ? OFFSET ?"

    with db_session() as db:
        total = db.execute(count_query, params).fetchone()[0]
        rows = db.execute(
            query, [*params, limit, offset]
        ).fetchall()

    return {
        **page_metadata(rows, total, limit, offset),
        "devices": [dict(row) for row in rows],
    }


@app.get("/api/v1/devices/{device_ip}", tags=["Devices"])
def get_device(device_ip: str):
    with db_session() as db:
        device = db.execute("""
            SELECT *
            FROM devices
            WHERE last_ip = ? OR lower(mac) = lower(?)
            LIMIT 1
        """, (device_ip, device_ip)).fetchone()

        if device is None:
            raise HTTPException(
                status_code=404,
                detail="Device not found.",
            )

        mac = device["mac"]

        history = db.execute("""
            SELECT *
            FROM device_ip_history
            WHERE mac = ?
            ORDER BY last_seen DESC
        """, (mac,)).fetchall()

        observation_count = db.execute("""
            SELECT COUNT(*)
            FROM device_observations
            WHERE mac = ?
        """, (mac,)).fetchone()[0]

        traffic = db.execute("""
            SELECT *
            FROM device_traffic
            WHERE device_ip = ?
            ORDER BY window_start DESC
            LIMIT 30
        """, (device["last_ip"],)).fetchall()

        metrics = db.execute("""
            SELECT *
            FROM device_window_metrics
            WHERE device_ip = ?
            ORDER BY window_start DESC
            LIMIT 30
        """, (device["last_ip"],)).fetchall()

        baselines = db.execute("""
            SELECT *
            FROM device_baselines
            WHERE device_ip = ?
            ORDER BY metric_name
        """, (device["last_ip"],)).fetchall()

        baseline_status = db.execute("""
            SELECT *
            FROM device_baseline_status
            WHERE device_ip = ?
            ORDER BY metric_name
        """, (device["last_ip"],)).fetchall()

        anomalies = db.execute("""
            SELECT *
            FROM anomaly_events
            WHERE device_ip = ?
            ORDER BY window_start DESC
            LIMIT 20
        """, (device["last_ip"],)).fetchall()

        risk = db.execute("""
            SELECT *
            FROM risk_assessments
            WHERE device_ip = ?
        """, (device["last_ip"],)).fetchone()

    traffic_data = [dict(row) for row in traffic]
    metric_data = [
        decode_json_field(dict(row), "protocol_distribution")
        for row in metrics
    ]
    anomaly_data = [
        decode_json_field(dict(row), "explanation")
        for row in anomalies
    ]

    if risk:
        risk_data = decode_json_field(dict(risk), "factors_json")
    else:
        risk_data = None

    return {
        "device": dict(device),
        "ip_history": [dict(row) for row in history],
        "observation_count": observation_count,
        "traffic_windows": traffic_data,
        "behavioural_metrics": metric_data,
        "baselines": [dict(row) for row in baselines],
        "baseline_status": [dict(row) for row in baseline_status],
        "anomalies": anomaly_data,
        "risk_assessment": risk_data,
    }


# ---------------------------------------------------------
# TRAFFIC INTELLIGENCE
# ---------------------------------------------------------

@app.get("/api/v1/traffic/summary", tags=["Traffic"])
def traffic_summary(
    window_minutes: int = Query(15, ge=1, le=10080),
    interface: str | None = None,
):
    cutoff = cutoff_time(minutes=window_minutes)

    with db_session() as db:
        query = """
            SELECT
                device_ip,
                SUM(tx_packets) AS tx_packets,
                SUM(rx_packets) AS rx_packets,
                SUM(tx_bytes) AS tx_bytes,
                SUM(rx_bytes) AS rx_bytes
            FROM device_traffic
            WHERE window_start >= ?
        """
        params = [cutoff]

        if interface:
            query += " AND interface = ?"
            params.append(interface)

        query += """
            GROUP BY device_ip
            ORDER BY SUM(tx_bytes + rx_bytes) DESC
        """

        devices = db.execute(query, params).fetchall()

        flow_query = """
            SELECT
                protocol,
                COUNT(*) AS flow_count,
                SUM(packets) AS packets,
                SUM(bytes) AS bytes
            FROM flow_summaries
            WHERE window_start >= ?
        """
        flow_params = [cutoff]

        if interface:
            flow_query += " AND interface = ?"
            flow_params.append(interface)

        flow_query += " GROUP BY protocol ORDER BY bytes DESC"

        protocols = db.execute(
            flow_query,
            flow_params,
        ).fetchall()

    device_data = [dict(row) for row in devices]
    protocol_data = [dict(row) for row in protocols]

    return {
        "window_minutes": window_minutes,
        "interface": interface,
        "devices": device_data,
        "protocols": protocol_data,
        "observed_device_count": len(device_data),
    }


@app.get("/api/v1/traffic/flows", tags=["Traffic"])
def list_flows(
    window_minutes: int = Query(15, ge=1, le=10080),
    interface: str | None = None,
    limit: int = Query(100, ge=1, le=1000),
    offset: int = Query(0, ge=0),
):
    cutoff = cutoff_time(minutes=window_minutes)

    query = """
        SELECT *
        FROM flow_summaries
        WHERE window_start >= ?
    """
    params = [cutoff]

    if interface:
        query += " AND interface = ?"
        params.append(interface)

    count_query = query.replace("SELECT *", "SELECT COUNT(*)", 1)
    query += " ORDER BY window_start DESC, bytes DESC LIMIT ? OFFSET ?"

    with db_session() as db:
        total = db.execute(count_query, params).fetchone()[0]
        rows = db.execute(
            query, [*params, limit, offset]
        ).fetchall()

    return {
        **page_metadata(rows, total, limit, offset),
        "flows": [dict(row) for row in rows],
    }


@app.get("/api/v1/traffic/devices/{device_ip}", tags=["Traffic"])
def device_traffic(
    device_ip: str,
    limit: int = Query(100, ge=1, le=1000),
    offset: int = Query(0, ge=0),
):
    with db_session() as db:
        totals = db.execute("""
            SELECT
                SUM(tx_packets) AS tx_packets,
                SUM(rx_packets) AS rx_packets,
                SUM(tx_bytes) AS tx_bytes,
                SUM(rx_bytes) AS rx_bytes
            FROM device_traffic
            WHERE device_ip = ?
        """, (device_ip,)).fetchone()

        total = db.execute("""
            SELECT COUNT(*)
            FROM device_traffic
            WHERE device_ip = ?
        """, (device_ip,)).fetchone()[0]

        windows = db.execute("""
            SELECT *
            FROM device_traffic
            WHERE device_ip = ?
            ORDER BY window_start DESC
            LIMIT ? OFFSET ?
        """, (device_ip, limit, offset)).fetchall()

    return {
        "device_ip": device_ip,
        "totals": row_dict(totals),
        **page_metadata(windows, total, limit, offset),
        "windows": [dict(row) for row in windows],
    }


# ---------------------------------------------------------
# BEHAVIOURAL ANALYSIS
# ---------------------------------------------------------

@app.get("/api/v1/anomalies", tags=["Behavioural Analysis"])
def list_anomalies(
    device_ip: str | None = None,
    severity: Literal["medium", "high", "critical"] | None = None,
    limit: int = Query(100, ge=1, le=500),
    offset: int = Query(0, ge=0),
):
    query = "SELECT * FROM anomaly_events WHERE 1=1"
    params = []

    if device_ip:
        query += " AND device_ip = ?"
        params.append(device_ip)

    if severity:
        query += " AND severity = ?"
        params.append(severity)

    count_query = query.replace("SELECT *", "SELECT COUNT(*)", 1)
    query += " ORDER BY window_start DESC LIMIT ? OFFSET ?"

    with db_session() as db:
        total = db.execute(count_query, params).fetchone()[0]
        rows = db.execute(
            query, [*params, limit, offset]
        ).fetchall()

    anomalies = [
        decode_json_field(dict(row), "evidence_json")
        for row in rows
    ]

    return {
        **page_metadata(rows, total, limit, offset),
        "anomalies": anomalies,
    }


# ---------------------------------------------------------
# SECURITY EVENTS
# ---------------------------------------------------------

@app.get("/api/v1/security/events", tags=["Security"])
def list_security_events(
    source_ip: str | None = None,
    severity: Literal[
        "informational",
        "low",
        "medium",
        "high",
        "critical",
    ] | None = None,
    status: Literal[
        "open",
        "acknowledged",
        "resolved",
        "false_positive",
    ] | None = None,
    lookback_hours: int = Query(24, ge=1, le=8760),
    limit: int = Query(100, ge=1, le=500),
    offset: int = Query(0, ge=0),
):
    cutoff = cutoff_time(hours=lookback_hours)

    query = """
        SELECT *
        FROM security_events
        WHERE created_at >= ?
    """
    params = [cutoff]

    if source_ip:
        query += " AND source_ip = ?"
        params.append(source_ip)

    if severity:
        query += " AND severity = ?"
        params.append(severity)

    if status:
        query += " AND status = ?"
        params.append(status)

    count_query = query.replace("SELECT *", "SELECT COUNT(*)", 1)
    query += " ORDER BY created_at DESC LIMIT ? OFFSET ?"

    with db_session() as db:
        total = db.execute(count_query, params).fetchone()[0]
        rows = db.execute(
            query, [*params, limit, offset]
        ).fetchall()

    events = [
        decode_json_field(dict(row), "evidence_json")
        for row in rows
    ]

    return {
        **page_metadata(rows, total, limit, offset),
        "lookback_hours": lookback_hours,
        "events": events,
    }


# ---------------------------------------------------------
# RISK ASSESSMENTS
# ---------------------------------------------------------

@app.get("/api/v1/risks", tags=["Risk"])
def list_risks(
    minimum_score: int = Query(0, ge=0, le=100),
    limit: int = Query(100, ge=1, le=500),
    offset: int = Query(0, ge=0),
):
    with db_session() as db:
        total = db.execute("""
            SELECT COUNT(*)
            FROM risk_assessments
            WHERE risk_score >= ?
        """, (minimum_score,)).fetchone()[0]

        rows = db.execute("""
            SELECT *
            FROM risk_assessments
            WHERE risk_score >= ?
            ORDER BY risk_score DESC
            LIMIT ? OFFSET ?
        """, (minimum_score, limit, offset)).fetchall()

    results = [
        decode_json_field(dict(row), "factors_json")
        for row in rows
    ]

    return {
        **page_metadata(rows, total, limit, offset),
        "assessments": results,
        "score_interpretation": (
            "Investigation priority, not probability of compromise."
        ),
    }


@app.get("/api/v1/risks/{device_ip}", tags=["Risk"])
def get_device_risk(device_ip: str):
    with db_session() as db:
        row = db.execute("""
            SELECT *
            FROM risk_assessments
            WHERE device_ip = ?
        """, (device_ip,)).fetchone()

        history = db.execute("""
            SELECT *
            FROM risk_assessment_history
            WHERE device_ip = ?
            ORDER BY assessed_at DESC
            LIMIT 30
        """, (device_ip,)).fetchall()

    if row is None:
        raise HTTPException(
            status_code=404,
            detail="Risk assessment not found.",
        )

    assessment = decode_json_field(
        dict(row),
        "factors_json",
    )

    return {
        "assessment": assessment,
        "history": [dict(item) for item in history],
        "interpretation": (
            "Investigation priority, not probability of compromise."
        ),
    }


# ---------------------------------------------------------
# INCIDENT MANAGEMENT
# ---------------------------------------------------------

@app.get("/api/v1/incidents", tags=["Incidents"])
def list_incidents(
    status: Literal[
        "open",
        "acknowledged",
        "resolved",
        "false_positive",
    ] | None = None,
    severity: Literal[
        "informational",
        "low",
        "medium",
        "high",
        "critical",
    ] | None = None,
    limit: int = Query(100, ge=1, le=500),
    offset: int = Query(0, ge=0),
):
    query = "SELECT * FROM incidents WHERE 1=1"
    params = []

    if status:
        query += " AND status = ?"
        params.append(status)

    if severity:
        query += " AND severity = ?"
        params.append(severity)

    count_query = query.replace("SELECT *", "SELECT COUNT(*)", 1)
    query += " ORDER BY updated_at DESC LIMIT ? OFFSET ?"

    with db_session() as db:
        total = db.execute(count_query, params).fetchone()[0]
        rows = db.execute(
            query, [*params, limit, offset]
        ).fetchall()

    return {
        **page_metadata(rows, total, limit, offset),
        "incidents": [dict(row) for row in rows],
    }


@app.get("/api/v1/incidents/{incident_id}", tags=["Incidents"])
def get_incident(incident_id: int):
    with db_session() as db:
        incident = db.execute("""
            SELECT *
            FROM incidents
            WHERE id = ?
        """, (incident_id,)).fetchone()

        if incident is None:
            raise HTTPException(
                status_code=404,
                detail="Incident not found.",
            )

        events = db.execute("""
            SELECT e.*
            FROM security_events AS e
            JOIN incident_events AS ie
                ON ie.event_id = e.id
            WHERE ie.incident_id = ?
            ORDER BY e.window_start, e.id
        """, (incident_id,)).fetchall()

        notes = db.execute("""
            SELECT *
            FROM incident_notes
            WHERE incident_id = ?
            ORDER BY id
        """, (incident_id,)).fetchall()

    event_data = [
        decode_json_field(dict(row), "evidence_json")
        for row in events
    ]

    return {
        "incident": dict(incident),
        "events": event_data,
        "notes": [dict(row) for row in notes],
    }


@app.patch("/api/v1/incidents/{incident_id}", tags=["Incidents"])
def update_incident(
    incident_id: int,
    payload: IncidentStatusUpdate,
):
    now = utc_now()
    new_status = payload.status

    with db_session() as db:
        incident = db.execute("""
            SELECT id, status
            FROM incidents
            WHERE id = ?
        """, (incident_id,)).fetchone()

        if incident is None:
            raise HTTPException(
                status_code=404,
                detail="Incident not found.",
            )

        previous_status = incident["status"]

        db.execute("""
            UPDATE incidents
            SET status = ?, updated_at = ?
            WHERE id = ?
        """, (new_status, now, incident_id))

        db.execute("""
            UPDATE security_events
            SET status = ?
            WHERE id IN (
                SELECT event_id
                FROM incident_events
                WHERE incident_id = ?
            )
        """, (new_status, incident_id))

        # Do not create duplicate audit entries for no-op updates.
        if previous_status != new_status:
            write_audit_log(
                db,
                action="incident.status_changed",
                resource_type="incident",
                resource_id=incident_id,
                details={
                    "previous_status": previous_status,
                    "new_status": new_status,
                },
            )

    return {
        "incident_id": incident_id,
        "status": new_status,
        "updated_at": now,
    }

@app.post(
    "/api/v1/incidents/{incident_id}/notes",
    tags=["Incidents"],
)
def create_incident_note(
    incident_id: int,
    payload: IncidentNoteCreate,
):
    now = utc_now()
    note_text = payload.note.strip()

    with db_session() as db:
        incident = db.execute("""
            SELECT id
            FROM incidents
            WHERE id = ?
        """, (incident_id,)).fetchone()

        if incident is None:
            raise HTTPException(
                status_code=404,
                detail="Incident not found.",
            )

        cursor = db.execute("""
            INSERT INTO incident_notes (
                incident_id,
                author,
                note,
                created_at
            )
            VALUES (?, ?, ?, ?)
        """, (
            incident_id,
            payload.author,
            note_text,
            now,
        ))

        note_id = cursor.lastrowid

        db.execute("""
            UPDATE incidents
            SET updated_at = ?
            WHERE id = ?
        """, (now, incident_id))

        write_audit_log(
            db,
            action="incident.note_created",
            resource_type="incident",
            resource_id=incident_id,
            details={
                "note_id": note_id,
                "note_author": payload.author,
                "note_length": len(note_text),
            },
        )

    return {
        "note_id": note_id,
        "incident_id": incident_id,
        "author": payload.author,
        "note": note_text,
        "created_at": now,
    }

# ---------------------------------------------------------
# DISCOVERY HISTORY
# ---------------------------------------------------------

@app.get("/api/v1/scans", tags=["Devices"])
def list_scans(
    limit: int = Query(50, ge=1, le=500),
    offset: int = Query(0, ge=0),
):
    with db_session() as db:
        total = db.execute(
            "SELECT COUNT(*) FROM scan_runs"
        ).fetchone()[0]

        rows = db.execute("""
            SELECT *
            FROM scan_runs
            ORDER BY id DESC
            LIMIT ? OFFSET ?
        """, (limit, offset)).fetchall()

    return {
        **page_metadata(rows, total, limit, offset),
        "scans": [dict(row) for row in rows],
    }

# ---------------------------------------------------------
# AUDIT LOG
# ---------------------------------------------------------

@app.get("/api/v1/audit", tags=["Audit"])
def list_audit_logs(
    action: str | None = Query(None, min_length=1, max_length=100),
    resource_type: str | None = Query(None, min_length=1, max_length=100),
    resource_id: str | None = Query(None, min_length=1, max_length=100),
    actor: str | None = Query(None, min_length=1, max_length=100),
    limit: int = Query(100, ge=1, le=500),
    offset: int = Query(0, ge=0),
):
    query = "SELECT * FROM api_audit_log WHERE 1=1"
    params = []

    filters = {
        "action": action,
        "resource_type": resource_type,
        "resource_id": resource_id,
        "actor": actor,
    }

    for column, value in filters.items():
        if value is not None:
            query += f" AND {column} = ?"
            params.append(value)

    count_query = query.replace(
        "SELECT *",
        "SELECT COUNT(*)",
        1,
    )

    query += " ORDER BY id DESC LIMIT ? OFFSET ?"

    with db_session() as db:
        total = db.execute(count_query, params).fetchone()[0]
        rows = db.execute(
            query,
            [*params, limit, offset],
        ).fetchall()

    entries = [
        decode_json_field(dict(row), "details_json")
        for row in rows
    ]

    return {
        **page_metadata(rows, total, limit, offset),
        "entries": entries,
    }

# ---------------------------------------------------------
# REAL-TIME EVENT STREAMING
# ---------------------------------------------------------

@app.post("/api/v1/ws-ticket", tags=["Realtime"])
def create_websocket_ticket():
    ticket = secrets.token_urlsafe(32)
    token_hash = hash_websocket_ticket(ticket)

    now_dt = datetime.now(timezone.utc)
    now = now_dt.isoformat(timespec="seconds").replace("+00:00", "Z")
    expires = (
        now_dt + timedelta(seconds=30)
    ).isoformat(timespec="seconds").replace("+00:00", "Z")

    with db_session() as db:
        # Remove expired tickets so the table does not grow indefinitely.
        db.execute(
            "DELETE FROM api_ws_tickets WHERE expires_at <= ?",
            (now,),
        )

        db.execute("""
            INSERT INTO api_ws_tickets (
                token_hash,
                created_at,
                expires_at
            )
            VALUES (?, ?, ?)
        """, (token_hash, now, expires))

    return {
        "ticket": ticket,
        "expires_in_seconds": 30,
        "websocket_path": "/ws/events",
    }


async def websocket_events(websocket: WebSocket):
    ticket = websocket.query_params.get("ticket")

    if not consume_websocket_ticket(ticket):
        await websocket.close(code=1008, reason="Invalid or expired ticket")
        return

    raw_after_id = websocket.query_params.get("after_id")

    if raw_after_id is not None:
        try:
            cursor = int(raw_after_id)
            if cursor < 0:
                raise ValueError
        except ValueError:
            await websocket.close(
                code=1008,
                reason="after_id must be a non-negative integer",
            )
            return
    else:
        cursor = None

    with db_session() as db:
        if cursor is None:
            cursor = db.execute(
                "SELECT COALESCE(MAX(id), 0) FROM api_realtime_events"
            ).fetchone()[0]

    await websocket.accept()

    await websocket.send_json({
        "type": "connection.ready",
        "last_event_id": cursor,
        "poll_interval_seconds": 1,
    })

    try:
        while True:
            with db_session() as db:
                rows = db.execute("""
                    SELECT
                        id,
                        event_type,
                        resource_type,
                        resource_id,
                        payload_json,
                        created_at
                    FROM api_realtime_events
                    WHERE id > ?
                    ORDER BY id ASC
                    LIMIT 100
                """, (cursor,)).fetchall()

            for row in rows:
                event = {
                    "id": row["id"],
                    "type": row["event_type"],
                    "resource": {
                        "type": row["resource_type"],
                        "id": row["resource_id"],
                    },
                    "timestamp": row["created_at"],
                    "data": json.loads(row["payload_json"]),
                }

                await websocket.send_json(event)
                cursor = row["id"]

            await asyncio.sleep(1)

    except WebSocketDisconnect:
        return


# Register as a plain Starlette WebSocket route. The connection is
# authenticated by its one-time ticket, not by the REST bearer token.
app.router.routes.append(
    WebSocketRoute(
        "/ws/events",
        websocket_events,
        name="realtime_events",
    )
)

