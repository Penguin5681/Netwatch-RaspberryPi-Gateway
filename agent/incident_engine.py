import argparse
import hashlib
import json

from collections import Counter
from datetime import datetime, timedelta, timezone

from agent.database import connect, initialize


ACTIVE_STATUSES = ("open", "acknowledged")

SEVERITY_RANK = {
    "informational": 0,
    "low": 1,
    "medium": 2,
    "high": 3,
    "critical": 4,
}


def utc_now():
    return (
        datetime.now(timezone.utc)
        .isoformat(timespec="seconds")
        .replace("+00:00", "Z")
    )


def parse_time(value):
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


def ensure_schema(db):
    db.executescript("""
        CREATE TABLE IF NOT EXISTS incidents (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            incident_key TEXT NOT NULL UNIQUE,
            subject_ip TEXT NOT NULL,
            title TEXT NOT NULL,
            severity TEXT NOT NULL,
            status TEXT NOT NULL DEFAULT 'open',
            first_seen TEXT NOT NULL,
            last_seen TEXT NOT NULL,
            event_count INTEGER NOT NULL DEFAULT 0,
            risk_score INTEGER NOT NULL DEFAULT 0,
            summary TEXT NOT NULL,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL
        );

        CREATE INDEX IF NOT EXISTS idx_incidents_subject
        ON incidents(subject_ip);

        CREATE INDEX IF NOT EXISTS idx_incidents_status
        ON incidents(status);

        CREATE INDEX IF NOT EXISTS idx_incidents_severity
        ON incidents(severity);

        CREATE TABLE IF NOT EXISTS incident_events (
            event_id INTEGER PRIMARY KEY,
            incident_id INTEGER NOT NULL,
            relationship TEXT NOT NULL DEFAULT 'related_evidence',
            linked_at TEXT NOT NULL,
            FOREIGN KEY(event_id) REFERENCES security_events(id),
            FOREIGN KEY(incident_id) REFERENCES incidents(id)
        );

        CREATE INDEX IF NOT EXISTS idx_incident_events_incident
        ON incident_events(incident_id);

        CREATE TABLE IF NOT EXISTS incident_notes (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            incident_id INTEGER NOT NULL,
            author TEXT NOT NULL DEFAULT 'operator',
            note TEXT NOT NULL,
            created_at TEXT NOT NULL,
            FOREIGN KEY(incident_id) REFERENCES incidents(id)
        );

        CREATE INDEX IF NOT EXISTS idx_incident_notes_incident
        ON incident_notes(incident_id);
    """)


def make_incident_key(subject_ip, first_event_id):
    value = f"{subject_ip}:{first_event_id}"
    return hashlib.sha256(value.encode()).hexdigest()


def severity_from_events(events):
    severities = [
        event["severity"].lower()
        for event in events
    ]

    if not severities:
        return "informational"

    return max(
        severities,
        key=lambda item: SEVERITY_RANK.get(item, 0),
    )


def get_current_risk(db, subject_ip):
    tables = {
        row["name"]
        for row in db.execute("""
            SELECT name
            FROM sqlite_master
            WHERE type = 'table'
        """)
    }

    if "risk_assessments" not in tables:
        return 0

    row = db.execute("""
        SELECT risk_score
        FROM risk_assessments
        WHERE device_ip = ?
    """, (subject_ip,)).fetchone()

    return int(row["risk_score"]) if row else 0


def create_incident(db, event):
    subject_ip = event["source_ip"]
    key = make_incident_key(subject_ip, event["id"])
    now = utc_now()
    event_time = event["window_start"]

    title = f"Suspicious Network Activity — {subject_ip}"

    summary = (
        f"Investigation created from security event "
        f"#{event['id']} ({event['detection_type']})."
    )

    cursor = db.execute("""
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
        VALUES (?, ?, ?, ?, 'open', ?, ?, 0, 0, ?, ?, ?)
    """, (
        key,
        subject_ip,
        title,
        event["severity"],
        event_time,
        event_time,
        summary,
        now,
        now,
    ))

    return cursor.lastrowid


def find_related_incident(
    db,
    subject_ip,
    event_time,
    gap_minutes,
):
    gap = timedelta(minutes=gap_minutes)

    rows = db.execute("""
        SELECT id, first_seen, last_seen
        FROM incidents
        WHERE subject_ip = ?
          AND status IN ('open', 'acknowledged')
        ORDER BY last_seen DESC
    """, (subject_ip,)).fetchall()

    candidates = []

    for row in rows:
        first = parse_time(row["first_seen"])
        last = parse_time(row["last_seen"])

        if event_time < first:
            distance = first - event_time
        elif event_time > last:
            distance = event_time - last
        else:
            distance = timedelta(0)

        if distance <= gap:
            candidates.append((distance, row["id"]))

    if not candidates:
        return None

    candidates.sort(key=lambda item: item[0])
    return candidates[0][1]


def refresh_incident(db, incident_id):
    events = db.execute("""
        SELECT e.*
        FROM security_events AS e
        JOIN incident_events AS ie
            ON ie.event_id = e.id
        WHERE ie.incident_id = ?
        ORDER BY e.window_start, e.id
    """, (incident_id,)).fetchall()

    if not events:
        return

    subject_ip = events[0]["source_ip"]

    timestamps = [
        event["window_start"]
        for event in events
    ]

    first_seen = min(timestamps)
    last_seen = max(timestamps)

    severity = severity_from_events(events)
    risk_score = get_current_risk(db, subject_ip)

    counts = Counter(
        event["detection_type"]
        for event in events
    )

    detection_summary = ", ".join(
        f"{name} ({count})"
        for name, count in sorted(counts.items())
    )

    summary = (
        f"{len(events)} correlated security event(s) associated "
        f"with {subject_ip}. Detection types: {detection_summary}."
    )

    now = utc_now()

    db.execute("""
        UPDATE incidents
        SET severity = ?,
            first_seen = ?,
            last_seen = ?,
            event_count = ?,
            risk_score = ?,
            summary = ?,
            updated_at = ?
        WHERE id = ?
    """, (
        severity,
        first_seen,
        last_seen,
        len(events),
        risk_score,
        summary,
        now,
        incident_id,
    ))


def correlate(lookback_hours=24, gap_minutes=10):
    if lookback_hours < 1 or gap_minutes < 1:
        raise ValueError("Lookback and gap must be positive.")

    initialize()

    db = connect()
    ensure_schema(db)

    cutoff = (
        datetime.now(timezone.utc)
        - timedelta(hours=lookback_hours)
    ).isoformat(timespec="seconds").replace("+00:00", "Z")

    events = db.execute("""
        SELECT e.*
        FROM security_events AS e
        LEFT JOIN incident_events AS ie
            ON ie.event_id = e.id
        WHERE e.created_at >= ?
          AND e.status IN ('open', 'acknowledged')
          AND e.source_ip IS NOT NULL
          AND ie.event_id IS NULL
        ORDER BY e.window_start, e.id
    """, (cutoff,)).fetchall()

    affected_incidents = set()
    linked_count = 0
    created_count = 0

    print("\n===== NETWATCH INCIDENT CORRELATION =====")
    print(f"Lookback period : {lookback_hours} hours")
    print(f"Correlation gap : {gap_minutes} minutes")
    print(f"Unlinked events : {len(events)}")

    with db:
        for event in events:
            event_time = parse_time(event["window_start"])
            subject_ip = event["source_ip"]

            incident_id = find_related_incident(
                db,
                subject_ip,
                event_time,
                gap_minutes,
            )

            if incident_id is None:
                incident_id = create_incident(db, event)
                created_count += 1

            db.execute("""
                INSERT INTO incident_events (
                    event_id,
                    incident_id,
                    relationship,
                    linked_at
                )
                VALUES (?, ?, 'related_evidence', ?)
            """, (
                event["id"],
                incident_id,
                utc_now(),
            ))

            affected_incidents.add(incident_id)
            linked_count += 1

        for incident_id in affected_incidents:
            refresh_incident(db, incident_id)

    total_incidents = db.execute("""
        SELECT COUNT(*)
        FROM incidents
    """).fetchone()[0]

    active_incidents = db.execute("""
        SELECT COUNT(*)
        FROM incidents
        WHERE status IN ('open', 'acknowledged')
    """).fetchone()[0]

    db.close()

    print(f"Events linked    : {linked_count}")
    print(f"New incidents    : {created_count}")
    print(f"Incidents updated: {len(affected_incidents)}")
    print(f"Total incidents  : {total_incidents}")
    print(f"Active incidents : {active_incidents}")


def list_incidents(limit=30, status=None):
    initialize()

    db = connect()
    ensure_schema(db)

    query = "SELECT * FROM incidents"
    params = []

    if status:
        query += " WHERE status = ?"
        params.append(status)

    query += " ORDER BY updated_at DESC LIMIT ?"
    params.append(limit)

    rows = db.execute(query, params).fetchall()

    print("\n===== NETWATCH INCIDENT REGISTER =====")

    if not rows:
        print("No incidents found.")
        db.close()
        return

    for row in rows:
        print("\n----------------------------------------")
        print(f"Incident ID : {row['id']}")
        print(f"Title       : {row['title']}")
        print(f"Subject IP  : {row['subject_ip']}")
        print(f"Severity    : {row['severity']}")
        print(f"Risk score  : {row['risk_score']}/100")
        print(f"Status      : {row['status']}")
        print(f"Events      : {row['event_count']}")
        print(f"First seen  : {row['first_seen']}")
        print(f"Last seen   : {row['last_seen']}")
        print(f"Summary     : {row['summary']}")

    db.close()


def show_incident(incident_id):
    initialize()

    db = connect()
    ensure_schema(db)

    incident = db.execute("""
        SELECT *
        FROM incidents
        WHERE id = ?
    """, (incident_id,)).fetchone()

    if incident is None:
        print(f"Incident {incident_id} not found.")
        db.close()
        return

    print("\n===== INCIDENT DETAILS =====")
    print(f"ID         : {incident['id']}")
    print(f"Title      : {incident['title']}")
    print(f"Subject IP : {incident['subject_ip']}")
    print(f"Severity   : {incident['severity']}")
    print(f"Risk score : {incident['risk_score']}/100")
    print(f"Status     : {incident['status']}")
    print(f"First seen : {incident['first_seen']}")
    print(f"Last seen  : {incident['last_seen']}")
    print(f"Summary    : {incident['summary']}")

    events = db.execute("""
        SELECT e.*
        FROM security_events AS e
        JOIN incident_events AS ie
            ON ie.event_id = e.id
        WHERE ie.incident_id = ?
        ORDER BY e.window_start, e.id
    """, (incident_id,)).fetchall()

    print("\n===== CORRELATED SECURITY EVENTS =====")

    for event in events:
        print("\n----------------------------------------")
        print(f"Event ID    : {event['id']}")
        print(f"Type        : {event['detection_type']}")
        print(f"Severity    : {event['severity']}")
        print(f"Source      : {event['source_ip']}")
        print(f"Destination : {event['destination_ip']}")
        print(f"Port        : {event['destination_port']}")
        print(f"Time        : {event['window_start']}")
        print(f"Explanation : {event['explanation']}")

        try:
            evidence = json.loads(event["evidence_json"])
            print(
                "Evidence    : "
                + json.dumps(evidence, sort_keys=True)
            )
        except (TypeError, json.JSONDecodeError):
            pass

    notes = db.execute("""
        SELECT author, note, created_at
        FROM incident_notes
        WHERE incident_id = ?
        ORDER BY id
    """, (incident_id,)).fetchall()

    print("\n===== INVESTIGATION NOTES =====")

    if not notes:
        print("No notes recorded.")

    for note in notes:
        print(
            f"{note['created_at']} | "
            f"{note['author']}: {note['note']}"
        )

    db.close()


def update_status(incident_id, status):
    allowed = {
        "open",
        "acknowledged",
        "resolved",
        "false_positive",
    }

    if status not in allowed:
        raise ValueError("Invalid incident status.")

    initialize()

    db = connect()
    ensure_schema(db)

    incident = db.execute("""
        SELECT id
        FROM incidents
        WHERE id = ?
    """, (incident_id,)).fetchone()

    if incident is None:
        print(f"Incident {incident_id} not found.")
        db.close()
        return

    with db:
        db.execute("""
            UPDATE incidents
            SET status = ?,
                updated_at = ?
            WHERE id = ?
        """, (status, utc_now(), incident_id))

        if status in {"open", "acknowledged"}:
            event_status = status
        elif status in {"resolved", "false_positive"}:
            event_status = status
        else:
            event_status = "open"

        db.execute("""
            UPDATE security_events
            SET status = ?
            WHERE id IN (
                SELECT event_id
                FROM incident_events
                WHERE incident_id = ?
            )
        """, (event_status, incident_id))

    db.close()

    print(f"Incident {incident_id} updated to: {status}")


def add_note(incident_id, note, author="operator"):
    if not note.strip():
        raise ValueError("Note cannot be empty.")

    initialize()

    db = connect()
    ensure_schema(db)

    incident = db.execute("""
        SELECT id
        FROM incidents
        WHERE id = ?
    """, (incident_id,)).fetchone()

    if incident is None:
        print(f"Incident {incident_id} not found.")
        db.close()
        return

    with db:
        db.execute("""
            INSERT INTO incident_notes (
                incident_id,
                author,
                note,
                created_at
            )
            VALUES (?, ?, ?, ?)
        """, (
            incident_id,
            author,
            note.strip(),
            utc_now(),
        ))

        db.execute("""
            UPDATE incidents
            SET updated_at = ?
            WHERE id = ?
        """, (utc_now(), incident_id))

    db.close()

    print(f"Note added to incident {incident_id}.")


def main():
    parser = argparse.ArgumentParser(
        description="NetWatch incident correlation and management"
    )

    subparsers = parser.add_subparsers(
        dest="command",
        required=True,
    )

    correlate_parser = subparsers.add_parser(
        "correlate",
        help="Correlate unassigned security events",
    )

    correlate_parser.add_argument(
        "--lookback-hours",
        type=int,
        default=24,
    )

    correlate_parser.add_argument(
        "--gap-minutes",
        type=int,
        default=10,
    )

    list_parser = subparsers.add_parser(
        "list",
        help="List incidents",
    )

    list_parser.add_argument("--limit", type=int, default=30)

    list_parser.add_argument(
        "--status",
        choices=[
            "open",
            "acknowledged",
            "resolved",
            "false_positive",
        ],
    )

    show_parser = subparsers.add_parser(
        "show",
        help="Show incident details",
    )

    show_parser.add_argument("incident_id", type=int)

    status_parser = subparsers.add_parser(
        "status",
        help="Change incident status",
    )

    status_parser.add_argument("incident_id", type=int)

    status_parser.add_argument(
        "status",
        choices=[
            "open",
            "acknowledged",
            "resolved",
            "false_positive",
        ],
    )

    note_parser = subparsers.add_parser(
        "note",
        help="Add an investigation note",
    )

    note_parser.add_argument("incident_id", type=int)
    note_parser.add_argument("text")
    note_parser.add_argument("--author", default="operator")

    args = parser.parse_args()

    if args.command == "correlate":
        correlate(
            lookback_hours=args.lookback_hours,
            gap_minutes=args.gap_minutes,
        )

    elif args.command == "list":
        if args.limit < 1:
            parser.error("--limit must be positive.")

        list_incidents(args.limit, args.status)

    elif args.command == "show":
        show_incident(args.incident_id)

    elif args.command == "status":
        update_status(args.incident_id, args.status)

    elif args.command == "note":
        add_note(
            args.incident_id,
            args.text,
            args.author,
        )


if __name__ == "__main__":
    main()
