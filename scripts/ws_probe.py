import json
import os
import sqlite3
import sys
import time
from urllib.parse import quote
from urllib.request import Request, urlopen

from websockets.sync.client import connect

API = "http://127.0.0.1:8000"
WS = "ws://127.0.0.1:8000/ws/events"
DB = "data/netwatch.db"

if len(sys.argv) != 2:
    raise SystemExit(
        "Usage: python scripts/ws_probe.py <expected-device-mac>"
    )

expected_mac = sys.argv[1]
token = os.getenv("NETWATCH_API_TOKEN")

if not token:
    raise SystemExit("NETWATCH_API_TOKEN is not configured.")

# Capture the current event cursor before the test event is inserted.
db = sqlite3.connect(f"file:{DB}?mode=ro", uri=True)
try:
    after_id = db.execute(
        "SELECT COALESCE(MAX(id), 0) FROM api_realtime_events"
    ).fetchone()[0]
finally:
    db.close()

# Get a one-time connection ticket through authenticated REST.
request = Request(
    f"{API}/api/v1/ws-ticket",
    method="POST",
    headers={"Authorization": f"Bearer {token}"},
)

with urlopen(request, timeout=10) as response:
    ticket = json.loads(response.read())["ticket"]

url = f"{WS}?ticket={quote(ticket)}&after_id={after_id}"

print(f"Connecting. Last event ID: {after_id}")

with connect(url, open_timeout=10, close_timeout=3) as websocket:
    ready = json.loads(websocket.recv(timeout=10))

    if ready["type"] != "connection.ready":
        raise RuntimeError(f"Unexpected handshake: {ready}")

    print("WebSocket authenticated and connected.")
    print("Waiting for the synthetic device event...")

    deadline = time.monotonic() + 60

    while time.monotonic() < deadline:
        event = json.loads(
            websocket.recv(timeout=max(1, deadline - time.monotonic()))
        )

        if (
            event.get("type") == "device.discovered"
            and event.get("resource", {}).get("id") == expected_mac
        ):
            print("\nCROSS-PROCESS EVENT RECEIVED:")
            print(json.dumps(event, indent=2))
            break
    else:
        raise TimeoutError(
            f"No discovery event received for {expected_mac}"
        )

print("\nCross-process WebSocket test PASSED.")
