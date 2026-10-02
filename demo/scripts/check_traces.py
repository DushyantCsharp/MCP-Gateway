"""CI check: the gateway's traces reached Jaeger. Polls Jaeger's API v3 for up to a minute."""

import json
import sys
import time
import urllib.request
from datetime import UTC, datetime, timedelta

JAEGER = sys.argv[1] if len(sys.argv) > 1 else "http://127.0.0.1:16686"


def span_names() -> set[str]:
    now = datetime.now(UTC)
    window = {
        "query.service_name": "mcp-customs",
        "query.start_time_min": (now - timedelta(hours=1)).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "query.start_time_max": (now + timedelta(minutes=5)).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "query.search_depth": "100",
    }
    url = f"{JAEGER}/api/v3/traces?" + "&".join(f"{key}={value}" for key, value in window.items())
    with urllib.request.urlopen(url, timeout=5) as response:  # noqa: S310 - fixed local URL
        payload = json.load(response)
    return {
        span["name"]
        for resource in payload.get("result", {}).get("resourceSpans", [])
        for scope in resource["scopeSpans"]
        for span in scope["spans"]
    }


required = {"tools/call transfer_funds", "stage policy", "POST finance"}
for _ in range(30):
    try:
        names = span_names()
    except OSError:
        names = set()
    if required <= names:
        print(f"traces ok: {sorted(names)}")
        sys.exit(0)
    time.sleep(2)
sys.exit(f"missing spans in Jaeger: {sorted(required - names)}")
