"""What an audit event says.

Five event types, all with ``v``, ``type``, ``id``, ``ts`` and ``upstream``:

``request``
    A client request, written *before* it is forwarded (or refused): who
    (``agent``, ``roles``, ``task``, ``client``), what (``method``, ``kind``,
    ``target``, ``arguments_sha256``), where (``session``, ``protocol``), the
    decision (``decision``: ``forwarded`` or ``denied``, with ``stage``,
    ``rule`` and ``reason``), and the ``trace_id`` that links it to its spans.
``result``
    The outcome of a forwarded request, linked by ``request``: ``status``
    (HTTP), ``outcome`` (``ok``, ``tool_error``, ``error``, ``none`` or
    ``refused``), ``error_code``, ``result_sha256`` and ``duration_ms``.
``message``
    A client notification, or an answer to one of the server's own requests.
``transport``
    A GET (server-initiated stream) or DELETE (end of session).
``rejected``
    A request refused before any message was read: bad credentials, an
    unknown upstream or session, a malformed body. These are attack signals.

Arguments are stored only as a SHA-256 digest unless ``record_arguments`` is
on: they may hold personal data or secrets.
"""

import uuid
from datetime import UTC, datetime
from typing import Any, Final

SCHEMA_VERSION: Final = 1


def event(event_type: str, upstream: str | None, /, **fields: Any) -> dict[str, Any]:
    """An event of type ``event_type``, with ``None`` fields left out."""
    body: dict[str, Any] = {
        "v": SCHEMA_VERSION,
        "type": event_type,
        "id": uuid.uuid4().hex,
        "ts": datetime.now(UTC).isoformat(timespec="milliseconds").replace("+00:00", "Z"),
        "upstream": upstream,
    }
    body.update(fields)
    return {key: value for key, value in body.items() if value is not None}
