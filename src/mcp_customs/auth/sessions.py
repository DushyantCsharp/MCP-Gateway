"""Binding handshake-era session ids to the agent that opened them.

A session id identifies a stream of server-to-client traffic, including the
server's own requests (sampling, elicitation) that may carry the opening
agent's data. Another agent holding a valid token must not be able to attach
to it, so the gateway never shows the client the upstream's session id.
Instead it issues ``<upstream id>.<tag>``, where the tag is an HMAC over the
upstream, the agent and the upstream id. The binding is stateless: it holds
across restarts and replicas that share the key.
"""

import base64
import hashlib
import hmac
import secrets
from typing import Final

_TAG_BYTES: Final = 16


class SessionBinder:
    def __init__(self, key: bytes | None = None) -> None:
        self._key = key if key is not None else secrets.token_bytes(32)

    def _tag(self, upstream: str, agent: str, session_id: str) -> str:
        message = "\0".join((upstream, agent, session_id)).encode()
        digest = hmac.new(self._key, message, hashlib.sha256).digest()[:_TAG_BYTES]
        return base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")

    def bind(self, upstream: str, agent: str, session_id: str) -> str:
        """The id to give the client for an upstream session."""
        return f"{session_id}.{self._tag(upstream, agent, session_id)}"

    def unbind(self, upstream: str, agent: str, client_session_id: str) -> str | None:
        """The upstream id behind ``client_session_id``, or ``None`` if it is not this agent's."""
        session_id, sep, tag = client_session_id.rpartition(".")
        if not sep or not session_id:
            return None
        expected = self._tag(upstream, agent, session_id)
        return session_id if hmac.compare_digest(tag, expected) else None
