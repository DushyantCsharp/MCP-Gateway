"""The redaction stage: keep secrets and personal data from crossing, in either direction.

On the way out, the string arguments of ``tools/call`` and ``prompts/get`` are
scanned for the kinds configured under ``requests`` (by default secrets, so a
model cannot paste a credential into a tool). On the way back, every string a
model would read in the answer is scanned for the kinds under ``responses``
(by default secrets and personal data). What happens on a finding depends on
the mode:

``redact``
    The value is replaced by ``[REDACTED:<kind>]`` and the message goes on.
    Results also say what was redacted, under ``_meta``.
``flag``
    Nothing is changed; the finding is recorded in the audit log and span,
    and in a result's ``_meta``.
``block``
    The call is refused (a request) or the result withheld (a response), with
    a reason that names the kinds and where they were, never the values.

Put this stage after the policy stage: policy decides on the real argument
values (an allowed recipient, an account number), and only then are they
scrubbed.
"""

import copy
import logging
from collections.abc import Iterable
from typing import Any, Final, Literal

from mcp_customs.detectors.sensitive import Finding, SensitiveScanner, expand, redact, strings
from mcp_customs.jsonrpc import JSONObject, MessageKind, error_object
from mcp_customs.pipeline.base import (
    CONTINUE,
    ClientMessageContext,
    ClientOutcome,
    Replace,
    ServerMessageContext,
    ServerOutcome,
    Stage,
)
from mcp_customs.pipeline.content import Path, set_at, text_fields
from mcp_customs.pipeline.replies import error_reply, tool_error_reply
from mcp_customs.proxy.routing import is_modern

logger = logging.getLogger(__name__)

type Mode = Literal["redact", "flag", "block"]

SENSITIVE_DATA: Final = -32092
META_KEY: Final = "io.github.mcp-customs/redaction"
ARGUMENT_METHODS: Final = frozenset({"tools/call", "prompts/get"})
RESULT_METHODS: Final = frozenset({"tools/call", "resources/read", "prompts/get"})

type Hits = list[tuple[Path, str, list[Finding]]]


def _describe(hits: Hits) -> tuple[str, str]:
    kinds = sorted({finding.kind for _, _, findings in hits for finding in findings})
    where = sorted({".".join(map(str, path)) for path, _, _ in hits})
    return ", ".join(kinds), ", ".join(where)


def _scrubbed(container: Any, hits: Hits) -> Any:
    scrubbed = copy.deepcopy(container)
    for path, text, findings in hits:
        set_at(scrubbed, path, redact(text, findings))
    return scrubbed


class RedactionStage(Stage):
    name = "redaction"

    def __init__(
        self,
        scanner: SensitiveScanner,
        *,
        requests: Iterable[str] = ("secrets",),
        responses: Iterable[str] = ("secrets", "pii"),
        mode: Mode = "redact",
    ) -> None:
        self.scanner = scanner
        self.request_kinds = expand(requests)
        self.response_kinds = expand(responses)
        self.mode = mode

    def _scan(self, fields: Iterable[tuple[Path, str]], kinds: frozenset[str]) -> Hits:
        hits: Hits = []
        for path, text in fields:
            if found := self.scanner.find(text, kinds):
                hits.append((path, text, found))
        return hits

    def _note(self, annotations: dict[str, dict[str, Any]], direction: str, hits: Hits) -> None:
        kinds, where = _describe(hits)
        count = sum(len(findings) for _, _, findings in hits)
        annotations[self.name] = {"direction": direction, "found": count, "kinds": kinds, "action": self.mode}
        logger.info("redaction: %d %s value(s) in a %s (%s); %s", count, kinds, direction, where, self.mode)

    # -- on the way out ---------------------------------------------------------------------------

    async def on_client_message(self, ctx: ClientMessageContext) -> ClientOutcome:
        message = ctx.message
        if not self.request_kinds or not message.is_request or message.method not in ARGUMENT_METHODS:
            return CONTINUE
        arguments = message.params.get("arguments")
        hits = self._scan(strings(arguments, ("arguments",)), self.request_kinds)
        if not hits:
            return CONTINUE
        self._note(ctx.annotations, "request", hits)
        kinds, where = _describe(hits)
        match self.mode:
            case "flag":
                return CONTINUE
            case "block":
                reason = f"Blocked by the gateway: the call's arguments contain {kinds} (in {where})."
                if message.method == "tools/call":
                    return tool_error_reply(ctx, reason)
                return error_reply(ctx, SENSITIVE_DATA, reason, {"kinds": kinds})
            case "redact":
                return Replace({**message.raw, "params": _scrubbed(message.params, hits)})

    # -- on the way back --------------------------------------------------------------------------

    async def on_server_message(self, ctx: ServerMessageContext) -> ServerOutcome:
        request = ctx.request
        method = request.method if request is not None else None
        if (
            not self.response_kinds
            or method not in RESULT_METHODS
            or ctx.message.kind is not MessageKind.RESPONSE
        ):
            return CONTINUE
        result = ctx.message.raw.get("result")
        if not isinstance(result, dict):
            return CONTINUE
        hits = self._scan(text_fields(result, method), self.response_kinds)
        if not hits:
            return CONTINUE
        self._note(ctx.annotations, "response", hits)
        kinds, where = _describe(hits)
        finding: JSONObject = {"kinds": kinds.split(", "), "fields": where.split(", "), "action": self.mode}
        match self.mode:
            case "block":
                reason = f"Withheld by the gateway: the result contains {kinds}."
                if method != "tools/call":
                    return Replace(error_object(ctx.message.id, SENSITIVE_DATA, reason, {"kinds": kinds}))
                blocked: JSONObject = {"content": [{"type": "text", "text": reason}], "isError": True}
                if is_modern(ctx.exchange.protocol_version):
                    blocked["resultType"] = "complete"
                return Replace({"jsonrpc": "2.0", "id": ctx.message.id, "result": blocked})
            case "flag":
                updated = copy.deepcopy(result)
            case "redact":
                updated = _scrubbed(result, hits)
        updated["_meta"] = {**(updated.get("_meta") or {}), META_KEY: finding}
        return Replace({**ctx.message.raw, "result": updated})
