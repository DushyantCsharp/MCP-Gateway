"""The approvals page and its JSON API (the resume webhook).

Approvers authenticate with a token from the same identity provider as the
agents, carrying the approver role. The page keeps the token in an HttpOnly,
``SameSite=Strict`` cookie scoped to ``/approvals``, and every form carries a
CSRF token derived from it. The API takes the token as a bearer header, for
chat bots, scripts and ``customs approvals``.

Everything shown is escaped, and the page sets a Content Security Policy that
allows no scripts: the arguments on display were written by an agent, possibly
one steered by a prompt injection aimed at the approver.
"""

import hashlib
import hmac
import html
import json
import logging
from datetime import UTC, datetime
from typing import Any, Final
from urllib.parse import quote

from fastapi import APIRouter, Request
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse, Response

from mcp_customs.approvals.service import ApprovalService, NotPendingError, SelfApprovalError
from mcp_customs.approvals.store import ApprovalStoreError, HeldCall, Status
from mcp_customs.auth import AuthError, Identity, JwtAuthenticator

logger = logging.getLogger(__name__)

COOKIE: Final = "customs_approver"
PATH: Final = "/approvals"
_MAX_ARGUMENTS_SHOWN: Final = 20_000
_SECURITY_HEADERS: Final = {
    "content-security-policy": (
        "default-src 'none'; style-src 'unsafe-inline'; form-action 'self'; "
        "frame-ancestors 'none'; base-uri 'none'"
    ),
    "x-content-type-options": "nosniff",
    "referrer-policy": "no-referrer",
    "cache-control": "no-store",
}


class ApprovalsWeb:
    def __init__(
        self,
        service: ApprovalService,
        authenticator: JwtAuthenticator,
        *,
        approver_role: str,
        csrf_key: bytes,
        secure_cookies: bool = True,
    ) -> None:
        self.service = service
        self.authenticator = authenticator
        self.approver_role = approver_role
        self.csrf_key = csrf_key
        self.secure_cookies = secure_cookies

    async def approver(self, token: str | None) -> Identity:
        """The approver a token identifies. Raises :class:`AuthError` for anyone else."""
        if not token:
            raise AuthError("sign in with an approver token", error=None)
        identity = await self.authenticator.authenticate(f"Bearer {token}")
        if self.approver_role not in identity.roles:
            raise AuthError(
                f"the token lacks the {self.approver_role!r} role", error="insufficient_scope", status=403
            )
        return identity

    def csrf(self, token: str) -> str:
        return hmac.new(self.csrf_key, token.encode("utf-8"), hashlib.sha256).hexdigest()


def _web(request: Request) -> ApprovalsWeb:
    web: ApprovalsWeb | None = getattr(request.app.state, "approvals_web", None)
    if web is None:
        raise RuntimeError("approvals are not configured")
    return web


def _bearer(request: Request) -> str | None:
    scheme, _, token = request.headers.get("authorization", "").partition(" ")
    return token.strip() if scheme.lower() == "bearer" and token.strip() else None


def describe(call: HeldCall) -> dict[str, Any]:
    """A held call as the API shows it: everything an approver needs, nothing to replay it with."""

    def when(value: datetime | None) -> str | None:
        return value.astimezone(UTC).isoformat(timespec="seconds").replace("+00:00", "Z") if value else None

    return {
        "id": call.id,
        "status": call.status.value,
        "agent": call.agent,
        "upstream": call.upstream,
        "method": call.method,
        "target": call.target,
        "arguments": call.arguments,
        "reason": call.reason,
        "stage": call.stage,
        "rule": call.rule,
        "created_at": when(call.created_at),
        "expires_at": when(call.expires_at),
        "decided_at": when(call.decided_at),
        "decided_by": call.decided_by,
        "decision_reason": call.decision_reason,
    }


def _problem(status: int, message: str) -> JSONResponse:
    return JSONResponse({"error": message}, status_code=status, headers={"cache-control": "no-store"})


async def _decide(
    web: ApprovalsWeb, held_id: str, decision: Any, reason: Any, approver: Identity
) -> HeldCall:
    if decision not in ("approve", "deny"):
        raise ValueError("decision must be 'approve' or 'deny'")
    if reason is not None and not isinstance(reason, str):
        raise ValueError("reason must be a string")
    text = reason.strip()[:500] if isinstance(reason, str) and reason.strip() else None
    return await web.service.decide(
        held_id, approve=decision == "approve", approver=approver.agent, reason=text
    )


def router() -> APIRouter:
    routes = APIRouter(include_in_schema=False)

    # -- JSON API: the resume webhook ------------------------------------------------------------

    @routes.get(f"{PATH}/api/calls")
    async def list_calls(request: Request, status: str = "pending", limit: int = 50) -> Response:
        web = _web(request)
        try:
            await web.approver(_bearer(request))
        except AuthError as exc:
            return _problem(exc.status, exc.description)
        try:
            statuses = None if status == "all" else [Status(name) for name in status.split(",")]
        except ValueError:
            return _problem(400, f"unknown status {status!r}")
        calls = await web.service.recent(statuses, max(1, min(limit, 500)))
        return JSONResponse([describe(call) for call in calls], headers={"cache-control": "no-store"})

    @routes.get(f"{PATH}/api/calls/{{held_id}}")
    async def get_call(request: Request, held_id: str) -> Response:
        web = _web(request)
        try:
            await web.approver(_bearer(request))
        except AuthError as exc:
            return _problem(exc.status, exc.description)
        call = await web.service.get(held_id)
        if call is None:
            return _problem(404, "no such held call")
        return JSONResponse(describe(call), headers={"cache-control": "no-store"})

    @routes.post(f"{PATH}/api/calls/{{held_id}}/decision")
    async def decide_call(request: Request, held_id: str) -> Response:
        web = _web(request)
        try:
            approver = await web.approver(_bearer(request))
        except AuthError as exc:
            return _problem(exc.status, exc.description)
        try:
            body = await request.json()
        except json.JSONDecodeError:
            return _problem(400, "expected a JSON object")
        if not isinstance(body, dict):
            return _problem(400, "expected a JSON object")
        try:
            call = await _decide(web, held_id, body.get("decision"), body.get("reason"), approver)
        except ValueError as exc:
            return _problem(400, str(exc))
        except SelfApprovalError:
            return _problem(403, "an agent cannot approve its own call")
        except NotPendingError:
            existing = await web.service.get(held_id)
            if existing is None:
                return _problem(404, "no such held call")
            return _problem(409, f"the call is already {existing.status.value}")
        except ApprovalStoreError:
            logger.exception("approval store unavailable")
            return _problem(503, "approval store unavailable")
        return JSONResponse(describe(call), headers={"cache-control": "no-store"})

    # -- the page -------------------------------------------------------------------------------

    @routes.get(PATH)
    async def page(request: Request, done: str | None = None) -> Response:
        web = _web(request)
        token = request.cookies.get(COOKIE)
        if token is None:
            return _html(_login_page(None))
        try:
            approver = await web.approver(token)
        except AuthError as exc:
            return _html(_login_page(exc.description), exc.status)
        try:
            pending = await web.service.recent([Status.PENDING], 200)
            decided = [c for c in await web.service.recent(None, 60) if c.status is not Status.PENDING][:30]
        except ApprovalStoreError:
            logger.exception("approval store unavailable")
            return _html(_frame("Approvals", "<p class=error>The approval store is unavailable.</p>"), 503)
        return _html(
            _list_page(approver, sorted(pending, key=lambda c: c.created_at), decided, web.csrf(token), done)
        )

    @routes.post(f"{PATH}/login")
    async def login(request: Request) -> Response:
        web = _web(request)
        form = await request.form()
        token = str(form.get("token") or "").strip()
        try:
            await web.approver(token)
        except AuthError as exc:
            return _html(_login_page(exc.description), exc.status)
        response = RedirectResponse(PATH, status_code=303)
        response.set_cookie(
            COOKIE,
            token,
            max_age=8 * 3600,
            path=PATH,
            secure=web.secure_cookies,
            httponly=True,
            samesite="strict",
        )
        return response

    @routes.post(f"{PATH}/logout")
    async def logout(request: Request) -> Response:
        response = RedirectResponse(PATH, status_code=303)
        response.delete_cookie(
            COOKIE, path=PATH, secure=_web(request).secure_cookies, httponly=True, samesite="strict"
        )
        return response

    @routes.post(f"{PATH}/{{held_id}}/decision")
    async def decide_form(request: Request, held_id: str) -> Response:
        web = _web(request)
        token = request.cookies.get(COOKIE)
        if token is None:
            return _html(_login_page("sign in with an approver token"), 401)
        try:
            approver = await web.approver(token)
        except AuthError as exc:
            return _html(_login_page(exc.description), exc.status)
        form = await request.form()
        if not hmac.compare_digest(str(form.get("csrf") or ""), web.csrf(token)):
            return _html(
                _frame("Approvals", "<p class=error>That form has expired. Go back and try again.</p>"), 403
            )
        decision = form.get("decision")
        try:
            call = await _decide(web, held_id, decision, form.get("reason"), approver)
            outcome = f"{call.status.value}:{held_id}"
        except SelfApprovalError:
            outcome = f"self:{held_id}"
        except (NotPendingError, ValueError):
            outcome = f"stale:{held_id}"
        return RedirectResponse(f"{PATH}?done={quote(outcome)}", status_code=303)

    return routes


# -- rendering ------------------------------------------------------------------------------------

_STYLE: Final = """
:root { color-scheme: light dark; --fg: #1d1d1f; --muted: #6e6e73; --line: #d2d2d7; --bg: #fbfbfd;
  --card: #fff; --ok: #1a7f37; --no: #c62828; --accent: #0b57d0; }
@media (prefers-color-scheme: dark) { :root { --fg: #f5f5f7; --muted: #a1a1a6; --line: #3a3a3c;
  --bg: #111113; --card: #1c1c1e; --ok: #3fb950; --no: #ff6b6b; --accent: #8ab4f8; } }
* { box-sizing: border-box; }
body { margin: 0; font: 15px/1.5 system-ui, -apple-system, "Segoe UI", sans-serif; color: var(--fg);
  background: var(--bg); }
main { max-width: 980px; margin: 0 auto; padding: 24px 16px 48px; }
header { display: flex; align-items: baseline; justify-content: space-between; gap: 16px; flex-wrap: wrap; }
h1 { font-size: 22px; margin: 0 0 4px; } h2 { font-size: 16px; margin: 32px 0 12px; }
.muted { color: var(--muted); } .error { color: var(--no); }
.card { background: var(--card); border: 1px solid var(--line); border-radius: 10px; padding: 16px;
  margin-bottom: 12px; }
.call { display: flex; justify-content: space-between; gap: 12px; flex-wrap: wrap; }
.call strong { font-size: 16px; }
pre { background: var(--bg); border: 1px solid var(--line); border-radius: 8px; padding: 12px;
  overflow: auto; max-height: 360px; font: 13px/1.45 ui-monospace, SFMono-Regular, Menlo, monospace;
  white-space: pre-wrap; word-break: break-word; }
form.decide { display: flex; gap: 8px; flex-wrap: wrap; margin-top: 12px; }
input[type=text], textarea { font: inherit; padding: 8px 10px; border: 1px solid var(--line);
  border-radius: 8px; background: var(--card); color: var(--fg); }
form.decide input[type=text] { flex: 1 1 240px; }
textarea { width: 100%; min-height: 120px; font-family: ui-monospace, Menlo, monospace; font-size: 13px; }
button { font: inherit; font-weight: 600; padding: 8px 16px; border-radius: 8px;
  border: 1px solid var(--line); background: var(--card); color: var(--fg); cursor: pointer; }
button.approve { background: var(--ok); border-color: var(--ok); color: #fff; }
button.deny { background: var(--no); border-color: var(--no); color: #fff; }
button.link { border: none; background: none; color: var(--accent); padding: 0; font-weight: 400; }
table { width: 100%; border-collapse: collapse; font-size: 14px; }
th, td { text-align: left; padding: 8px 6px; border-bottom: 1px solid var(--line); vertical-align: top; }
th { color: var(--muted); font-weight: 500; }
.status { font-weight: 600; } .status.denied, .status.expired, .status.unknown { color: var(--no); }
.status.completed, .status.approved, .status.executing { color: var(--ok); }
.flash { padding: 10px 14px; border-radius: 8px; border: 1px solid var(--line); background: var(--card); }
"""


def _html(body: str, status: int = 200) -> HTMLResponse:
    return HTMLResponse(body, status_code=status, headers=_SECURITY_HEADERS)


def _frame(title: str, content: str) -> str:
    return (
        "<!doctype html><html lang=en><head><meta charset=utf-8>"
        "<meta name=viewport content='width=device-width, initial-scale=1'>"
        f"<title>{html.escape(title)} · mcp-customs</title><style>{_STYLE}</style></head>"
        f"<body><main>{content}</main></body></html>"
    )


def _e(value: object) -> str:
    return html.escape("" if value is None else str(value), quote=True)


def _ago(when: datetime | None) -> str:
    if when is None:
        return ""
    seconds = int((datetime.now(UTC) - when).total_seconds())
    future, seconds = seconds < 0, abs(seconds)
    if seconds < 60:
        amount = f"{seconds}s"
    elif seconds < 3600:
        amount = f"{seconds // 60}m"
    elif seconds < 86400:
        amount = f"{seconds // 3600}h {seconds % 3600 // 60}m"
    else:
        amount = f"{seconds // 86400}d"
    return f"in {amount}" if future else f"{amount} ago"


def _login_page(message: str | None) -> str:
    error = f"<p class=error>{_e(message)}</p>" if message else ""
    return _frame(
        "Sign in",
        "<h1>Approvals</h1><p class=muted>Calls held by the gateway wait here for a human decision.</p>"
        f"<div class=card>{error}<form method=post action='{PATH}/login'>"
        "<p><label for=token>Paste an approver token: a JWT from your identity provider that carries "
        "the approver role.</label></p>"
        "<textarea id=token name=token required autocomplete=off spellcheck=false></textarea>"
        "<p><button type=submit>Sign in</button></p></form></div>",
    )


def _flash(done: str | None) -> str:
    if not done:
        return ""
    outcome, _, held_id = done.partition(":")
    short = _e(held_id[:8])
    messages = {
        "approved": f"Approved {short}. The call goes ahead now.",
        "denied": f"Denied {short}. The agent has been told.",
        "self": f"You cannot approve {short}: you made that call.",
        "stale": f"{short} was already decided or has expired.",
    }
    return f"<p class=flash>{messages.get(outcome, '')}</p>" if outcome in messages else ""


def _arguments(call: HeldCall) -> str:
    text = json.dumps(call.arguments, indent=2, ensure_ascii=False, sort_keys=True)
    if len(text) > _MAX_ARGUMENTS_SHOWN:
        text = text[:_MAX_ARGUMENTS_SHOWN] + f"\n... ({len(text) - _MAX_ARGUMENTS_SHOWN} more characters)"
    return f"<pre>{_e(text)}</pre>"


def _pending_card(call: HeldCall, csrf: str) -> str:
    what = _e(call.target or call.method)
    return (
        "<div class=card><div class=call>"
        f"<div><strong>{what}</strong> <span class=muted>on {_e(call.upstream)}</span><br>"
        f"<span class=muted>by</span> {_e(call.agent or 'an anonymous caller')} · "
        f"<span class=muted>{_e(call.reason)}</span></div>"
        f"<div class=muted>held {_e(_ago(call.created_at))} · expires {_e(_ago(call.expires_at))}</div></div>"
        f"{_arguments(call)}"
        f"<form class=decide method=post action='{PATH}/{_e(call.id)}/decision'>"
        f"<input type=hidden name=csrf value='{_e(csrf)}'>"
        "<input type=text name=reason maxlength=500 placeholder='Reason (optional, shown to the agent)'>"
        "<button class=approve name=decision value=approve>Approve</button>"
        "<button class=deny name=decision value=deny>Deny</button></form></div>"
    )


def _decided_row(call: HeldCall) -> str:
    return (
        f"<tr><td>{_e(_ago(call.decided_at or call.created_at))}</td><td>{_e(call.target or call.method)}"
        f" <span class=muted>on {_e(call.upstream)}</span></td><td>{_e(call.agent)}</td>"
        f"<td class='status {_e(call.status.value)}'>{_e(call.status.value)}</td>"
        f"<td>{_e(call.decided_by or '')}</td><td>{_e(call.decision_reason or '')}</td></tr>"
    )


def _list_page(
    approver: Identity, pending: list[HeldCall], decided: list[HeldCall], csrf: str, done: str | None
) -> str:
    cards = "".join(_pending_card(call, csrf) for call in pending) or "<p class=muted>Nothing is waiting.</p>"
    rows = "".join(_decided_row(call) for call in decided)
    history = (
        "<table><tr><th>When</th><th>Call</th><th>Agent</th><th>Status</th><th>By</th><th>Reason</th></tr>"
        f"{rows}</table>"
        if rows
        else "<p class=muted>No decisions yet.</p>"
    )
    return _frame(
        "Approvals",
        "<header><div><h1>Approvals</h1><span class=muted>Calls held by the gateway for a human decision. "
        f"<a href='{PATH}'>Refresh</a></span></div>"
        f"<form method=post action='{PATH}/logout'>"
        f"<span class=muted>Signed in as {_e(approver.agent)}</span> "
        "<button class=link type=submit>Sign out</button></form></header>"
        f"{_flash(done)}<h2>Waiting ({len(pending)})</h2>{cards}<h2>Recent decisions</h2>{history}",
    )
