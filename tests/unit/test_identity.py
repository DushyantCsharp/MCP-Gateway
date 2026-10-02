import pytest

from mcp_customs.auth import Grant, Identity, SessionBinder, parse_grants


def test_grants_come_from_mcp_scopes_only() -> None:
    grants = parse_grants(["openid", "mcp:finance:get_*", "profile", "mcp:workspace:workspace://docs/*"])
    assert grants == (Grant("finance", "get_*"), Grant("workspace", "workspace://docs/*"))


def test_no_mcp_scopes_means_no_narrowing() -> None:
    assert parse_grants(["openid", "email"]) is None
    assert Identity("a").permits("finance", "transfer_funds")


@pytest.mark.parametrize("scope", ["mcp:", "mcp:finance", "mcp::read_doc", "mcp:finance:"])
def test_malformed_mcp_scopes_are_errors(scope: str) -> None:
    with pytest.raises(ValueError, match="malformed scope"):
        parse_grants([scope])


def test_grants_narrow_what_an_identity_may_attempt() -> None:
    identity = Identity("a", grants=parse_grants(["mcp:finance:get_*", "mcp:*:read_doc"]))
    assert identity.permits("finance", "get_balance")
    assert identity.permits("workspace", "read_doc")
    assert not identity.permits("finance", "transfer_funds")
    assert not identity.permits("workspace", "send_email")
    assert str(Grant("finance", "get_*")) == "mcp:finance:get_*"


def test_session_ids_round_trip_for_the_same_agent_and_upstream() -> None:
    binder = SessionBinder(b"k" * 32)
    bound = binder.bind("workspace", "ap-agent", "abc123")
    assert bound.startswith("abc123.")
    assert binder.unbind("workspace", "ap-agent", bound) == "abc123"


def test_session_ids_containing_dots_survive() -> None:
    binder = SessionBinder()
    assert binder.unbind("w", "a", binder.bind("w", "a", "a.b.c")) == "a.b.c"


@pytest.mark.parametrize(
    ("upstream", "agent", "tamper"),
    [
        ("workspace", "intruder", lambda s: s),
        ("finance", "ap-agent", lambda s: s),
        ("workspace", "ap-agent", lambda s: "other" + s[s.index(".") :]),
        ("workspace", "ap-agent", lambda s: s[:-1] + ("A" if s[-1] != "A" else "B")),
        ("workspace", "ap-agent", lambda s: s.split(".")[0]),
        ("workspace", "ap-agent", lambda s: "." + s.split(".")[1]),
    ],
    ids=["other-agent", "other-upstream", "swapped-id", "tampered-tag", "unbound", "empty-id"],
)
def test_session_ids_do_not_transfer(upstream: str, agent: str, tamper: object) -> None:
    binder = SessionBinder(b"k" * 32)
    bound = binder.bind("workspace", "ap-agent", "abc123")
    assert callable(tamper)
    assert binder.unbind(upstream, agent, tamper(bound)) is None


def test_bindings_depend_on_the_key() -> None:
    bound = SessionBinder(b"a" * 32).bind("w", "agent", "s")
    assert SessionBinder(b"b" * 32).unbind("w", "agent", bound) is None
    assert SessionBinder(b"a" * 32).unbind("w", "agent", bound) == "s"
