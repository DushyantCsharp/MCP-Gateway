"""A stand-in identity provider for the demo: it mints one token per demo agent.

In a real deployment tokens come from your identity provider and the gateway
verifies them against its JWKS. Here a shared HS256 secret plays both parts,
so the demo runs with no external services. The agent containers only ever
see their own token file, never the secret.
"""

import argparse
import os
import time
from pathlib import Path
from typing import Any

import jwt

DEMO_AGENTS: dict[str, dict[str, Any]] = {
    "ap-agent": {"sub": "ap-agent", "task": "ap-demo"},
    "auditor": {"sub": "audit-bot", "roles": ["auditor"]},
    "intruder": {"sub": "intruder"},
    "approver": {"sub": "demo-approver", "roles": ["approver"]},  # a human, deciding held calls
}


def mint(claims: dict[str, Any], *, secret: str, audience: str, ttl_s: int) -> str:
    now = int(time.time())
    return jwt.encode({**claims, "aud": audience, "iat": now, "exp": now + ttl_s}, secret, algorithm="HS256")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n", 1)[0])
    parser.add_argument("--out-dir", type=Path, default=Path(os.environ.get("TOKEN_DIR", "/tokens")))
    parser.add_argument("--audience", default="mcp-customs")
    parser.add_argument("--ttl", type=int, default=12 * 3600, help="token lifetime in seconds")
    args = parser.parse_args()
    secret = os.environ.get("CUSTOMS_JWT_SECRET", "")
    if len(secret.encode()) < 32:
        raise SystemExit("CUSTOMS_JWT_SECRET must hold at least 32 bytes")
    args.out_dir.mkdir(parents=True, exist_ok=True)
    for name, claims in DEMO_AGENTS.items():
        path = args.out_dir / f"{name}.jwt"
        path.write_text(mint(claims, secret=secret, audience=args.audience, ttl_s=args.ttl))
        path.chmod(0o644)
        print(f"issued {path} for {claims['sub']}")


if __name__ == "__main__":
    main()
