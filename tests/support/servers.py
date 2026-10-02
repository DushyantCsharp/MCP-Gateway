"""Run ASGI apps on real sockets for contract tests.

Each app gets its own uvicorn server and event loop in a daemon thread, bound
to an ephemeral port before the thread starts, so there is no port race and
the tests talk to it over real HTTP exactly as an agent would.
"""

import socket
import threading
import time
from collections.abc import Iterator
from contextlib import contextmanager

import uvicorn
from starlette.types import ASGIApp


@contextmanager
def serve_in_thread(app: ASGIApp, *, startup_timeout_s: float = 10.0) -> Iterator[str]:
    """Serve ``app`` on 127.0.0.1 and yield its base URL."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind(("127.0.0.1", 0))
    port = sock.getsockname()[1]
    server = uvicorn.Server(uvicorn.Config(app, log_level="warning", lifespan="on", ws="none"))
    thread = threading.Thread(target=server.run, kwargs={"sockets": [sock]}, daemon=True)
    thread.start()
    deadline = time.monotonic() + startup_timeout_s
    while not server.started:
        if not thread.is_alive() or time.monotonic() > deadline:
            raise RuntimeError("test server failed to start")
        time.sleep(0.01)
    try:
        yield f"http://127.0.0.1:{port}"
    finally:
        server.should_exit = True
        thread.join(timeout=10)
        sock.close()
