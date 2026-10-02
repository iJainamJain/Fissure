"""Shared test fixtures: a live VulnLab server in a background thread."""

from __future__ import annotations

import sys
import threading
from pathlib import Path
from wsgiref.simple_server import make_server

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from benchmark.vulnlab import app  # noqa: E402


@pytest.fixture(scope="session")
def vulnlab_url():
    server = make_server("127.0.0.1", 0, app)  # port 0 -> OS picks a free port
    port = server.server_address[1]
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{port}"
    finally:
        server.shutdown()
