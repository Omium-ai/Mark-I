"""rm_serve.py's liveness and request framing: a dead llama-server fails /health and ends the
process; Content-Length is one plain decimal in 1..MAX_BODY and the read is exactly that long."""

import importlib.util
import json
import socket
import subprocess
import sys
import threading
import time
from http.server import ThreadingHTTPServer
from pathlib import Path

import pytest

_spec = importlib.util.spec_from_file_location(
    "rm_serve", Path(__file__).resolve().parents[1] / "data/rm_serve.py"
)
serve = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(serve)
MANIFEST = {
    "name": "mark1-rm-a",
    "version": 1,
    "calibration_version": "c1",
    "scoring": {"method": "logit_diff", "yes": " yes", "no": " no"},
}


def fake_post(path, body):
    if path == "/tokenize":
        return {"tokens": {" yes": [7], " no": [8]}.get(body["content"], [1, 2])}
    probs = [{"id": 7, "logprob": -0.1}, {"id": 8, "logprob": -2.4}]
    return {"completion_probabilities": [{"top_probs": probs}]}


@pytest.fixture
def server():
    state = {"alive": True}
    scorer = serve.Scorer(MANIFEST, "ab" * 32, fake_post)
    httpd = ThreadingHTTPServer(("127.0.0.1", 0), serve.handler(scorer, lambda: state["alive"]))
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    yield httpd.server_address[1], state
    httpd.shutdown()


def raw(port: int, head: str, body: bytes = b"") -> int:
    """Sends exactly these bytes without closing the write side; the status line's code."""
    with socket.create_connection(("127.0.0.1", port), timeout=5) as s:
        s.sendall(head.encode() + b"\r\n" + body)
        return int(s.recv(4096).split(b" ", 2)[1])


def test_health_fails_once_the_runtime_child_is_dead(server):
    port, state = server
    assert raw(port, "GET /health HTTP/1.1\r\nHost: x\r\n") == 200
    state["alive"] = False
    assert raw(port, "GET /health HTTP/1.1\r\nHost: x\r\n") == 503


def test_a_dead_child_ends_the_process_for_a_platform_restart():
    proc = subprocess.Popen([sys.executable, "-c", "raise SystemExit(3)"])  # noqa: S603
    exits = []
    serve.exit_when_dead(proc, exits.append)
    assert exits == [1] and proc.returncode == 3


@pytest.mark.parametrize(
    ("length", "status"),
    [
        (None, 411),
        ("-1", 400),
        ("0", 400),
        ("+5", 400),
        ("1e3", 400),
        ("0x10", 400),
        ("٥", 400),
        (str(serve.MAX_BODY + 1), 413),
        ("99999999999", 400),
    ],
)
def test_content_length_must_be_one_plain_decimal_in_range(server, length, status):
    port, _ = server
    cl = "" if length is None else f"Content-Length: {length}\r\n"
    head = f"POST /predict HTTP/1.1\r\nHost: x\r\n{cl}"
    assert raw(port, head, b'{"model_id": "x"}') == status


def test_duplicate_content_length_is_refused(server):
    port, _ = server
    head = "POST /predict HTTP/1.1\r\nHost: x\r\nContent-Length: 2\r\nContent-Length: 4\r\n"
    assert raw(port, head, b"null") == 400


def test_the_read_is_exactly_content_length(server):
    port, _ = server
    body = json.dumps({"model_id": "rm:mark1-rm-a@1", "prefix": "<|task|>\nx"}).encode()
    head = f"POST /predict HTTP/1.1\r\nHost: x\r\nContent-Length: {len(body)}\r\n"
    assert raw(port, head, body + b"trailing bytes never read as body") == 200
    with socket.create_connection(("127.0.0.1", port), timeout=5) as s:
        s.sendall(f"{head}\r\n".encode() + body[:5])
        s.shutdown(socket.SHUT_WR)
        assert int(s.recv(4096).split(b" ", 2)[1]) == 400


@pytest.mark.parametrize("body", [b"{not json", b"\xff\xfe", b'{"a": 1'])
def test_bad_json_is_a_client_error_not_a_runtime_outage(server, body):
    port, _ = server
    head = f"POST /predict HTTP/1.1\r\nHost: x\r\nContent-Length: {len(body)}\r\n"
    assert raw(port, head, body) == 400


def test_a_trickled_body_is_cut_off_at_the_whole_body_deadline(server, monkeypatch):
    port, _ = server
    monkeypatch.setattr(serve, "BODY_DEADLINE", 0.5)
    head = "POST /predict HTTP/1.1\r\nHost: x\r\nContent-Length: 100\r\n\r\n"
    with socket.create_connection(("127.0.0.1", port), timeout=5) as s:
        started = time.monotonic()
        s.sendall(head.encode() + b"x")
        time.sleep(0.2)
        s.sendall(b"x")
        assert int(s.recv(4096).split(b" ", 2)[1]) == 400
        assert time.monotonic() - started < 2
