"""Mark 1 cloud RM (16 §L6): the edge's scoring of the published GGUF on llama.cpp b11193."""

from __future__ import annotations

import hashlib
import json
import logging
import math
import os
import re
import secrets
import socket
import subprocess
import sys
import threading
import time
import urllib.request
from collections.abc import Callable
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any

log = logging.getLogger("mark1-rm")

RUNTIME = "llama.cpp b11193"
TEMPLATE_VERSION = "rm-input/v1"
SUFFIX = "\n<|end|>\nIs this change a correct and complete solution to the task? Answer:"
TEMPLATE_SHA = hashlib.sha256((TEMPLATE_VERSION + SUFFIX).encode()).hexdigest()
MAX_SEQ_LEN = 4096
CTX = MAX_SEQ_LEN + 256
BIAS = 100.0
MAX_PREFIX_CHARS = 64_000
MAX_BODY = 4 * MAX_PREFIX_CHARS
CONTENT_LENGTH = re.compile(r"[0-9]{1,7}")
SOCKET_TIMEOUT = 10  # per socket op, headers included
BODY_DEADLINE = 10.0  # whole-body wall clock: a trickled body cannot pin a handler thread
GGUF_PATH = "/tmp/model.gguf"  # noqa: S108 — the container's writable scratch
LISTEN = "0.0.0.0"  # noqa: S104 — Baseten's proxy reaches the container port
SCORE_REQUEST = {
    "n_predict": 1,
    "n_probs": 2,
    "post_sampling_probs": True,
    "temperature": 1.0,
    "top_k": 0,
    "top_p": 1.0,
    "min_p": 0.0,
    "typical_p": 1.0,
    "repeat_penalty": 1.0,
    "presence_penalty": 0.0,
    "frequency_penalty": 0.0,
    "cache_prompt": False,
}
Post = Callable[[str, dict[str, Any]], dict[str, Any]]


def runtime_id(binary: str) -> str:
    """The runtime identity llama.cpp b<build> as the binary reports it (the edge's RuntimeID)."""
    out = subprocess.run(  # noqa: S603 — the image's own pinned runtime
        [binary, "--version"], capture_output=True, text=True, timeout=60, check=False
    )
    m = re.search(r"\(build ([0-9]+),", out.stdout + out.stderr)
    if not m:
        raise RuntimeError(f"{binary} --version names no llama.cpp build")
    return f"llama.cpp b{m.group(1)}"


def execution_hash(gguf: Path, runtime: str) -> str:
    """rm-exec/v1: BLAKE3-256(GGUF bytes || 0x00 || runtime || 0x00 || template_sha hex), hex."""
    import blake3

    h = blake3.blake3()
    with gguf.open("rb") as f:
        for c in iter(lambda: f.read(1 << 20), b""):
            h.update(c)
    h.update(b"\x00" + runtime.encode() + b"\x00" + TEMPLATE_SHA.encode())
    return h.hexdigest()


def verify(gguf: Path, manifest: dict[str, Any]) -> None:
    """The manifest's sha256 and size, or the file is deleted and nothing serves."""
    h = hashlib.sha256()
    with gguf.open("rb") as f:
        for c in iter(lambda: f.read(1 << 20), b""):
            h.update(c)
    if gguf.stat().st_size != manifest["size_bytes"] or h.hexdigest() != manifest["sha256"]:
        gguf.unlink(missing_ok=True)
        raise RuntimeError(f"{gguf} is not {manifest['name']}@{manifest['version']}'s pinned GGUF")


def fetch(url: str, dest: Path, manifest: dict[str, Any]) -> Path:
    if not dest.exists():
        part = dest.with_suffix(".part")
        with urllib.request.urlopen(url, timeout=600) as r, part.open("wb") as f:  # noqa: S310
            left = manifest["size_bytes"] + 1
            while left > 0 and (c := r.read(min(1 << 20, left))):
                f.write(c)
                left -= len(c)
        part.rename(dest)
    verify(dest, manifest)
    return dest


def input_ids(post: Post, prefix: str, yes: str, no: str) -> tuple[list[int], int, int]:
    """objective.encode on the served GGUF's tokenizer, exactly as the edge (plane.go inputIDs)."""

    def tok(text: str, special: bool) -> list[int]:
        body = {"content": text, "add_special": False, "parse_special": special}
        return list(post("/tokenize", body)["tokens"])

    body, suffix = tok(prefix, False), tok(SUFFIX, True)
    y, n = tok(yes, True), tok(no, True)
    if len(y) != 1 or len(n) != 1 or y == n or not suffix or len(suffix) >= MAX_SEQ_LEN:
        raise RuntimeError(f"not a scoring vocabulary: {yes!r}->{y} {no!r}->{n}")
    return body[: MAX_SEQ_LEN - len(suffix)] + suffix, y[0], n[0]


def logit_diff(post: Post, ids: list[int], yes: int, no: int) -> float:
    """ln p(yes) - ln p(no) with both answers +100-biased = logit(yes) - logit(no)."""
    d = post(
        "/completion", {**SCORE_REQUEST, "prompt": ids, "logit_bias": [[yes, BIAS], [no, BIAS]]}
    )
    lp = {}
    for e in d["completion_probabilities"][0]["top_probs"]:
        lp[e["id"]] = e["logprob"] if "logprob" in e else math.log(max(e["prob"], 1e-300))
    if yes not in lp or no not in lp:
        raise RuntimeError("runtime did not rank both answer tokens")
    return float(lp[yes] - lp[no])


class Llama:
    """One llama-server child with the edge's flags: loopback, one slot, a per-start key."""

    def __init__(self, binary: str, gguf: Path, threads: int) -> None:
        with socket.socket() as s:
            s.bind(("127.0.0.1", 0))
            self.port = s.getsockname()[1]
        self.key = secrets.token_hex(16)
        argv = [binary, "-m", str(gguf), "--host", "127.0.0.1", "--port", str(self.port)]
        argv += ["-np", "1", "-c", str(CTX), "-t", str(threads)]
        argv += ["--cache-ram", "0", "--ctx-checkpoints", "0", "--no-webui", "--offline"]
        env = {**os.environ, "LLAMA_API_KEY": self.key}
        self.proc = subprocess.Popen(argv, env=env)  # noqa: S603 — fixed argv, pinned binary
        deadline = time.monotonic() + 600
        while time.monotonic() < deadline:
            if self.proc.poll() is not None:
                raise RuntimeError(f"llama-server exited {self.proc.returncode}")
            try:
                with urllib.request.urlopen(f"{self.base}/health", timeout=5) as r:  # noqa: S310
                    if r.status == 200:
                        return
            except OSError:
                pass
            time.sleep(0.25)
        raise TimeoutError("llama-server not healthy in 600 s")

    @property
    def base(self) -> str:
        return f"http://127.0.0.1:{self.port}"

    def post(self, path: str, body: dict[str, Any]) -> dict[str, Any]:
        req = urllib.request.Request(  # noqa: S310 — loopback child
            self.base + path,
            data=json.dumps(body).encode(),
            headers={"Content-Type": "application/json", "Authorization": f"Bearer {self.key}"},
        )
        with urllib.request.urlopen(req, timeout=600) as r:  # noqa: S310
            return json.loads(r.read())

    def stop(self) -> None:
        self.proc.kill()
        self.proc.wait(10)


class Scorer:
    """POST /predict {model_id, prefix} -> the served logit and execution; one at a time."""

    def __init__(self, manifest: dict[str, Any], xh: str, post: Post) -> None:
        self.manifest, self.xh, self.post = manifest, xh, post
        self.model_id = f"rm:{manifest['name']}@{manifest['version']}"
        self.lock = threading.Lock()

    def predict(self, body: Any) -> tuple[int, dict[str, Any]]:
        if not isinstance(body, dict) or set(body) != {"model_id", "prefix"}:
            return 400, {"error": "body is exactly {model_id, prefix}"}
        if body["model_id"] != self.model_id:
            return 400, {"error": f"this deployment serves {self.model_id}"}
        prefix = body["prefix"]
        if not isinstance(prefix, str) or not prefix.startswith("<|task|>\n"):
            return 400, {"error": "prefix is an rm-input/v1 prefix"}
        if len(prefix) > MAX_PREFIX_CHARS:
            return 400, {"error": "prefix is longer than any rm-input/v1 render"}
        sc = self.manifest["scoring"]
        with self.lock:
            ids, yes, no = input_ids(self.post, prefix, sc["yes"], sc["no"])
            s = logit_diff(self.post, ids, yes, no)
        return 200, {
            "model_id": self.model_id,
            "logit": s,
            "calibration_version": self.manifest["calibration_version"],
            "execution_hash": self.xh,
            "n_tokens": len(ids),
        }


def exit_when_dead(proc: subprocess.Popen, exit: Callable[[int], Any] = os._exit) -> None:
    """A dead llama-server ends the process, so the platform restarts it instead of 503s forever."""
    code = proc.wait()
    log.error("llama-server exited %s; exiting for a restart", code)
    exit(1)


def body_length(headers: Any) -> tuple[int, int]:
    """(status, n): 200 and 0 < n <= MAX_BODY for exactly one plain decimal Content-Length."""
    vals = headers.get_all("Content-Length") or []
    if not vals:
        return 411, 0
    if len(vals) != 1 or not CONTENT_LENGTH.fullmatch(vals[0]) or int(vals[0]) == 0:
        return 400, 0
    n = int(vals[0])
    return (200, n) if n <= MAX_BODY else (413, 0)


def read_body(rfile: Any, conn: socket.socket, n: int, limit: float) -> bytes:
    """Up to n bytes within limit seconds in total; short on EOF, timeout or a socket error."""
    buf, deadline = bytearray(), time.monotonic() + limit
    try:
        while len(buf) < n and (left := deadline - time.monotonic()) > 0:
            conn.settimeout(left)
            c = rfile.read1(n - len(buf))
            if not c:
                break
            buf += c
    except OSError:
        pass
    return bytes(buf)


def handler(
    scorer: Scorer, alive: Callable[[], bool] = lambda: True
) -> type[BaseHTTPRequestHandler]:
    class H(BaseHTTPRequestHandler):
        timeout = SOCKET_TIMEOUT

        def _send(self, status: int, doc: dict[str, Any]) -> None:
            b = json.dumps(doc).encode()
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(b)))
            self.end_headers()
            self.wfile.write(b)

        def do_GET(self) -> None:  # noqa: N802
            if self.path == "/health" and alive():
                self._send(200, {"status": "ok", "model_id": scorer.model_id})
            elif self.path == "/health":
                self._send(503, {"status": "runtime exited", "model_id": scorer.model_id})
            else:
                self._send(404, {"error": "not found"})

        def do_POST(self) -> None:  # noqa: N802
            if self.path != "/predict":
                return self._send(404, {"error": "not found"})
            status, n = body_length(self.headers)
            if status != 200:
                self.close_connection = True
                return self._send(status, {"error": f"Content-Length must be 1..{MAX_BODY}"})
            raw = read_body(self.rfile, self.connection, n, BODY_DEADLINE)
            if len(raw) != n:
                self.close_connection = True
                return self._send(400, {"error": "body shorter than Content-Length"})
            try:
                body = json.loads(raw)
            except ValueError:
                return self._send(400, {"error": "body is not JSON"})
            try:
                status, doc = scorer.predict(body)
            except (ValueError, RuntimeError, OSError) as exc:
                log.warning("predict failed: %s", type(exc).__name__)
                status, doc = 503, {"error": "runtime unavailable"}
            self._send(status, doc)

        def log_message(self, *args: Any) -> None:
            return None

    return H


def main() -> int:
    logging.basicConfig(level=logging.INFO)
    manifest = json.loads(os.environ["RM_MANIFEST"])
    if manifest.get("template_sha") != TEMPLATE_SHA:
        raise RuntimeError("manifest template_sha is not rm-input/v1")
    binary = os.environ.get("RM_RUNTIME", "/opt/rm-runtime/llama-server")
    runtime = runtime_id(binary)
    if runtime != RUNTIME:
        raise RuntimeError(f"image runtime is {runtime}, pinned {RUNTIME}")
    gguf = fetch(os.environ["RM_GGUF_URL"], Path(os.environ.get("RM_GGUF", GGUF_PATH)), manifest)
    xh = execution_hash(gguf, runtime)
    if xh != manifest["execution_hash"]:
        raise RuntimeError(
            f"execution hash {xh} is not the manifest's {manifest['execution_hash']}"
        )
    llama = Llama(binary, gguf, int(os.environ.get("RM_THREADS") or os.cpu_count() or 4))
    threading.Thread(target=exit_when_dead, args=(llama.proc,), daemon=True).start()
    scorer = Scorer(manifest, xh, llama.post)
    alive = lambda: llama.proc.poll() is None  # noqa: E731
    server = ThreadingHTTPServer(
        (LISTEN, int(os.environ.get("PORT", "8000"))), handler(scorer, alive)
    )
    log.info("serving %s@%s execution %s on %s", manifest["name"], manifest["version"], xh, runtime)
    try:
        server.serve_forever()
    finally:
        llama.stop()
    return 0


if __name__ == "__main__":
    sys.exit(main())
