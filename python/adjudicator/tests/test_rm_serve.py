"""deploy/baseten/mark1-rm/data/rm_serve.py, the cloud RM deployment: rm-input/v1 constants shared
with the renderer, the edge's token-id cut and logit read, rm-exec/v1, and a strict /predict."""

import hashlib
import importlib.util
import json
import math
import os
import threading
import urllib.error
import urllib.request
from http.server import ThreadingHTTPServer
from pathlib import Path

import pytest
from app.rm import cloud, render

ROOT = Path(__file__).resolve().parents[3]
_spec = importlib.util.spec_from_file_location(
    "rm_serve", ROOT / "deploy/baseten/mark1-rm/data/rm_serve.py"
)
serve = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(serve)
YES, NO = 1 << 20, (1 << 20) + 1
MANIFEST = {
    "name": "mark1-rm-a",
    "version": 1,
    "calibration_version": "rm-a-cal@1",
    "scoring": {"method": "logit_diff", "yes": " yes", "no": " no"},
}


def fake_post(logit: float = 1.25):
    """llama-server over a rune tokenizer: " yes"/" no" are single tokens when parsed special."""
    seen = []

    def post(path, body):
        seen.append((path, body))
        if path == "/tokenize":
            text, special = body["content"], body["parse_special"]
            if special and text in (" yes", " no"):
                return {"tokens": [YES if text == " yes" else NO]}
            return {"tokens": [ord(c) for c in text]}
        top = [{"id": YES, "logprob": logit / 2}, {"id": NO, "logprob": -logit / 2}]
        return {"completion_probabilities": [{"top_probs": top}]}

    return post, seen


def test_constants_are_the_renderers_and_the_edges():
    assert (serve.SUFFIX, serve.TEMPLATE_SHA) == (render.SUFFIX, render.TEMPLATE_SHA)
    assert serve.MAX_SEQ_LEN == cloud.MAX_SEQ_LEN == 4096 and serve.RUNTIME == "llama.cpp b11193"


def test_execution_hash_is_the_edge_recipe(tmp_path):
    gguf = tmp_path / "model.gguf"
    gguf.write_bytes(b"GGUF rm-exec/v1 vector")
    want = "32a997ee8842d4906314d2175efa4b9b5d83c2def873f4577dbe12758db03fea"
    assert serve.execution_hash(gguf, "llama.cpp b11193") == want


def test_a_gguf_off_the_manifest_is_deleted_not_served(tmp_path):
    gguf = tmp_path / "model.gguf"
    gguf.write_bytes(b"weights")
    good = {**MANIFEST, "size_bytes": 7, "sha256": hashlib.sha256(b"weights").hexdigest()}
    serve.verify(gguf, good)
    with pytest.raises(RuntimeError):
        serve.verify(gguf, {**good, "sha256": "0" * 64})
    assert not gguf.exists()


def test_ids_are_objective_encode_and_the_request_is_score_request():
    post, seen = fake_post()
    prefix = "<|task|>\n" + "x" * 9000
    ids, yes, no = serve.input_ids(post, prefix, " yes", " no")
    keep = serve.MAX_SEQ_LEN - len(render.SUFFIX)
    assert len(ids) == serve.MAX_SEQ_LEN and ids == [
        ord(c) for c in (prefix[:keep] + render.SUFFIX)
    ]
    assert [b["parse_special"] for _, b in seen] == [False, True, True, True]
    assert serve.logit_diff(post, ids, yes, no) == pytest.approx(1.25)
    path, body = seen[-1]
    assert path == "/completion" and body["prompt"] == ids
    assert body["logit_bias"] == [[YES, 100.0], [NO, 100.0]]
    assert {k: body[k] for k in serve.SCORE_REQUEST} == serve.SCORE_REQUEST
    with pytest.raises(RuntimeError):
        serve.input_ids(post, prefix, " maybe", " no")


@pytest.fixture
def server():
    post, _ = fake_post()
    scorer = serve.Scorer(MANIFEST, "ab" * 32, post)
    httpd = ThreadingHTTPServer(("127.0.0.1", 0), serve.handler(scorer))
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    yield f"http://127.0.0.1:{httpd.server_address[1]}"
    httpd.shutdown()


def call(base, body):
    req = urllib.request.Request(f"{base}/predict", data=json.dumps(body).encode())
    try:
        with urllib.request.urlopen(req, timeout=10) as r:  # noqa: S310
            return r.status, json.loads(r.read())
    except urllib.error.HTTPError as e:
        return e.code, json.loads(e.read())


def test_predict_answers_exactly_what_the_adjudicator_parses(server):
    inp = cloud.RmInput(task="Fix the off-by-one", hunks="@@ -1 +1 @@\n-a\n+b\n")
    status, doc = call(server, {"model_id": "rm:mark1-rm-a@1", "prefix": cloud.prompt(inp).prefix})
    assert status == 200 and set(doc) == cloud.REPLY
    rs = cloud.parse(doc, "rm:mark1-rm-a@1")
    assert rs.score == pytest.approx(1 / (1 + math.exp(-1.25)))
    assert rs.execution_hash == bytes.fromhex("ab" * 32)


@pytest.mark.parametrize(
    "body",
    [
        {"model_id": "rm:mark1-rm-b@1", "prefix": "<|task|>\nx"},
        {"model_id": "rm:mark1-rm-a@1", "prefix": "free text"},
        {"model_id": "rm:mark1-rm-a@1", "prefix": "<|task|>\n", "anchors": "VIOLATED"},
        {"model_id": "rm:mark1-rm-a@1", "prefix": "<|task|>\n" + "x" * 70_000},
        ["<|task|>\n"],
    ],
)
def test_predict_refuses_anything_but_one_rm_input_prefix(server, body):
    assert call(server, body)[0] == 400


@pytest.mark.skipif(
    not all(
        os.environ.get(k)
        for k in ("MARK1_RM_LIVE_SERVER", "MARK1_RM_LIVE_GGUF", "MARK1_RM_LIVE_PARITY")
    ),
    reason="MARK1_RM_LIVE_SERVER / MARK1_RM_LIVE_GGUF / MARK1_RM_LIVE_PARITY unset",
)
def test_live_parity_on_the_pinned_runtime():
    """The deployment's scorer on the real b11193 child: the export's ids and its GGUF score."""
    binary, gguf = os.environ["MARK1_RM_LIVE_SERVER"], Path(os.environ["MARK1_RM_LIVE_GGUF"])
    doc = json.loads(Path(os.environ["MARK1_RM_LIVE_PARITY"]).read_text())
    assert serve.runtime_id(binary) == serve.RUNTIME
    llama = serve.Llama(binary, gguf, max(1, (os.cpu_count() or 2) // 2))
    try:
        for v in doc["vectors"]:
            ids, yes, no = serve.input_ids(
                llama.post, render.render(v["task"], v["diff"]).prefix, " yes", " no"
            )
            assert (ids, yes, no) == (v["input_ids"], doc["yes_token_id"], doc["no_token_id"])
            assert serve.logit_diff(llama.post, ids, yes, no) == pytest.approx(
                v["gguf_q8_0_score"], abs=0.05
            )
    finally:
        llama.stop()
