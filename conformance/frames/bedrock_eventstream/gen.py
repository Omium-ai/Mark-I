#!/usr/bin/env python3
"""SYNTHETIC Bedrock eventstream fixtures, built to the documented framing (prelude | headers | payload | CRC-32),
not recorded from a live endpoint: no Bedrock transcript exists in this repo. Replace with recordings when one lands."""
import base64, json, os, struct, zlib

HERE = os.path.dirname(os.path.abspath(__file__))


def header(name, value):
    n, v = name.encode(), value.encode()
    return struct.pack(">B", len(n)) + n + b"\x07" + struct.pack(">H", len(v)) + v


def message(headers, payload, corrupt=False):
    h = b"".join(header(k, v) for k, v in headers)
    total = 12 + len(h) + len(payload) + 4
    prelude = struct.pack(">II", total, len(h))
    body = prelude + struct.pack(">I", zlib.crc32(prelude)) + h + payload
    crc = zlib.crc32(body) ^ (0xFFFFFFFF if corrupt else 0)
    return body + struct.pack(">I", crc)


def event(event_type, obj):
    return message([(":event-type", event_type), (":content-type", "application/json"), (":message-type", "event")],
                   json.dumps(obj, separators=(",", ":")).encode())


def chunk(obj):
    inner = json.dumps(obj, separators=(",", ":")).encode()
    return event("chunk", {"bytes": base64.b64encode(inner).decode(), "p": "abcdefghijklmnop"})


START = {"type": "message_start", "message": {"id": "msg_bdrk_01Xy", "type": "message", "role": "assistant", "model": "claude-sonnet-4-5",
         "content": [], "stop_reason": None, "usage": {"input_tokens": 25, "output_tokens": 1, "cache_creation_input_tokens": 0, "cache_read_input_tokens": 0}}}
INVOKE = [
    chunk(START),
    chunk({"type": "content_block_start", "index": 0, "content_block": {"type": "text", "text": ""}}),
    chunk({"type": "content_block_delta", "index": 0, "delta": {"type": "text_delta", "text": "Hello"}}),
    chunk({"type": "content_block_delta", "index": 0, "delta": {"type": "text_delta", "text": " from Bedrock"}}),
    chunk({"type": "content_block_stop", "index": 0}),
    chunk({"type": "message_delta", "delta": {"stop_reason": "end_turn", "stop_sequence": None}, "usage": {"output_tokens": 12}}),
    chunk({"type": "message_stop", "amazon-bedrock-invocationMetrics": {"inputTokenCount": 25, "outputTokenCount": 12, "invocationLatency": 700, "firstByteLatency": 300}}),
]
CONVERSE = [
    event("messageStart", {"role": "assistant"}),
    event("contentBlockDelta", {"contentBlockIndex": 0, "delta": {"text": "Hi"}}),
    event("contentBlockStop", {"contentBlockIndex": 0}),
    event("messageStop", {"stopReason": "end_turn"}),
    event("metadata", {"usage": {"inputTokens": 40, "outputTokens": 9, "totalTokens": 49, "cacheReadInputTokens": 30, "cacheWriteInputTokens": 0},
                       "metrics": {"latencyMs": 512}}),
]
EXCEPTION = [
    chunk(START),
    message([(":exception-type", "throttlingException"), (":content-type", "application/json"), (":message-type", "exception")],
            b'{"message":"Too many requests, please wait before trying again."}'),
]
usage_start = {"kind": "usage", "message_id": "msg_bdrk_01Xy", "model": "claude-sonnet-4-5", "input_tokens": 25, "output_tokens": 1,
               "cache_creation_input_tokens": 0, "cache_read_input_tokens": 0, "service_tier": ""}
usage_end = dict(usage_start, output_tokens=12)

FIXTURES = {
    "invoke_stream_anthropic": (INVOKE, {"observations": [usage_start, usage_end, {"kind": "response_end", "stop_reason": "end_turn"}], "degraded": None}),
    "converse_stream": (CONVERSE, {"observations": [
        {"kind": "response_end", "stop_reason": "end_turn"},
        {"kind": "usage", "message_id": "", "model": "", "input_tokens": 40, "output_tokens": 9, "cache_creation_input_tokens": 0, "cache_read_input_tokens": 30, "service_tier": ""},
    ], "degraded": None}),
    "throttling_exception": (EXCEPTION, {"observations": [usage_start, {"kind": "upstream_error", "error_type": "throttlingException"}], "degraded": None}),
    # Message 2's CRC is flipped: everything before it parses, the stream degrades at its first byte.
    "corrupt_message_crc": (INVOKE[:1] + [message([(":event-type", "chunk"), (":content-type", "application/json"), (":message-type", "event")], b'{"bytes":"e30="}', corrupt=True)] + INVOKE[2:],
                            {"observations": [usage_start], "degraded": {"at_byte": len(INVOKE[0]), "reason": "malformed_event"}}),
}
for name, (msgs, expected) in FIXTURES.items():
    with open(os.path.join(HERE, name + ".bytes"), "wb") as f:
        f.write(b"".join(msgs))
    with open(os.path.join(HERE, name + ".expected.json"), "w") as f:
        json.dump(expected, f, indent=2)
        f.write("\n")
