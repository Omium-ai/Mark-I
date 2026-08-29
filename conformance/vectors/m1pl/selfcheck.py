#!/usr/bin/env python3
"""Audit that manifest.json and the frozen .bin vectors agree — see README.md.

Not a decoder under test (12 §3.4's three implementations are Rust/Go/Python-payload);
this re-derives each expectation from 07 §5's rules so a mis-frozen byte is caught here,
before it teaches two languages the same wrong answer. Named outside the gate's filters
(conf_vectors / ConfVectors) on purpose: it audits the vectors, it does not represent a
language in the cross-language agreement.
"""
import json
import struct
import sys
from pathlib import Path

MAGIC = b"M1PL"
VERS = {0x01}
MAX_FRAME = 4_194_304  # M1PL_MAX_FRAME, 08 §4.2 (normative owner 07 §5)


def decode(buf: bytes):
    # README §Decoder model rule 1: <9 bytes is incomplete, content uninspected.
    if len(buf) < 9:
        return {"outcome": "incomplete"}
    if buf[:4] != MAGIC:
        return {"outcome": "reject", "reject_code": "M1E-4002"}
    if buf[4] not in VERS:
        return {"outcome": "reject", "reject_code": "M1E-4003"}
    ln = struct.unpack("<I", buf[5:9])[0]
    if ln == 0 or ln > MAX_FRAME:
        return {"outcome": "reject", "reject_code": "M1E-4002"}
    if len(buf) < 9 + ln:
        return {"outcome": "incomplete"}
    return {"outcome": "accept", "payload_len": ln, "consumed": 9 + ln}


def derive(buf: bytes):
    outs = []
    while True:
        out = decode(buf)
        outs.append(out)
        if out["outcome"] != "accept":
            return outs
        buf = buf[out["consumed"]:]
        if not buf:
            return outs


def strip(entry):
    return {k: v for k, v in entry.items() if k != "note"}


def main() -> int:
    root = Path(__file__).parent
    manifest = json.loads((root / "manifest.json").read_text())
    fails = []

    listed = set(manifest)
    on_disk = {p.name for p in root.glob("*.bin")}
    for name in sorted(listed - on_disk):
        fails.append(f"{name}: in manifest, not on disk")
    for name in sorted(on_disk - listed):
        fails.append(f"{name}: on disk, not in manifest")

    for name, exp in manifest.items():
        if name not in on_disk:
            continue
        expected = [strip(e) for e in exp["sequence"]] if "sequence" in exp else [strip(exp)]
        got = derive((root / name).read_bytes())
        # A single-outcome accept entry describes a buffer holding exactly one frame.
        if got != expected:
            fails.append(f"{name}: manifest says {expected}, bytes derive {got}")

    # README §Split iteration, mirrored here so the audit exercises the same loop
    # the language tests must implement.
    for name, seq in [("accept_min.bin", 1), ("accept_two_frames.bin", 2)]:
        data = (root / name).read_bytes()
        for k in range(1, len(data)):
            head = derive(data[:k])
            accepted = [o for o in head if o["outcome"] == "accept"]
            if head[-1]["outcome"] == "reject":
                fails.append(f"{name} split@{k}: prefix rejects")
            consumed = sum(o["consumed"] for o in accepted)
            rest = derive(data[consumed:])
            total = accepted + [o for o in rest if o["outcome"] == "accept"]
            if len(total) != seq or rest[-1]["outcome"] == "reject":
                fails.append(f"{name} split@{k}: cumulative outcomes {total + [rest[-1]]}")

    for line in fails:
        print(f"FAIL: {line}")
    if fails:
        return 1
    print(f"selfcheck: OK — {len(manifest)} vectors consistent with manifest.json")
    return 0


if __name__ == "__main__":
    sys.exit(main())
