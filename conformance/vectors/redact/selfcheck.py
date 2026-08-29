#!/usr/bin/env python3
"""Audit the frozen redact vectors for internal consistency (README §selfcheck).

Not a third scanner implementation: nothing here re-derives ruleset behavior.
It catches a corrupted or mis-frozen pair before it poisons two languages.
Exit 0 = consistent.
"""

import json
import re
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
TOKEN = re.compile(r"⟨redacted:([a-z_]+):([0-9a-f]{16})⟩")

def fail(msg: str) -> None:
    print(f"selfcheck FAIL: {msg}")
    sys.exit(1)

def main() -> None:
    manifest = json.loads((HERE / "manifest.json").read_text(encoding="utf-8"))
    if not manifest.get("hmac_key_utf8"):
        fail("manifest carries no hmac_key_utf8 — the hash leg is untestable without it")
    vectors = manifest["vectors"]

    on_disk = {p.name for p in HERE.glob("*.in")}
    listed = set(vectors)
    if on_disk != listed:
        fail(f"manifest/disk drift: only-on-disk={sorted(on_disk - listed)} "
             f"only-in-manifest={sorted(listed - on_disk)}")

    for name, exp in vectors.items():
        raw_in = (HERE / name).read_bytes()
        out_path = HERE / name.replace(".in", ".out")
        if not out_path.exists():
            fail(f"{name}: missing {out_path.name}")
        raw_out = out_path.read_bytes()
        text_out = raw_out.decode("utf-8")
        tokens = TOKEN.findall(text_out)

        if exp["outcome"] == "clean":
            if raw_in != raw_out:
                fail(f"{name}: clean vector mutated — Clean must not touch the buffer")
            continue

        if exp["outcome"] != "redacted":
            fail(f"{name}: unknown outcome {exp['outcome']!r}")
        if raw_in == raw_out:
            fail(f"{name}: redacted vector is byte-identical to its input")
        if len(tokens) != exp["substitutions"]:
            fail(f"{name}: {len(tokens)} tokens in output, manifest says {exp['substitutions']}")
        if [c for c, _ in tokens] != exp["classes"]:
            fail(f"{name}: token classes {[c for c, _ in tokens]} != manifest {exp['classes']}")
        for secret in exp["planted"]:
            if secret.encode() not in raw_in:
                fail(f"{name}: planted secret not present in the input — the vector proves nothing")
            if secret.encode() in raw_out:
                fail(f"{name}: PLANTED SECRET SURVIVES in {out_path.name} (CON-008)")

    print(f"selfcheck OK: {len(vectors)} vector pair(s) consistent")

if __name__ == "__main__":
    main()
