#!/usr/bin/env python3
"""Audit the frozen bundle vectors for internal consistency (README §selfcheck).

Not a third decoder implementation: nothing here re-derives verify/decode
behavior. It catches a corrupted or mis-frozen family — manifest/disk drift,
a vector file whose bytes no longer match the frozen digest, a negative
missing its named reject — before it poisons two languages.
Exit 0 = consistent.
"""

import hashlib
import json
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
CODES = {"M1E-3001", "M1E-3002", "M1E-3003", "M1E-3005"}


def fail(msg: str) -> None:
    print(f"selfcheck FAIL: {msg}")
    sys.exit(1)


def main() -> None:
    manifest = json.loads((HERE / "manifest.json").read_text(encoding="utf-8"))
    vectors = manifest["vectors"]
    if not vectors:
        fail("manifest lists no vectors — an empty family passes every gate vacuously")

    for section in ("verify", "route", "memory", "cortex", "gates", "agent_maps"):
        key = manifest["keys"].get(section, {})
        for field in ("seed_hex", "public_hex", "key_id"):
            if not key.get(field):
                fail(f"keys.{section}.{field} missing — the section-split contract is untestable")

    expired = manifest.get("expired_key", {})
    for field in ("section", "seed_hex", "public_hex", "key_id", "not_after"):
        if not expired.get(field):
            fail(f"expired_key.{field} missing — outside_validity is undrivable")

    rotation = manifest.get("rotation", {})
    rot_vectors = rotation.get("vectors", [])
    if not rot_vectors or "bundle" not in rotation:
        fail("rotation family missing — the ADR-0004 cross-sign chain is undrivable")
    listed = {v["file"] for v in vectors} | {rotation["bundle"]["file"]}
    on_disk = {p.name for p in HERE.glob("*.cbor")}
    if listed != on_disk:
        fail(
            f"manifest/disk drift: only-on-disk={sorted(on_disk - listed)} "
            f"only-in-manifest={sorted(listed - on_disk)}"
        )

    for v in vectors:
        raw = (HERE / v["file"]).read_bytes()
        digest = hashlib.sha256(raw).hexdigest()
        if digest != v["file_sha256_hex"]:
            fail(f"{v['name']}: file bytes drifted from the frozen manifest digest")
        if v["expect"] == "accept":
            if "body_sha256_hex" not in v or "summary" not in v:
                fail(f"{v['name']}: accept vector without body hash + summary")
        elif v["expect"] == "reject":
            if v.get("code") not in CODES:
                fail(f"{v['name']}: reject without a valid M1E code (got {v.get('code')!r})")
            if not v.get("kind"):
                fail(f"{v['name']}: reject without its finer kind")
        else:
            fail(f"{v['name']}: unknown expect {v['expect']!r}")

    rot_files = [rotation["bundle"]] + rot_vectors
    if {v["file"] for v in rot_vectors} != {p.name for p in HERE.glob("rotation_*.json")}:
        fail("rotation manifest/disk drift")
    for v in rot_files:
        raw = (HERE / v["file"]).read_bytes()
        if hashlib.sha256(raw).hexdigest() != v["file_sha256_hex"]:
            fail(f"{v['file']}: bytes drifted from the frozen manifest digest")
        if "expect" in v and v["expect"] == "reject" and not v.get("kind"):
            fail(f"{v['name']}: rotation reject without its kind")

    print(f"selfcheck OK: {len(vectors)} vectors + {len(rot_vectors)} rotation manifests consistent")


if __name__ == "__main__":
    main()
