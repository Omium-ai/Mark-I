#!/usr/bin/env python3
"""Audit the frozen fusion vectors for internal consistency (README).

Not a third implementation of ADJUDICATE: nothing here re-derives a posterior or a
verdict — that is gen_fusion_vectors.py's job, and re-deriving here would just make
the same mistake twice. This catches a corrupted or mis-frozen family — manifest/disk
drift, a vector whose bytes no longer match the frozen digest, a posterior that is not
a distribution, a `bit_identical_to` pointing at nothing — before it poisons two
languages.
Exit 0 = consistent.
"""

import hashlib
import json
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
CLASSES = ("satisfied", "violated", "refused", "error")
VERDICTS = set(CLASSES)
PROVENANCE_CLASSES = ("doc-derived", "mixed", "fixture-local")  # D-AG; mirrors the generator
WIRE_VERDICTS = set(CLASSES)  # what a verifier may report on the wire
EXPECTS = {"fuse", "degenerate", "zero_mass"}


def fail(msg: str) -> None:
    print(f"selfcheck FAIL: {msg}")
    sys.exit(1)


def check_input(name: str, vec: dict) -> None:
    if len(vec["priors"]) != 4:
        fail(f"{name}: priors arity {len(vec['priors'])}, want 4 ({', '.join(CLASSES)})")
    for vid, spec in vec["verifiers"].items():
        conf = spec["confusion"]
        if len(conf) != 4 or any(len(r) != 3 for r in conf):
            fail(f"{name}/{vid}: confusion must be 4 rows (latent classes) x 3 cols (D-R)")
        if not spec.get("kind"):
            fail(f"{name}/{vid}: no kind — the unlisted-voter fallback path is untestable")
    for v in vec["votes"]:
        if v["verdict"] not in WIRE_VERDICTS:
            fail(f"{name}: vote by {v['verifier_id']} has unknown verdict {v['verdict']!r}")
        if not isinstance(v["tamper"], bool):
            fail(f"{name}: vote by {v['verifier_id']} has a non-boolean tamper flag")
    if not vec.get("doc"):
        fail(f"{name}: no doc — a vector nobody can explain cannot be maintained")


def check_expectation(entry: dict, vec: dict) -> None:
    name = entry["name"]
    if entry["expect"] not in EXPECTS:
        fail(f"{name}: unknown expect {entry['expect']!r}")
    kept = sum(1 for v in vec["votes"] if not v["tamper"])
    if entry["vote_count"] != kept:
        fail(f"{name}: vote_count {entry['vote_count']} != {kept} untampered votes")
    if entry["expect"] == "zero_mass":
        if "posterior" in entry:
            fail(f"{name}: a zero-mass bundle has no correct posterior — none may be listed")
        return
    post = entry["posterior"]
    if len(post) != 4:
        fail(f"{name}: posterior arity {len(post)}, want exactly 4 (frozen wire invariant)")
    if any(p < 0.0 or p != p for p in post):
        fail(f"{name}: posterior has a negative or NaN component: {post}")
    if abs(sum(post) - 1.0) > 1e-9:
        fail(f"{name}: posterior sums to {sum(post)!r}, not 1")
    if entry["verdict"] not in VERDICTS:
        fail(f"{name}: unknown verdict {entry['verdict']!r}")
    if entry["expect"] == "degenerate" and sorted(post) != [0.0, 0.0, 0.0, 1.0]:
        fail(f"{name}: a step-0 return must be one-hot on its verdict, got {post}")


def main() -> None:
    manifest = json.loads((HERE / "manifest.json").read_text(encoding="utf-8"))
    vectors = manifest["vectors"]
    if not vectors:
        fail("manifest lists no vectors — an empty family passes every gate vacuously")
    if list(manifest["classes"]) != list(CLASSES):
        fail(f"manifest classes {manifest['classes']} are not 06 §3's fixed order")
    if not manifest.get("tolerance", 0) > 0:
        fail("manifest carries no positive tolerance — every posterior assertion is vacuous")

    listed = {v["file"] for v in vectors}
    on_disk = {p.name for p in HERE.glob("*.json")} - {"manifest.json"}
    if listed != on_disk:
        fail(
            f"manifest/disk drift: only-on-disk={sorted(on_disk - listed)} "
            f"only-in-manifest={sorted(listed - on_disk)}"
        )

    names = {v["name"] for v in vectors}
    for entry in vectors:
        raw = (HERE / entry["file"]).read_bytes()
        if hashlib.sha256(raw).hexdigest() != entry["file_sha256_hex"]:
            fail(f"{entry['name']}: file bytes drifted from the frozen manifest digest")
        vec = json.loads(raw)
        if vec["name"] != entry["name"]:
            fail(f"{entry['file']}: names itself {vec['name']!r}, listed as {entry['name']!r}")
        check_input(entry["name"], vec)
        check_expectation(entry, vec)
        twin = entry.get("bit_identical_to")
        if twin is not None and twin not in names:
            fail(f"{entry['name']}: bit_identical_to names {twin!r}, which is not in the family")
        # D-AG: a vector must declare which consumed inputs are printed in a frozen doc and
        # which this fixture invented. anchor_reject_clamp had to invent the reject columns
        # 06 §3.2 declines to print, and on disk they read exactly like the printed ones —
        # so a number laundered from a guess was indistinguishable from a verified one.
        prov = entry.get("provenance") or {}
        if prov.get("class") not in PROVENANCE_CLASSES:
            fail(
                f"{entry['name']}: provenance class {prov.get('class')!r} is not one of "
                f"{list(PROVENANCE_CLASSES)} — an undeclared vector may be doc-derived or invented "
                "and the family cannot tell you which"
            )
        if not (prov.get("note") or "").strip():
            fail(f"{entry['name']}: provenance carries no note — the class alone names no input")

    # The order-sensitivity vectors only prove anything while a twin exists: without one,
    # the sorted-group rule (04 §2.3) has no test in either language.
    if not any(v.get("bit_identical_to") for v in vectors):
        fail("no bit_identical_to pair — nothing pins deterministic group order")

    print(f"selfcheck OK: {len(vectors)} vectors consistent")


if __name__ == "__main__":
    main()
