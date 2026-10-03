# ADR-0014 — Detach removes the fence, not the file: drift-aware revert and host-owned config surfaces

- **Status:** Accepted — directed by Anurag Upadhyay (founder) 2026-10-03 as Part 3 of the host-agnostic integration
- **Date:** 2026-10-03
- **Deciders:** Anurag Upadhyay (founder), Omium
- **Reversibility:** cheap. One pure classifier in a new shared package, one additive manifest field (`post_image`), one branch per adapter's `Revert`, one refusal in `provision.Apply`. The fence format (08 §8.1) and the manifest's existing fields do not change; a manifest written before this ADR reverts exactly as before.
- **Blocks:** nothing downstream; Part 4 and later touch other surfaces.

## Context

08 §8.4 already distinguishes "the file is exactly as we left it" (restore the pre-image verbatim) from "the user edited it after us" (surgical removal of our entries). Two things were left implicit:

1. **What "exactly as we left it" means for a strict-JSON file.** The check was a byte hash of the whole file. A user who reformats `settings.json` — their editor rewrites it with CRLF, re-indents, drops the trailing newline — changed nothing of theirs, yet the hash moves and revert takes the surgical path, leaving a file that is not byte-identical to their original when it could have been.
2. **Who owns the surface at all.** A host that writes the agent's configuration itself (ADR-0013 `owns_config_surface`) must not have Mark 1's provisioning fence anything into it. There was no way to say so and no refusal for it.

Each adapter also carried its own copy of the drift judgement, inline in its `Revert`, which is how two copies drift from each other with both test suites green (D-AY).

## Decision

1. **Three drift classes, one classifier.** `go/mark1d/adapters/fence.Classify(pre, post, cur)` is the single pure function every strict-JSON fence uses, over the pre-image, the recorded post-apply image and the file as it is now:

   | Verdict | Meaning | Revert does |
   |---|---|---|
   | `DriftNone` | structurally identical to what we wrote — byte-identical, or reformatted only (CRLF, indentation, trailing newline) | restore the pre-image verbatim, as today |
   | `DriftOutsideFence` | our entries are exactly what we wrote; something else in the document changed (a second writer's entry before or after ours, a key of theirs) | remove exactly our entries (JSON: our tagged entries and the managed object) and write, preserving everything else — today's surgical path |
   | `DriftInsideFence` | our entries are present but not what we wrote | the existing four-state handling (08 §7.4 FRAGMENT-DAMAGED), unchanged |
   | `FenceMissing` | none of our entries is present | the existing handling (08 §7.4 MISSING), unchanged |

   "Outside the fence" for strict JSON is **the document with our keys removed, compared structurally**; "inside" is our entries compared structurally. Ours is what 08 §8.1 says is ours: an array element carrying `"_mark1"`, and the `_mark1_managed` object. No comment-style fence exists in the tree today; if one lands, the same four verdicts apply to the bytes outside its markers.

2. **The post-apply image is recorded.** The manifest (08 §8.2) gains `post_image` (zstd+base64 of the bytes we wrote), beside the existing `post_image_hash`. It is what `DriftNone`-by-structure and the outside comparison are computed against. A manifest without it (written before this ADR) takes the previous path: whole-file hash equal ⇒ verbatim, else surgical.

3. **Pre-image restore stays exactly where it was.** Only `DriftNone` restores the pre-image. Restoring it over an outside-fence edit would delete a second writer's lines; restoring it over an inside-fence edit would silently overwrite a human's bytes. Both are the rewrite 08 §8 forbids.

4. **A host that owns the config surface is refused, not written.** `provision.Apply` reads the session's profile. When a **declared host** (`HostID` non-empty) has `OwnsConfigSurface: true`, every adapter in the walk is refused with **`M1E-7107`** — *host owns config surface* — naming the host, nothing is written, and the manifest is left as it is. `Revert` for such a session is a no-op with the same reason. `hostprofile.Default` is Mark 1's own posture, so its `OwnsConfigSurface: true` reads "the surface's owner — Mark 1 — owns it" and provisioning writes as it always has; the refusal keys on the declared host, which is the only case where the owner is not Mark 1.

5. **The CLI says so in one line.** `mark1 enable`, `mark1 off` and `mark1 doctor` surface the refusal in their existing style with one line: the active host owns its own configuration and Mark 1 is attached through the fabric.

## Consequences

- Revert is byte-faithful in one more case (reformat-only) and identical in every other.
- Four adapters (claudecode incl. its base-URL fragment, codex, gemini, cursor) share one judgement; copilot and opencode are mechanism A (owned files) and need none.
- 08 §8.2 (manifest), §8.3 (step 1 refusal), §8.4 (rewritten drift-aware), §9 (`M1E-7107`); 02 §9 FR-SPINE-039..042.
- `consent_test.go` and every §8 fixture are unchanged and green: the surgical and damaged paths are the same code.

## Not decided here

- A comment-style fence's byte rules beyond "the same four verdicts over the bytes outside the markers": no such fence exists yet.
- Whether a host that owns the surface should be offered Mark 1's fragment *as text* to install itself. Plausible; a later feature.
