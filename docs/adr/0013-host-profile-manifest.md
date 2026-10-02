# ADR-0013 — Host profile manifest: a host declares ownership, Mark 1 yields

- **Status:** Accepted — directed by Anurag Upadhyay (founder) 2026-10-03 as the Host Profile Manifest feature, built on ADR-0012's external-writer binding
- **Date:** 2026-10-03
- **Deciders:** Anurag Upadhyay (founder), Omium
- **Reversibility:** cheap. Two additive `m1p.v1` fields (an enum, a message, one optional `Hello` field and one optional sidecar block), one new package that stores and exposes a value, and consumers that only log it. Nothing decides on the profile yet; retiring it is deleting the field and the package.
- **Blocks:** every later feature in which a consumer switches on the profile — provisioning yielding a host-owned config surface, the gate recommending instead of acting, memory deferring to a host-owned store, receipts echoing the host identity

## Context

ADR-0012 lets a third-party host that owns its execution loop hand Mark 1 its events. It says nothing about what else the host owns. Mark 1's edge assumes it owns three things on a developer machine: the agent's **config surface** (08 §8 fenced fragments, written by provisioning), **memory** (06 §9, injected by the daemon), and the **arrest** (04 §2.3: a knee arrest acts — it blocks). A host like CEM888 owns its own loop, writes its own config, may hold its own memory, and wants an arrest **recommended** to its loop rather than enforced on it. Today there is no way for a host to say so, and no place for Mark 1 to remember it per session.

Two constraints shaped the decision:

- **Absence must be today's behaviour, exactly.** Every first-party writer — hookshim, cortexd, the transcript tailers, the loopback door — sends no manifest and must resolve to the posture the daemon has now. That posture is therefore a named constant, not an implied zero value.
- **Storing is not switching.** This feature makes the profile exist, be validated, be stored per session and be reachable where decisions are made. It changes no decision. Consumers switch on it in later features, each its own change with its own tests, so that "the host said it owns memory" and "Mark 1 stopped injecting" are two reviewable events, not one.

## Decision

1. **The manifest.** `m1p.v1.HostManifest` (fabric.proto), seven fields:

   | Field | Meaning |
   |---|---|
   | `host_id` | the host's stable identifier, e.g. `cem888`; non-empty |
   | `host_version` | the host's own version string; non-empty |
   | `owns_execution` | the host runs the agent loop (an `ext:` writer: must be `true`) |
   | `owns_config_surface` | the host writes the agent's config; Mark 1's provisioning must not |
   | `owns_memory` | the host holds the memory the agent sees; Mark 1 must not inject |
   | `arrest_mode` | `ARREST_MODE_ACT` — Mark 1 enforces an arrest; `ARREST_MODE_RECOMMEND` — Mark 1 reports it and the host's loop decides |
   | `supplies_identity` | the host attaches its own identity to the session (its `host_correlation_id` is authoritative for correlation) |
   | `schema_version` | the manifest's revision; must be in the accepted set, currently `{"m1p.v1"}` |

   It rides `Hello.host_manifest` (optional, field 7) on the socket and an optional `host_manifest` block in the file-tail sidecar (07 "Partner event files"), in protojson — the same message, the same validator, so the two transports resolve identical input to an identical profile.

2. **The profile and its default.** `go/mark1d/internal/hostprofile` holds `Profile`, a plain Go struct mirroring the seven fields, and **one** constant:

   ```go
   var Default = Profile{
       HostID: "", HostVersion: "",
       OwnsExecution: false, OwnsConfigSurface: true, OwnsMemory: true,
       ArrestMode: Act, SuppliesIdentity: false, SchemaVersion: "",
   }
   ```

   `Default` is today's behaviour written down: Mark 1 provisions the config surface, injects memory, acts on an arrest, supplies the identity, and the writer does not own execution. A session with no manifest resolves to `Default`; nothing else does.

3. **Validation and the error code.** `FromManifest(m, ext bool)` refuses: `arrest_mode` `UNSPECIFIED` (a present manifest must choose), `owns_execution` `false` on an `ext:` connection, a `schema_version` outside the accepted set, an empty `host_id` or `host_version`. A manifest on a **non-`ext:`** connection is refused outright: hookshim and cortexd never send one, so its presence there is a bug. Every refusal closes the connection (or leaves the file untailed) with **`M1E-4007`** — host manifest invalid — logged once. `Canonical(Profile)` is a deterministic encoding (sorted-key compact JSON) pinned by a golden test, because a later feature hashes it into receipts and it must never drift.

4. **Storage and exposure.** The fabric session stores the resolved profile behind an accessor; the daemon keeps a per-session `hostprofile.Registry` (session → profile, `Default` for an unknown session) filled from both transports and handed to provisioning, the gate and memory, which read it and **log it at debug once per session**. They do not decide on it (§Consequences).

5. **The host registry is informational.** `hostprofile` embeds a checked-in `hosts.json` — the same convention as the hookshim's checked-in `maps/<agent>.json` defaults that `agent_maps` bundle data overrides — listing known hosts with their expected manifest; the first entry is `cem888`. The handshake logs "known host" or "unknown host". No enforcement: a host that is not listed integrates exactly as a listed one. The registry exists so an operator can tell a recognised partner from a stranger in the log, and so a later feature can pin expectations; making it an allow-list would turn a partner's first version bump into an outage.

## Consequences

- `m1p.v1` gains `ArrestMode`, `HostManifest`, `Hello.host_manifest`; `buf breaking` at `WIRE_JSON` is clean.
- First-party paths are byte-identical: no manifest ⇒ `Default`, and `TestSocketStreamGolden` still passes unchanged.
- Three consumer sites gain a read and a debug line. **No decision changes in this feature.** Provisioning still writes fences for a host that says `owns_config_surface: true`; the gate still blocks for a host that says `RECOMMEND`; memory still injects for a host that says `owns_memory: true`. Each switch is a later ADR-cited change.
- 08 §4.3 documents the field and validation; 08 §9 the code; 07 the sidecar block; 02 §9 FR-SPINE-033..038 with their tests.

## Not decided here

- When each consumer switches, and what "recommend" looks like on the wire to the host (a `GuardDecision` with a new outcome? a reply frame?). Each is its own decision.
- Whether `supplies_identity` changes receipt payloads. Receipts are untouched here.
- Whether the registry ever enforces anything.
