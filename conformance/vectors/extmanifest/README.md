# `extmanifest` conformance vectors — the sample session with a host profile

The `ext` family's sample session, declared by a host (ADR-0013): the same nine
events, byte for byte, with a sidecar that carries the `host_manifest` block —
the cem888 profile of `go/mark1d/internal/hostprofile/hosts.json`. On the socket the
same declaration rides `Hello.host_manifest`.

```
sample.jsonl            identical to ../ext/sample.jsonl (the events do not change
                        because the host declared itself)
sample.manifest.json    the ext sidecar plus "host_manifest": one m1p.v1.HostManifest in
                        protojson, message field order
```

**Frozen.** `mark1-emitter -manifest -out <dir>` and `python emit.py --manifest <dir>`
reproduce both files exactly; a byte change is a finding against an emitter.

## What locks on it

| Lane | Test | Claim |
|---|---|---|
| Go, `go/mark1d/cmd` | `TestConfVectorsExtmanifestEmitterIsPinned` | both emitter outputs equal these files; the events equal the `ext` family's |
| Go, `go/mark1d/cmd` | `TestConfVectorsExtmanifestTransportsAgree` | the session pushed with `Hello.host_manifest` into one daemon and tailed from this sidecar by another resolves the **identical** `hostprofile.Profile` (compared by `Canonical`), equal to the cem888 profile, and yields identical internal streams |
| Python, `python/shared/mark1_receipts/tests` | `test_conf_vectors_extmanifest_emitter_matches_golden` | `emit.py --manifest` reproduces both files byte for byte |

No Rust twin, as for `ext`. The family name has no hyphen because the gate derives
the Go test token (`ConfVectorsExtmanifest`) and the Python token
(`conf_vectors_extmanifest`) from it.
