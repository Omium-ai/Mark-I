# `claudecode` conformance corpora — one frozen directory per recorded agent version

| Version | Recorded | How | Pinned by |
|---|---|---|---|
| [v2.1.251](v2.1.251/) | 2026-08-29 | transcribed from live on-disk shapes (see its README) | `claudecode.SupportedVersions`, `recordedCorpusDigest` |
| [v2.1.273](v2.1.273/) | 2026-09-16 | `mark1 corpus record` against the installed `claude` | `claudecode.SupportedVersions`, `recordedCorpusDigest` |

A version outside this table is admitted only through the structural probe (`claudecode.Compatibility`,
D-EE): capture runs UNVERIFIED under a receipted `unsupported_agent_version` window until a directory
lands here. Record one with `mark1 corpus record`, then add the two constants it prints.
