// Package anchors is the local anchor catalog, consent flow, sandboxed
// runner, and activity-aware scheduler (04 §2.2; FR-VERIFY-001…004; CON-009).
//
// The three load-bearing properties, in the order an attacker meets them:
//
//  1. THE CATALOG IS LOCALLY DERIVED. Every entry comes from probing the
//     enabled worktree (pyproject/ruff config, tsconfig.json, Cargo.toml,
//     go.mod, eslint config) and the local PATH for the matching tool.
//     Bundles enable entries by catalog ID only; a command string in a bundle
//     fails decode upstream (M1E-3005, CON-009) — this package has no code
//     path that accepts an argv from anywhere but its own derivation table.
//
//  2. NOTHING RUNS WITHOUT CONSENT — and "runs" includes derivation. The
//     only exec before the consent prompt is the version sniff, and it goes
//     through the SAME sandbox as an anchor run (Derive takes the Sandbox),
//     because PATH at `mark1 enable` time routinely resolves a freshly cloned
//     repo's own node_modules/.bin. At run time the consented binary is
//     re-hashed at its resolved path BEFORE exec: a mismatch refuses the
//     execution and emits a tamper-flagged VERDICT_ERROR vote, so a swapped
//     binary is never executed and merely flagged afterwards. The consent
//     store (<state>/anchors/catalog.json, 0600) records exactly which IDs
//     the user approved and the effective-execution hash
//     (argv ‖ binary BLAKE3 ‖ env allow-list) each approval covered. Any
//     derivation drift — argv, binary path/content, tool version — changes
//     that hash, which disables the entry until re-consented; `mark1 doctor`
//     reads Doctor() to show the diff (04 §2.2 "Consent catalog lifecycle").
//
//     How consent arrives: mark1d publishes every derivable entry with its
//     exec_hash to <state>/anchors/candidates.json; `mark1 enable` shows
//     them at a terminal and appends each `y` to <state>/anchors/
//     approvals.jsonl naming that exact hash; the daemon approves a line
//     only while the (id, exec_hash) still derives (candidates.go).
//
//     Consent file format (documented here because the CLI reads it):
//
//     {
//     "version": 1,
//     "entries": [
//     {
//     "id": "ruff@cat-1",           // catalog ID, the only bundle handle
//     "tool": "ruff",               // EvidenceRecord.tool vocabulary
//     "argv": ["/usr/bin/ruff", "check", ...],  // shown verbatim by doctor
//     "binary_path": "/usr/bin/ruff",
//     "binary_hash": "<hex BLAKE3>",// of the binary at consent time
//     "tool_version": "ruff 0.6.2", // sniffed at derivation
//     "class": "fast",              // fast | slow
//     "side_effect": "static",      // static | test
//     "exec_hash": "<hex BLAKE3>",  // effective-execution hash (above)
//     "consented_at": "RFC3339"
//     }
//     ]
//     }
//
//  3. EXECUTION IS SANDBOXED — and the claim is exact (11 §5's honesty rule:
//     an overclaimed sandbox is worse than a modest one honestly stated).
//     On Linux the sandbox enforces, per run:
//
//     ENFORCED — network denied, in two parts because one mechanism does not
//     cover the whole surface:
//     (a) IP: the anchor runs in a fresh network namespace
//     (CLONE_NEWUSER|CLONE_NEWNET) with no interfaces, loopback included. A
//     kernel that refuses unprivileged user namespaces refuses the run
//     (ErrSandboxUnavailable).
//     (b) AF_UNIX: a netns does NOT scope pathname unix sockets and Landlock
//     (ABI v1–v3) does not govern connect(2), so a seccomp filter fails
//     socket(AF_UNIX, …) with EACCES (sandbox_linux.go denyUnixSockets).
//     Without it a sandboxed anchor could connect to any same-uid socket on
//     the host — mark1d's own m1p.sock included, whose 0600/0700 boundary
//     stops other USERS, not a process running as the user (07 §5). The
//     filter is mandatory: a kernel without CONFIG_SECCOMP_FILTER fails
//     sandbox setup and the run errors. Both renumbering escapes are closed
//     with it: a foreign audit arch (i386 compat, whose syscall NUMBERS
//     differ) is denied outright, and so is any nr carrying the x32 bit
//     (0x40000000) — x32 arrives as AUDIT_ARCH_X86_64 with socket = 0x40000029,
//     which a nr-equality filter alone would wave through.
//     socketpair(2) stays permitted — it reaches nothing outside the
//     sandboxed process tree.
//     Together: no anchor ever runs network-attached, and no anchor can speak
//     to a host daemon.
//
//     ENFORCED — env scrub: the child is exec'd with exactly the allow-list
//     env (PATH = resolved catalog dirs, HOME = a per-run scratch dir, LANG,
//     TZ); nothing is inherited. The exact env is attested in
//     AnchorIntegrity.env_scrub_attestation.
//
//     ENFORCED — rlimits: CPU, AS, NOFILE, FSIZE (soft = hard), wall-clock
//     SIGKILL of the process group, kill-switch via context cancel, and a
//     combined stdout+stderr byte cap that kills the run when exceeded.
//
//     ENFORCED WHERE THE KERNEL HAS LANDLOCK (>= 5.13) — writes confined to
//     the worktree and the scratch dir; a write anywhere else fails with
//     EACCES. Reads stay unconfined: linters need /usr, and "read-only
//     outside the worktree" means exactly that — reads allowed, writes not.
//
//     NOT ENFORCED, BY CONSTRUCTION — read confinement, and therefore
//     exfiltration INTO the worktree. State it plainly (11 §5): the sandbox
//     is a one-way valve, not a container. Unconfined reads plus a writable
//     worktree mean anchor code that executes repo-supplied input (the
//     ExecsRepoCode set above) can copy any file the user can read —
//     ~/.ssh keys, <state>/redact.key, the spill private key, the spool —
//     into the repository the agent is editing, where a later commit or
//     upload carries it off the device. Egress is what the netns and the
//     AF_UNIX filter close; local copy is not, and no Landlock rule can
//     close it without an allow-list of every path a toolchain reads.
//     What actually bounds this: per-entry consent over a locally derived
//     argv (property 2), the fixed detector table (property 1), and the
//     tamper envelope on the vote. A consented anchor is trusted with the
//     user's read set; that is the deal being made at the consent prompt,
//     and it is the reason the prompt exists.
//
//     NOT ENFORCED without Landlock: filesystem write confinement degrades
//     to chdir-into-worktree + the scrubbed env. Per 04 §11.5 weaker
//     isolation gets a smaller privilege, not a waiver: only anchors that
//     execute NO repo-controlled code (ruff, tsc — they parse the worktree,
//     they never evaluate it) still run under the remaining caps. Anchors
//     that DO execute repo-controlled code — eslint evaluates
//     eslint.config.js in node, cargo check runs build.rs and proc macros,
//     go vet compiles cgo with repo-supplied flags — REFUSE to run without
//     write confinement, exactly like test-class anchors (FR-VERIFY-003
//     precondition; CatalogEntry.ExecsRepoCode): "static analysis" describes
//     their argv, not the code their own config makes them run.
//     Sandbox.FSConfined reports which regime is live. cgroup caps
//     (memory.max, pids.max) are not applied in this phase — RLIMIT_DATA
//     stands in for memory. It caps committed private anonymous memory, which
//     is the thing memory.max means; RLIMIT_AS would cap address space, which
//     a per-core allocator reserves far past what it ever commits.
//
//     On macOS the same contract rides /usr/bin/sandbox-exec (Seatbelt) with
//     a per-run 0600 profile (sandbox_darwin.go). ENFORCED — network* denied
//     (TCP/UDP and unix-domain: the netns+seccomp twin); writes confined to
//     the worktree, the scratch dir and /dev/null, reads unconfined (the same
//     one-way valve); the env scrub as above plus __CF_USER_TEXT_ENCODING
//     (CoreFoundation would set it inside sandbox-exec otherwise; it is
//     attested like the rest); RLIMIT_CPU/NOFILE/FSIZE/CORE, wall clock, kill
//     switch and output cap as above. ENFORCED BY MARK1D, NOT THE KERNEL —
//     the memory cap: Darwin accepts RLIMIT_DATA/AS and applies neither
//     (arm64 refuses them outright), so mark1d polls the process group's
//     resident set every 250 ms and SIGKILLs it past the cap. NOT ENFORCED —
//     an anchor that ignores SIGXCPU runs to the wall clock (Darwin sends it
//     once and no SIGKILL follows); no Pdeathsig, so a crashed daemon can
//     orphan an anchor for up to its wall cap; and the helper has no positive
//     confinement self-check, so the residual exec gadget is a network-denied
//     exec into attacker-chosen writable dirs. sandbox-exec absent ⇒ every run
//     refused (ErrSandboxUnavailable), never degraded.
//
//     Elsewhere (Windows) every run is refused until 04 §11.5's job-object +
//     AppContainer sandbox lands. Wherever runs are refused, Derive publishes
//     no entry that could only vote sandbox_unavailable, and candidates.json's
//     sandbox field carries the reason (candidates.go).
//
// The runner registry mirrors the estate's PROBE_HANDLERS discipline
// (recovery-orchestrator app/verify/probes.py, adopted per 06 §2.1): a map of
// kind → handler with an init-time exhaustiveness assert against the detector
// table. An unimplemented kind is REFUSED — no vote is emitted, ever faked.
//
// Failure posture (04 §2.2, F-31): crash, timeout, or sandbox-setup failure
// produces AnchorVote{VERDICT_ERROR} — error, never violated — and one
// anchor's failure never blocks another's schedule.
package anchors
