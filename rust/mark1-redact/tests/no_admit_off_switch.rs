//! CON-008 structural gate: the admit-to-upload axis has NO off switch.
//!
//! The control this file protects is an *absence* — no env read, no cargo
//! feature, no config parameter can reach `Scanner::admit`. An absence cannot
//! regress loudly on its own: adding `Scanner::with_options(disable: bool)`
//! leaves every behavioural test in the repo green while a P0 compliance
//! control quietly dies. So this test asserts over the crate's own source that
//! the absence still holds.
//!
//! It reads `src/`, blanks comments and literals, tokenizes what is left, and
//! reports findings over *code tokens only* — a doc comment or a string that
//! mentions `std::env::var` must not trip the gate, because a gate that
//! false-positives on its own documentation gets disabled, and then it
//! protects nothing.

// House style (see conf_vectors.rs): workspace lints deny unwrap/expect/panic
// on the production path; clippy.toml exempts test code, restated at file scope.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::fs;
use std::path::{Path, PathBuf};

/// Public methods on `Scanner` as of the CON-008 review. Every entry here has
/// been checked to carry no channel that can influence the admit decision:
/// `new` takes only the per-tenant HMAC key, `scan` is the other (detect) axis,
/// `admit` is the axis itself. A method appearing on `Scanner` that is not in
/// this list fails the gate on purpose — the question "can this reach
/// `admit()`?" gets a human answer before the list grows.
const SCANNER_PUB_FNS: &[&str] = &["new", "scan", "admit"];

/// Free `pub fn`s at the crate root. Empty today: `Scanner::new` is the entire
/// construction surface, and a `pub fn scanner_with_options(..)` beside it
/// would be a bypass wearing a different hat.
const FREE_PUB_FNS: &[&str] = &[];

/// Identifiers that read process environment. Matched as code tokens, so
/// `env!("CARGO_MANIFEST_DIR")` in a *test* harness is out of scope (this gate
/// only walks `src/`) but any appearance inside the library is a finding.
const ENV_TOKENS: &[&str] = &["env", "option_env", "var_os", "vars", "vars_os", "set_var"];

// ---------------------------------------------------------------------------
// Lexing: blank the non-code, then tokenize.
// ---------------------------------------------------------------------------

fn is_ident(c: char) -> bool {
    c.is_alphanumeric() || c == '_'
}

fn blank(out: &mut String, ch: char) {
    // Newlines survive so a finding's line number still points at the real file.
    out.push(if ch == '\n' { '\n' } else { ' ' });
}

/// Replace every comment — and, unless `keep_literals`, every literal — with
/// spaces. Handles nested block comments, raw and byte strings of any hash
/// count, escapes, and the `'a` lifetime / `'a'` char-literal ambiguity.
/// `keep_literals` is the fingerprint mode: a sink's `format!` string is part of
/// what it writes, while a comment beside it is not.
fn code_only(src: &str, keep_literals: bool) -> String {
    let c: Vec<char> = src.chars().collect();
    let mut out = String::with_capacity(c.len());
    let lit: fn(&mut String, char) = if keep_literals {
        |o, ch| o.push(ch)
    } else {
        blank
    };
    let mut i = 0;
    while i < c.len() {
        let ch = c[i];

        if ch == '/' && c.get(i + 1) == Some(&'/') {
            while i < c.len() && c[i] != '\n' {
                blank(&mut out, c[i]);
                i += 1;
            }
            continue;
        }

        if ch == '/' && c.get(i + 1) == Some(&'*') {
            let mut depth = 0usize;
            while i < c.len() {
                if c[i] == '/' && c.get(i + 1) == Some(&'*') {
                    depth += 1;
                } else if c[i] == '*' && c.get(i + 1) == Some(&'/') {
                    depth -= 1;
                } else {
                    blank(&mut out, c[i]);
                    i += 1;
                    continue;
                }
                blank(&mut out, c[i]);
                blank(&mut out, c[i + 1]);
                i += 2;
                if depth == 0 {
                    break;
                }
            }
            continue;
        }

        // String literals, with their `b` / `r` / `br` / `r#` prefixes. The
        // `prev is not ident` guard keeps `bread` and `rule` from being read
        // as literal prefixes.
        let prev_ident = i > 0 && is_ident(c[i - 1]);
        if !prev_ident && (ch == '"' || ch == 'b' || ch == 'r') {
            let mut j = i;
            if c[j] == 'b' {
                j += 1;
            }
            let raw = c.get(j) == Some(&'r');
            if raw {
                j += 1;
            }
            let hash_start = j;
            if raw {
                while c.get(j) == Some(&'#') {
                    j += 1;
                }
            }
            let hashes = j - hash_start;
            if c.get(j) == Some(&'"') {
                while i <= j {
                    lit(&mut out, c[i]);
                    i += 1;
                }
                while i < c.len() {
                    if !raw && c[i] == '\\' {
                        lit(&mut out, c[i]);
                        i += 1;
                        if i < c.len() {
                            lit(&mut out, c[i]);
                            i += 1;
                        }
                        continue;
                    }
                    if c[i] == '"' && (1..=hashes).all(|k| c.get(i + k) == Some(&'#')) {
                        for _ in 0..=hashes {
                            lit(&mut out, c[i]);
                            i += 1;
                        }
                        break;
                    }
                    lit(&mut out, c[i]);
                    i += 1;
                }
                continue;
            }
            // Not a literal after all; fall through and copy the identifier.
        }

        if ch == '\'' {
            // `'\n'` and `'x'` are char literals; anything else after the tick
            // is a lifetime or a loop label, which is ordinary code.
            let is_char_lit = c.get(i + 1) == Some(&'\\') || c.get(i + 2) == Some(&'\'');
            if !is_char_lit {
                out.push(ch);
                i += 1;
                continue;
            }
            lit(&mut out, c[i]);
            i += 1;
            while i < c.len() {
                if c[i] == '\\' {
                    lit(&mut out, c[i]);
                    i += 1;
                    if i < c.len() {
                        lit(&mut out, c[i]);
                        i += 1;
                    }
                    continue;
                }
                let done = c[i] == '\'';
                lit(&mut out, c[i]);
                i += 1;
                if done {
                    break;
                }
            }
            continue;
        }

        out.push(ch);
        i += 1;
    }
    out
}

/// `(token, line)` pairs. Identifiers are one token and `::` is one token, so
/// a path split across lines (`std ::\n env`) still matches.
fn tokenize(code: &str) -> Vec<(String, usize)> {
    let cs: Vec<char> = code.chars().collect();
    let mut out = Vec::new();
    let mut line = 1usize;
    let mut i = 0;
    while i < cs.len() {
        let ch = cs[i];
        if ch == '\n' {
            line += 1;
            i += 1;
        } else if ch.is_whitespace() {
            i += 1;
        } else if is_ident(ch) {
            let s = i;
            while i < cs.len() && is_ident(cs[i]) {
                i += 1;
            }
            out.push((cs[s..i].iter().collect(), line));
        } else if ch == ':' && cs.get(i + 1) == Some(&':') {
            out.push(("::".to_string(), line));
            i += 2;
        } else {
            out.push((ch.to_string(), line));
            i += 1;
        }
    }
    out
}

// ---------------------------------------------------------------------------
// The checker.
// ---------------------------------------------------------------------------

#[derive(Default)]
struct Report {
    findings: Vec<String>,
    bytes: usize,
    files: usize,
    saw_fn_admit: bool,
    saw_cfg_test: bool,
    saw_pub_fn_new: bool,
    /// Every `pub fn` the checker actually enumerated inside an inherent
    /// `impl Scanner`. Kept so the gate can prove the block was found and
    /// walked: an empty list would otherwise be indistinguishable from a
    /// clean one, and the whole check would pass by not looking.
    scanner_pub_fns: Vec<String>,
}

/// Brace depth *before* each token.
fn depths(t: &[(String, usize)]) -> Vec<usize> {
    let mut d = Vec::with_capacity(t.len());
    let mut cur = 0usize;
    for (tok, _) in t {
        d.push(cur);
        match tok.as_str() {
            "{" => cur += 1,
            "}" => cur = cur.saturating_sub(1),
            _ => {}
        }
    }
    d
}

fn inspect(name: &str, src: &str, r: &mut Report) {
    r.files += 1;
    r.bytes += src.len();
    let t = tokenize(&code_only(src, false));
    let d = depths(&t);
    let tok = |i: usize| t.get(i).map_or("", |(s, _)| s.as_str());
    let line = |i: usize| t.get(i).map_or(0, |(_, l)| *l);
    // Findings quote the untouched source line. String literals are blanked
    // before tokenizing, so a parsed predicate reads `feature=`; the real text
    // is what a reader needs to act on.
    let at = |i: usize| {
        let l = line(i);
        format!(
            "{name}:{l}: `{}`",
            src.lines().nth(l.max(1) - 1).unwrap_or("").trim()
        )
    };

    for i in 0..t.len() {
        // 1. Environment reads.
        if ENV_TOKENS.contains(&tok(i)) {
            r.findings.push(format!(
                "{} — environment access `{}`; CON-008 forbids any env-derived input to the \
                 admit axis",
                at(i),
                tok(i)
            ));
        }

        // 2. cfg gating. Only `#[cfg(test)]` may exist; a feature gate anywhere
        //    in this crate is a compile-time off switch by construction.
        if (tok(i) == "cfg" || tok(i) == "cfg_attr") && tok(i + 1) == "(" {
            let pred = paren_group(&t, i + 1).0.join("");
            if tok(i) == "cfg" && pred == "test" {
                r.saw_cfg_test = true;
            } else {
                r.findings.push(format!(
                    "{} — conditional compilation on `{pred}`; the only cfg allowed in this \
                     crate is `#[cfg(test)]` (CON-008: no feature may gate admit)",
                    at(i)
                ));
            }
        }

        // 3a. Free `pub fn` at crate/module top level.
        if tok(i) == "pub" && tok(i + 1) == "fn" && d[i] == 0 && !FREE_PUB_FNS.contains(&tok(i + 2))
        {
            r.findings.push(format!(
                "{} — new free `pub fn {}`; a construction/config entry point beside \
                 `Scanner::new` must be reviewed against CON-008 before FREE_PUB_FNS grows",
                at(i),
                tok(i + 2)
            ));
        }

        if tok(i) == "fn" && tok(i + 1) == "admit" {
            r.saw_fn_admit = true;
        }
        if tok(i) == "pub" && tok(i + 1) == "fn" && tok(i + 2) == "new" {
            r.saw_pub_fn_new = true;
        }

        // 3b. `struct Scanner` must expose no public field — a `pub` field is a
        //     setter with the ceremony removed.
        if tok(i) == "struct" && tok(i + 1) == "Scanner" {
            for (j, _) in body(&t, &d, i + 1) {
                if tok(j) == "pub" {
                    r.findings.push(format!(
                        "{} — `Scanner` gains a public field; CON-008 requires the scanner's \
                         state be unreachable from outside the crate",
                        at(j)
                    ));
                }
            }
        }

        // 3c. Methods on `Scanner`.
        if tok(i) == "impl" {
            let mut h = i + 1;
            while h < t.len() && tok(h) != "{" {
                h += 1;
            }
            let header: Vec<&str> = (i + 1..h).map(tok).collect();
            if !header.contains(&"Scanner") {
                continue;
            }
            if header.contains(&"for") {
                r.findings.push(format!(
                    "{} — trait impl `{}` for Scanner; a trait can hand out a second \
                     constructor (`From<Config>`, `Default`), so review against CON-008",
                    at(i),
                    header.join(" ")
                ));
                continue;
            }
            let inner = d[h] + 1;
            for (j, jd) in body(&t, &d, i) {
                if jd != inner || tok(j) != "pub" || tok(j + 1) != "fn" {
                    continue;
                }
                r.scanner_pub_fns.push(tok(j + 2).to_string());
                if !SCANNER_PUB_FNS.contains(&tok(j + 2)) {
                    r.findings.push(format!(
                        "{} — `Scanner::{}` is a new public method; CON-008 requires proof it \
                         cannot influence the admit decision before SCANNER_PUB_FNS grows to \
                         admit it",
                        at(j),
                        tok(j + 2)
                    ));
                }
            }
        }
    }
}

/// `(open_brace, one_past_close)` of the first `{..}` block at or after `from`.
fn brace_range(t: &[(String, usize)], d: &[usize], from: usize) -> Option<(usize, usize)> {
    let open = (from..t.len()).find(|&i| t[i].0 == "{")?;
    let outer = d[open];
    let end = (open + 1..t.len())
        .find(|&i| d[i] <= outer)
        .unwrap_or(t.len());
    Some((open, end))
}

/// Token indices (with their depths) inside the first `{..}` block at or after
/// `from`, exclusive of the braces themselves.
fn body(t: &[(String, usize)], d: &[usize], from: usize) -> Vec<(usize, usize)> {
    match brace_range(t, d, from) {
        Some((open, end)) => (open + 1..end).map(|i| (i, d[i])).collect(),
        None => Vec::new(),
    }
}

/// Tokens inside the `(..)` opening at `open`, flattened across nesting, plus
/// the index of the matching `)`. Used for `cfg` predicates, where flattening
/// is what makes `cfg(all(test, unix))` read as containing `test`.
fn paren_group(t: &[(String, usize)], open: usize) -> (Vec<&str>, usize) {
    let mut depth = 0usize;
    let mut out = Vec::new();
    for (j, (tok, _)) in t.iter().enumerate().skip(open) {
        let s = tok.as_str();
        if s == "(" {
            depth += 1;
            if depth == 1 {
                continue;
            }
        } else if s == ")" {
            depth -= 1;
            if depth == 0 {
                return (out, j);
            }
        }
        out.push(s);
    }
    (out, t.len())
}

fn rust_files(dir: &Path, out: &mut Vec<PathBuf>) {
    // Every IO error panics. A gate that asserts "the set is empty" must never
    // be able to reach "empty" by failing to look.
    let entries =
        fs::read_dir(dir).unwrap_or_else(|e| panic!("CON-008 gate cannot read {dir:?}: {e}"));
    for entry in entries {
        let p = entry.unwrap().path();
        if p.is_dir() {
            rust_files(&p, out);
        } else if p.extension().is_some_and(|x| x == "rs") {
            out.push(p);
        }
    }
}

// ---------------------------------------------------------------------------
// Caller-side gate. `mark1-redact` having no off switch is worth nothing if a
// caller routes around it, and both callers live outside this crate's `src/`.
// ---------------------------------------------------------------------------

/// The two functions that put an event frame on disk. Every `spill::append`
/// call site in either crate lands in one of these (proxy `fabric.rs:94,109`;
/// hookshim `main.rs:147` and `gate.rs:77`), so pinning these two pins the
/// admit axis at the caller boundary.
const SPILL_GUARDS: &[(&str, &str)] = &[
    ("mark1-proxy/src/tee/spill.rs", "append"),
    ("mark1-hookshim/src/spill.rs", "append"),
];

/// Every non-test function in the two caller crates that emits bytes, what it
/// emits, and a fingerprint of its text as reviewed (`fn_fingerprint`).
/// `admit_guards_every_spill_write` proves the two ring writers keep their
/// gate; this list is what stops a *third* writer appearing beside them
/// unnoticed, which no amount of checking the existing two would catch. The
/// fingerprint is what stops a *reviewed* writer being widened in place: any
/// edit to the function's code or literals turns the gate red, and the
/// re-review is what re-pins it — a changed hash is a new consent, the same
/// shape the anchor catalog uses.
#[rustfmt::skip]
const REVIEWED_SINKS: &[(&str, &str, &str)] = &[
    // Sealed ring records — the admit axis applies, and is asserted below.
    ("mark1-proxy/src/tee/spill.rs", "append", "fad86f88270416d6"),
    ("mark1-hookshim/src/spill.rs", "append", "a7e3c71a7c1230da"),
    // Fixed or non-event bytes: no event frame can reach these.
    ("mark1-proxy/src/main.rs", "write_port", "a061b025faee4a4f"), // the listener port
    ("mark1-proxy/src/main.rs", "main", "ba1a3633112865e7"), // startup errors to stderr, pre-`run` (re-reviewed 2026-09-16: mark1_harden::apply)
    ("mark1-proxy/src/router.rs", "record_kill", "afc6365810cd742e"), // cred_ref + fingerprint + reason
    ("mark1-proxy/src/router.rs", "set_route", "7a51b04ba05099d5"), // RwLock write guard swapping the RouteTable; no byte leaves the process
    ("mark1-hookshim/src/context.rs", "run", "47f42531d408c737"), // rendered ContextReply JSON to stdout (the daemon's reply, never the event frame); the frame goes to fabric::context_query and the admit-guarded spill
    ("mark1-hookshim/src/spill.rs", "count", "3c7cadf50427b079"), // one constant byte, a counter
    ("mark1-hookshim/src/spill.rs", "record_timing", "e5e3baa575366c5d"), // elapsed millis, test-only (MARK1_HOOKSHIM_TIMING=1); no event bytes
    ("mark1-hookshim/src/gate.rs", "answer", "327f7e31ff94cc43"), // block-decision or at-knee systemMessage JSON to stdout (block/knee build the value; this is the one write)
    // `write!` into a `String` — an in-memory formatter, no byte leaves the
    // process. Listed rather than special-cased in `classify`: keeping the
    // detector over-eager and the judgement in this table is what makes a new
    // `write!` that *is* a file write show up in review.
    ("mark1-proxy/src/guard/provenance.rs", "fingerprint_hex", "a432238306ab3c2b"),
    // Frames to the LOCAL mark1d socket. Not disk and not off-machine, so
    // invariant 5 does not bind here; mark1d owns redaction on its side.
    // Listed rather than filtered so the judgement is visible and reviewable.
    ("mark1-proxy/src/fabric.rs", "deliver", "7e552da67b62157f"), // re-reviewed 2026-10-02 (ADR-0012: Hello gains an empty host_correlation_id, nothing else); 2026-09-18: Hello + the frame to the local socket or the owner-only named pipe; `send` only connects now
    ("mark1-hookshim/src/fabric.rs", "write_frame", "eb1a5e88683f885e"), // re-reviewed 2026-09-18: one frame to the per-platform Stream below
    ("mark1-hookshim/src/fabric.rs", "write_all", "869fe8b224b21db6"), // the Stream itself: unix socket (write timeout) and the owner-only named pipe (File); local only
    // Status-line mode (2026-09-19): Claude Code's status JSON, never an event frame. `append`
    // files the {rate_limits, model, context_window, prompt_cache} slice to the 0600
    // ~/.omium/mark1/claude/ratelimits.jsonl; `trim` rewrites that same file; `chain` replays
    // stdin to the status-line command the user had before Mark 1 took the slot (a local
    // child), or prints Mark 1's own one-liner to stdout — unless the app's statusline.off marker
    // exists (re-reviewed 2026-09-19: one more read of a local marker file, the same two sinks).
    // Nothing leaves the machine.
    ("mark1-hookshim/src/statusline.rs", "append", "bde702fcbf93c02f"),
    ("mark1-hookshim/src/statusline.rs", "trim", "7f6332810d04dd43"),
    ("mark1-hookshim/src/statusline.rs", "chain", "cb457bf6fbe13132"),
    // Hook-shape file (2026-09-19): key -> JSON type name plus the map's missing vendor keys, never a
    // value from the payload, to the 0600 ~/.omium/mark1/shape/<agent>/<event>.json. Both cfg arms.
    ("mark1-hookshim/src/shape.rs", "write_private", "f603d2077f954bd4"),
];

/// A write-like call, as this token walk can see it.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Shape {
    /// The bytes leave inside the enclosing `fn`, so that `fn` is what gets
    /// admit-guarded or reviewed.
    Sink,
    /// A write-like name whose bytes the walk cannot attribute to a body: a
    /// temp file persisted, a path renamed or linked into place, a bare
    /// `copy(..)` that may be `io::copy` behind a `use`. The gate fails closed
    /// on these until a human classifies the shape here — an allowlist entry
    /// is not the fix, because the entry would pin the wrong function.
    Unrecognised,
}

/// Byte-emitting call shapes. Over-eager by design (`write!` into a `String`
/// counts; the judgement lives in `REVIEWED_SINKS`), but not blind: a handle
/// being configured (`OpenOptions::write(true)`, `std::io::stdout()`) emits
/// nothing and is not a sink, while the same names as a redirect or a partial
/// write are. A write-like name in neither arm is invisible to this gate —
/// that is the ceiling of a token walk, and the list below is its edge.
fn classify(t: &[(String, usize)], i: usize) -> Option<Shape> {
    let tk = |k: usize| t.get(k).map_or("", |(s, _)| s.as_str());
    let (prev, next) = (tk(i.wrapping_sub(1)), tk(i + 1));
    if prev == "fn" {
        // A definition emits nothing; its body is walked like any other.
        return None;
    }
    let call = next == "(";
    let mac = next == "!";
    let qualified = |m: &str| prev == "::" && tk(i.wrapping_sub(2)) == m;
    let shape = match tk(i) {
        // io::Write / fmt::Write / AsyncWriteExt, plus the `write!` family and
        // `fs::write`. `.write(true)` is an `OpenOptions` flag; `.write(buf)`
        // is the partial-write method and lands bytes like `write_all`.
        // `flush` only as a method: the hookshim's `fabric::flush` is a drain
        // barrier whose bytes leave through the pinned `write_frame`.
        "write_all" | "write_fmt" | "write_str" | "write_char" | "write_vectored"
        | "write_all_vectored" | "write_at" | "write_all_at" | "seek_write"
            if call =>
        {
            Shape::Sink
        }
        "flush" if call && prev == "." => Shape::Sink,
        "write" | "writeln" if mac || qualified("fs") => Shape::Sink,
        "write" if call && prev == "." && !matches!(tk(i + 2), "true" | "false") => Shape::Sink,
        // The shapes the CON-008 ledger named as invisible, now attributed:
        // `io::copy` / `fs::copy` land bytes here; `to_writer` serialises
        // straight into a handle; a `BufWriter` is pinned where it is built,
        // because once handed off it is written through a generic `W: Write`
        // this walk cannot follow; a `Command` redirect (`.stdout(..)`,
        // `Stdio::from(file)`) puts a child's bytes on disk with no write call
        // of ours; an mmap is a write with no call at all, so the mapping is
        // the sink. `print!`-family macros are `write_all` to a std stream.
        "copy" if call && (qualified("io") || qualified("fs")) => Shape::Sink,
        "to_writer" | "to_writer_pretty" | "serialize_into" if call => Shape::Sink,
        "BufWriter" | "LineWriter" | "Stdio" | "Mmap" | "MmapMut" | "MmapOptions"
            if next == "::" =>
        {
            Shape::Sink
        }
        "stdout" | "stderr" if call && prev == "." => Shape::Sink,
        "mmap" | "map_mut" | "map_copy" if call => Shape::Sink,
        "print" | "println" | "eprint" | "eprintln" | "dbg" if mac => Shape::Sink,
        // Write-like, but the bytes were landed somewhere this walk did not see.
        "copy" | "persist" | "persist_noclobber" | "rename" | "hard_link" | "symlink"
        | "copy_file_range" | "sendfile" | "splice" | "set_len" | "write_to" | "encode_into"
            if call =>
        {
            Shape::Unrecognised
        }
        _ => return None,
    };
    Some(shape)
}

/// `(name, open_brace, one_past_close)` for every `fn NAME` at any nesting —
/// `write_frame` lives in `impl Conn` inside `mod imp`, so a top-level-only
/// scan would miss it and silently under-report sinks.
fn fn_spans(t: &[(String, usize)], d: &[usize]) -> Vec<(String, usize, usize)> {
    let mut out = Vec::new();
    for i in 0..t.len() {
        // `fn` as a bare type (`fn(u32) -> u32`) is followed by `(`, not a name.
        if t[i].0 != "fn" {
            continue;
        }
        let Some(name) = t.get(i + 1).map(|(s, _)| s.clone()) else {
            continue;
        };
        if !name.starts_with(|c: char| c.is_alphabetic() || c == '_') {
            continue;
        }
        let Some((open, end)) = brace_range(t, d, i + 1) else {
            continue;
        };
        // A bodiless trait/extern declaration ends in `;`; without this guard
        // it would claim the next unrelated block as its body. Only a `;`
        // outside every bracket counts: `fn f(x: &[u8; 32])` has one inside
        // both, and skipping that signature would drop a real fn — and with
        // it every sink it contains — out of the inventory silently.
        let (mut par, mut sq) = (0i32, 0i32);
        let mut bodiless = false;
        for (tok, _) in t.iter().take(open).skip(i + 1) {
            match tok.as_str() {
                "(" => par += 1,
                ")" => par -= 1,
                "[" => sq += 1,
                "]" => sq -= 1,
                ";" if par == 0 && sq == 0 => bodiless = true,
                _ => {}
            }
        }
        if bodiless {
            continue;
        }
        out.push((name, open, end));
    }
    out
}

/// Fingerprint of every `fn NAME` in a file: each one's `{`-line through its
/// `}`-line with comments blanked, literals kept and whitespace collapsed,
/// concatenated in source order and hashed. Same-named twins (`#[cfg(unix)]`
/// / `#[cfg(not(unix))]` pairs) share one pin, so editing either re-pins.
/// Sixteen hex chars: this pins consent, it does not resist an adversary who
/// can edit the table in the same commit anyway.
/// Returns `(line of the first such fn, fingerprint)`.
fn fn_fingerprint(
    src: &str,
    t: &[(String, usize)],
    d: &[usize],
    name: &str,
) -> Option<(usize, String)> {
    let stripped = code_only(src, true);
    let lines: Vec<&str> = stripped.lines().collect();
    let mut text = String::new();
    let mut line = None;
    for (n, open, end) in fn_spans(t, d) {
        if n != name {
            continue;
        }
        let (first, last) = (t[open].1, t[end - 1].1);
        line.get_or_insert(first);
        for l in &lines[first - 1..last] {
            text.push_str(l);
            text.push(' ');
        }
    }
    let normalised = text.split_whitespace().collect::<Vec<_>>().join(" ");
    use sha2::Digest;
    let hash = format!("{:x}", sha2::Sha256::digest(normalised.as_bytes()))[..16].to_string();
    line.map(|l| (l, hash))
}

/// Token ranges of every closure body and `async` block inside `open..end`,
/// in the `(opener, one_past_close)` convention of `in_ranges`. A sink in one
/// of these runs when the closure runs — later, repeatedly, or never — not
/// where it is written, so textual order says nothing about it.
fn deferred_ranges(
    t: &[(String, usize)],
    d: &[usize],
    open: usize,
    end: usize,
) -> Vec<(usize, usize)> {
    let tk = |k: usize| t.get(k).map_or("", |(s, _)| s.as_str());
    // A `|` after something that can end an expression is binary-or, or the
    // second bar of `||`; after anything else it opens a parameter list.
    let ends_expr = |s: &str| {
        matches!(s, ")" | "]" | "}" | "|")
            || (s.starts_with(is_ident) && !matches!(s, "move" | "return" | "break"))
    };
    let mut out = Vec::new();
    let mut i = open + 1;
    while i < end {
        // Index of the token that closes the head: the `{` of an async block,
        // or the second `|` of a closure.
        let head_close = if tk(i) == "async" && tk(i + 1) == "{" {
            Some(i + 1)
        } else if tk(i) == "async" && tk(i + 1) == "move" && tk(i + 2) == "{" {
            Some(i + 2)
        } else if tk(i) == "|" && !ends_expr(tk(i - 1)) {
            (i + 1..end).find(|&j| tk(j) == "|")
        } else {
            None
        };
        let Some(hc) = head_close else {
            i += 1;
            continue;
        };
        let body = hc + 1;
        let stop = if tk(hc) == "{" || tk(body) == "{" {
            // Block body: the matching brace.
            let b = if tk(hc) == "{" { hc } else { body };
            brace_range(t, d, b).map_or(end, |(_, e)| e)
        } else {
            // Expression body: runs to the first separator at its own nesting.
            let mut depth = 0i32;
            let mut j = body;
            while j < end {
                match tk(j) {
                    "(" | "[" | "{" => depth += 1,
                    ")" | "]" | "}" | "," | ";" if depth == 0 => break,
                    ")" | "]" | "}" => depth -= 1,
                    _ => {}
                }
                j += 1;
            }
            j
        };
        out.push((hc, stop));
        i = body;
    }
    out
}

/// Brace ranges of items behind a `test` cfg. Test code writes tempfiles all
/// over these crates; counting it would drown the sink inventory in noise
/// while asserting nothing about what ships.
fn test_ranges(t: &[(String, usize)], d: &[usize]) -> Vec<(usize, usize)> {
    let mut out = Vec::new();
    for i in 0..t.len() {
        if t[i].0 != "cfg" || t.get(i + 1).map(|(s, _)| s.as_str()) != Some("(") {
            continue;
        }
        let (pred, close) = paren_group(t, i + 1);
        if !pred.contains(&"test") {
            continue;
        }
        // Step past the attribute's `]`, then take the gated item's body.
        let mut k = close + 1;
        while k < t.len() && t[k].0 == "]" {
            k += 1;
        }
        if let Some((open, end)) = brace_range(t, d, k) {
            if !(k..open).any(|x| t[x].0 == ";") {
                out.push((open, end));
            }
        }
    }
    out
}

fn in_ranges(ranges: &[(usize, usize)], i: usize) -> bool {
    ranges.iter().any(|&(a, b)| i > a && i < b)
}

/// Innermost `fn` containing token `i`.
fn enclosing_fn(spans: &[(String, usize, usize)], i: usize) -> Option<&str> {
    spans
        .iter()
        .filter(|(_, o, e)| i > *o && i < *e)
        .min_by_key(|(_, o, e)| e - o)
        .map(|(n, _, _)| n.as_str())
}

/// Both caller crates' `src/` trees as `(rust-relative path, source)`. Reuses
/// `rust_files`, so a missing directory panics rather than yielding nothing.
fn caller_sources() -> Vec<(String, String)> {
    let rust = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("mark1-redact must live under rust/")
        .to_path_buf();
    let mut out = Vec::new();
    for krate in ["mark1-proxy", "mark1-hookshim"] {
        let mut files = Vec::new();
        rust_files(&rust.join(krate).join("src"), &mut files);
        files.sort();
        for f in files {
            let rel = f
                .strip_prefix(&rust)
                .unwrap()
                .to_string_lossy()
                .replace('\\', "/");
            out.push((rel, fs::read_to_string(&f).unwrap()));
        }
    }
    out
}

// ---------------------------------------------------------------------------
// Tests.
// ---------------------------------------------------------------------------

/// The gate itself: over `mark1-redact/src`, the set of off-switch findings is
/// empty — and the run is proved non-vacuous before that emptiness is claimed.
#[test]
fn admit_axis_has_no_off_switch() {
    let src = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("src");
    let mut files = Vec::new();
    rust_files(&src, &mut files);
    files.sort();

    let mut r = Report::default();
    for f in &files {
        let text = fs::read_to_string(f).unwrap();
        inspect(&f.file_name().unwrap().to_string_lossy(), &text, &mut r);
    }

    // Anti-vacuity FIRST. "No findings" is also what a checker reports when it
    // read zero files or walked the wrong directory, so the run must prove it
    // saw the crate before it is allowed to vouch for it.
    assert!(
        r.files >= 3,
        "vacuous: expected at least lib.rs, rules.rs, tests.rs under {src:?}, walked {} file(s)",
        r.files
    );
    assert!(
        r.bytes > 10_000,
        "vacuous: only {} bytes of source scanned under {src:?}",
        r.bytes
    );
    assert!(
        r.saw_fn_admit,
        "vacuous: never saw `fn admit` — the tokenizer is not seeing the crate"
    );
    assert!(r.saw_pub_fn_new, "vacuous: never saw `pub fn new`");
    assert!(
        r.saw_cfg_test,
        "vacuous: never saw a `#[cfg(test)]` — cfg parsing is not reaching real attributes"
    );
    // Proves the `impl Scanner` block was located and its methods enumerated at
    // the right brace depth. Without it the method check could "pass" by walking
    // nothing at all. Deliberately a subset check: anything *extra* is the gate's
    // job to report below, with a message that says what to do about it.
    for want in SCANNER_PUB_FNS {
        assert!(
            r.scanner_pub_fns.iter().any(|s| s == want),
            "vacuous: never enumerated `Scanner::{want}` — the inherent `impl Scanner` block \
             was not walked, so the method check proves nothing (saw {:?})",
            r.scanner_pub_fns
        );
    }

    assert!(
        r.findings.is_empty(),
        "CON-008: the admit-to-upload axis must have no off switch, but the crate source now \
         carries {} way(s) to reach one:\n  {}",
        r.findings.len(),
        r.findings.join("\n  ")
    );
}

/// `Cargo.toml` declares no features. A `[features]` table, or an `optional`
/// dependency (which creates an implicit feature of the same name), is a
/// cargo-level off switch even when no `#[cfg(feature)]` exists yet.
#[test]
fn cargo_manifest_declares_no_features() {
    let here = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let rust = here.parent().expect("mark1-redact must live under rust/");
    // The scanner crate and both crates that call `admit()`: a feature declared
    // in a caller is just as much an off switch as one declared here.
    let manifests = [
        here.clone(),
        rust.join("mark1-proxy"),
        rust.join("mark1-hookshim"),
    ];

    for dir in manifests {
        let path = dir.join("Cargo.toml");
        let raw = fs::read_to_string(&path).unwrap();
        assert!(
            raw.contains("[dependencies]"),
            "vacuous: {path:?} is not a manifest"
        );

        for (n, l) in raw.lines().enumerate() {
            let l = l.trim();
            if l.starts_with('#') {
                continue;
            }
            assert!(
                l != "[features]" && !l.starts_with("[features."),
                "CON-008: {path:?}:{} declares a feature table; no cargo feature may exist on \
                 the admit path, because a feature is a compile-time off switch",
                n + 1
            );
            assert!(
                !l.contains("optional"),
                "CON-008: {path:?}:{} declares an optional dependency, which creates an implicit \
                 cargo feature",
                n + 1
            );
        }
    }
}

/// Positive control. Without this, a checker whose matching never fires looks
/// exactly like a clean crate. Every rule the gate enforces is planted here at
/// least once, so no branch of the checker is itself unexercised; `INNOCENT`
/// says the same words in comments and strings and must stay silent.
#[test]
fn checker_flags_a_planted_off_switch() {
    const POISON: &str = r#"
#[cfg(feature = "unsafe_admit")]
fn gated() {}
pub struct Scanner {
    pub admit_enabled: bool,
}
impl Scanner {
    pub fn with_admit_disabled(cfg: RedactConfig) -> Self { todo!() }
}
impl Default for Scanner {
    fn default() -> Self { todo!() }
}
pub fn scanner_with_options(off: bool) -> Scanner { todo!() }
fn bypass() -> bool { std::env::var("MARK1_DISABLE_ADMIT").is_ok() }
"#;
    const INNOCENT: &str = r##"
//! Callers must never read std::env::var("MARK1_DISABLE_ADMIT") to skip admit,
//! and #[cfg(feature = "x")] is banned. Example: Scanner::with_admit_disabled.
/* std::env::var and #[cfg(feature = "y")] in a /* nested */ block comment. */
fn admit() { let _ = "std::env::var + #[cfg(feature = \"z\")]"; let _ = r#"env!("X")"#; }
#[cfg(test)]
mod t {}
"##;

    let mut p = Report::default();
    inspect("poison.rs", POISON, &mut p);
    let joined = p.findings.join("\n");
    assert!(
        joined.contains("environment access `env`"),
        "env read not flagged:\n{joined}"
    );
    // The echoed source line is the untouched original, feature name and all.
    assert!(
        joined.contains(r#"#[cfg(feature = "unsafe_admit")]"#),
        "feature gate not flagged:\n{joined}"
    );
    assert!(
        joined.contains("Scanner::with_admit_disabled"),
        "new Scanner constructor not flagged:\n{joined}"
    );
    assert!(
        joined.contains("gains a public field"),
        "public Scanner field not flagged:\n{joined}"
    );
    assert!(
        joined.contains("trait impl `Default for Scanner`"),
        "trait impl on Scanner not flagged:\n{joined}"
    );
    assert!(
        joined.contains("new free `pub fn scanner_with_options`"),
        "free constructor not flagged:\n{joined}"
    );

    // The other half of the control: the gate must not fire on its own docs.
    let mut clean = Report::default();
    inspect("innocent.rs", INNOCENT, &mut clean);
    assert!(
        clean.findings.is_empty(),
        "false positive on comments/strings — a gate that flags its own documentation gets \
         disabled:\n  {}",
        clean.findings.join("\n  ")
    );
    assert!(
        clean.saw_cfg_test && clean.saw_fn_admit,
        "stripper ate real code alongside the noise"
    );
}

/// The walker cannot succeed by looking at nothing: a wrong path panics, and an
/// empty-but-real directory trips the anti-vacuity floors rather than passing.
#[test]
fn empty_or_wrong_directory_is_not_a_pass() {
    let bogus = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("src-does-not-exist");
    let walk = std::panic::catch_unwind(|| {
        let mut v = Vec::new();
        rust_files(&bogus, &mut v);
    });
    assert!(
        walk.is_err(),
        "walking a nonexistent directory must panic, not report zero files"
    );

    // And an empty report — what a wrong-but-readable directory yields — fails
    // the same floors the real gate applies before it trusts an empty finding set.
    let r = Report::default();
    assert!(r.findings.is_empty() && r.files == 0 && !r.saw_fn_admit);
}

/// The caller boundary. In each of the two functions that put an event frame on
/// disk, `admit()` must be called at statement depth, its result compared
/// against `AdmitOutcome::Quarantine`, and every byte-emitting call in that
/// function must come after it — with no loop, no environment read and no
/// conditional compilation in the body.
///
/// What that is worth: those bodies are straight-line with early returns, so
/// within one body "textually after the statement-depth `admit()`" *is*
/// domination — which is why the loop ban, and the refusal of a sink inside a
/// closure or async block, are load-bearing rather than decorative. It says
/// nothing about paths that never enter these functions;
/// `caller_crates_have_no_unreviewed_byte_sink` is what covers those.
#[test]
fn admit_guards_every_spill_write() {
    let sources = caller_sources();
    let mut findings: Vec<String> = Vec::new();
    let mut located = 0usize;

    for &(file, fname) in SPILL_GUARDS {
        let Some((_, src)) = sources.iter().find(|(p, _)| p == file) else {
            panic!("vacuous: {file} was not found under the caller crates — the walk is wrong");
        };
        located += 1;
        findings.extend(guard_findings(file, fname, src));
    }

    assert_eq!(
        located,
        SPILL_GUARDS.len(),
        "vacuous: not every guarded spill writer file was located"
    );
    assert!(
        findings.is_empty(),
        "CON-008 at the caller boundary — {} problem(s):\n  {}",
        findings.len(),
        findings.join("\n  ")
    );
}

/// The per-function half of the caller gate, over source text rather than a
/// path, so `caller_checker_flags_planted_regressions` can feed it synthetic
/// poison. Every rule it enforces is documented on `admit_guards_every_spill_write`.
fn guard_findings(file: &str, fname: &str, src: &str) -> Vec<String> {
    let mut findings: Vec<String> = Vec::new();
    {
        let t = tokenize(&code_only(src, false));
        let d = depths(&t);
        let tk = |i: usize| t.get(i).map_or("", |(s, _)| s.as_str());
        let ln = |i: usize| t.get(i).map_or(0, |(_, l)| *l);

        let span = fn_spans(&t, &d)
            .iter()
            .find(|(n, _, _)| n == fname)
            .map(|(_, o, e)| (*o, *e));
        let Some((open, end)) = span else {
            return vec![format!(
                "{file}: `fn {fname}` is gone — the guarded spill writer was renamed or removed"
            )];
        };

        let stmt = d[open] + 1;
        let admits: Vec<usize> = (open + 1..end)
            .filter(|&i| tk(i) == "admit" && tk(i + 1) == "(")
            .collect();
        let sinks: Vec<usize> = (open + 1..end)
            .filter(|&i| classify(&t, i).is_some())
            .collect();

        match admits.iter().copied().find(|&i| d[i] == stmt) {
            None if admits.is_empty() => findings.push(format!(
                "{file}: `{fname}` no longer calls `admit()` — bytes reach the ring unredacted \
                 (CON-008, invariant 5)"
            )),
            None => findings.push(format!(
                "{file}:{}: the only `admit()` in `{fname}` sits inside a branch or closure; it \
                 must be at statement depth or some path reaches a write without it",
                ln(admits[0])
            )),
            Some(g) => {
                // The tokenizer emits punctuation one char at a time, so a
                // comparison is an adjacent `=`/`=` (or `!`/`=`) pair.
                let head: Vec<&str> = (g..end).take_while(|&i| tk(i) != "{").map(&tk).collect();
                let cmp = head.windows(2).any(|w| w == ["=", "="] || w == ["!", "="]);
                let variant = head
                    .iter()
                    .any(|s| matches!(*s, "Quarantine" | "Clean" | "Redacted"));
                if !(cmp && variant) {
                    findings.push(format!(
                        "{file}:{}: the `admit()` in `{fname}` is no longer compared against an \
                         `AdmitOutcome` variant — its result must gate the write",
                        ln(g)
                    ));
                }
                for &s in sinks.iter().filter(|&&s| s < g) {
                    findings.push(format!(
                        "{file}:{}: `{}` emits bytes before `admit()` runs in `{fname}` (CON-008)",
                        ln(s),
                        tk(s)
                    ));
                }
            }
        }

        if sinks.is_empty() {
            findings.push(format!(
                "vacuous: no byte-emitting call found inside {file}::{fname} — the sink detector \
                 is not seeing this function, so the ordering check proves nothing"
            ));
        }

        // Textual order is execution order only in straight-line code. A loop
        // anywhere in the body is refused outright (none exists, so the ban is
        // free); a closure is refused only when a sink sits inside it, because
        // `.map(|m| m.len())` is everywhere and cannot reorder a write.
        let deferred = deferred_ranges(&t, &d, open, end);
        for &s in sinks.iter().filter(|&&s| in_ranges(&deferred, s)) {
            findings.push(format!(
                "{file}:{}: `{}` in `{fname}` sits inside a closure or async block — it runs \
                 when that runs, not where it is written, so this gate cannot establish \
                 domination by `admit()`; hoist the write into the function body",
                ln(s),
                tk(s)
            ));
        }
        for i in open + 1..end {
            if matches!(tk(i), "loop" | "while" | "for") {
                findings.push(format!(
                    "{file}:{}: `{}` in `{fname}` — cannot establish domination: this gate \
                     reads textual order as execution order, which a loop breaks; re-derive \
                     the ordering before allowing one",
                    ln(i),
                    tk(i)
                ));
            }
            if ENV_TOKENS.contains(&tk(i)) {
                findings.push(format!(
                    "{file}:{}: environment access `{}` inside `{fname}` — no env value may \
                     reach the admit decision (CON-008)",
                    ln(i),
                    tk(i)
                ));
            }
            if tk(i) == "cfg" || tk(i) == "cfg_attr" {
                findings.push(format!(
                    "{file}:{}: conditional compilation inside `{fname}` — the admit path may \
                     not vary by cfg or cargo feature (CON-008)",
                    ln(i)
                ));
            }
        }
    }
    findings
}

/// Byte sinks in one file as `(enclosing fn, token, line)` with test code
/// excluded, plus the findings that need no allowlist lookup: a `cfg(feature)`,
/// an unrecognised sink shape (fails closed), and a reviewed sink whose text no
/// longer matches its pinned fingerprint. Split out for the same reason as
/// `guard_findings`: so the positive controls can drive it.
fn file_sinks(file: &str, src: &str) -> (Vec<(String, String, usize)>, Vec<String>) {
    let t = tokenize(&code_only(src, false));
    let d = depths(&t);
    let tests = test_ranges(&t, &d);
    let spans = fn_spans(&t, &d);
    let (mut sinks, mut findings) = (Vec::new(), Vec::new());

    for &(f, name, want) in REVIEWED_SINKS.iter().filter(|(f, _, _)| *f == file) {
        // A missing fn is the inventory test's "never re-found" failure; here
        // only a present-but-edited one is a finding.
        if let Some((line, got)) = fn_fingerprint(src, &t, &d, name) {
            if got != want {
                findings.push(format!(
                    "{f}:{line}: `{name}` was edited since its CON-008 review (fingerprint \
                     {got}, reviewed {want}) — re-review what it writes, then pin the new \
                     fingerprint in REVIEWED_SINKS"
                ));
            }
        }
    }

    for i in 0..t.len() {
        if t[i].0 == "cfg" && t.get(i + 1).map(|(s, _)| s.as_str()) == Some("(") {
            let (pred, _) = paren_group(&t, i + 1);
            if pred.contains(&"feature") {
                findings.push(format!(
                    "{file}:{}: `cfg(feature = ..)` — neither caller crate declares a cargo \
                     feature, and a feature is a compile-time off switch (CON-008)",
                    t[i].1
                ));
            }
        }
        let Some(shape) = classify(&t, i).filter(|_| !in_ranges(&tests, i)) else {
            continue;
        };
        let owner = enclosing_fn(&spans, i)
            .unwrap_or("<file scope>")
            .to_string();
        match shape {
            Shape::Sink => sinks.push((owner, t[i].0.clone(), t[i].1)),
            Shape::Unrecognised => findings.push(format!(
                "{file}:{}: unrecognised sink shape `{}` in `{owner}` — this gate cannot say \
                 where those bytes land, so it fails closed; classify the shape in `classify` \
                 (an allowlist entry would pin the wrong function) (CON-008)",
                t[i].1, t[i].0
            )),
        }
    }
    (sinks, findings)
}

/// Nothing in either caller crate emits bytes from a function that has not been
/// reviewed against CON-008, and neither crate carries a cargo feature gate.
/// This is the check that makes deleting an `admit()` call hard to route
/// around: a new writer has to be added to `REVIEWED_SINKS` by hand.
/// One file's inventory: the `(file, fn)` sinks it re-found, and every finding
/// — `file_sinks`'s own plus the `REVIEWED_SINKS` lookup. Split out so the
/// positive controls exercise the allowlist path, not just the detector.
fn inventory(file: &str, src: &str) -> (Vec<(String, String)>, Vec<String>) {
    let (sinks, mut findings) = file_sinks(file, src);
    let mut seen = Vec::new();
    for (owner, tok, line) in sinks {
        if !REVIEWED_SINKS
            .iter()
            .any(|&(f, n, _)| f == file && n == owner)
        {
            findings.push(format!(
                "{file}:{line}: `{tok}` in `{owner}` emits bytes from an unreviewed path — \
                 decide whether an event frame can reach it, put `admit()` in front of it if \
                 it can, and only then add it to REVIEWED_SINKS (CON-008)"
            ));
        }
        seen.push((file.to_string(), owner));
    }
    (seen, findings)
}

#[test]
fn caller_crates_have_no_unreviewed_byte_sink() {
    let sources = caller_sources();
    let (mut files, mut bytes) = (0usize, 0usize);
    let mut seen: Vec<(String, String)> = Vec::new();
    let mut findings: Vec<String> = Vec::new();

    for (file, src) in &sources {
        files += 1;
        bytes += src.len();
        let (s, f) = inventory(file, src);
        seen.extend(s);
        findings.extend(f);
    }

    // Anti-vacuity before the emptiness claim: prove the walk saw both crates.
    assert!(
        files >= 15,
        "vacuous: walked {files} caller source files, expected the whole of both crates"
    );
    assert!(
        bytes > 100_000,
        "vacuous: only {bytes} bytes of caller source scanned"
    );
    // The strongest marker available: every reviewed sink must actually be
    // re-found, which exercises the sink detector, the nested-`fn` mapping and
    // the test-range exclusion together on every known call site in both crates.
    for &(f, n, _) in REVIEWED_SINKS {
        assert!(
            seen.iter().any(|(sf, sn)| sf == f && sn == n),
            "vacuous or regressed: never re-found the reviewed byte sink {f}::{n} — the sink \
             walk is not seeing production code"
        );
    }

    assert!(
        findings.is_empty(),
        "CON-008 caller sink inventory — {} problem(s):\n  {}",
        findings.len(),
        findings.join("\n  ")
    );
}

/// Positive control for the caller half. The two tests above assert an
/// *absence* over real files; if `guard_findings` or `file_sinks` silently
/// stopped matching, both would go green while the property died. So every
/// caller-side regression they claim to catch is planted here on synthetic
/// source and asserted to fire, and a clean shape is asserted to stay silent.
#[test]
fn caller_checker_flags_planted_regressions() {
    // The real shape, minus the parts that do not affect this checker.
    const CLEAN: &str = r#"
pub fn append(base: &Path, mut frame: Vec<u8>) {
    let Some(scanner) = scanner(base) else { return };
    if scanner.admit(&mut frame) == AdmitOutcome::Quarantine {
        frame.zeroize();
        return;
    }
    let _ = file.write_all(&sealed);
}
"#;
    assert!(
        guard_findings("f.rs", "append", CLEAN).is_empty(),
        "false positive on the shape that ships: {:?}",
        guard_findings("f.rs", "append", CLEAN)
    );

    // The regression that needs no new API at all — one deleted line.
    const NO_ADMIT: &str = r#"
pub fn append(base: &Path, mut frame: Vec<u8>) {
    let _ = file.write_all(&frame);
}
"#;
    let f = guard_findings("f.rs", "append", NO_ADMIT).join("\n");
    assert!(
        f.contains("no longer calls `admit()`"),
        "a deleted admit() went unnoticed: {f}"
    );

    // Called, but only down one arm — the "the string admit( appears" trap.
    const ADMIT_IN_BRANCH: &str = r#"
pub fn append(base: &Path, mut frame: Vec<u8>) {
    if paranoid {
        if scanner.admit(&mut frame) == AdmitOutcome::Quarantine { return; }
    }
    let _ = file.write_all(&frame);
}
"#;
    let f = guard_findings("f.rs", "append", ADMIT_IN_BRANCH).join("\n");
    assert!(
        f.contains("sits inside a branch or closure"),
        "admit() in a dead branch passed for a guard: {f}"
    );

    // Called and ignored: the result never gates anything.
    const RESULT_DROPPED: &str = r#"
pub fn append(base: &Path, mut frame: Vec<u8>) {
    let _ = scanner.admit(&mut frame);
    let _ = file.write_all(&frame);
}
"#;
    let f = guard_findings("f.rs", "append", RESULT_DROPPED).join("\n");
    assert!(
        f.contains("no longer compared against an `AdmitOutcome` variant"),
        "a discarded admit() result passed for a guard: {f}"
    );

    // Bytes on disk before the axis runs.
    const WRITE_FIRST: &str = r#"
pub fn append(base: &Path, mut frame: Vec<u8>) {
    let _ = file.write_all(&frame);
    if scanner.admit(&mut frame) == AdmitOutcome::Quarantine { return; }
}
"#;
    let f = guard_findings("f.rs", "append", WRITE_FIRST).join("\n");
    assert!(
        f.contains("emits bytes before `admit()` runs"),
        "a pre-admit write went unnoticed: {f}"
    );

    // An env kill switch and a feature gate on the guarded path.
    const ENV_AND_CFG: &str = r#"
pub fn append(base: &Path, mut frame: Vec<u8>) {
    if std::env::var("M1_SKIP").is_ok() { let _ = file.write_all(&frame); return; }
    #[cfg(feature = "fast_path")]
    let _ = file.write_all(&frame);
    if scanner.admit(&mut frame) == AdmitOutcome::Quarantine { return; }
    let _ = file.write_all(&frame);
}
"#;
    let f = guard_findings("f.rs", "append", ENV_AND_CFG).join("\n");
    assert!(f.contains("environment access `env`"), "env missed: {f}");
    assert!(
        f.contains("conditional compilation inside `append`"),
        "cfg missed: {f}"
    );

    // The loop ban, which is what licenses reading textual order as domination.
    const LOOPED: &str = r#"
pub fn append(base: &Path, mut frame: Vec<u8>) {
    if scanner.admit(&mut frame) == AdmitOutcome::Quarantine { return; }
    for chunk in frame.chunks(64) { let _ = file.write_all(chunk); }
}
"#;
    let f = guard_findings("f.rs", "append", LOOPED).join("\n");
    assert!(
        f.contains("cannot establish domination"),
        "loop not flagged: {f}"
    );

    // A renamed guard must not read as a clean guard.
    let f = guard_findings("f.rs", "append_v2", CLEAN).join("\n");
    assert!(f.contains("is gone"), "a renamed guard passed: {f}");

    // And a guard whose sink the detector cannot see reports itself vacuous,
    // rather than reporting a passing ordering check over zero writes.
    const NO_SINK: &str = r#"
pub fn append(base: &Path, mut frame: Vec<u8>) {
    if scanner.admit(&mut frame) == AdmitOutcome::Quarantine { return; }
}
"#;
    let f = guard_findings("f.rs", "append", NO_SINK).join("\n");
    assert!(f.contains("vacuous: no byte-emitting call"), "{f}");

    // The inventory half: a new writer in a new function is unreviewed, a
    // `write(true)` handle option is not a write, and test code is excluded.
    const NEW_SINK: &str = r#"
fn upload(frame: &[u8]) {
    let mut f = OpenOptions::new().write(true).open(p).unwrap();
    let _ = f.write_all(frame);
}
#[cfg(test)]
mod tests {
    fn t() { let _ = f.write_all(b"fixture"); }
}
"#;
    let (sinks, _) = file_sinks("n.rs", NEW_SINK);
    assert_eq!(
        sinks
            .iter()
            .map(|(o, t, _)| (o.as_str(), t.as_str()))
            .collect::<Vec<_>>(),
        vec![("upload", "write_all")],
        "sink inventory should see exactly the one non-test write"
    );
    let (_, cfgs) = file_sinks("n.rs", "#[cfg(feature = \"off\")]\nfn x() {}\n");
    assert!(
        cfgs.iter().any(|c| c.contains("cfg(feature = ..)")),
        "caller-crate feature gate not flagged: {cfgs:?}"
    );
}

/// Positive control for the fingerprint pin. A reviewed sink widened in place
/// — one token, `sealed` → `frame`, the redacted-and-sealed record replaced by
/// the raw event — changes nothing the inventory keys on (same file, same fn,
/// same `write_all`), so only the fingerprint can catch it. A literal edit is
/// also a widening (`format!` strings are what `record_kill` writes); a comment
/// edit is not, and must not flip the pin, or the pin gets bumped unread.
#[test]
fn widened_reviewed_sink_is_named() {
    const FILE: &str = "mark1-proxy/src/tee/spill.rs";
    let sources = caller_sources();
    let (_, real) = sources
        .iter()
        .find(|(p, _)| p == FILE)
        .expect("vacuous: proxy spill.rs not found");
    let (_, clean) = inventory(FILE, real);
    assert!(
        clean.is_empty(),
        "control cannot start from a red gate: {clean:?}"
    );

    let widened = real.replace("file.write_all(&sealed)", "file.write_all(&frame)");
    assert_ne!(
        widened, *real,
        "vacuous: the planted widening changed nothing"
    );
    let (_, f) = inventory(FILE, &widened);
    assert!(
        f.iter()
            .any(|x| x.contains("`append` was edited since its CON-008 review")),
        "a one-token widening of a reviewed sink went unnoticed: {f:?}"
    );

    let literal = real.replace("\"proxy.ring\"", "\"proxy.ring.plain\"");
    assert_ne!(
        literal, *real,
        "vacuous: the planted literal edit changed nothing"
    );
    let (_, f) = inventory(FILE, &literal);
    assert!(
        f.iter().any(|x| x.contains("`append` was edited")),
        "a literal edit inside a reviewed sink went unnoticed: {f:?}"
    );

    let commented = real.replace(
        "    let _ = file.write_all(&sealed);",
        "    // reviewed 2026-09: sealed only\n    let _ = file.write_all(&sealed);",
    );
    assert_ne!(
        commented, *real,
        "vacuous: the planted comment changed nothing"
    );
    let (_, f) = inventory(FILE, &commented);
    assert!(
        f.is_empty(),
        "a comment flipped the fingerprint — a pin that moves on prose gets re-pinned \
         without a re-review: {f:?}"
    );
}

/// Positive control for the sink model. Each shape the ledger called invisible
/// is planted alone in a fresh `fn` and must surface as an unreviewed sink (the
/// allowlist path) and, ahead of `admit()`, as a pre-admit write (the
/// domination path); a write-like name the model cannot attribute must fail
/// closed as an unrecognised shape; and the look-alikes that emit nothing
/// (`OpenOptions::write(true)`, a `stdout()` handle, a `BufWriter` type, a
/// `fn flush` definition) must stay silent, because a gate that fires on its
/// own plumbing gets disabled.
#[test]
fn sink_shapes_are_recognised_or_refused() {
    // `(token the finding names, one statement that emits through that shape)`.
    const RECOGNISED: &[(&str, &str)] = &[
        (
            "copy",
            "let _ = std::io::copy(&mut frame.as_slice(), &mut file);",
        ),
        ("to_writer", "let _ = serde_json::to_writer(&file, &frame);"),
        ("BufWriter", "let w = BufWriter::new(file);"),
        (
            "stdout",
            "let _ = Command::new(\"tee\").stdout(file).spawn();",
        ),
        ("Stdio", "let s = Stdio::from(file);"),
        (
            "map_mut",
            "let m = unsafe { MmapOptions::new().map_mut(&file) };",
        ),
        ("write", "let _ = file.write(&frame);"),
        ("eprintln", "eprintln!(\"{frame:?}\");"),
        (
            "write_vectored",
            "let _ = file.write_vectored(&[IoSlice::new(&frame)]);",
        ),
        ("flush", "let _ = file.flush();"),
    ];
    for &(tok, stmt) in RECOGNISED {
        let src = format!("fn f(mut file: File, frame: Vec<u8>) {{ {stmt} }}");
        let (seen, f) = inventory("scratch.rs", &src);
        assert!(
            seen.contains(&("scratch.rs".to_string(), "f".to_string())),
            "`{tok}` not recognised as a sink in `f`: {f:?}"
        );
        assert!(
            f.iter().any(|x| x.contains(&format!(
                "`{tok}` in `f` emits bytes from an unreviewed path"
            ))),
            "`{tok}` recognised but not put through the allowlist: {f:?}"
        );
        // Ahead of admit() inside a guarded body, the same shape is a pre-admit write.
        let guarded = format!(
            "pub fn append(base: &Path, mut frame: Vec<u8>) {{\n    {stmt}\n    if \
             scanner.admit(&mut frame) == AdmitOutcome::Quarantine {{ return; }}\n    let _ = \
             ring.write_all(&frame);\n}}"
        );
        let g = guard_findings("g.rs", "append", &guarded).join("\n");
        assert!(
            g.contains(&format!("`{tok}` emits bytes before `admit()`")),
            "`{tok}` ahead of admit() passed the domination check: {g}"
        );
    }

    const UNRECOGNISED: &[(&str, &str)] = &[
        (
            "persist",
            "fn f(t: NamedTempFile, p: &Path) { let _ = t.persist(p); }",
        ),
        (
            "copy",
            "fn f(mut a: File, mut b: File) { let _ = copy(&mut a, &mut b); }",
        ),
        (
            "rename",
            "fn f(a: &Path, b: &Path) { let _ = std::fs::rename(a, b); }",
        ),
        ("set_len", "fn f(file: &File) { let _ = file.set_len(0); }"),
    ];
    for &(tok, src) in UNRECOGNISED {
        let (seen, f) = inventory("scratch.rs", src);
        assert!(
            f.iter()
                .any(|x| x.contains(&format!("unrecognised sink shape `{tok}` in `f`"))),
            "`{tok}` did not fail closed: {f:?}"
        );
        assert!(
            seen.is_empty(),
            "`{tok}` must be refused, not attributed as a reviewable sink: {seen:?}"
        );
    }

    const SILENT: &str = r#"
use std::io::BufWriter;
fn open(p: &Path) -> std::io::Result<File> { OpenOptions::new().write(true).create(true).open(p) }
fn handle() -> Stdout { std::io::stdout() }
fn child(c: &mut Child) -> Option<ChildStdout> { c.stdout.take() }
fn flush(home: Option<&Path>) { if fabric::flush(&frame, id, budget).is_err() { count(home) } }
fn sink(w: BufWriter<File>) -> usize { w.capacity() }
fn either(a: bool, b: bool) -> bool { a || b }
"#;
    let (seen, f) = inventory("silent.rs", SILENT);
    assert!(
        seen.is_empty() && f.is_empty(),
        "false positive on a non-emitting shape — a gate that fires on its own plumbing gets \
         disabled: seen {seen:?}, findings {f:?}"
    );
}

/// Positive control for the domination refusal. Textual order is execution
/// order only in straight-line code; a sink inside a closure or an `async`
/// block runs when that runs. The clean shapes — a sink-free closure (the real
/// `append` bodies have `.map(|m| m.len() ..)`), a logical `||`, a `|` in a
/// match pattern — must stay silent, or the refusal gets allowlisted away.
#[test]
fn sink_inside_loop_or_closure_refuses_domination() {
    const PLANTED: &[(&str, &str)] = &[
        (
            "block closure",
            "pub fn append(base: &Path, mut frame: Vec<u8>) {\n    if scanner.admit(&mut frame) \
             == AdmitOutcome::Quarantine { return; }\n    let w = move |b: &[u8]| { let _ = \
             file.write_all(b); };\n    w(&frame);\n}",
        ),
        (
            "expression closure",
            "pub fn append(base: &Path, mut frame: Vec<u8>) {\n    if scanner.admit(&mut frame) \
             == AdmitOutcome::Quarantine { return; }\n    let _ = frame.chunks(64).map(|c| \
             file.write_all(c)).count();\n}",
        ),
        (
            "empty-params closure",
            "pub fn append(base: &Path, mut frame: Vec<u8>) {\n    if scanner.admit(&mut frame) \
             == AdmitOutcome::Quarantine { return; }\n    later(|| file.write_all(&frame));\n}",
        ),
        (
            "async block",
            "pub fn append(base: &Path, mut frame: Vec<u8>) {\n    if scanner.admit(&mut frame) \
             == AdmitOutcome::Quarantine { return; }\n    spawn(async move { let _ = \
             file.write_all(&frame).await; });\n}",
        ),
        (
            "loop after admit",
            "pub fn append(base: &Path, mut frame: Vec<u8>) {\n    if scanner.admit(&mut frame) \
             == AdmitOutcome::Quarantine { return; }\n    while retry() { let _ = \
             file.write_all(&frame); }\n}",
        ),
    ];
    for &(what, src) in PLANTED {
        let f = guard_findings("g.rs", "append", src).join("\n");
        assert!(
            f.contains("cannot establish domination"),
            "{what}: a sink whose execution point is not its textual position passed as \
             dominated: {f}"
        );
    }

    const CLEAN: &str = r#"
pub fn append(base: &Path, mut frame: Vec<u8>) {
    if scanner.admit(&mut frame) == AdmitOutcome::Quarantine { return; }
    if frame.is_empty() || base.as_os_str().is_empty() { return; }
    let full = file.metadata().map(|m| m.len() + frame.len() as u64 > MAX).unwrap_or(true);
    match mode { Mode::A | Mode::B => {} _ => return }
    if full { return; }
    let _ = file.write_all(&frame);
}
"#;
    let f = guard_findings("g.rs", "append", CLEAN);
    assert!(
        f.is_empty(),
        "false positive on a sink-free closure, a logical `||` or a pattern `|`: {f:?}"
    );
}
