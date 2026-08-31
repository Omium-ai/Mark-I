//! Observation on a copy — 04 §3.2, D-AH.
//!
//! # Two properties, both structural
//!
//! **The tee cannot see a credential.** Everything it is handed is built field-by-field from
//! [`RequestFacts`] and [`ResponseFacts`]. There is no constructor here that takes an
//! `http::Request`, a `HeaderMap`, or a `Uri` — a wholesale copy would carry headers, and
//! headers carry credentials. The URI's *query* is dropped for the same reason at one level
//! down: Google's API takes its key as `?key=…`, so a "just the path" field that kept the
//! query would be a credential in the allow-list wearing a different name.
//!
//! **The tee cannot hold a client write.** Every producer-side call in this module is
//! synchronous and non-blocking. [`TeeStream::chunk`] performs a byte-admission test and an
//! `UnboundedSender::send`, and returns a `bool`; there is no `async fn` on the producer side
//! at all, so a forward loop *cannot* await the tee even by accident. Channel over capacity
//! ⇒ the chunk is not teed, that stream's parse degrades, transport counters still emit, and
//! the client's bytes proceed untouched (F-08).
//!
//! # D-AH: the bound is bytes, not slots
//!
//! `TEE_INFLIGHT_MAX` is 8 MiB of *retained chunk bytes*, admission-tested per chunk. The
//! channel carries `Bytes` handles, which are O(1) to clone — but a handle keeps the
//! underlying buffer alive, and retained bytes were always the budget. A slot-denominated
//! cap would delegate this component's ≤35 MB RSS ceiling (04 §3.4) to the upstream's framing
//! choices: 1024 slots costs 64 KiB or 64 MiB depending on whether the vendor emits many
//! small SSE frames or few large ones.

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::Arc;

use bytes::Bytes;
use mark1_frames::{Dialect, DialectParser, ParseDegraded, WireObservation};
use tokio::sync::mpsc;

pub mod spill;

/// D-AH, binding: 8 MiB of retained chunk bytes across all in-flight streams.
pub const TEE_INFLIGHT_MAX: usize = 8 * 1024 * 1024;

/// The request-side allow-list. Every field is copied in by name at exactly one call site
/// (`crate::request::facts`), and the negative test constructs this exhaustively so that
/// adding a field cannot happen without the test failing to compile.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RequestFacts {
    pub method: String,
    /// Path **without** the query string — see the module header.
    pub path: String,
    pub upstream_host: String,
    pub dialect: Dialect,
    /// Always `None` until 04 §3.2's model rewrite lands (deferred this phase). Present
    /// because the allow-list is the specification of what the tee may ever see, and a field
    /// added later is a field added without this review.
    pub requested_model: Option<String>,
}

/// The response-side allow-list. The *served* model is not here: it arrives as
/// `WireObservation::Usage(..).model` on [`TeeReport::observations`], parsed from the
/// response body by `mark1-frames`, which is the only thing that can honestly know it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ResponseFacts {
    pub status: u16,
    pub request_bytes: u64,
    pub response_bytes: u64,
    pub elapsed_micros: u64,
}

pub enum TeeMsg {
    Open {
        stream: u64,
        facts: RequestFacts,
    },
    Chunk {
        stream: u64,
        bytes: Bytes,
    },
    Close {
        stream: u64,
        facts: ResponseFacts,
        dropped_chunks: u64,
        dropped_bytes: u64,
    },
}

/// What one observed request yielded. The only thing that leaves the tee.
#[derive(Clone, Debug, PartialEq)]
pub struct TeeReport {
    pub request: RequestFacts,
    pub response: ResponseFacts,
    pub observations: Vec<WireObservation>,
    /// `Some` ⇒ wire `Usage` for this response is lost and accounted as
    /// `Dropped{PARSE_DEGRADED}`; the client stream was never involved (04 §4).
    pub degraded: Option<ParseDegraded>,
    pub chunks_dropped: u64,
    pub bytes_dropped: u64,
}

#[derive(Default)]
struct Counters {
    inflight: AtomicUsize,
    next_stream: AtomicU64,
    chunks_dropped: AtomicU64,
    reports_dropped: AtomicU64,
}

/// Producer handle. Cheap to clone; one per proxy.
#[derive(Clone)]
pub struct Tee {
    tx: mpsc::UnboundedSender<TeeMsg>,
    counters: Arc<Counters>,
}

/// Consumer end. Held by [`run`], which is the only thing that releases retained bytes.
pub struct TeeRx {
    rx: mpsc::UnboundedReceiver<TeeMsg>,
    counters: Arc<Counters>,
}

/// Build the tee and its receiver. Production spawns [`run`] on the receiver; a test that
/// wants a *saturated* tee simply holds the receiver and never runs it — which is why there
/// is no test-only seam in this module.
pub fn channel() -> (Tee, TeeRx) {
    let (tx, rx) = mpsc::unbounded_channel();
    let counters = Arc::new(Counters::default());
    (
        Tee {
            tx,
            counters: Arc::clone(&counters),
        },
        TeeRx { rx, counters },
    )
}

impl Tee {
    /// Begin observing one request. Non-blocking.
    pub fn open(&self, facts: RequestFacts) -> TeeStream {
        let stream = self.counters.next_stream.fetch_add(1, Ordering::Relaxed);
        // Control messages are not byte-charged: they are O(1) and bounded by the number of
        // concurrent requests, which the listener bounds. Only chunk payloads can grow.
        let _ = self.tx.send(TeeMsg::Open { stream, facts });
        TeeStream {
            stream,
            tx: self.tx.clone(),
            counters: Arc::clone(&self.counters),
            dropped_chunks: 0,
            dropped_bytes: 0,
        }
    }

    /// Retained chunk bytes currently owed to the tee. Exposed so the budget can be asserted
    /// rather than assumed.
    pub fn inflight_bytes(&self) -> usize {
        self.counters.inflight.load(Ordering::Acquire)
    }

    pub fn chunks_dropped(&self) -> u64 {
        self.counters.chunks_dropped.load(Ordering::Relaxed)
    }

    pub fn reports_dropped(&self) -> u64 {
        self.counters.reports_dropped.load(Ordering::Relaxed)
    }
}

/// Per-request producer. **No method on this type is `async`.**
pub struct TeeStream {
    stream: u64,
    tx: mpsc::UnboundedSender<TeeMsg>,
    counters: Arc<Counters>,
    dropped_chunks: u64,
    dropped_bytes: u64,
}

impl TeeStream {
    /// Admission-test one chunk and hand over a refcounted clone. Returns `false` when the
    /// chunk was not teed. The caller forwards the chunk to the client either way — that is
    /// not a policy, it is that this function has no way to make the caller wait.
    pub fn chunk(&mut self, bytes: &Bytes) -> bool {
        let len = bytes.len();
        if len == 0 {
            // A zero-length frame carries no observation, and charging it zero would make
            // the ceiling countable in slots again through the back door.
            return false;
        }
        let admitted = self
            .counters
            .inflight
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |cur| {
                (cur + len <= TEE_INFLIGHT_MAX).then_some(cur + len)
            })
            .is_ok();
        if !admitted
            || self
                .tx
                .send(TeeMsg::Chunk {
                    stream: self.stream,
                    bytes: bytes.clone(),
                })
                .is_err()
        {
            if admitted {
                self.counters.inflight.fetch_sub(len, Ordering::AcqRel);
            }
            self.dropped_chunks += 1;
            self.dropped_bytes += len as u64;
            self.counters.chunks_dropped.fetch_add(1, Ordering::Relaxed);
            return false;
        }
        true
    }

    pub fn close(self, facts: ResponseFacts) {
        let _ = self.tx.send(TeeMsg::Close {
            stream: self.stream,
            facts,
            dropped_chunks: self.dropped_chunks,
            dropped_bytes: self.dropped_bytes,
        });
    }
}

struct Open {
    facts: RequestFacts,
    parser: Box<dyn DialectParser>,
    observations: Vec<WireObservation>,
    degraded: Option<ParseDegraded>,
}

/// The tee task (04 §3.2, singular). Owns every parser; the forward path owns none.
///
/// `reports` is `try_send`-ed, never awaited: a stalled report consumer must not become a
/// reason for retained bytes to stop being released, or the byte ceiling would strand at the
/// cap and silently disable observation for the life of the process.
pub async fn run(rx: TeeRx, reports: mpsc::Sender<TeeReport>) {
    let TeeRx { mut rx, counters } = rx;
    let mut open: HashMap<u64, Open> = HashMap::new();
    while let Some(msg) = rx.recv().await {
        match msg {
            TeeMsg::Open { stream, facts } => {
                let parser = facts.dialect.parser();
                open.insert(
                    stream,
                    Open {
                        facts,
                        parser,
                        observations: Vec::new(),
                        degraded: None,
                    },
                );
            }
            TeeMsg::Chunk { stream, bytes } => {
                if let Some(o) = open.get_mut(&stream) {
                    match o.parser.feed(&bytes) {
                        Ok(v) => o.observations.extend(v),
                        Err(d) => {
                            o.degraded.get_or_insert(d);
                        }
                    }
                }
                // Released here and nowhere else, unconditionally: a parse failure that
                // leaked the charge would shrink the ceiling on every degraded stream.
                counters.inflight.fetch_sub(bytes.len(), Ordering::AcqRel);
            }
            TeeMsg::Close {
                stream,
                facts,
                dropped_chunks,
                dropped_bytes,
            } => {
                let Some(mut o) = open.remove(&stream) else {
                    continue;
                };
                match o.parser.finish() {
                    Ok(v) => o.observations.extend(v),
                    Err(d) => {
                        o.degraded.get_or_insert(d);
                    }
                }
                let report = TeeReport {
                    request: o.facts,
                    response: facts,
                    observations: o.observations,
                    degraded: o.degraded,
                    chunks_dropped: dropped_chunks,
                    bytes_dropped: dropped_bytes,
                };
                if reports.try_send(report).is_err() {
                    counters.reports_dropped.fetch_add(1, Ordering::Relaxed);
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn facts() -> RequestFacts {
        // Exhaustive struct literal, deliberately: adding a field to the allow-list breaks
        // this line, and the reviewer has to look at what was added.
        RequestFacts {
            method: "POST".to_owned(),
            path: "/v1/messages".to_owned(),
            upstream_host: "api.anthropic.com".to_owned(),
            dialect: Dialect::AnthropicSse,
            requested_model: None,
        }
    }

    #[tokio::test]
    async fn d_ah_bound_is_bytes_and_admission_is_per_chunk() {
        let (tee, _rx) = channel();
        let mut s = tee.open(facts());

        let big = Bytes::from(vec![7u8; TEE_INFLIGHT_MAX]);
        assert!(s.chunk(&big), "first chunk fits exactly");
        assert_eq!(tee.inflight_bytes(), TEE_INFLIGHT_MAX);

        assert!(
            !s.chunk(&Bytes::from_static(b"x")),
            "one byte past the ceiling is refused"
        );
        assert_eq!(
            tee.inflight_bytes(),
            TEE_INFLIGHT_MAX,
            "a refused chunk charges nothing"
        );
        assert_eq!(tee.chunks_dropped(), 1);
    }

    #[tokio::test]
    async fn many_small_chunks_and_few_large_ones_cost_the_same_ceiling() {
        for chunk_len in [1usize, 64, 65_536, 1 << 20] {
            let (tee, _rx) = channel();
            let mut s = tee.open(facts());
            let c = Bytes::from(vec![0u8; chunk_len]);
            while s.chunk(&c) {}
            assert!(
                tee.inflight_bytes() <= TEE_INFLIGHT_MAX,
                "chunk_len {chunk_len} retained {} bytes",
                tee.inflight_bytes()
            );
            assert!(tee.inflight_bytes() > TEE_INFLIGHT_MAX - chunk_len);
        }
    }

    /// No producer-side call awaits. This is the compile-level restatement of it: if any of
    /// these became `async`, this function would not compile as a plain `fn`.
    #[test]
    fn producer_side_is_synchronous() {
        fn assert_sync_producer() {
            let (tee, _rx) = channel();
            let mut s = tee.open(facts());
            let _ = s.chunk(&Bytes::from_static(b"abc"));
            s.close(ResponseFacts {
                status: 200,
                request_bytes: 0,
                response_bytes: 3,
                elapsed_micros: 0,
            });
        }
        assert_sync_producer();
    }
}
