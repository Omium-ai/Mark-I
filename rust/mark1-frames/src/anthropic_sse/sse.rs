//! A `text/event-stream` framer: bytes in, complete SSE events out.
//!
//! Written to the WHATWG event-stream rules rather than to Anthropic's happy path,
//! because the parser is fed by a tee that can split a chunk at any offset — including
//! between the `\r` and the `\n` of a line terminator, and mid-UTF-8. Nothing here
//! interprets bytes as text except the two field names it matches; a `data:` payload is
//! handed to the caller as bytes and only `serde_json` decides whether it is UTF-8.

/// Cap on bytes retained for one in-progress event.
///
/// Real Anthropic events are a few hundred bytes; the largest plausible one is a
/// `content_block_delta` carrying a tool-input fragment. 1 MiB is three orders of
/// magnitude of headroom and still 8× under the tee's own `TEE_INFLIGHT_MAX` (D-AH,
/// 8 MiB), which is what keeps parser state a rounding error against the proxy's
/// ≤35 MB RSS budget. Exceeding it degrades the stream; it never grows the buffer.
pub(super) const MAX_PENDING_BYTES: usize = 1 << 20;

pub(super) struct Event {
    pub(super) name: String,
    pub(super) data: Vec<u8>,
    /// Stream offset just past this event's terminating blank line. Independent of how
    /// the caller chunked its input, which is what makes a degrade offset reproducible.
    pub(super) end_offset: u64,
}

pub(super) struct Framer {
    /// Bytes received but not yet resolved into complete lines.
    pending: Vec<u8>,
    /// Accumulated `data:` payload of the event currently being built.
    data: Vec<u8>,
    name: String,
    /// Bytes drained from `pending` as complete lines. Never counts bytes we refused.
    consumed: u64,
    /// Offset into `pending` already searched for a line terminator. Without it, a long
    /// line arriving in small chunks is rescanned from the front on every chunk — O(n²)
    /// CPU that an upstream dribbling bytes could aim at the tee. Each byte is examined
    /// once instead.
    scan_from: usize,
}

impl Framer {
    pub(super) fn new() -> Self {
        Framer {
            pending: Vec::new(),
            data: Vec::new(),
            name: String::new(),
            consumed: 0,
            scan_from: 0,
        }
    }

    /// Offset used to report a buffer-overflow degrade: the last byte we were willing
    /// to retain.
    pub(super) fn retained_offset(&self) -> u64 {
        self.consumed + self.held() as u64
    }

    fn held(&self) -> usize {
        self.pending.len() + self.data.len() + self.name.len()
    }

    /// Returns `Err(())` when the chunk cannot be admitted without breaking the cap.
    /// The chunk is not appended in that case — refusing bytes is what makes the bound
    /// a bound rather than a post-hoc observation.
    pub(super) fn push(&mut self, chunk: &[u8], out: &mut Vec<Event>) -> Result<(), ()> {
        if self.held() + chunk.len() > MAX_PENDING_BYTES {
            return Err(());
        }
        self.pending.extend_from_slice(chunk);

        // `pending` is taken out for the scan so line slices and the event buffers are
        // provably disjoint borrows; it goes back at the end of the call.
        let pending = std::mem::take(&mut self.pending);
        let mut cursor = 0usize; // start of the line being built
        let mut search = self.scan_from; // never revisits a byte already searched
        let next_scan;
        loop {
            let Some(rel) = pending[search..]
                .iter()
                .position(|&b| b == b'\n' || b == b'\r')
            else {
                next_scan = pending.len();
                break;
            };
            let end = search + rel;
            let consume = if pending[end] == b'\n' {
                end + 1
            } else if let Some(&b) = pending.get(end + 1) {
                if b == b'\n' {
                    end + 2
                } else {
                    end + 1
                }
            } else {
                // A trailing lone `\r` is held back: it may be the first half of a `\r\n`
                // that lands in the next chunk, and guessing would split one line in two.
                next_scan = end;
                break;
            };

            let line = &pending[cursor..end];
            self.consumed += (consume - cursor) as u64;
            cursor = consume;
            search = consume;

            if line.is_empty() {
                // Blank line dispatches. An event with no data is not dispatched
                // (spec rule); it only resets the name, which is how a stray `\n\n`
                // in a keepalive cannot manufacture a phantom event.
                if !self.data.is_empty() {
                    out.push(Event {
                        name: std::mem::take(&mut self.name),
                        data: std::mem::take(&mut self.data),
                        end_offset: self.consumed,
                    });
                } else {
                    self.name.clear();
                }
                continue;
            }
            self.absorb_field(line);
        }
        self.pending = pending;
        self.pending.drain(..cursor);
        self.scan_from = next_scan - cursor;
        Ok(())
    }

    fn absorb_field(&mut self, line: &[u8]) {
        if line[0] == b':' {
            return; // comment / keepalive
        }
        let (field, value) = match line.iter().position(|&b| b == b':') {
            Some(i) => {
                let v = &line[i + 1..];
                (&line[..i], v.strip_prefix(b" ").unwrap_or(v))
            }
            None => (line, &b""[..]),
        };
        match field {
            b"event" => {
                self.name.clear();
                // Lossy: a non-UTF-8 event name matches no known event and is ignored
                // downstream. It must not be a parse failure — unknown event types are
                // explicitly a "handle gracefully" case in the vendor's grammar.
                self.name.push_str(&String::from_utf8_lossy(value));
            }
            b"data" => {
                if !self.data.is_empty() {
                    self.data.push(b'\n');
                }
                self.data.extend_from_slice(value);
            }
            _ => {} // `id`, `retry`, and anything the vendor adds later
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn events(chunks: &[&[u8]]) -> Vec<(String, Vec<u8>)> {
        let mut f = Framer::new();
        let mut out = Vec::new();
        for c in chunks {
            f.push(c, &mut out).unwrap();
        }
        out.into_iter().map(|e| (e.name, e.data)).collect()
    }

    #[test]
    fn crlf_split_across_chunks_is_one_line() {
        let whole = events(&[b"event: a\r\ndata: 1\r\n\r\n"]);
        let split = events(&[b"event: a\r", b"\ndata: 1\r", b"\n\r", b"\n"]);
        assert_eq!(whole, split);
        assert_eq!(whole, vec![("a".to_string(), b"1".to_vec())]);
    }

    #[test]
    fn multi_data_lines_join_with_newline() {
        assert_eq!(
            events(&[b"event: a\ndata: x\ndata: y\n\n"]),
            vec![("a".to_string(), b"x\ny".to_vec())]
        );
    }

    #[test]
    fn comments_and_empty_events_dispatch_nothing() {
        assert_eq!(
            events(&[b": keepalive\n\n\n\nevent: a\ndata: z\n\n"]),
            vec![("a".to_string(), b"z".to_vec())]
        );
    }

    /// Resuming the terminator search mid-buffer must not lose a line boundary.
    #[test]
    fn resumed_scanning_frames_a_long_line_split_across_chunks() {
        let long = format!("data: {}\n\n", "y".repeat(4096));
        let per_byte: Vec<&[u8]> = long.as_bytes().chunks(1).collect();
        let whole = events(&[long.as_bytes()]);
        assert_eq!(whole, events(&per_byte));
        assert_eq!(whole.len(), 1);
        assert_eq!(whole[0].1.len(), 4096);
    }

    #[test]
    fn oversize_pending_is_refused_not_buffered() {
        let mut f = Framer::new();
        let mut out = Vec::new();
        let big = vec![b'x'; MAX_PENDING_BYTES + 1];
        assert!(f.push(&big, &mut out).is_err());
        assert!(
            f.held() <= MAX_PENDING_BYTES,
            "refused bytes must not be retained"
        );
    }
}
