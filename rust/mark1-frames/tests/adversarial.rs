//! Pathological input. The parse-tee contract (04 §4) says a parse failure narrows
//! observation and nothing else — but only because this crate cannot panic, cannot block,
//! and cannot grow without bound. A panic in the tee task takes down a worker that is
//! carrying a customer's response; these are the tests that keep that from being true.

use mark1_frames::{DegradeReason, Dialect};

/// Feeds `bytes` whole and then one byte at a time. Returns the byte-at-a-time terminal
/// state. Surviving the call *is* the assertion: a panic here fails the test.
fn survive(bytes: &[u8]) -> Option<DegradeReason> {
    let mut whole = Dialect::AnthropicSse.parser();
    let _ = whole.feed(bytes);
    let _ = whole.finish();

    let mut split = Dialect::AnthropicSse.parser();
    let mut last = None;
    for i in 0..bytes.len() {
        if let Err(d) = split.feed(&bytes[i..=i]) {
            last = Some(d.reason);
            break;
        }
    }
    if last.is_none() {
        if let Err(d) = split.finish() {
            last = Some(d.reason);
        }
    }
    // Calling twice past the end must also be safe — the tee may finish a cancelled stream.
    let _ = split.finish();
    last
}

#[test]
fn pathological_input_never_panics() {
    // 200k nested arrays: past serde_json's recursion limit (an error, not a stack
    // overflow) and long enough to double as the quadratic-rescan guard below.
    let deep_json = {
        let mut s = b"event: message_start\ndata: ".to_vec();
        s.extend(std::iter::repeat_n(b'[', 200_000));
        s.extend_from_slice(b"\n\n");
        s
    };
    let started = std::time::Instant::now();

    let cases: Vec<Vec<u8>> = vec![
        b"".to_vec(),
        b"\0\0\0\0".to_vec(),
        b"\r".to_vec(),
        b"\n\n\n\n".to_vec(),
        b"\r\n\r\n".to_vec(),
        b": comment with no event\n\n".to_vec(),
        b"data\n\n".to_vec(),                 // field name, no colon, no value
        b"event: message_start\n\n".to_vec(), // dispatchable event with no data at all
        b"data: {}\n\n".to_vec(),             // data with no event name
        b"event: message_start\ndata: {\"messa".to_vec(), // truncated mid-JSON, no terminator
        b"event: message_start\ndata: \xff\xfe\xfd\n\n".to_vec(), // invalid UTF-8 payload
        b"event: \xff\xfe\ndata: {}\n\n".to_vec(), // invalid UTF-8 event name
        b"event: message_delta\ndata: {\"usage\":{\"output_tokens\":1}}\n\n".to_vec(), // no message_start
        b"event: message_start\ndata: {\"message\":{\"id\":1,\"model\":[],\"usage\":null}}\n\n"
            .to_vec(),
        vec![0xf0, 0x9f, 0xa7], // a lone truncated UTF-8 code point, nothing else
        deep_json,
    ];

    let expected_cases = 16;
    assert_eq!(
        cases.len(),
        expected_cases,
        "case table changed; update the count"
    );
    for case in &cases {
        survive(case);
    }

    // The framer must examine each byte once. When it rescanned the pending buffer per
    // chunk instead, the 200k case above took ~2 minutes in a debug build feeding one byte
    // at a time; it takes well under a second now. The margin is wide enough that this is a
    // regression tripwire rather than a timing test — a dribbling upstream must not be able
    // to spend the tee's CPU quadratically.
    let elapsed = started.elapsed();
    assert!(
        elapsed.as_secs() < 10,
        "framing went quadratic: {elapsed:?} for 200k bytes"
    );
}

#[test]
fn a_single_unterminated_line_degrades_instead_of_buffering() {
    // 10 MB with no line terminator anywhere: the shape that turns a naive SSE framer into
    // an out-of-memory. It must be refused, and refused well inside the proxy's ≤35 MB RSS
    // budget (04 §3.4) — if raising the cap ever makes this fail, the budget moved with it.
    const BUDGET: usize = 2 << 20;
    let chunk = vec![b'x'; 64 * 1024];

    let mut parser = Dialect::AnthropicSse.parser();
    let mut accepted = 0usize;
    let mut reason = None;
    while accepted < 10 * 1024 * 1024 {
        match parser.feed(&chunk) {
            Ok(v) => assert!(
                v.is_empty(),
                "an unterminated line cannot yield an observation"
            ),
            Err(d) => {
                reason = Some(d.reason);
                break;
            }
        }
        accepted += chunk.len();
        assert!(
            accepted <= BUDGET,
            "retained {accepted} bytes of one line without degrading"
        );
    }

    assert_eq!(reason, Some(DegradeReason::PendingBufferOverflow));
    // Sticky, so the tee stops paying for a stream it can no longer observe.
    assert_eq!(
        parser
            .feed(b"event: ping\ndata: {}\n\n")
            .unwrap_err()
            .reason,
        DegradeReason::PendingBufferOverflow
    );
}

#[test]
fn overflow_does_not_swallow_usage_already_observed() {
    // A degrade must not retroactively erase a billing fact the parser already read: the
    // `message_start` usage is emitted before the oversize line arrives, and the tee keeps it.
    let mut parser = Dialect::AnthropicSse.parser();
    let start = br#"event: message_start
data: {"type":"message_start","message":{"id":"msg_1","model":"claude-opus-5","usage":{"input_tokens":5,"output_tokens":1}}}

"#;
    assert_eq!(parser.feed(start).unwrap().len(), 1);
    while parser.feed(&vec![b'x'; 64 * 1024]).is_ok() {}
    assert_eq!(
        parser.finish().unwrap_err().reason,
        DegradeReason::PendingBufferOverflow
    );
}

#[test]
fn unimplemented_dialects_degrade_on_every_input() {
    for dialect in Dialect::ALL {
        if dialect == Dialect::AnthropicSse {
            continue;
        }
        let mut parser = dialect.parser();
        for case in [
            &b""[..],
            b"\0\xff",
            b"data: {\"usage\":{\"output_tokens\":9}}\n\n",
        ] {
            assert_eq!(
                parser.feed(case).unwrap_err().reason,
                DegradeReason::NotImplemented,
                "{dialect:?} answered for input it cannot parse"
            );
        }
        assert_eq!(
            parser.finish().unwrap_err().reason,
            DegradeReason::NotImplemented
        );
    }
}
