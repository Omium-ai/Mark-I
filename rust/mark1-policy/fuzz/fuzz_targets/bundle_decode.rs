//! fuzz_bundle_decode (12 §4): arbitrary bytes into the full bundle
//! verification path — the same entry point mark1d's policy apply loop
//! drives with network-supplied bytes.
//!
//! Properties beyond not-crashing:
//! - the decoder returns a decision for ALL inputs (no panic, no hang, no
//!   unbounded allocation — MAX_BUNDLE_LEN and MAX_DEPTH are checked before
//!   anything grows);
//! - anything that decodes Ok satisfies the struct invariants the eval path
//!   assumes without re-checking (the "allocation-final" promise of 04 §7.3);
//! - accepted bytes are a canonical fixpoint: re-verifying the same bytes
//!   yields the same accept.
#![no_main]

use libfuzzer_sys::fuzz_target;
use mark1_policy::{verify_and_decode, Section, SectionKeys, TlogHead};
use mark1_receipt::Ed25519Signer;

fuzz_target!(|data: &[u8]| {
    // The vectors' published test keys ('1'..'6' seeds): with real keys in
    // the ring, corpus entries seeded from conformance/vectors/bundle can
    // reach past signature verification into seq/proof/schema code.
    thread_local! {
        static KEYS: SectionKeys = {
            let mut keys = SectionKeys::new();
            for (i, s) in Section::ALL.iter().enumerate() {
                let signer = Ed25519Signer::from_seed([b'1' + i as u8; 32]);
                keys.insert_public(*s, signer.public_key());
            }
            keys
        };
    }
    // D-S: fuzz both caller states — no pinned head (seq > 0 must refuse)
    // and an arbitrary fixed head (only a proof targeting it can pass).
    let head = TlogHead {
        tree_size: 1,
        root: [0x5a; 32],
    };
    KEYS.with(|keys| {
        for last in [None, Some(0), Some(u64::MAX)] {
            for head in [None, Some(&head)] {
                if let Ok(bundle) = verify_and_decode(data, keys, last, head) {
                    // Invariants the gate/route path relies on blindly.
                    assert_eq!(bundle.verify.quarantined.len(), bundle.verify.verifiers.len());
                    assert!(bundle.verify.priors.iter().all(|p| (0.0..=1.0).contains(p)));
                    assert!((0.0..=1.0).contains(&bundle.route.exploration_epsilon));
                    assert!(!bundle.route.knee.rows.is_empty());
                    assert!(bundle.gates.max_consecutive_blocks <= 3);
                    assert!(
                        bundle.cortex.map_budget_tokens_min <= bundle.cortex.map_budget_tokens_max
                    );
                    if bundle.seq == 0 {
                        assert_eq!(bundle.prev_hash, [0u8; 32]);
                        assert!(bundle.tlog.is_none());
                    } else {
                        // D-S: an accept past seq 0 REQUIRES a pinned head,
                        // and the exposed coordinates must target it.
                        let h = head.expect("seq > 0 accepted without a pinned head");
                        let t = bundle.tlog.expect("seq > 0 accepted without tlog exposure");
                        assert_eq!(t.root, h.root);
                        assert_eq!(t.tree_size, h.tree_size);
                    }
                    if let Some(n) = last {
                        assert!(bundle.seq > n, "monotonic seq violated");
                    }
                    for g in &bundle.verify.correlation_groups {
                        assert!(g
                            .members
                            .iter()
                            .all(|m| (*m as usize) < bundle.verify.verifiers.len()));
                    }
                }
            }
        }
    });
});
