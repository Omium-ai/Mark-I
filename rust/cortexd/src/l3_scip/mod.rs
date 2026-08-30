//! L3 — opportunistic SCIP precision. **Later delivery-registry row**: no
//! SCIP indexer ships at Phase 2 (the doc.go-equivalent stub).
//!
//! The contract this stub preserves (04 §6.1): L3 is strictly best-effort —
//! no answer ever waits on it, and its ABSENCE only degrades edge confidence
//! from "scip" to "tags" (08 §6.2), never blocks or fabricates. Shedding L3
//! is also the FIRST rung of the memory-ceiling ladder (04 §6.6), which a
//! not-yet-built L3 satisfies vacuously.

/// Confidence label for every symbol answer until a SCIP index exists
/// (08 §6.2 `confidence` enum: "scip" = L3 precise, "tags" = L1 heuristic).
pub const CONFIDENCE: &str = "tags";
