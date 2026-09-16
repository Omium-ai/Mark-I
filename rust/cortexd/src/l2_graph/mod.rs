//! L2 — petgraph import/reference graph + personalized PageRank (04 §6.1).
//!
//! PPR is evaluated lazily at query time, seeded per query, memoized per
//! (seed-set, index_clock). ENG-09 resolution (RECONCILIATION): every
//! query-time evaluation runs under a per-call WALL BUDGET with bounded
//! power-iteration steps; on budget exhaustion it falls back to the global
//! PageRank cached at settle, and if even that is unavailable it REFUSES with
//! `retry_after_ms` — a budget without an enforcement point is a wish.

use std::collections::{BTreeMap, HashMap};
use std::sync::Arc;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use petgraph::graph::{DiGraph, NodeIndex};

use crate::l1_tags::{Role, Tag};

/// ENG-09: per-call PPR wall budget (≈500 ms) and iteration cap.
pub const PPR_WALL_BUDGET: Duration = Duration::from_millis(500);
pub const PPR_MAX_ITERS: usize = 64;
const DAMPING: f64 = 0.85;
const CONVERGENCE_L1: f64 = 1e-9;

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
pub enum EdgeKind {
    Imports,
    References,
    Calls,
}

impl EdgeKind {
    /// 08 §6.4 edge vocabulary.
    pub fn as_str(&self) -> &'static str {
        match self {
            EdgeKind::Imports => "imports",
            EdgeKind::References => "references",
            EdgeKind::Calls => "calls",
        }
    }
}

#[derive(Debug, Clone)]
pub struct DefSite {
    pub path: String,
    pub line: u32,
    pub kind: String,
    pub signature: String,
}

#[derive(Debug, Clone)]
pub struct RefSite {
    pub path: String,
    pub line: u32,
}

#[derive(Default)]
pub struct SymbolGraph {
    /// Node weight = rel path; one node per indexed file.
    pub graph: DiGraph<String, EdgeKind>,
    pub node_of: HashMap<String, NodeIndex>,
    /// symbol name → definition sites (find_definition's table).
    pub defs: HashMap<String, Vec<DefSite>>,
    /// symbol name → reference sites (find_references' table).
    pub refs: HashMap<String, Vec<RefSite>>,
    /// Global PageRank computed at settle — off the serving path, and the
    /// ENG-09 coarse fallback when a query-time PPR blows its wall budget.
    pub global_ranks: Vec<f64>,
    /// PPR memo per (seed-set hash, index_clock) — 04 §6.1.
    ppr_cache: Mutex<PprMemo>,
}

/// (seed-set hash, index_clock) → memoized rank vector.
type PprMemo = HashMap<(u64, u64), Arc<Vec<f64>>>;

/// Time-budget refusal (ENG-09). Surfaced by MCP as the retryable refusal
/// envelope; 08 §7's taxonomy pins no dedicated time code, so the wire code
/// is M1E-6401 (the retryable row) — see the mcp module.
#[derive(Debug, thiserror::Error)]
#[error("PPR wall budget exhausted with no global fallback; retry after {retry_after_ms} ms")]
pub struct RankRefusal {
    pub retry_after_ms: u64,
}

#[derive(Debug)]
pub struct RankVec {
    pub scores: Arc<Vec<f64>>,
    /// false ⇒ the coarse global-PageRank fallback answered (budget hit).
    pub exact: bool,
}

impl SymbolGraph {
    /// Rebuild from the L1 tag plane. ponytail: wholesale rebuild per settle —
    /// pure function of `tags`, O(repo); the 04 §6.1 per-file delta lands when
    /// settle latency on the L fixture demands it (output is identical).
    pub fn build(tags: &BTreeMap<String, Vec<Tag>>) -> SymbolGraph {
        let mut g = SymbolGraph::default();
        for path in tags.keys() {
            let idx = g.graph.add_node(path.clone());
            g.node_of.insert(path.clone(), idx);
        }
        let paths: Vec<&String> = tags.keys().collect();
        for (path, file_tags) in tags {
            for tag in file_tags {
                match tag.role {
                    Role::Def => g.defs.entry(tag.name.clone()).or_default().push(DefSite {
                        path: path.clone(),
                        line: tag.line,
                        kind: tag.kind.clone(),
                        signature: tag.signature.clone(),
                    }),
                    Role::Ref => g.refs.entry(tag.name.clone()).or_default().push(RefSite {
                        path: path.clone(),
                        line: tag.line,
                    }),
                    Role::Import => {}
                }
            }
        }
        // Edges pass (defs table must be complete first).
        let mut seen: HashMap<(NodeIndex, NodeIndex), EdgeKind> = HashMap::new();
        for (path, file_tags) in tags {
            let from = g.node_of[path];
            for tag in file_tags {
                match tag.role {
                    Role::Import => {
                        if let Some(target) = resolve_import(&tag.name, &paths) {
                            if target != *path {
                                let to = g.node_of[&target];
                                seen.entry((from, to)).or_insert(EdgeKind::Imports);
                            }
                        }
                    }
                    Role::Ref => {
                        if let Some(sites) = g.defs.get(&tag.name) {
                            for site in sites {
                                if site.path != *path {
                                    let to = g.node_of[&site.path];
                                    seen.entry((from, to)).or_insert(EdgeKind::Calls);
                                }
                            }
                        }
                    }
                    Role::Def => {}
                }
            }
        }
        for ((from, to), kind) in seen {
            g.graph.add_edge(from, to, kind);
        }
        // Global PageRank at settle — precomputed, off the serving path.
        g.global_ranks = ppr(&g.graph, &[], PPR_WALL_BUDGET, PPR_MAX_ITERS).unwrap_or_default();
        g
    }

    /// Query-time ranks under the ENG-09 ladder: memo hit → bounded PPR →
    /// global fallback → refusal.
    pub fn ranks_for(
        &self,
        seeds: &[NodeIndex],
        budget: Duration,
        index_clock: u64,
    ) -> Result<RankVec, RankRefusal> {
        if seeds.is_empty() {
            // Unseeded ⇒ the global ranking IS the intended answer, not a
            // degraded fallback.
            return self.global_or_refuse().map(|mut r| {
                r.exact = true;
                r
            });
        }
        let mut key_ids: Vec<u64> = seeds.iter().map(|n| n.index() as u64).collect();
        key_ids.sort_unstable();
        let mut hasher = blake3::Hasher::new();
        for id in &key_ids {
            hasher.update(&id.to_le_bytes());
        }
        let mut first8 = [0u8; 8];
        first8.copy_from_slice(&hasher.finalize().as_bytes()[..8]);
        let key = (u64::from_le_bytes(first8), index_clock);
        if let Some(hit) = self
            .ppr_cache
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .get(&key)
        {
            return Ok(RankVec {
                scores: Arc::clone(hit),
                exact: true,
            });
        }
        match ppr(&self.graph, seeds, budget, PPR_MAX_ITERS) {
            Ok(scores) => {
                let scores = Arc::new(scores);
                let mut cache = self.ppr_cache.lock().unwrap_or_else(|e| e.into_inner());
                // Memo is per index_clock; a settle invalidates by key. Cap the
                // map so a seed-spraying caller cannot grow it unbounded.
                if cache.len() >= 256 {
                    cache.clear();
                }
                cache.insert(key, Arc::clone(&scores));
                Ok(RankVec {
                    scores,
                    exact: true,
                })
            }
            Err(BudgetExceeded) => self.global_or_refuse(),
        }
    }

    fn global_or_refuse(&self) -> Result<RankVec, RankRefusal> {
        if self.global_ranks.len() == self.graph.node_count() && !self.global_ranks.is_empty() {
            Ok(RankVec {
                scores: Arc::new(self.global_ranks.clone()),
                exact: false,
            })
        } else if self.graph.node_count() == 0 {
            Ok(RankVec {
                scores: Arc::new(Vec::new()),
                exact: true,
            })
        } else {
            // No usable fallback: refuse rather than serve an unranked guess —
            // refusal beats fabrication (04 §6.3).
            Err(RankRefusal {
                retry_after_ms: 1_500,
            })
        }
    }
}

/// Marker error: the wall budget or iteration cap tripped before convergence.
#[derive(Debug)]
pub struct BudgetExceeded;

/// Personalized PageRank by power iteration. Empty `seeds` ⇒ global PageRank
/// (uniform personalization). Wall budget checked every iteration — bounded
/// iteration is the ENG-09 enforcement point.
pub fn ppr(
    graph: &DiGraph<String, EdgeKind>,
    seeds: &[NodeIndex],
    wall: Duration,
    max_iters: usize,
) -> Result<Vec<f64>, BudgetExceeded> {
    let n = graph.node_count();
    if n == 0 {
        return Ok(Vec::new());
    }
    let start = Instant::now();
    let mut personalization = vec![0f64; n];
    if seeds.is_empty() {
        personalization.fill(1.0 / n as f64);
    } else {
        let w = 1.0 / seeds.len() as f64;
        for s in seeds {
            personalization[s.index()] += w;
        }
    }
    let out_deg: Vec<usize> = graph
        .node_indices()
        .map(|i| graph.neighbors(i).count())
        .collect();
    let mut rank = personalization.clone();
    let mut converged = false;
    for _ in 0..max_iters {
        if start.elapsed() > wall {
            return Err(BudgetExceeded);
        }
        let mut next = vec![0f64; n];
        let mut dangling = 0f64;
        for i in graph.node_indices() {
            let r = rank[i.index()];
            if out_deg[i.index()] == 0 {
                dangling += r;
                continue;
            }
            let share = r / out_deg[i.index()] as f64;
            for j in graph.neighbors(i) {
                next[j.index()] += share;
            }
        }
        // Dangling mass teleports along the personalization, keeping the
        // vector a distribution (prop_ppr_ranks_normalized).
        let mut delta = 0f64;
        for i in 0..n {
            let v = (1.0 - DAMPING) * personalization[i]
                + DAMPING * (next[i] + dangling * personalization[i]);
            delta += (v - rank[i]).abs();
            rank[i] = v;
        }
        if delta < CONVERGENCE_L1 {
            converged = true;
            break;
        }
    }
    // The iteration cap bounds work; hitting it without convergence is still
    // a usable ranking (power iteration is monotone-improving), not a refusal.
    let _ = converged;
    Ok(rank)
}

/// Number of per-file features the ranker seam scores (`Index::file_features`).
pub const FEATURES: usize = 4;

/// 06 §12.4 stages at the edge: probation/shadow are diagnostic-only, `Active` blends.
/// Serde spelling is the bundle's closed enum, as mark1d writes it to `--ranker-file`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum RankerStage {
    Probation,
    Shadow,
    Active,
}

/// Phase 6 learned re-ranker; weights arrive ONLY via the signed bundle's cortex
/// `learned_ranker`, relayed by mark1d as `--ranker-file` (session::Shared::set_ranker).
#[derive(Debug, Clone, PartialEq)]
pub struct RankerWeights {
    stage: RankerStage,
    weight: f64,
    bias: f64,
    coefficients: [f64; FEATURES],
}

#[derive(Debug, thiserror::Error, PartialEq)]
pub enum RankerRefusal {
    #[error("blend weight {0} outside [0,1]")]
    Weight(f64),
    #[error("non-finite bias or coefficient")]
    Coefficient,
}

impl RankerWeights {
    /// Refuses at load what the blend could not bound (NaN fails the range check).
    pub fn new(
        stage: RankerStage,
        weight: f64,
        bias: f64,
        coefficients: [f64; FEATURES],
    ) -> Result<Self, RankerRefusal> {
        if !(0.0..=1.0).contains(&weight) {
            return Err(RankerRefusal::Weight(weight));
        }
        if !bias.is_finite() || coefficients.iter().any(|c| !c.is_finite()) {
            return Err(RankerRefusal::Coefficient);
        }
        Ok(RankerWeights {
            stage,
            weight,
            bias,
            coefficients,
        })
    }

    pub fn stage(&self) -> RankerStage {
        self.stage
    }

    /// ponytail: linear model over the 4 PPR-side features clamped to [0,1]; a trained
    /// ranker (bundle-delivered weights of anything richer) replaces this fn behind the seam.
    pub fn learned(&self, features: &[f64; FEATURES]) -> f64 {
        let dot: f64 = self
            .coefficients
            .iter()
            .zip(features)
            .map(|(c, x)| c * x)
            .sum();
        (self.bias + dot).clamp(0.0, 1.0)
    }
}

/// The served SET is always PPR's top-k; a learned member may reorder inside it, never
/// remove from it (10 §11.3). Active blends `(ppr + w·learned) / (1 + w)`, staying in [0,1].
pub fn rerank(
    ppr_order: Vec<(String, f64)>,
    features: impl Fn(&str) -> [f64; FEATURES],
    weights: &RankerWeights,
    k: usize,
) -> Vec<(String, f64)> {
    let top: Vec<(String, f64, f64)> = ppr_order
        .into_iter()
        .take(k)
        .map(|(path, ppr)| {
            let learned = weights.learned(&features(&path));
            (path, ppr, learned)
        })
        .collect();
    if weights.stage != RankerStage::Active {
        for (path, ppr, learned) in &top {
            tracing::debug!(path, ppr, learned, stage = ?weights.stage, "learned ranker diagnostic");
        }
        return top.into_iter().map(|(p, s, _)| (p, s)).collect();
    }
    let w = weights.weight;
    let mut out: Vec<(String, f64)> = top
        .into_iter()
        .map(|(p, ppr, learned)| (p, (ppr + w * learned) / (1.0 + w)))
        .collect();
    out.sort_by(|a, b| {
        b.1.partial_cmp(&a.1)
            .unwrap_or(std::cmp::Ordering::Equal)
            .then(a.0.cmp(&b.0))
    });
    out
}

/// Import-string → file resolution, one heuristic across all 5 languages:
/// normalize separators to `/`, strip relative markers and quotes, then match
/// the longest trailing-segment suffix against indexed paths (extension
/// dropped). ponytail: no per-language module-system model (tsconfig paths,
/// go module roots, python packages) — suffix matching covers intra-repo
/// imports, which are the only edges the graph wants.
fn resolve_import(import: &str, paths: &[&String]) -> Option<String> {
    let norm = import
        .trim_matches(|c| c == '"' || c == '\'')
        .replace("::", "/")
        .replace('.', "/");
    let segs: Vec<&str> = norm
        .split('/')
        .filter(|s| !s.is_empty() && *s != "crate" && *s != "self" && *s != "super")
        .collect();
    if segs.is_empty() {
        return None;
    }
    let mut best: Option<(usize, &String)> = None;
    for path in paths {
        let stem = path.rsplit_once('.').map(|(s, _)| s).unwrap_or(path);
        let path_segs: Vec<&str> = stem.split('/').collect();
        // Longest k such that the import's LAST k segments equal the path's
        // last k segments ("a/b/mod" matches "src/a/b/mod.rs").
        let max_k = segs.len().min(path_segs.len());
        for k in (1..=max_k).rev() {
            if segs[segs.len() - k..] == path_segs[path_segs.len() - k..] {
                if best.is_none_or(|(bk, _)| k > bk) {
                    best = Some((k, path));
                }
                break;
            }
        }
    }
    best.map(|(_, p)| p.clone())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tag(name: &str, role: Role) -> Tag {
        Tag {
            name: name.into(),
            line: 1,
            role,
            kind: if role == Role::Def {
                "function".into()
            } else {
                "call".into()
            },
            signature: format!("sig {name}"),
        }
    }

    fn sample() -> BTreeMap<String, Vec<Tag>> {
        let mut tags = BTreeMap::new();
        tags.insert("core/util.py".to_string(), vec![tag("fmt", Role::Def)]);
        tags.insert(
            "app/main.py".to_string(),
            vec![
                tag("main", Role::Def),
                tag("fmt", Role::Ref),
                tag("core.util", Role::Import),
            ],
        );
        tags.insert("lone.py".to_string(), vec![tag("nothing", Role::Def)]);
        tags
    }

    #[test]
    fn build_wires_call_and_import_edges() {
        let g = SymbolGraph::build(&sample());
        assert_eq!(g.graph.node_count(), 3);
        let from = g.node_of["app/main.py"];
        let to = g.node_of["core/util.py"];
        assert!(g.graph.find_edge(from, to).is_some());
        assert_eq!(g.global_ranks.len(), 3);
    }

    #[test]
    fn ppr_is_normalized_and_seed_biased() {
        let g = SymbolGraph::build(&sample());
        let seed = g.node_of["app/main.py"];
        let ranks = ppr(&g.graph, &[seed], Duration::from_secs(5), PPR_MAX_ITERS).unwrap();
        let sum: f64 = ranks.iter().sum();
        assert!(
            (sum - 1.0).abs() < 1e-6,
            "rank vector must be a distribution, got {sum}"
        );
        // The seed and its import target outrank the disconnected file.
        let lone = g.node_of["lone.py"].index();
        assert!(ranks[seed.index()] > ranks[lone]);
        assert!(ranks[g.node_of["core/util.py"].index()] > ranks[lone]);
    }

    #[test]
    fn ppr_deterministic() {
        let g = SymbolGraph::build(&sample());
        let seed = g.node_of["app/main.py"];
        let a = ppr(&g.graph, &[seed], Duration::from_secs(5), PPR_MAX_ITERS).unwrap();
        let b = ppr(&g.graph, &[seed], Duration::from_secs(5), PPR_MAX_ITERS).unwrap();
        assert_eq!(a, b);
    }

    #[test]
    fn zero_budget_trips_and_global_fallback_answers() {
        let g = SymbolGraph::build(&sample());
        let seed = g.node_of["app/main.py"];
        assert!(ppr(&g.graph, &[seed], Duration::ZERO, PPR_MAX_ITERS).is_err());
        // ranks_for falls back to the settle-time global PageRank, flagged inexact.
        let out = g
            .ranks_for(&[seed], Duration::ZERO, 1)
            .expect("fallback must answer");
        assert!(!out.exact);
        assert_eq!(*out.scores, g.global_ranks);
    }

    #[test]
    fn no_fallback_means_refusal_with_retry() {
        let mut g = SymbolGraph::build(&sample());
        g.global_ranks.clear(); // simulate cold settle
        let seed = g.node_of["app/main.py"];
        let err = g
            .ranks_for(&[seed], Duration::ZERO, 1)
            .expect_err("must refuse");
        assert!(err.retry_after_ms > 0);
    }

    #[test]
    fn ranker_weights_refuse_what_the_blend_cannot_bound() {
        for w in [-0.1, 1.000_001, f64::NAN, f64::INFINITY] {
            assert!(
                RankerWeights::new(RankerStage::Active, w, 0.0, [0.0; FEATURES]).is_err(),
                "weight {w} must refuse"
            );
        }
        assert_eq!(
            RankerWeights::new(RankerStage::Active, 0.5, f64::NAN, [0.0; FEATURES]),
            Err(RankerRefusal::Coefficient)
        );
        assert_eq!(
            RankerWeights::new(
                RankerStage::Shadow,
                0.5,
                0.0,
                [0.0, f64::INFINITY, 0.0, 0.0]
            ),
            Err(RankerRefusal::Coefficient)
        );
        let ok = RankerWeights::new(RankerStage::Active, 1.0, 0.0, [1.0, 0.0, 0.0, 0.0]).unwrap();
        assert_eq!(ok.learned(&[50.0, 0.0, 0.0, 0.0]), 1.0, "clamped to [0,1]");
        assert_eq!(ok.learned(&[0.0, 0.0, 0.0, 0.0]), 0.0);
        let neg = RankerWeights::new(RankerStage::Active, 1.0, -3.0, [0.0; FEATURES]).unwrap();
        assert_eq!(neg.learned(&[9.0; FEATURES]), 0.0);
    }

    #[test]
    fn rerank_is_bounded_and_keeps_pprs_top_k() {
        let order = vec![
            ("a.rs".to_string(), 1.0),
            ("b.rs".to_string(), 0.5),
            ("c.rs".to_string(), 0.0),
        ];
        // Learned score = fan_in feature; c.rs is the outsider the learned model loves.
        let feats = |p: &str| match p {
            "a.rs" => [1.0, 0.0, 0.0, 0.0],
            "b.rs" => [0.0, 0.0, 0.0, 0.0],
            _ => [1.0, 0.0, 0.0, 0.0],
        };
        let active =
            RankerWeights::new(RankerStage::Active, 1.0, 0.0, [1.0, 0.0, 0.0, 0.0]).unwrap();
        let out = rerank(order.clone(), feats, &active, 2);
        assert_eq!(
            out.iter().map(|(p, _)| p.as_str()).collect::<Vec<_>>(),
            ["a.rs", "b.rs"],
            "the served set is PPR's top-2; c.rs cannot enter"
        );
        assert!(out.iter().all(|(_, s)| (0.0..=1.0).contains(s)), "{out:?}");
        assert_eq!(out[0].1, 1.0, "(1 + 1·1)/(1 + 1)");
        assert_eq!(out[1].1, 0.25, "(0.5 + 1·0)/(1 + 1)");
        for stage in [RankerStage::Probation, RankerStage::Shadow] {
            let w = RankerWeights::new(stage, 1.0, 0.0, [1.0, 0.0, 0.0, 0.0]).unwrap();
            assert_eq!(
                rerank(order.clone(), feats, &w, 3),
                order,
                "{stage:?} serves PPR order"
            );
        }
    }

    #[test]
    fn import_resolution_suffix_match() {
        let a = "src/core/util.rs".to_string();
        let b = "src/other/util.rs".to_string();
        let paths = vec![&a, &b];
        assert_eq!(resolve_import("core::util", &paths), Some(a.clone()));
        assert_eq!(resolve_import("./helper", &paths), None);
    }
}
