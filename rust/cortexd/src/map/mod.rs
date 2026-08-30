//! Budgeted ranked map assembly (04 §6.4): PPR over L2 seeded by the live
//! recent-edit set, files ranked, per-file symbol signatures richest-first,
//! then BINARY SEARCH over inclusion depth until the rendering fits the token
//! budget. Precomputed at index settle; a SessionStart serve is a read.

use serde::Serialize;

use crate::l1_tags::Role;
use crate::l2_graph::PPR_WALL_BUDGET;
use crate::session::Index;

#[derive(Debug, Clone, Serialize)]
pub struct MapRender {
    pub text: String,
    pub tokens_used: u32,
    pub files_ranked: u32,
    pub truncated: bool,
}

/// ponytail: bytes/4 token estimate — the estate-standard coarse ratio; a
/// real tokenizer is a dependency the budget check does not need (the budget
/// is a ceiling, and /4 over-counts for code, erring under budget).
pub fn estimate_tokens(text: &str) -> u32 {
    (text.len() as u32).div_ceil(4)
}

/// Assemble the ranked map. `seeds` are rel paths (recent edits or a query's
/// focus set); unresolvable seeds are ignored — an empty seed set degrades to
/// the global ranking, never errors.
pub fn assemble(index: &Index, seeds: &[String], budget_tokens: u32) -> MapRender {
    let graph = &index.graph;
    let seed_nodes: Vec<_> = seeds
        .iter()
        .filter_map(|p| graph.node_of.get(p).copied())
        .collect();
    // Settle-path assembly tolerates budget misses silently: on refusal the
    // ranking degrades to file order (deterministic), never a missing map.
    let scores: Vec<f64> = match graph.ranks_for(&seed_nodes, PPR_WALL_BUDGET, 0) {
        Ok(r) => (*r.scores).clone(),
        Err(_) => vec![0.0; graph.graph.node_count()],
    };

    // Rank files by score desc, path asc for determinism.
    let mut ranked: Vec<(&str, f64)> = graph
        .graph
        .node_indices()
        .map(|i| {
            (
                graph.graph[i].as_str(),
                scores.get(i.index()).copied().unwrap_or(0.0),
            )
        })
        .collect();
    ranked.sort_by(|a, b| {
        b.1.partial_cmp(&a.1)
            .unwrap_or(std::cmp::Ordering::Equal)
            .then(a.0.cmp(b.0))
    });

    // Per-file signatures, richest-first: defs ordered by kind weight.
    let sig_lists: Vec<(&str, Vec<&str>)> = ranked
        .iter()
        .map(|(path, _)| {
            let mut defs: Vec<(u32, &str)> = index
                .tags
                .get(*path)
                .map(|tags| {
                    tags.iter()
                        .filter(|t| t.role == Role::Def && !t.signature.is_empty())
                        .map(|t| (kind_weight(&t.kind), t.signature.as_str()))
                        .collect()
                })
                .unwrap_or_default();
            defs.sort_by(|a, b| a.0.cmp(&b.0).then(a.1.cmp(b.1)));
            (*path, defs.into_iter().map(|(_, s)| s).collect())
        })
        .collect();

    let max_depth = sig_lists.iter().map(|(_, s)| s.len()).max().unwrap_or(0);

    // Binary search the largest inclusion depth whose rendering fits (04 §6.4).
    let mut lo = 0usize;
    let mut hi = max_depth;
    let mut best = render(&sig_lists, 0, budget_tokens);
    while lo < hi {
        let mid = (lo + hi).div_ceil(2);
        let candidate = render(&sig_lists, mid, budget_tokens);
        if candidate.tokens_used <= budget_tokens {
            best = candidate;
            lo = mid;
        } else {
            hi = mid - 1;
        }
    }
    best
}

fn kind_weight(kind: &str) -> u32 {
    // Interfaces/types first — the signatures an agent orients by.
    match kind {
        "interface" | "trait" | "class" | "struct" | "enum" | "type" => 0,
        "function" | "method" => 1,
        "module" => 2,
        _ => 3,
    }
}

/// Render at a fixed depth. Files are appended in rank order until the budget
/// would be crossed — ranked truncation, never a mid-record cut (08 §6).
fn render(sig_lists: &[(&str, Vec<&str>)], depth: usize, budget_tokens: u32) -> MapRender {
    let mut text = String::new();
    let mut files_ranked = 0u32;
    let mut truncated = false;
    for (path, sigs) in sig_lists {
        let mut block = String::new();
        block.push_str(path);
        block.push('\n');
        for sig in sigs.iter().take(depth) {
            block.push_str("  ");
            block.push_str(sig);
            block.push('\n');
        }
        if estimate_tokens(&text) + estimate_tokens(&block) > budget_tokens {
            truncated = true;
            break;
        }
        text.push_str(&block);
        files_ranked += 1;
    }
    // Depth below the richest file is also a truncation of the full answer.
    if !truncated {
        truncated = sig_lists.iter().any(|(_, s)| s.len() > depth);
    }
    MapRender {
        tokens_used: estimate_tokens(&text),
        files_ranked,
        truncated,
        text,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::l1_tags::Tag;
    use crate::l2_graph::SymbolGraph;
    use std::collections::BTreeMap;

    fn index_with(n_files: usize, sigs_per_file: usize) -> Index {
        let mut tags = BTreeMap::new();
        for f in 0..n_files {
            let list: Vec<Tag> = (0..sigs_per_file)
                .map(|s| Tag {
                    name: format!("sym_{f}_{s}"),
                    line: s as u32 + 1,
                    role: Role::Def,
                    kind: "function".into(),
                    signature: format!("fn sym_{f}_{s}(argument: usize) -> usize"),
                })
                .collect();
            tags.insert(format!("dir/file_{f}.rs"), list);
        }
        let graph = SymbolGraph::build(&tags);
        Index {
            tags,
            graph,
            ..Index::default()
        }
    }

    #[test]
    fn budget_is_a_ceiling_and_truncation_is_flagged() {
        let index = index_with(10, 8);
        let small = assemble(&index, &[], 100);
        assert!(
            small.tokens_used <= 100,
            "budget exceeded: {}",
            small.tokens_used
        );
        assert!(small.truncated);

        let big = assemble(&index, &[], 8_000);
        assert!(big.tokens_used <= 8_000);
        assert!(!big.truncated, "everything fits, nothing to flag");
        assert_eq!(big.files_ranked, 10);
        assert!(big.tokens_used > small.tokens_used);
    }

    #[test]
    fn deeper_budget_means_deeper_map() {
        let index = index_with(4, 6);
        let a = assemble(&index, &[], 200);
        let b = assemble(&index, &[], 2_000);
        assert!(b.text.lines().count() >= a.text.lines().count());
    }
}
