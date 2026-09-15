//! L1 — tree-sitter tag extraction for the 5 pinned grammars (04 §6.1).
//!
//! Queries are vendored here (not the grammar crates' tags.scm) so `QUERY_REV`
//! is owned by this file: editing a query below MUST bump `QUERY_REV`, which
//! invalidates exactly the derived tag artifacts in the CAS — never the
//! content hashes (04 §6.1 CAS key rule).

use serde::{Deserialize, Serialize};
use std::sync::OnceLock;
use tree_sitter::{Language, Parser, Query, QueryCursor, StreamingIterator};

/// Bump when any query string below changes.
pub const QUERY_REV: u32 = 1;
/// Bump when extraction logic changes shape (kind mapping, signature rules).
pub const INDEXER_REV: u32 = 1;

/// Grammar revision = the pinned grammar-crate version of the grammar that
/// produced the entry — per language, so bumping one pin invalidates exactly
/// that language's CAS rows (04 §6.1). The root Cargo.toml calls these pins
/// load-bearing for exactly this key. TypeScript and TSX share one crate.
pub fn grammar_rev(lang: Lang) -> &'static str {
    match lang {
        Lang::Python => "py0.23",
        Lang::Rust => "rs0.24",
        Lang::Go => "go0.23",
        Lang::TypeScript | Lang::Tsx => "ts0.23",
        Lang::JavaScript => "js0.23",
    }
}

/// One extracted tag. `kind` uses the 08 §6.2 enum vocabulary for defs;
/// refs/imports carry the referenced name.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Tag {
    pub name: String,
    /// 1-based, matching every 08 §6 `line` field.
    pub line: u32,
    pub role: Role,
    /// 08 §6.2 kind for defs; "call"/"import" for the other roles.
    pub kind: String,
    /// The defining line, verbatim-trimmed — the map's symbol signature
    /// (04 §6.4) and find_definition's `signature`.
    pub signature: String,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum Role {
    Def,
    Ref,
    Import,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Lang {
    Python,
    Rust,
    Go,
    TypeScript,
    Tsx,
    JavaScript,
}

#[derive(Debug, thiserror::Error)]
pub enum TagError {
    /// The M1E-6403 case: grammar/query unavailable for the language.
    #[error("grammar unavailable: {0}")]
    Grammar(String),
    #[error("parse produced no tree")]
    NoTree,
}

pub fn lang_of(path: &str) -> Option<Lang> {
    let ext = path.rsplit('.').next()?;
    match ext {
        "py" => Some(Lang::Python),
        "rs" => Some(Lang::Rust),
        "go" => Some(Lang::Go),
        "ts" | "mts" | "cts" => Some(Lang::TypeScript),
        "tsx" => Some(Lang::Tsx),
        "js" | "mjs" | "cjs" | "jsx" => Some(Lang::JavaScript),
        _ => None,
    }
}

// Capture-name convention: `def.<kind>` (kind from the 08 §6.2 enum),
// `ref.call`, `import`. Extraction below parses the capture name, so adding a
// capture is a query edit + QUERY_REV bump, no code change.
const PYTHON_QUERY: &str = r#"
(function_definition name: (identifier) @def.function)
(class_definition name: (identifier) @def.class)
(import_statement name: (dotted_name) @import)
(import_from_statement module_name: (dotted_name) @import)
(call function: (identifier) @ref.call)
(call function: (attribute attribute: (identifier)) @ref.call)
"#;

const RUST_QUERY: &str = r#"
(function_item name: (identifier) @def.function)
(struct_item name: (type_identifier) @def.struct)
(enum_item name: (type_identifier) @def.enum)
(trait_item name: (type_identifier) @def.trait)
(mod_item name: (identifier) @def.module)
(const_item name: (identifier) @def.const)
(static_item name: (identifier) @def.const)
(type_item name: (type_identifier) @def.type)
(use_declaration argument: (scoped_identifier) @import)
(use_declaration argument: (identifier) @import)
(use_declaration argument: (scoped_use_list) @import)
(use_declaration argument: (use_wildcard) @import)
(call_expression function: (identifier) @ref.call)
(call_expression function: (scoped_identifier name: (identifier)) @ref.call)
(call_expression function: (field_expression field: (field_identifier)) @ref.call)
"#;

const GO_QUERY: &str = r#"
(function_declaration name: (identifier) @def.function)
(method_declaration name: (field_identifier) @def.method)
(type_declaration (type_spec name: (type_identifier) @def.type))
(const_declaration (const_spec name: (identifier) @def.const))
(import_spec path: (interpreted_string_literal) @import)
(call_expression function: (identifier) @ref.call)
(call_expression function: (selector_expression field: (field_identifier)) @ref.call)
"#;

// TypeScript and TSX share one query (same node names); JS uses a reduced set
// (no interface/type_alias, class names are (identifier)).
const TS_QUERY: &str = r#"
(function_declaration name: (identifier) @def.function)
(class_declaration name: (type_identifier) @def.class)
(interface_declaration name: (type_identifier) @def.interface)
(type_alias_declaration name: (type_identifier) @def.type)
(method_definition name: (property_identifier) @def.method)
(enum_declaration name: (identifier) @def.enum)
(import_statement source: (string (string_fragment) @import))
(call_expression function: (identifier) @ref.call)
(call_expression function: (member_expression property: (property_identifier)) @ref.call)
"#;

const JS_QUERY: &str = r#"
(function_declaration name: (identifier) @def.function)
(class_declaration name: (identifier) @def.class)
(method_definition name: (property_identifier) @def.method)
(import_statement source: (string (string_fragment) @import))
(call_expression function: (identifier) @ref.call)
(call_expression function: (member_expression property: (property_identifier)) @ref.call)
"#;

struct Compiled {
    language: Language,
    query: Query,
}

/// Compile once per language per process. A compile failure is remembered as
/// the M1E-6403 refusal (grammar unavailable) — degrade loudly, never fake.
fn compiled(lang: Lang) -> Result<&'static Compiled, TagError> {
    fn build(language: Language, source: &str) -> Option<Compiled> {
        match Query::new(&language, source) {
            Ok(query) => Some(Compiled { language, query }),
            Err(e) => {
                tracing::error!(error = %e, "tags query failed to compile");
                None
            }
        }
    }
    macro_rules! slot {
        ($cell:ident, $lang:expr, $query:expr) => {{
            static $cell: OnceLock<Option<Compiled>> = OnceLock::new();
            $cell
                .get_or_init(|| build($lang.into(), $query))
                .as_ref()
                .ok_or_else(|| TagError::Grammar(format!("{:?}", lang)))
        }};
    }
    match lang {
        Lang::Python => slot!(PY, tree_sitter_python::LANGUAGE, PYTHON_QUERY),
        Lang::Rust => slot!(RS, tree_sitter_rust::LANGUAGE, RUST_QUERY),
        Lang::Go => slot!(GO, tree_sitter_go::LANGUAGE, GO_QUERY),
        Lang::TypeScript => {
            slot!(TS, tree_sitter_typescript::LANGUAGE_TYPESCRIPT, TS_QUERY)
        }
        Lang::Tsx => slot!(TSX, tree_sitter_typescript::LANGUAGE_TSX, TS_QUERY),
        Lang::JavaScript => slot!(JS, tree_sitter_javascript::LANGUAGE, JS_QUERY),
    }
}

/// Cap on the bytes handed to a parser: a generated multi-MB file costs parse
/// time with no map value; past the cap the file stays L0-only.
const MAX_PARSE_BYTES: usize = 2 * 1024 * 1024;

pub fn extract(lang: Lang, source: &[u8]) -> Result<Vec<Tag>, TagError> {
    if source.len() > MAX_PARSE_BYTES {
        return Ok(Vec::new());
    }
    let compiled = compiled(lang)?;
    let mut parser = Parser::new();
    parser
        .set_language(&compiled.language)
        .map_err(|e| TagError::Grammar(e.to_string()))?;
    let tree = parser.parse(source, None).ok_or(TagError::NoTree)?;
    let lines: Vec<&[u8]> = source.split(|&b| b == b'\n').collect();

    let mut out = Vec::new();
    let mut cursor = QueryCursor::new();
    let mut matches = cursor.matches(&compiled.query, tree.root_node(), source);
    while let Some(m) = matches.next() {
        for cap in m.captures {
            let cap_name = &compiled.query.capture_names()[cap.index as usize];
            let Ok(text) = cap.node.utf8_text(source) else {
                continue;
            };
            let row = cap.node.start_position().row;
            let (role, kind) = match *cap_name {
                "import" => (Role::Import, "import"),
                "ref.call" => (Role::Ref, "call"),
                other => match other.strip_prefix("def.") {
                    Some(kind) => (Role::Def, kind),
                    None => continue,
                },
            };
            let name = normalize_name(role, text);
            if name.is_empty() {
                continue;
            }
            let signature = lines
                .get(row)
                .map(|l| {
                    String::from_utf8_lossy(l)
                        .trim()
                        .chars()
                        .take(200)
                        .collect()
                })
                .unwrap_or_default();
            out.push(Tag {
                name,
                line: (row + 1) as u32,
                role,
                kind: kind.to_string(),
                signature,
            });
        }
    }
    Ok(out)
}

/// Import captures carry raw grammar text (quoted strings, `a::b::{c,d}`);
/// normalize to a plain path-ish name the L2 resolver can chew on.
fn normalize_name(role: Role, text: &str) -> String {
    if role != Role::Import {
        return text.to_string();
    }
    text.trim_matches(|c| c == '"' || c == '\'')
        .trim()
        .to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn python_defs_and_refs() {
        let src = b"import helper\n\ndef greet(name):\n    return helper.fmt(name)\n\nclass App:\n    def run(self):\n        greet('x')\n";
        let tags = extract(Lang::Python, src).unwrap();
        let def_names: Vec<&str> = tags
            .iter()
            .filter(|t| t.role == Role::Def)
            .map(|t| t.name.as_str())
            .collect();
        assert!(def_names.contains(&"greet"));
        assert!(def_names.contains(&"App"));
        assert!(tags
            .iter()
            .any(|t| t.role == Role::Import && t.name == "helper"));
        assert!(tags
            .iter()
            .any(|t| t.role == Role::Ref && t.name == "greet"));
    }

    #[test]
    fn rust_defs_and_imports() {
        let src = b"use crate::util::helper;\n\npub struct Thing { x: u32 }\n\npub fn make() -> Thing {\n    helper();\n    Thing { x: 1 }\n}\n";
        let tags = extract(Lang::Rust, src).unwrap();
        assert!(tags
            .iter()
            .any(|t| t.role == Role::Def && t.name == "Thing" && t.kind == "struct"));
        assert!(tags.iter().any(|t| t.role == Role::Def && t.name == "make"));
        assert!(tags.iter().any(|t| t.role == Role::Import));
        assert!(tags
            .iter()
            .any(|t| t.role == Role::Ref && t.name == "helper"));
    }

    #[test]
    fn typescript_defs() {
        let src = b"import { fmt } from './helper';\nexport interface Shape { area(): number }\nexport function draw(s: Shape) { return fmt(s); }\n";
        let tags = extract(Lang::TypeScript, src).unwrap();
        assert!(tags
            .iter()
            .any(|t| t.role == Role::Def && t.name == "Shape" && t.kind == "interface"));
        assert!(tags.iter().any(|t| t.role == Role::Def && t.name == "draw"));
        assert!(tags
            .iter()
            .any(|t| t.role == Role::Import && t.name == "./helper"));
    }

    #[test]
    fn go_defs() {
        let src = b"package main\n\nimport \"fmt\"\n\ntype Point struct{ X int }\n\nfunc Dist(p Point) int {\n\tfmt.Println(p)\n\treturn p.X\n}\n";
        let tags = extract(Lang::Go, src).unwrap();
        assert!(tags
            .iter()
            .any(|t| t.role == Role::Def && t.name == "Point" && t.kind == "type"));
        assert!(tags.iter().any(|t| t.role == Role::Def && t.name == "Dist"));
        assert!(tags
            .iter()
            .any(|t| t.role == Role::Import && t.name == "fmt"));
    }

    #[test]
    fn oversized_file_stays_untagged() {
        let big = vec![b'x'; MAX_PARSE_BYTES + 1];
        assert!(extract(Lang::Python, &big).unwrap().is_empty());
    }
}
