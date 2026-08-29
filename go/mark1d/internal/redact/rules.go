// The starter ruleset as DATA — the Go twin of rust/mark1-redact/src/rules.rs
// (04 §2.0: "same ruleset source, validated bit-identical against the Rust
// crate by shared conformance vectors"). A row here diverging from the Rust
// table is exactly what conformance/vectors/redact/ exists to catch, so every
// field mirrors its Rust counterpart verbatim, including table order (priority)
// and the entropy floors.
package redact

// Class is 04 §7.1's frozen class vocabulary; the string is the `class` leg of
// the `⟨redacted:class:hash⟩` token, pinned by the redact vectors.
type Class string

const (
	ClassAPIKey Class = "api_key"
	//nolint:gosec // G101 false positive: a token CLASS label (04 §7.1 frozen vocabulary), not a credential
	ClassOauthToken  Class = "oauth_token"
	ClassPrivateKey  Class = "private_key"
	ClassPassword    Class = "password" // frozen vocabulary; no starter rule yet (rules.rs)
	ClassHighEntropy Class = "high_entropy"
)

// rule mirrors rules.rs's Rule: anchors MUST be byte-prefixes of anything the
// pattern can match (the confirm step requires the match to start exactly at
// the anchor hit); empty anchors ⇒ full-buffer pass (the entropy classes).
type rule struct {
	id         string
	class      Class
	anchors    []string
	pattern    string
	minEntropy float32 // 0 = structural match is enough (Rust's None)
	hasFloor   bool
}

// Go's regexp/syntax caps counted repetition at 1000, so the Rust table's
// larger bounds are expanded into concatenated runs of the SAME character
// class: for a uniform class, greedy `C{8,2048}` and `C{8,1000}C{0,1000}C{0,48}`
// prefer the same (maximal) total and reach the same totals, and lazy runs
// likewise prefer the same (minimal) total — so the observable match is
// identical while every bound stays exactly the Rust ceiling, never loosened.
var rules = []rule{
	{
		id:      "aws_access_key_id",
		class:   ClassAPIKey,
		anchors: []string{"AKIA", "ASIA"},
		pattern: `(?:AKIA|ASIA)[0-9A-Z]{16}`,
	},
	{
		id:      "github_token",
		class:   ClassAPIKey,
		anchors: []string{"ghp_", "gho_", "ghu_", "ghs_", "ghr_", "github_pat_"},
		pattern: `(?:gh[pousr]_[A-Za-z0-9]{36,255}|github_pat_[A-Za-z0-9_]{22,255})`,
	},
	{
		id:      "anthropic_api_key",
		class:   ClassAPIKey,
		anchors: []string{"sk-ant-"},
		pattern: `sk-ant-[A-Za-z0-9_\-]{24,512}`,
	},
	{
		id:      "openai_api_key",
		class:   ClassAPIKey,
		anchors: []string{"sk-"},
		pattern: `sk-[A-Za-z0-9_\-]{20,512}`,
	},
	{
		id:      "pem_private_key",
		class:   ClassPrivateKey,
		anchors: []string{"-----BEGIN "},
		// Rust: `.{0,8192}?` — the lazy body bound that keeps a BEGIN with no
		// END from scanning to end-of-buffer, split 8×1000+192.
		pattern: `(?s)-----BEGIN [A-Z0-9 ]{0,32}PRIVATE KEY-----` +
			`.{0,1000}?.{0,1000}?.{0,1000}?.{0,1000}?.{0,1000}?.{0,1000}?.{0,1000}?.{0,1000}?.{0,192}?` +
			`-----END [A-Z0-9 ]{0,32}PRIVATE KEY-----`,
	},
	{
		id:      "jwt",
		class:   ClassOauthToken,
		anchors: []string{"eyJ"},
		// Rust: eyJ x{8,2048} . x{8,4096} . x{8,1024} — each segment split to
		// stay under Go's 1000 cap with the exact same ceilings.
		pattern: `eyJ[A-Za-z0-9_\-]{8,1000}[A-Za-z0-9_\-]{0,1000}[A-Za-z0-9_\-]{0,48}` +
			`\.[A-Za-z0-9_\-]{8,1000}[A-Za-z0-9_\-]{0,1000}[A-Za-z0-9_\-]{0,1000}[A-Za-z0-9_\-]{0,1000}[A-Za-z0-9_\-]{0,96}` +
			`\.[A-Za-z0-9_\-]{8,1000}[A-Za-z0-9_\-]{0,24}`,
	},
	{
		id:         "high_entropy_hex",
		class:      ClassHighEntropy,
		pattern:    `[0-9a-fA-F]{40,128}`,
		minEntropy: 3.4,
		hasFloor:   true,
	},
	{
		id:         "high_entropy_base64",
		class:      ClassHighEntropy,
		pattern:    `[A-Za-z0-9+/]{40,512}={0,2}`,
		minEntropy: 4.8,
		hasFloor:   true,
	},
}
