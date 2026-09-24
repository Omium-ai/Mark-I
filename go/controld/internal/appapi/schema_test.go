package appapi

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"github.com/Omium-ai/omium-mark1/go/controld/internal/appapi/schemacheck"
)

type schemaSet = schemacheck.Set

func loadSchemas(t *testing.T) *schemaSet { return schemacheck.Load(t, "schema") }

// The validator's own positive controls: it must red on each violation class it claims to catch.
func TestSchemaValidatorReds(t *testing.T) {
	s := loadSchemas(t)
	for name, body := range map[string]string{
		"additional property": `{"error":{"code":"M1E-2001","message":"x","extra":1}}`,
		"missing required":    `{"error":{"code":"M1E-2001"}}`,
		"pattern":             `{"error":{"code":"E-1","message":"x"}}`,
		"type":                `{"error":{"code":2001,"message":"x"}}`,
	} {
		var inst any
		dec := json.NewDecoder(strings.NewReader(body))
		dec.UseNumber()
		if err := dec.Decode(&inst); err != nil {
			t.Fatal(err)
		}
		var errs []string
		s.Walk("error.json", s.Docs()["error.json"], inst, "$", &errs)
		if len(errs) == 0 {
			t.Errorf("%s: validator passed %s", name, body)
		}
	}
	s.Validate("error.json", []byte(`{"error":{"code":"M1E-2001","message":"x"}}`))
}

// Every $ref in every schema resolves, and every schema is self-describing.
func TestSchemasResolveAndDeclare(t *testing.T) {
	s := loadSchemas(t)
	var visit func(file string, node any)
	visit = func(file string, node any) {
		m, ok := node.(map[string]any)
		if !ok {
			return
		}
		if ref, ok := m["$ref"].(string); ok {
			s.Resolve(file, ref)
		}
		for _, v := range m {
			switch vv := v.(type) {
			case map[string]any:
				for _, sub := range vv {
					visit(file, sub)
				}
				visit(file, vv)
			}
		}
	}
	for file, doc := range s.Docs() {
		if doc["$schema"] != "https://json-schema.org/draft/2020-12/schema" || doc["$id"] != "https://omium.ai/mark1/appapi/"+file {
			t.Errorf("%s: $schema/$id not declared as the contract requires", file)
		}
		visit(file, doc)
	}
}

// The agent vocabulary is the daemon's catalog and nothing else: every schema that names an agent pins the one enum, and the enum reds on the old spelling.
func TestAgentEnumPinned(t *testing.T) {
	s := loadSchemas(t)
	sites := map[string][]string{
		"sessions.json":        {"$defs", "session", "properties", "agent"},
		"moments.json":         {"properties", "moments", "items", "properties", "agent"},
		"route_decisions.json": {"properties", "decisions", "items", "properties", "agent"},
	}
	for file, path := range sites {
		node := any(s.Docs()[file])
		for _, p := range path {
			node = node.(map[string]any)[p]
		}
		ref, _ := node.(map[string]any)["$ref"].(string)
		if !strings.HasSuffix(ref, "#/$defs/agent") {
			t.Fatalf("%s: agent is %v, want a $ref to sessions.json#/$defs/agent", file, node)
		}
		for want, agent := range map[bool]string{true: "claudecode", false: "claude-code"} {
			var errs []string
			s.Walk(file, node.(map[string]any), agent, "$", &errs)
			if (len(errs) == 0) != want {
				t.Errorf("%s: agent %q: violations %v, want ok=%v", file, agent, errs, want)
			}
		}
	}
	enum := s.Docs()["sessions.json"]["$defs"].(map[string]any)["agent"].(map[string]any)["enum"].([]any)
	if got := fmt.Sprint(enum); got != "[claudecode codex gemini opencode copilot cursor crush]" {
		t.Fatalf("catalog enum drifted: %s", got)
	}
}

// One export line is rust/verifier's ExportRow; the schema reds on a line the verifier could not load.
func TestReceiptsExportLineSchema(t *testing.T) {
	s := loadSchemas(t)
	line := `{"seq":1042,"payload":"{\"type\":\"checkpoint\",\"v\":1}","receipt_hash_hex":"` + strings.Repeat("ab", 32) + `","device_key_id":"ed25519:a1cf5c00b2784f6e","device_signature_hex":"` + strings.Repeat("01", 64) + `","server_key_id":"ed25519:1325b850c2871916","server_signature_hex":"` + strings.Repeat("02", 64) + `"}`
	s.Validate("receipts_export.json", []byte(line))
	for name, bad := range map[string]string{
		"no server signature": strings.Replace(line, `,"server_signature_hex":"`+strings.Repeat("02", 64)+`"`, "", 1),
		"seq zero":            strings.Replace(line, `"seq":1042`, `"seq":0`, 1),
		"short hash":          strings.Replace(line, strings.Repeat("ab", 32), "abcd", 1),
	} {
		var inst any
		dec := json.NewDecoder(strings.NewReader(bad))
		dec.UseNumber()
		if err := dec.Decode(&inst); err != nil {
			t.Fatal(err)
		}
		var errs []string
		s.Walk("receipts_export.json", s.Docs()["receipts_export.json"], inst, "$", &errs)
		if len(errs) == 0 {
			t.Errorf("%s: validator passed %s", name, bad)
		}
	}
}
