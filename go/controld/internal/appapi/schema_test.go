package appapi

import (
	"encoding/json"
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
