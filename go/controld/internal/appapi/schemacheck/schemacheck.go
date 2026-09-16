// Package schemacheck is the test-side JSON Schema 2020-12 SUBSET validator for appapi/schema: it implements exactly the keywords those files use and fails the test on any other keyword, so a schema cannot silently carry a constraint no test enforced. ponytail: a full validator is a go.mod change (out of the lane's territory); the subset is the belt until one lands.
package schemacheck

import (
	"bytes"
	"encoding/json"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
)

var supportedKeywords = map[string]bool{
	"$schema": true, "$id": true, "title": true, "description": true, "$defs": true, "$ref": true,
	"type": true, "properties": true, "required": true, "additionalProperties": true, "items": true,
	"enum": true, "minimum": true, "maximum": true, "minItems": true, "pattern": true, "format": true,
}

type Set struct {
	t    *testing.T
	docs map[string]map[string]any
}

// Load reads every *.json under dir and refuses unknown keywords.
func Load(t *testing.T, dir string) *Set {
	t.Helper()
	files, err := filepath.Glob(filepath.Join(dir, "*.json"))
	if err != nil || len(files) == 0 {
		t.Fatalf("no schema files: %v", err)
	}
	s := &Set{t: t, docs: map[string]map[string]any{}}
	for _, f := range files {
		raw, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		var doc map[string]any
		dec := json.NewDecoder(bytes.NewReader(raw))
		dec.UseNumber()
		if err := dec.Decode(&doc); err != nil {
			t.Fatalf("%s: %v", f, err)
		}
		s.docs[filepath.Base(f)] = doc
		s.checkKeywords(filepath.Base(f), doc)
	}
	return s
}

// Docs exposes the parsed documents for structural tests.
func (s *Set) Docs() map[string]map[string]any { return s.docs }

func (s *Set) checkKeywords(where string, node any) {
	switch n := node.(type) {
	case map[string]any:
		for k, v := range n {
			if !supportedKeywords[k] {
				s.t.Fatalf("%s: keyword %q is not implemented by the test validator; add it there before using it", where, k)
			}
			switch k {
			case "properties", "$defs":
				for name, sub := range v.(map[string]any) {
					s.checkKeywords(where+"/"+k+"/"+name, sub)
				}
			case "items":
				s.checkKeywords(where+"/items", v)
			}
		}
	}
}

// Resolve follows a $ref of the forms "#/$defs/x", "file.json" or "file.json#/$defs/x" relative to file.
func (s *Set) Resolve(file, ref string) (string, map[string]any) {
	doc, frag, hasFrag := strings.Cut(ref, "#")
	if doc == "" {
		doc = file
	}
	if !hasFrag {
		frag = ""
	}
	root, ok := s.docs[doc]
	if !ok {
		s.t.Fatalf("$ref %q: unknown schema file %q", ref, doc)
	}
	node := any(root)
	for _, part := range strings.Split(strings.TrimPrefix(frag, "/"), "/") {
		if part == "" {
			continue
		}
		m, ok := node.(map[string]any)
		if !ok || m[part] == nil {
			s.t.Fatalf("$ref %q: path element %q not found", ref, part)
		}
		node = m[part]
	}
	return doc, node.(map[string]any)
}

// Validate asserts body (a JSON document) against <file>; every violation is reported with its instance path.
func (s *Set) Validate(file string, body []byte) {
	s.t.Helper()
	var inst any
	dec := json.NewDecoder(bytes.NewReader(body))
	dec.UseNumber()
	if err := dec.Decode(&inst); err != nil {
		s.t.Fatalf("%s: body is not JSON: %v\n%s", file, err, body)
	}
	var errs []string
	s.Walk(file, s.docs[file], inst, "$", &errs)
	if len(errs) > 0 {
		sort.Strings(errs)
		s.t.Fatalf("%s: %d schema violation(s):\n  %s\nbody: %s", file, len(errs), strings.Join(errs, "\n  "), body)
	}
}

func (s *Set) Walk(file string, schema map[string]any, inst any, path string, errs *[]string) {
	fail := func(format string, a ...any) { *errs = append(*errs, path+": "+fmt.Sprintf(format, a...)) }
	if ref, ok := schema["$ref"].(string); ok {
		f, target := s.Resolve(file, ref)
		s.Walk(f, target, inst, path, errs)
		return
	}
	if t, ok := schema["type"]; ok {
		var types []string
		switch tt := t.(type) {
		case string:
			types = []string{tt}
		case []any:
			for _, e := range tt {
				types = append(types, e.(string))
			}
		}
		if !typeMatches(types, inst) {
			fail("type: want %v, got %s", types, typeName(inst))
			return
		}
	}
	if enum, ok := schema["enum"].([]any); ok {
		hit := false
		for _, e := range enum {
			if fmt.Sprint(e) == fmt.Sprint(inst) {
				hit = true
			}
		}
		if !hit {
			fail("enum: %v not in %v", inst, enum)
		}
	}
	switch v := inst.(type) {
	case map[string]any:
		props, _ := schema["properties"].(map[string]any)
		if req, ok := schema["required"].([]any); ok {
			for _, r := range req {
				if _, present := v[r.(string)]; !present {
					fail("required property %q missing", r)
				}
			}
		}
		for k, val := range v {
			sub, known := props[k]
			if !known {
				if ap, ok := schema["additionalProperties"].(bool); ok && !ap {
					fail("additional property %q not allowed", k)
				}
				continue
			}
			s.Walk(file, sub.(map[string]any), val, path+"."+k, errs)
		}
	case []any:
		if minItems, ok := schema["minItems"].(json.Number); ok {
			if n, _ := minItems.Int64(); int64(len(v)) < n {
				fail("minItems: %d < %d", len(v), n)
			}
		}
		if items, ok := schema["items"].(map[string]any); ok {
			for i, e := range v {
				s.Walk(file, items, e, fmt.Sprintf("%s[%d]", path, i), errs)
			}
		}
	case json.Number:
		f, _ := new(big.Rat).SetString(v.String())
		if minimum, ok := schema["minimum"].(json.Number); ok {
			if m, _ := new(big.Rat).SetString(minimum.String()); f.Cmp(m) < 0 {
				fail("minimum: %s < %s", v, minimum)
			}
		}
		if maximum, ok := schema["maximum"].(json.Number); ok {
			if m, _ := new(big.Rat).SetString(maximum.String()); f.Cmp(m) > 0 {
				fail("maximum: %s > %s", v, maximum)
			}
		}
	case string:
		if p, ok := schema["pattern"].(string); ok && !regexp.MustCompile(p).MatchString(v) {
			fail("pattern: %q !~ %s", v, p)
		}
		if err := checkFormat(schema["format"], v); err != nil {
			fail("format: %v", err)
		}
	}
}

// checkFormat asserts the three formats the contract uses (a validator that treated format as annotation would let a garbage timestamp through).
func checkFormat(format any, v string) error {
	switch format {
	case nil:
		return nil
	case "uuid":
		_, err := uuid.Parse(v)
		return err
	case "date-time":
		_, err := time.Parse(time.RFC3339Nano, v)
		return err
	case "date":
		_, err := time.Parse(time.DateOnly, v)
		return err
	}
	return fmt.Errorf("unknown format %v", format)
}

func typeMatches(types []string, inst any) bool {
	for _, t := range types {
		switch t {
		case "null":
			if inst == nil {
				return true
			}
		case "object":
			if _, ok := inst.(map[string]any); ok {
				return true
			}
		case "array":
			if _, ok := inst.([]any); ok {
				return true
			}
		case "string":
			if _, ok := inst.(string); ok {
				return true
			}
		case "boolean":
			if _, ok := inst.(bool); ok {
				return true
			}
		case "number":
			if _, ok := inst.(json.Number); ok {
				return true
			}
		case "integer":
			if n, ok := inst.(json.Number); ok {
				if _, err := n.Int64(); err == nil {
					return true
				}
			}
		}
	}
	return false
}

func typeName(inst any) string {
	switch inst.(type) {
	case nil:
		return "null"
	case map[string]any:
		return "object"
	case []any:
		return "array"
	case string:
		return "string"
	case bool:
		return "boolean"
	case json.Number:
		return "number"
	}
	return fmt.Sprintf("%T", inst)
}
