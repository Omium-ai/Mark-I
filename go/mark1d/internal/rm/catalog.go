package rm

import (
	"bytes"
	_ "embed"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"strconv"
	"strings"
)

// DefaultBaseURL serves <name>@<version>/{manifest.json,model.gguf}; catalog.json pins one Manifest per release, newest last, never edited in place.
const DefaultBaseURL = "https://dl.omium.ai/mark1/models/rm"

//go:embed catalog.json
var catalogJSON []byte

type Scoring struct {
	Method string `json:"method"`
	Yes    string `json:"yes"`
	No     string `json:"no"`
}

// Manifest is training_jobs/rm/export.py edge_manifest, byte for byte the manifest.json served beside model.gguf.
type Manifest struct {
	Name               string  `json:"name"`
	Version            int     `json:"version"`
	SHA256             string  `json:"sha256"`
	SizeBytes          int64   `json:"size_bytes"`
	CalibrationVersion string  `json:"calibration_version"`
	TemplateSHA        string  `json:"template_sha"`
	EvalCardSHA        string  `json:"eval_card_sha"`
	ExecutionHash      string  `json:"execution_hash"`
	Scoring            Scoring `json:"scoring"`
}

var reToken = regexp.MustCompile(`^ ?[A-Za-z]{1,16}$`)

// Slot is "a" (RM-A, Qwen family) or "b" (RM-B, another family): the name is mark1-rm-<slot> (m1_098).
func (m Manifest) Slot() string { return strings.TrimPrefix(m.Name, "mark1-rm-") }

// Ref is <name>@<version>, the artifact directory under DefaultBaseURL and the state dir.
func (m Manifest) Ref() string { return m.Name + "@" + strconv.Itoa(m.Version) }

func (m Manifest) ModelID() string { return "rm:" + m.Ref() }

func (m Manifest) Validate() error {
	hex64 := func(s string) bool { b, err := hex.DecodeString(s); return err == nil && len(b) == 32 }
	switch {
	case m.Name != "mark1-rm-a" && m.Name != "mark1-rm-b":
		return fmt.Errorf("rm: name %q is not mark1-rm-a (Qwen family) or mark1-rm-b (another family) (m1_098)", m.Name)
	case m.Version < 1:
		return fmt.Errorf("rm: version %d is not a registry version (m1_073: [1-9][0-9]*)", m.Version)
	case !hex64(m.SHA256) || !hex64(m.EvalCardSHA) || !hex64(m.ExecutionHash):
		return errors.New("rm: sha256, eval_card_sha and execution_hash must be 64 hex chars")
	case m.SizeBytes <= 0:
		return errors.New("rm: size_bytes must be positive")
	case m.CalibrationVersion == "":
		return errors.New("rm: calibration_version is required")
	case m.TemplateSHA != TemplateSHA():
		return fmt.Errorf("rm: template_sha %s is not this edge's %s (%s)", m.TemplateSHA, TemplateSHA(), TemplateVersion)
	case m.Scoring.Method != "logit_diff" || !reToken.MatchString(m.Scoring.Yes) || !reToken.MatchString(m.Scoring.No) || m.Scoring.Yes == m.Scoring.No:
		return errors.New(`rm: scoring must be {"method":"logit_diff","yes":" yes","no":" no"}-shaped`)
	}
	return nil
}

// Active is the newest valid entry per slot, a before b; an invalid entry is skipped, never served.
func Active(catalog []Manifest) []Manifest {
	var out []Manifest
	for _, slot := range []string{"a", "b"} {
		for i := len(catalog) - 1; i >= 0; i-- {
			if catalog[i].Slot() == slot && catalog[i].Validate() == nil {
				out = append(out, catalog[i])
				break
			}
		}
	}
	return out
}

// Catalog is the embedded catalog.json, strictly decoded: a field outside the export's manifest fails the whole catalog, so nothing is served.
func Catalog() []Manifest {
	c, err := parseCatalog(catalogJSON)
	if err != nil {
		return nil
	}
	return c
}

func parseCatalog(b []byte) ([]Manifest, error) {
	d := json.NewDecoder(bytes.NewReader(b))
	d.DisallowUnknownFields()
	c := []Manifest{}
	if err := d.Decode(&c); err != nil {
		return nil, err
	}
	return c, nil
}
