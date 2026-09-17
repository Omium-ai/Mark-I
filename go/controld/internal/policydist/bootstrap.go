// The bootstrap bundle: every tenant's `stable` seq 1, published at first enrollment so a fresh edge fuses, arms the knee and can BLOCK before any compiled bundle exists; every number is a prior with a named source.
package policydist

import (
	"context"
	"embed"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"sort"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/Omium-ai/omium-mark1/go/controld/internal/querychoke"
)

// BootstrapChannel is the channel every edge polls by default (08 §3.2).
const BootstrapChannel = "stable"

// BootstrapMaxAge: the content is priors, it does not rot like a fitted table; a week (the compiler's) would drop every edge to built-ins before any compiled bundle exists.
// ponytail: one year; cut to the compiler's 7 d once compiled bundles own `stable`.
const BootstrapMaxAge = 365 * 24 * time.Hour

// Priors are 06 §3.2's bundle π = [satisfied, violated, refused, error] (adjudicator DEFAULT_PRIORS, mark1d verdict.DefaultPriors).
var bootstrapPriors = [4]float64{0.55, 0.30, 0.10, 0.05}

// The literature-calibrated per-kind rows of python/adjudicator/app/adjudicate/likelihoods.py, provenance 'prior' (rows: S,V,R,E; cols: accept, reject, abstain).
var (
	anchorRows    = [4][3]float64{{0.93, 0.02, 0.05}, {0.55, 0.40, 0.05}, {0.30, 0.10, 0.60}, {0.25, 0.15, 0.60}}
	syntacticRows = [4][3]float64{{0.80, 0.10, 0.10}, {0.55, 0.35, 0.10}, {0.30, 0.20, 0.50}, {0.25, 0.25, 0.50}}
)

// bootstrapAnchors mirrors mark1d/internal/anchors/catalog.go's detector table: the tool names the edge derives (id "<tool>@cat-1") and the adjudicator kind each is (06 §2.5).
var bootstrapAnchors = []struct{ tool, kind string }{
	{"cargo-check", "compile"}, {"cargo-test", "test"}, {"eslint", "lint"}, {"go-test", "test"},
	{"go-vet", "typecheck"}, {"npm-test", "test"}, {"pytest", "test"}, {"ruff", "lint"}, {"tsc", "typecheck"},
}

// The knee prior under Paper I's model (06 §8.1): p(n) = p1·γ^(n−1), ρ = c(1)/(p1·V), k* = 1 + ⌊ln ρ/ln γ⌋ = 2; the table first stops at n = 3, within the compiler's ±1 gate (06 §10.3).
const (
	kneeP1    = 0.5
	kneeGamma = 0.6
	kneeRho   = 0.4
	kneeRows  = 8 // D34
)

//go:embed maps/*.json
var shimMaps embed.FS

// bootstrapRegime is the m1_tenant_regimes row that picks the basis; absent ⇒ quota (a subscription is the default regime) at unit value.
type bootstrapRegime struct {
	CostBasis string
	VDefault  float64
}

func kneeTable(r bootstrapRegime) KneeTable {
	t := KneeTable{CostBasis: r.CostBasis, VDefault: r.VDefault}
	cN := kneeRho * kneeP1 * r.VDefault
	p := kneeP1
	for n := 1; n <= kneeRows; n++ {
		lcb := p
		t.Rows = append(t.Rows, KneeRow{N: uint64(n), CN: cN, PLCB: &lcb}) // #nosec G115 -- 1..8
		p = p * kneeGamma
	}
	return t
}

// BootstrapSections is the six-section map for r as canonical CBOR — what Publish takes.
func BootstrapSections(r bootstrapRegime) ([]byte, error) {
	if !costBases[r.CostBasis] {
		return nil, fmt.Errorf("policydist: bootstrap cost_basis %q is not usd|quota", r.CostBasis)
	}
	verifiers := make([]VerifierModel, 0, len(bootstrapAnchors))
	members := make([]string, 0, len(bootstrapAnchors))
	for _, a := range bootstrapAnchors {
		rows := syntacticRows
		if a.kind == "compile" || a.kind == "test" {
			rows = anchorRows
		}
		id := a.tool + "@cat-1"
		verifiers = append(verifiers, VerifierModel{VerifierID: id, Confusion: rows})
		members = append(members, id)
	}
	agents, err := shimAgentMaps()
	if err != nil {
		return nil, err
	}
	s := Sections{
		Verify: VerifySection{
			Anchors:   []AnchorEnable{},
			Verifiers: verifiers,
			Priors:    bootstrapPriors,
			// 06 §4.1: syntactic ∪ tests is ONE clique — a linter and a test failing on the same diff is one observation.
			CorrelationGroups: []CorrelationGroup{{GroupID: "syntactic", Members: members}},
			Quarantine:        []string{},
		},
		Route:     RouteSection{CPVS: []CPVSRow{}, Ladders: []Ladder{}, Knee: kneeTable(r)},
		Memory:    MemorySection{InjectionRules: []InjectionRule{}},
		Cortex:    CortexSection{Channels: []string{}},
		Gates:     GatesSection{StopGateEnabled: true, MaxConsecutiveBlocks: 3, HourlyBlockCeiling: maxHourlyBlockCeiling},
		AgentMaps: AgentMapsSection{Agents: agents},
	}
	if err := ValidateSections(s); err != nil {
		return nil, err
	}
	return canonEnc.Marshal(s)
}

// shimMap is rust/mark1-hookshim/maps/<agent>.json (maps.rs FieldMap), the subset the bundle grammar can carry.
type shimMap struct {
	Agent          string `json:"agent"`
	AgentVersion   string `json:"agent_version"`
	EventField     string `json:"event_field"`
	SessionIDField string `json:"session_id_field"`
	Events         map[string]struct {
		Fields map[string]string `json:"fields"`
	} `json:"events"`
}

func pointerOf(field string) string {
	return "/" + strings.ReplaceAll(strings.ReplaceAll(field, "~", "~0"), "/", "~1")
}

// shimAgentMaps flattens each shipped map into 07's `hook_fields` (m1p-field ⇒ pointer): `event`, `session_id`, and `<event>.<logical>` per event rule.
func shimAgentMaps() ([]AgentMap, error) {
	names, err := fs.Glob(shimMaps, "maps/*.json")
	if err != nil {
		return nil, err
	}
	sort.Strings(names)
	out := make([]AgentMap, 0, len(names))
	for _, name := range names {
		raw, err := shimMaps.ReadFile(name)
		if err != nil {
			return nil, err
		}
		var m shimMap
		if err := json.Unmarshal(raw, &m); err != nil {
			return nil, fmt.Errorf("policydist: %s: %w", name, err)
		}
		fields := map[string]string{"event": pointerOf(m.EventField), "session_id": pointerOf(m.SessionIDField)}
		for event, rule := range m.Events {
			for logical, vendor := range rule.Fields {
				fields[strings.ToLower(event)+"."+logical] = pointerOf(vendor)
			}
		}
		out = append(out, AgentMap{AgentID: m.Agent, AgentVersion: m.AgentVersion, HookFields: fields, TailerRules: map[string]string{}})
	}
	return out, nil
}

func (s *Store) regime(ctx context.Context, tenant querychoke.TenantID) (bootstrapRegime, error) {
	r := bootstrapRegime{CostBasis: "quota", VDefault: 1}
	err := s.db.WithTenant(ctx, tenant, func(tx pgx.Tx) error {
		err := tx.QueryRow(ctx, `SELECT cost_basis, v_default::float8 FROM m1_tenant_regimes WHERE tenant_id = $1`, tenant.UUID()).
			Scan(&r.CostBasis, &r.VDefault)
		if errors.Is(err, pgx.ErrNoRows) {
			return nil
		}
		return err
	})
	return r, err
}

// Bootstrap publishes the tenant's bootstrap bundle as `stable` seq 1, idempotently: a tenant that already has a head keeps it (published=false, no error).
func (m *Module) Bootstrap(ctx context.Context, tenant querychoke.TenantID) (Published, bool, error) {
	r, err := m.store.regime(ctx, tenant)
	if err != nil {
		return Published{}, false, err
	}
	body, err := BootstrapSections(r)
	if err != nil {
		return Published{}, false, err
	}
	p, err := m.Publish(ctx, tenant, Draft{Channel: BootstrapChannel, MaxAge: BootstrapMaxAge, SectionsCBOR: body, FirstOnly: true})
	if errors.Is(err, ErrChannelHasHead) {
		return Published{}, false, nil
	}
	if err != nil {
		return Published{}, false, err
	}
	return p, true, nil
}
