// Package hostprofile is ADR-0013: what a host declared it owns, resolved per
// session, stored, and exposed to the consumers that will one day switch on
// it. In this revision nothing decides on a Profile; it is stored and logged.
//
// Absence is the point. Every first-party writer sends no manifest and
// resolves to Default, which is today's behaviour written down — so a wrong
// default here is a behaviour change for every solo developer, and the
// golden tests pin it.
package hostprofile

import (
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"sync"

	m1pv1 "github.com/Omium-ai/omium-mark1/proto/gen/go/m1p/v1"
)

// CodeInvalid is 08 §9's row for a refused manifest.
const CodeInvalid = "M1E-4007"

// AcceptedSchemaVersions is the set HostManifest.schema_version must be in:
// the current m1p.v1 revision. Additive within the major, so one entry.
var AcceptedSchemaVersions = []string{"m1p.v1"}

// ArrestMode mirrors m1p.v1.ArrestMode as a plain Go type: ACT enforces the
// arrest (today's BLOCK), RECOMMEND reports it to the host's loop.
type ArrestMode string

const (
	Act       ArrestMode = "act"
	Recommend ArrestMode = "recommend"
)

// Profile is the resolved host profile — a plain struct, not the proto, so
// consumers never carry wire types and Canonical never depends on protojson.
type Profile struct {
	HostID            string
	HostVersion       string
	OwnsExecution     bool
	OwnsConfigSurface bool
	OwnsMemory        bool
	ArrestMode        ArrestMode
	SuppliesIdentity  bool
	SchemaVersion     string
}

// Default is today's behaviour, exactly, defined ONCE: Mark 1 owns the
// config surface (provisioning writes fences) and memory (the daemon
// injects), acts on an arrest, supplies the identity, and the writer does
// not own execution. A session with no manifest resolves to this.
var Default = Profile{
	HostID:            "",
	HostVersion:       "",
	OwnsExecution:     false,
	OwnsConfigSurface: true,
	OwnsMemory:        true,
	ArrestMode:        Act,
	SuppliesIdentity:  false,
	SchemaVersion:     "",
}

// IsDefault reports whether p is the no-manifest posture.
func (p Profile) IsDefault() bool { return p == Default }

// FromManifest validates m under 08 §4.3 step 2b and returns the Profile.
// ext says whether the connection (or file) is an external writer; a
// manifest from anything else is refused outright. A nil manifest is the
// caller's "absent" and resolves to Default without error.
func FromManifest(m *m1pv1.HostManifest, ext bool) (Profile, error) {
	if m == nil {
		return Default, nil
	}
	if !ext {
		return Default, fmt.Errorf("%s: host_manifest from a non-ext: writer; only external writers declare ownership (ADR-0013)", CodeInvalid)
	}
	var mode ArrestMode
	switch m.GetArrestMode() {
	case m1pv1.ArrestMode_ARREST_MODE_ACT:
		mode = Act
	case m1pv1.ArrestMode_ARREST_MODE_RECOMMEND:
		mode = Recommend
	default:
		return Default, fmt.Errorf("%s: arrest_mode must be ACT or RECOMMEND when a manifest is present, got %s", CodeInvalid, m.GetArrestMode())
	}
	if m.GetHostId() == "" {
		return Default, errors.New(CodeInvalid + ": host_id is empty")
	}
	if m.GetHostVersion() == "" {
		return Default, errors.New(CodeInvalid + ": host_version is empty")
	}
	if !m.GetOwnsExecution() {
		return Default, errors.New(CodeInvalid + ": owns_execution must be true for an external writer, which owns its loop by definition")
	}
	if !slices.Contains(AcceptedSchemaVersions, m.GetSchemaVersion()) {
		return Default, fmt.Errorf("%s: schema_version %q not in the accepted set %v", CodeInvalid, m.GetSchemaVersion(), AcceptedSchemaVersions)
	}
	return Profile{
		HostID:            m.GetHostId(),
		HostVersion:       m.GetHostVersion(),
		OwnsExecution:     true,
		OwnsConfigSurface: m.GetOwnsConfigSurface(),
		OwnsMemory:        m.GetOwnsMemory(),
		ArrestMode:        mode,
		SuppliesIdentity:  m.GetSuppliesIdentity(),
		SchemaVersion:     m.GetSchemaVersion(),
	}, nil
}

// canonical is Canonical's wire shape: snake_case keys, which encoding/json
// emits in struct-field order — fixed here, alphabetical, so the bytes are
// a function of the values alone.
type canonical struct {
	ArrestMode        ArrestMode `json:"arrest_mode"`
	HostID            string     `json:"host_id"`
	HostVersion       string     `json:"host_version"`
	OwnsConfigSurface bool       `json:"owns_config_surface"`
	OwnsExecution     bool       `json:"owns_execution"`
	OwnsMemory        bool       `json:"owns_memory"`
	SchemaVersion     string     `json:"schema_version"`
	SuppliesIdentity  bool       `json:"supplies_identity"`
}

// Canonical is the deterministic encoding a later feature hashes into
// receipts: compact JSON, keys in alphabetical order, every field present.
// Pinned by a golden test; it must never drift.
func Canonical(p Profile) []byte {
	b, err := json.Marshal(canonical{
		ArrestMode: p.ArrestMode, HostID: p.HostID, HostVersion: p.HostVersion,
		OwnsConfigSurface: p.OwnsConfigSurface, OwnsExecution: p.OwnsExecution, OwnsMemory: p.OwnsMemory,
		SchemaVersion: p.SchemaVersion, SuppliesIdentity: p.SuppliesIdentity,
	})
	if err != nil {
		panic("hostprofile: canonical encoding failed: " + err.Error()) // strings and bools cannot fail to marshal
	}
	return b
}

// Registry is the per-session store the daemon keeps: filled by both
// transports at bind time, read by provisioning, the gate and memory. An
// unknown session is Default — the absent-manifest posture — so a consumer
// never has to special-case "not registered".
type Registry struct{ m sync.Map }

func NewRegistry() *Registry { return &Registry{} }

// Set records session's resolved profile.
func (r *Registry) Set(session [16]byte, p Profile) { r.m.Store(session, p) }

// Get returns session's profile, Default when none was recorded.
func (r *Registry) Get(session [16]byte) Profile {
	if v, ok := r.m.Load(session); ok {
		return v.(Profile)
	}
	return Default
}

// Known reports whether a profile was recorded for session at all.
func (r *Registry) Known(session [16]byte) bool {
	_, ok := r.m.Load(session)
	return ok
}
