package anchors

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"time"
)

// ConsentPath is the consent store location under the daemon state root —
// 04 §2.2 fixes it at <state>/anchors/catalog.json.
func ConsentPath(stateDir string) string {
	return filepath.Join(stateDir, "anchors", "catalog.json")
}

// consentFile is the on-disk shape; the format is documented in doc.go
// because `mark1 doctor` (the CLI) reads the same file.
type consentFile struct {
	Version int             `json:"version"`
	Entries []ConsentRecord `json:"entries"`
}

// ConsentRecord is one approved catalog entry plus the effective-execution
// hash the approval covered. The hash — not the ID — is what consent binds
// to: same ID with a different hash is NOT consented (04 §2.2 re-consent).
type ConsentRecord struct {
	ID          string     `json:"id"`
	Tool        string     `json:"tool"`
	Argv        []string   `json:"argv"`
	BinaryPath  string     `json:"binary_path"`
	BinaryHash  string     `json:"binary_hash"` // hex BLAKE3
	ToolVersion string     `json:"tool_version"`
	Class       Class      `json:"class"`
	SideEffect  SideEffect `json:"side_effect"`
	ExecHash    string     `json:"exec_hash"` // hex, see ExecHash
	ConsentedAt time.Time  `json:"consented_at"`
}

// LoadConsent reads the store; a missing file is an empty store (nothing has
// been consented), any other failure is an error — an unreadable consent
// store must not read as "everything consented" OR silently as "nothing".
func LoadConsent(path string) ([]ConsentRecord, error) {
	b, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var f consentFile
	if err := json.Unmarshal(b, &f); err != nil {
		return nil, fmt.Errorf("anchors: corrupt consent store %s: %w", path, err)
	}
	if f.Version != 1 {
		return nil, fmt.Errorf("anchors: consent store %s has unknown version %d", path, f.Version)
	}
	return f.Entries, nil
}

// Approve records the user's consent for the given derived entries,
// replacing any prior record with the same ID and keeping the rest. Written
// 0600, tmp+rename (the store gates code execution; a torn write must not
// half-approve).
func Approve(path string, now time.Time, entries ...CatalogEntry) error {
	existing, err := LoadConsent(path)
	if err != nil {
		return err
	}
	byID := map[string]ConsentRecord{}
	for _, r := range existing {
		byID[r.ID] = r
	}
	for _, e := range entries {
		byID[e.ID] = ConsentRecord{
			ID:          e.ID,
			Tool:        e.Tool,
			Argv:        append([]string(nil), e.Argv...),
			BinaryPath:  e.BinaryPath,
			BinaryHash:  hex.EncodeToString(e.BinaryHash),
			ToolVersion: e.ToolVersion,
			Class:       e.Class,
			SideEffect:  e.SideEffect,
			ExecHash:    hex.EncodeToString(ExecHash(e)),
			ConsentedAt: now.UTC(),
		}
	}
	f := consentFile{Version: 1}
	for _, r := range byID {
		f.Entries = append(f.Entries, r)
	}
	return saveConsent(path, f)
}

// Revoke removes consent for the given IDs. Missing IDs are a no-op: revoking
// what was never consented is already the desired state.
func Revoke(path string, ids ...string) error {
	existing, err := LoadConsent(path)
	if err != nil {
		return err
	}
	drop := map[string]bool{}
	for _, id := range ids {
		drop[id] = true
	}
	f := consentFile{Version: 1}
	for _, r := range existing {
		if !drop[r.ID] {
			f.Entries = append(f.Entries, r)
		}
	}
	return saveConsent(path, f)
}

// saveConsent writes the store sorted (deterministic bytes ⇒ stable doctor
// diffs), 0600, tmp+fsync+rename — the store gates code execution, so a torn
// OR power-lost write must never half-approve; worst case after a crash is a
// missing/corrupt file, which reads as "nothing consented" or an explicit
// error, never as consent.
func saveConsent(path string, f consentFile) error {
	sort.Slice(f.Entries, func(i, j int) bool { return f.Entries[i].ID < f.Entries[j].ID })
	b, err := json.MarshalIndent(f, "", "  ")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	tmp := path + ".tmp"
	tf, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
	if err != nil {
		return err
	}
	if _, err := tf.Write(b); err != nil {
		tf.Close()
		return err
	}
	if err := tf.Sync(); err != nil {
		tf.Close()
		return err
	}
	if err := tf.Close(); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

// stillConsented re-reads the store and reports whether e is still covered by
// a live record — the same binding Reconcile applies: the ID must exist AND
// its ExecHash must equal e's (revocation removes the record; a re-consent
// under a different derivation must not cover the old entry). Any load
// failure reads as "not consented" — an unreadable store must never read as
// consent (LoadConsent's own rule, applied at the execution point).
func stillConsented(path string, e CatalogEntry) bool {
	recs, err := LoadConsent(path)
	if err != nil {
		return false
	}
	want := hex.EncodeToString(ExecHash(e))
	for _, r := range recs {
		if r.ID == e.ID && r.ExecHash == want {
			return true
		}
	}
	return false
}

// Drift is one doctor-visible divergence between a consent record and the
// current derivation: the entry is DISABLED until re-consented (04 §2.2).
type Drift struct {
	ID      string
	Reason  string // human line for doctor; the decision input is the hash
	Consent ConsentRecord
	Derived *CatalogEntry // nil when the entry no longer derives at all
}

// DoctorReport is the consent API surface `mark1 doctor` renders (FR-CLI-004:
// the consented catalog with timestamps, plus every diff).
type DoctorReport struct {
	Enabled []CatalogEntry  // consented AND derivation-stable: these may run
	Pending []CatalogEntry  // derived, never consented: shown, never run
	Drifted []Drift         // consented but derivation changed: disabled until re-consent
	Stale   []ConsentRecord // consented but no longer derivable (tool/config gone)
}

// Reconcile joins the current derivation against the consent store. Only
// Enabled entries are runnable; every entry there carries its consent-time
// BinaryHash and ConsentedAt so the runner's tamper check compares against
// what the USER approved, not against whatever is on disk today.
func Reconcile(derived []CatalogEntry, consented []ConsentRecord) DoctorReport {
	var rep DoctorReport
	byID := map[string]ConsentRecord{}
	for _, r := range consented {
		byID[r.ID] = r
	}
	seen := map[string]bool{}
	for _, e := range derived {
		seen[e.ID] = true
		rec, ok := byID[e.ID]
		if !ok {
			rep.Pending = append(rep.Pending, e)
			continue
		}
		if rec.ExecHash != hex.EncodeToString(ExecHash(e)) {
			e := e
			rep.Drifted = append(rep.Drifted, Drift{
				ID:      e.ID,
				Reason:  driftReason(rec, e),
				Consent: rec,
				Derived: &e,
			})
			continue
		}
		// Hydrate consent-time fields: the tamper reference is the approved
		// hash (identical to the derived one here, by the ExecHash equality —
		// but sourced from the record so the provenance is the store).
		bh, err := hex.DecodeString(rec.BinaryHash)
		if err != nil {
			rep.Drifted = append(rep.Drifted, Drift{ID: e.ID, Reason: "corrupt binary_hash in consent record", Consent: rec})
			continue
		}
		e.BinaryHash = bh
		e.ConsentedAt = rec.ConsentedAt
		rep.Enabled = append(rep.Enabled, e)
	}
	for _, r := range consented {
		if !seen[r.ID] {
			rep.Stale = append(rep.Stale, r)
		}
	}
	return rep
}

func driftReason(rec ConsentRecord, e CatalogEntry) string {
	switch {
	case rec.BinaryHash != hex.EncodeToString(e.BinaryHash):
		return fmt.Sprintf("binary changed at %s since consent (%s)", e.BinaryPath, rec.ConsentedAt.Format(time.RFC3339))
	case rec.ToolVersion != e.ToolVersion:
		return fmt.Sprintf("tool version changed: %q -> %q", rec.ToolVersion, e.ToolVersion)
	case fmt.Sprint(rec.Argv) != fmt.Sprint(e.Argv):
		return "derived argv changed"
	default:
		return "effective-execution hash changed"
	}
}

// Doctor is the one-call surface for the CLI: derive, load, reconcile. sb is
// the sandbox derivation's version sniff runs inside (see Derive — the sniff
// execs an unconsented binary, so it is never unsandboxed).
func Doctor(sb Sandbox, worktree, consentPath string) (DoctorReport, error) {
	derived, err := Derive(sb, worktree)
	if err != nil {
		return DoctorReport{}, err
	}
	consented, err := LoadConsent(consentPath)
	if err != nil {
		return DoctorReport{}, err
	}
	return Reconcile(derived, consented), nil
}
