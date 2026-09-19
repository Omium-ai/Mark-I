package anchors

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"sort"
	"time"
)

// The consent surface between mark1d and the mark1 CLI is two files, both
// under <state>/anchors/ and both 0600. The CLI cannot import this package
// (module-private) and cannot derive (Derive needs the sandbox), so:
//
//   - candidates.json is DAEMON → CLI: every anchor derivable for every enabled
//     workspace, with its exact exec_hash and whether the store already covers
//     it. mark1d rewrites it on boot, on every workspaces.json change, after
//     every approval it applies, and on the re-derive tick. Absent ⇒ the daemon
//     has not published; an empty workspace list ⇒ nothing is enabled; a
//     workspace with an empty anchor list ⇒ nothing derivable there, and the
//     sandbox field says whether that is because no anchor can RUN here.
//   - approvals.jsonl is CLI → DAEMON, append-only: one line per anchor the
//     user consented to at a TTY, naming the EXACT exec_hash shown. The daemon
//     applies a line only while that (id, exec_hash) is a current candidate —
//     a hash that no longer derives is refused, never approved, so the 04 §2.2
//     re-consent-on-change rule needs no extra machinery.

func CandidatesPath(stateDir string) string {
	return filepath.Join(stateDir, "anchors", "candidates.json")
}

func ApprovalsPath(stateDir string) string {
	return filepath.Join(stateDir, "anchors", "approvals.jsonl")
}

// Candidates is candidates.json. Workspaces are sorted by path, anchors by ID
// (Derive's order): deterministic bytes.
type Candidates struct {
	Version    int                   `json:"version"`
	Sandbox    SandboxStatus         `json:"sandbox"` // additive (v1): why Derive dropped what it dropped
	Workspaces []WorkspaceCandidates `json:"workspaces"`
}

type WorkspaceCandidates struct {
	Path    string      `json:"path"`
	Anchors []Candidate `json:"anchors"`
	Looked  []Miss      `json:"looked"` // additive (v1): every kind Explain did not derive here, and why
}

// Candidate is one derived entry in ConsentRecord's own field names, plus the
// store's answer. ConsentedAt is zero unless Consented.
type Candidate struct {
	ConsentRecord
	Consented bool `json:"consented"`
}

// Approval is one line of approvals.jsonl. The CLI writes it (its Approval
// type copies these tags); the daemon only reads.
type Approval struct {
	TS        string `json:"ts"`
	User      string `json:"user,omitempty"`
	UID       string `json:"uid,omitempty"`
	Workspace string `json:"workspace"`
	ID        string `json:"id"`
	ExecHash  string `json:"exec_hash"`
}

// PublishCandidates joins each workspace's derivation against the store and
// writes candidates.json. Same binding as Reconcile: consented iff the store
// holds the ID under this exact exec_hash. looked is Explain's misses per
// root (nil is fine); sandbox is the Sandbox's Status() as of this derivation.
func PublishCandidates(path string, consented []ConsentRecord, derived map[string][]CatalogEntry, looked map[string][]Miss, sandbox SandboxStatus) error {
	byID := map[string]ConsentRecord{}
	for _, r := range consented {
		byID[r.ID] = r
	}
	c := Candidates{Version: 1, Sandbox: sandbox, Workspaces: []WorkspaceCandidates{}}
	for root, entries := range derived {
		ws := WorkspaceCandidates{Path: root, Anchors: []Candidate{}, Looked: looked[root]}
		if ws.Looked == nil {
			ws.Looked = []Miss{}
		}
		for _, e := range entries {
			cand := Candidate{ConsentRecord: toRecord(e, time.Time{})}
			if rec, ok := byID[e.ID]; ok && rec.ExecHash == cand.ExecHash {
				cand.Consented, cand.ConsentedAt = true, rec.ConsentedAt
			}
			ws.Anchors = append(ws.Anchors, cand)
		}
		c.Workspaces = append(c.Workspaces, ws)
	}
	sort.Slice(c.Workspaces, func(i, j int) bool { return c.Workspaces[i].Path < c.Workspaces[j].Path })
	b, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		return err
	}
	return writePrivate(path, b)
}

// ApplyApprovals reads approvals.jsonl from byte offset `from` and approves
// every line whose (id, exec_hash) is a current candidate; it returns the
// offset to resume from and whether the store changed. Replay-idempotent: a
// line the store already covers under that hash is skipped without a write,
// so a restarted daemon re-reading the whole file changes nothing. A line
// whose hash matches no current candidate is logged and dropped — consent
// binds to the exact effective-execution hash, never to the ID alone.
func ApplyApprovals(consentPath, approvalsPath string, from int64, derived map[string][]CatalogEntry, now time.Time, log *slog.Logger) (int64, bool, error) {
	f, err := os.Open(approvalsPath)
	if errors.Is(err, os.ErrNotExist) {
		return 0, false, nil
	}
	if err != nil {
		return from, false, err
	}
	defer func() { _ = f.Close() }()
	fi, err := f.Stat()
	if err != nil {
		return from, false, err
	}
	if fi.Size() < from {
		from = 0 // truncated: re-read from the top (idempotent)
	}
	tail, err := io.ReadAll(io.NewSectionReader(f, from, fi.Size()-from))
	if err != nil {
		return from, false, err
	}
	// Only complete lines are consumed; a line the CLI is still appending
	// stays unread until its newline lands.
	consumed := bytes.LastIndexByte(tail, '\n') + 1
	offset := from + int64(consumed)
	consented, err := LoadConsent(consentPath)
	if err != nil {
		return from, false, err
	}
	held := map[string]string{} // id → exec_hash in the store
	for _, r := range consented {
		held[r.ID] = r.ExecHash
	}
	var approve []CatalogEntry
	for _, line := range bytes.Split(tail[:consumed], []byte{'\n'}) {
		if len(bytes.TrimSpace(line)) == 0 {
			continue
		}
		var a Approval
		if err := json.Unmarshal(line, &a); err != nil {
			log.Warn("anchors: unparseable approval line ignored", "path", approvalsPath, "err", err)
			continue
		}
		if held[a.ID] == a.ExecHash {
			continue // already consented under this exact hash: replay
		}
		e, ok := candidate(derived, a.ID, a.ExecHash)
		if !ok {
			log.Warn("anchors: approval names no current candidate; NOT approved (consent binds to the exact exec_hash — re-run `mark1 enable`)",
				"anchor", a.ID, "exec_hash", a.ExecHash, "workspace", a.Workspace)
			continue
		}
		held[a.ID] = a.ExecHash
		approve = append(approve, e)
		log.Info("anchors: consent recorded", "anchor", a.ID, "exec_hash", a.ExecHash, "user", a.User, "workspace", a.Workspace)
	}
	if len(approve) == 0 {
		return offset, false, nil
	}
	if err := Approve(consentPath, now, approve...); err != nil {
		return from, false, err
	}
	return offset, true, nil
}

// candidate finds the derived entry with this ID whose exec_hash is exactly
// h. The store is keyed by ID across workspaces (one tool on the daemon's
// PATH derives one hash), so the first match is the match.
func candidate(derived map[string][]CatalogEntry, id, h string) (CatalogEntry, bool) {
	for _, entries := range derived {
		for _, e := range entries {
			if e.ID == id && hex.EncodeToString(ExecHash(e)) == h {
				return e, true
			}
		}
	}
	return CatalogEntry{}, false
}

// toRecord is the one CatalogEntry → ConsentRecord rendering (Approve's and
// the candidates file's), so both carry the same exec_hash bytes.
func toRecord(e CatalogEntry, at time.Time) ConsentRecord {
	return ConsentRecord{
		ID:          e.ID,
		Tool:        e.Tool,
		Argv:        append([]string(nil), e.Argv...),
		BinaryPath:  e.BinaryPath,
		BinaryHash:  hex.EncodeToString(e.BinaryHash),
		ToolVersion: e.ToolVersion,
		Class:       e.Class,
		SideEffect:  e.SideEffect,
		ExecHash:    hex.EncodeToString(ExecHash(e)),
		ConsentedAt: at,
	}
}

// writePrivate is the 0600 tmp+fsync+rename write both anchor files use: a
// torn candidates file would show the CLI a hash nobody derived.
func writePrivate(path string, b []byte) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	tmp := path + ".tmp"
	tf, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
	if err != nil {
		return err
	}
	if _, err := tf.Write(b); err != nil {
		_ = tf.Close()
		return err
	}
	if err := tf.Sync(); err != nil {
		_ = tf.Close()
		return err
	}
	if err := tf.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmp, path); err != nil {
		return fmt.Errorf("anchors: publish %s: %w", path, err)
	}
	return nil
}
