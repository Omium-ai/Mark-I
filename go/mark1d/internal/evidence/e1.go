package evidence

import (
	"crypto/sha256"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	m1pv1 "github.com/Omium-ai/omium-mark1/proto/gen/go/m1p/v1"
	"github.com/google/uuid"

	"github.com/Omium-ai/omium-mark1/go/mark1d/internal/identity"
	"github.com/Omium-ai/omium-mark1/go/mark1d/internal/receipt"
	"github.com/Omium-ai/omium-mark1/go/mark1d/internal/redact"
)

// ErrQuarantined: the scanner failed on the hunk; nothing is written and no excerpt exists (F-35).
var ErrQuarantined = errors.New("evidence: E1 hunk quarantined by the admit axis")

// Identity signs the redaction receipt: the enrolled device key and the ids controld rebuilds from token claims (receipt.Config).
type Identity struct {
	Key      identity.DeviceKey
	TenantID string
	DeviceID string
}

// E1Dir holds the sanitized parts awaiting the attach upload (08 §2.1), post-redaction bytes only.
func E1Dir(stateDir string) string { return filepath.Join(Dir(stateDir), "e1") }

// AttachmentName is 08 §2.1's part name for the excerpt expanding evidenceEventID.
func AttachmentName(evidenceEventID uuid.UUID) string {
	return "attach." + evidenceEventID.String() + ".e1"
}

// PrepareE1 is the only E1 producer (FR-VERIFY-016): scan, receipt, persist post-redaction bytes only; raw is zeroed.
func (s *Store) PrepareE1(sc *redact.Scanner, id Identity, evidenceEventID [16]byte, raw []byte, now time.Time) (*m1pv1.EvidenceExcerpt, error) {
	if s == nil {
		return nil, errors.New("evidence: no store; an E1 excerpt cannot be receipted")
	}
	subject := uuid.UUID(evidenceEventID)
	if len(raw) == 0 {
		return nil, errors.New("evidence: an empty hunk is not an excerpt")
	}
	pre := sha256.Sum256(raw)
	out, outcome, spans := sc.AdmitSpans(raw)
	if outcome == redact.Quarantine {
		return nil, ErrQuarantined
	}
	signed, err := receipt.SignRedaction(id.Key, receipt.Redaction{
		TenantID:  id.TenantID,
		DeviceID:  id.DeviceID,
		SubjectID: subject,
		IssuedAt:  now.UTC().Truncate(time.Second).Format(time.RFC3339),
		PreHash:   pre,
		PostHash:  sha256.Sum256(out),
		Spans:     spans,
	})
	if err != nil {
		return nil, err
	}
	dir := E1Dir(s.state)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	name := AttachmentName(subject)
	if err := os.WriteFile(filepath.Join(dir, name), out, 0o600); err != nil {
		return nil, err
	}
	if _, err := receipt.WriteRedaction(s.state, id.Key.KeyID(), signed); err != nil {
		return nil, fmt.Errorf("evidence: receipt not persisted: %w", err)
	}
	return &m1pv1.EvidenceExcerpt{
		Tier:               m1pv1.EvidenceTier_EVIDENCE_TIER_E1,
		EvidenceEventId:    subject[:],
		AttachmentName:     name,
		RedactionReceiptId: signed.ReceiptHash[:],
	}, nil
}
