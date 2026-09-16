package receipt

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"

	"github.com/google/uuid"

	"github.com/Omium-ai/omium-mark1/go/mark1d/internal/identity"
	"github.com/Omium-ai/omium-mark1/go/mark1d/internal/redact"
)

// RedactionType is the receipt class the E1 door demands (FR-VERIFY-016, 10 §10.4 C-50).
const RedactionType = "redaction"

// Redaction attests one E1 scrub: pre/post hashes and what was cut by class and token digest, never a pre-image.
type Redaction struct {
	TenantID  string
	DeviceID  string
	SubjectID uuid.UUID
	IssuedAt  string // RFC 3339 UTC seconds, the checkpoint rendering
	PreHash   [32]byte
	PostHash  [32]byte
	Spans     []redact.Span
}

// Payload is the signed field set; deviceKeyID goes inside like a checkpoint's.
func (r Redaction) Payload(deviceKeyID string) map[string]any {
	classes := map[string]any{}
	digests := make([]string, 0, len(r.Spans))
	for _, sp := range r.Spans {
		n, _ := classes[string(sp.Class)].(int)
		classes[string(sp.Class)] = n + 1
		digests = append(digests, sp.Digest)
	}
	sort.Strings(digests)
	spans := make([]any, len(digests))
	for i, d := range digests {
		spans[i] = d
	}
	return map[string]any{
		"v":             1,
		"type":          RedactionType,
		"tenant_id":     r.TenantID,
		"device_id":     r.DeviceID,
		"device_key_id": deviceKeyID,
		"subject_id":    r.SubjectID.String(),
		"issued_at":     r.IssuedAt,
		"tier":          "E1",
		"pre_hash":      hex.EncodeToString(r.PreHash[:]),
		"post_hash":     hex.EncodeToString(r.PostHash[:]),
		"classes":       classes,
		"span_digests":  spans,
	}
}

// SignRedaction origin-signs like a checkpoint; ReceiptHash is EvidenceExcerpt.redaction_receipt_id.
func SignRedaction(key identity.DeviceKey, r Redaction) (identity.OriginSigned, error) {
	if key == nil || r.TenantID == "" || r.DeviceID == "" || r.SubjectID == uuid.Nil || r.IssuedAt == "" {
		return identity.OriginSigned{}, fmt.Errorf("receipt: redaction needs key, tenant, device, subject and issued_at")
	}
	return identity.OriginSign(key, r.Payload(key.KeyID()))
}

// RedactionFile is what the attach upload ships beside the sanitized part (08 §2.1).
type RedactionFile struct {
	Payload         string `json:"payload"`
	DeviceKeyID     string `json:"device_key_id"`
	DeviceSignature string `json:"device_signature"`
	ReceiptHash     string `json:"receipt_hash"`
}

// RedactionDir is where WriteRedaction files receipts under the daemon state root.
func RedactionDir(stateDir string) string { return filepath.Join(stateDir, "receipt", "redaction") }

// WriteRedaction persists one signed receipt as <state>/receipt/redaction/<hex hash>.json (0600).
func WriteRedaction(stateDir, deviceKeyID string, signed identity.OriginSigned) (string, error) {
	dir := RedactionDir(stateDir)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", err
	}
	b, err := json.Marshal(RedactionFile{
		Payload:         signed.PayloadText,
		DeviceKeyID:     deviceKeyID,
		DeviceSignature: hex.EncodeToString(signed.DeviceSig),
		ReceiptHash:     hex.EncodeToString(signed.ReceiptHash[:]),
	})
	if err != nil {
		return "", err
	}
	path := filepath.Join(dir, hex.EncodeToString(signed.ReceiptHash[:])+".json")
	return path, os.WriteFile(path, b, 0o600)
}
