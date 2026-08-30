package enroll

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/google/uuid"
)

// The device_code we hand the CLI is OUR opaque credential (08 §3.1: "auth:
// none — device_code is the secret"), composed as
//
//	b64url(JSON{v,t,p,h}) + "." + <the IdP's device_code>
//
// WHY composed rather than random: controld_app cannot read ANY row without a
// tenant GUC (05 §7.1 NULLIF — an unset GUC matches nothing), so the poll
// request must carry its own routing key; and m1_device_enrollments has no
// columns for platform/hostname or the IdP's code (hashes only — the raw code
// is a credential, migrations/m1_001), so the PENDING-state facts the APPROVED
// transition needs ride inside the credential itself. Tampering with any part
// changes SHA-256(code), which no longer matches the stored
// device_code_hash ⇒ M1E-1004, so the embedding adds routing, never trust.
// This also keeps enrollment stateless across pods and restarts — an
// in-memory pending table would strand a 15-minute flow on every deploy.
type codeHeader struct {
	V        int    `json:"v"`
	TenantID string `json:"t"`
	Platform string `json:"p"`
	// hostname HMAC, hex — per-tenant HMAC of the hostname, never the
	// hostname (m1_devices.hostname_hmac discipline).
	HostnameHMAC string `json:"h"`
}

func encodeDeviceCode(tenant uuid.UUID, platform string, hostnameHMAC []byte, idpCode string) string {
	hdr, _ := json.Marshal(codeHeader{
		V: 1, TenantID: tenant.String(), Platform: platform,
		HostnameHMAC: hex.EncodeToString(hostnameHMAC),
	})
	return base64.RawURLEncoding.EncodeToString(hdr) + "." + idpCode
}

func decodeDeviceCode(code string) (tenant uuid.UUID, platform string, hostnameHMAC []byte, idpCode string, err error) {
	head, rest, ok := strings.Cut(code, ".")
	if !ok {
		return uuid.Nil, "", nil, "", fmt.Errorf("enroll: malformed device_code")
	}
	raw, err := base64.RawURLEncoding.DecodeString(head)
	if err != nil {
		return uuid.Nil, "", nil, "", fmt.Errorf("enroll: malformed device_code header")
	}
	var h codeHeader
	if err := json.Unmarshal(raw, &h); err != nil || h.V != 1 {
		return uuid.Nil, "", nil, "", fmt.Errorf("enroll: unknown device_code version")
	}
	tenant, err = uuid.Parse(h.TenantID)
	if err != nil || tenant == uuid.Nil {
		return uuid.Nil, "", nil, "", fmt.Errorf("enroll: device_code carries no tenant")
	}
	hostnameHMAC, err = hex.DecodeString(h.HostnameHMAC)
	if err != nil || len(hostnameHMAC) != 32 {
		return uuid.Nil, "", nil, "", fmt.Errorf("enroll: device_code hostname hmac malformed")
	}
	return tenant, h.Platform, hostnameHMAC, rest, nil
}

// hashCode is what m1_device_enrollments stores: SHA-256 of the full opaque
// code — the raw code is a credential and never lands in Postgres (m1_001).
func hashCode(code string) []byte {
	h := sha256.Sum256([]byte(code))
	return h[:]
}

// parseDevicePubkey accepts 08 §3.1's wire form "ed25519:BASE64…" and returns
// the raw 32-byte key.
func parseDevicePubkey(s string) ([]byte, error) {
	b64, ok := strings.CutPrefix(s, "ed25519:")
	if !ok {
		return nil, fmt.Errorf("enroll: device_pubkey must be ed25519:<base64>")
	}
	raw, err := decodeAny(b64)
	if err != nil || len(raw) != 32 {
		return nil, fmt.Errorf("enroll: device_pubkey must decode to 32 bytes")
	}
	return raw, nil
}

// parseHostnameHash accepts the §3.1 hostname_hash ("hmac…" — encoding left
// open by the contract; hex and base64 both accepted, 32 bytes required to
// satisfy ck_m1_devices_hostname_len).
func parseHostnameHash(s string) ([]byte, error) {
	s = strings.TrimPrefix(s, "hmac-sha256:")
	raw, err := decodeAny(s)
	if err != nil || len(raw) != 32 {
		return nil, fmt.Errorf("enroll: hostname_hash must decode to 32 bytes")
	}
	return raw, nil
}

func decodeAny(s string) ([]byte, error) {
	for _, dec := range []func(string) ([]byte, error){
		hex.DecodeString,
		base64.StdEncoding.DecodeString,
		base64.RawStdEncoding.DecodeString,
		base64.URLEncoding.DecodeString,
		base64.RawURLEncoding.DecodeString,
	} {
		if b, err := dec(s); err == nil {
			return b, nil
		}
	}
	return nil, fmt.Errorf("neither hex nor base64")
}

// deviceKeyID is the m1_device_keys derivation, verbatim from the migration:
// "ed25519:" + first 16 hex of SHA-256(pubkey) — derived, so key_id and
// public_key cannot disagree.
func deviceKeyID(pubkey []byte) string {
	sum := sha256.Sum256(pubkey)
	return "ed25519:" + hex.EncodeToString(sum[:])[:16]
}
