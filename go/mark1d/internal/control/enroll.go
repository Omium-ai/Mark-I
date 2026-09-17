package control

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/Omium-ai/omium-mark1/go/mark1d/internal/coverage"
	"github.com/Omium-ai/omium-mark1/go/mark1d/internal/identity"
	"github.com/Omium-ai/omium-mark1/go/mark1d/internal/receipt"
)

// enrollmentDoc mirrors go/mark1/internal/cli.Enrollment byte-compatibly: the file, not the type, is the contract (that module's internal/ is out of reach, as cmd/main.go's reader notes).
type enrollmentDoc struct {
	Version        int       `json:"version"`
	State          string    `json:"state"`
	DeviceID       string    `json:"device_id"`
	TenantID       string    `json:"tenant_id"`
	DeviceToken    string    `json:"device_token"`
	TokenExpiresAt time.Time `json:"token_expires_at"`
	TenantRootHex  string    `json:"tenant_root_hex,omitempty"`
	Server         string    `json:"server"`
	Channel        string    `json:"channel"`
	ServerMinEdge  string    `json:"server_min_edge,omitempty"`
	KeyManifestURI string    `json:"key_manifest_uri,omitempty"`
	Endpoints      endpoints `json:"endpoints"`
	EnrolledAt     time.Time `json:"enrolled_at"`
}

type endpoints struct {
	Ingest       string `json:"ingest,omitempty"`
	Attach       string `json:"attach,omitempty"`
	PolicyStream string `json:"policy_stream,omitempty"`
}

// activeBody is controld's /enroll/device/approve (= /poll ACTIVE) body, 08 §3.1.
type activeBody struct {
	Status         string    `json:"status"`
	DeviceID       string    `json:"device_id"`
	TenantID       string    `json:"tenant_id"`
	DeviceToken    string    `json:"device_token"`
	ExpiresIn      int       `json:"expires_in"`
	ServerMinEdge  string    `json:"server_min_edge"`
	Endpoints      endpoints `json:"endpoints"`
	KeyManifestURI string    `json:"key_manifest_uri"`
	TenantRootHex  string    `json:"tenant_root_hex"`
	// BundleSectionKeys is 08 §3.5's bundle_section_keys list, delivered by controld's enroll module; it becomes the daemon's pinned ring (bundle/client.go keysFile).
	BundleSectionKeys json.RawMessage `json:"bundle_section_keys,omitempty"`
}

func (s *Server) pinnedKeysPath() string { return filepath.Join(s.cfg.StateDir, "policy", "keys.json") }

// pinKeys writes the trust file the bundle client loads (bundle.trustFile shape); an absent or empty list pins nothing and leaves any prior pin in place.
func (s *Server) pinKeys(keys json.RawMessage) error {
	var list []json.RawMessage
	if len(keys) == 0 || json.Unmarshal(keys, &list) != nil || len(list) == 0 {
		return nil
	}
	if err := os.MkdirAll(filepath.Dir(s.pinnedKeysPath()), 0o700); err != nil {
		return err
	}
	b, err := json.Marshal(map[string]json.RawMessage{"bundle_section_keys": keys})
	if err != nil {
		return err
	}
	return writeAtomic(s.pinnedKeysPath(), b)
}

// purgePolicy drops the pinned ring and last-known-good on sign-out: both are the old tenant's, and a bundle from the next tenant must not lose to the old one's seq.
func (s *Server) purgePolicy() error {
	for _, name := range []string{"keys.json", "lkg.cbor", "lkg.json"} {
		if err := os.Remove(filepath.Join(s.cfg.StateDir, "policy", name)); err != nil && !errors.Is(err, os.ErrNotExist) {
			return err
		}
	}
	return nil
}

func (s *Server) enrollmentPath() string { return filepath.Join(s.cfg.StateDir, "enrollment.json") }
func (s *Server) keyPath() string        { return filepath.Join(s.cfg.StateDir, "device.key") }

func (s *Server) readEnrollment() (*enrollmentDoc, error) {
	path := s.enrollmentPath()
	fi, err := os.Stat(path)
	if err != nil {
		return nil, err
	}
	if runtime.GOOS != "windows" && fi.Mode().Perm()&0o077 != 0 {
		return nil, fmt.Errorf("%s has mode %o; must be 0600 — refusing to read it", path, fi.Mode().Perm())
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var doc enrollmentDoc
	if err := json.Unmarshal(b, &doc); err != nil {
		return nil, fmt.Errorf("%s is corrupt: %w", path, err)
	}
	return &doc, nil
}

// liveState is cli.Enrollment.LiveState: a stamped revoked is terminal, and past token_expires_at the document alone never claims active.
func (d *enrollmentDoc) liveState() string {
	switch {
	case d.State == "revoked":
		return "revoked"
	case !time.Now().Before(d.TokenExpiresAt):
		return "expired"
	}
	return d.State
}

// otherTenantLive refuses a silent tenant switch: a live enrollment is released by DELETE /v1/enroll, never overwritten.
func (s *Server) otherTenantLive(w http.ResponseWriter, tenant string) bool {
	cur, err := s.readEnrollment()
	if err != nil || cur.liveState() != "active" || tenant == "" || cur.TenantID == tenant {
		return false
	}
	refuse(w, http.StatusConflict, "M1E-2001", "device is enrolled with tenant "+cur.TenantID+"; DELETE /v1/enroll first")
	return true
}

func (s *Server) notifyEnrolled() {
	s.mu.Lock()
	fn := s.enrolled
	s.mu.Unlock()
	if fn != nil {
		fn()
	}
}

type keygenBody struct {
	TenantID string `json:"tenant_id"`
}

// keygen mints (or re-reads) <state>/device.key through identity's generator — O_EXCL, 0600, the 32-byte seed `mark1 enroll` and receipt.OpenKey read — and returns only the public half.
func (s *Server) keygen(w http.ResponseWriter, r *http.Request) {
	var body keygenBody
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxBody))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&body); err != nil && !errors.Is(err, io.EOF) {
		refuse(w, http.StatusBadRequest, "M1E-2001", "body: "+err.Error())
		return
	}
	s.files.Lock()
	defer s.files.Unlock()
	if s.otherTenantLive(w, body.TenantID) {
		return
	}
	k, err := identity.NewDeviceKey(identity.FileCustody{Path: s.keyPath()})
	if err != nil {
		internal(w, err)
		return
	}
	pub := k.(interface{ Public() ed25519.PublicKey }).Public()
	writeJSON(w, map[string]any{"device_pubkey": "ed25519:" + base64.StdEncoding.EncodeToString(pub), "key_id": k.KeyID()})
}

// tokenClaims reads the device token's claims (controld auth.devClaims, second-to-last dot segment) without verifying them: the daemon holds no server key, so this binds the body to this device, it does not authenticate it.
func tokenClaims(tok string) (tenantID, deviceID, keyID string, ok bool) {
	parts := strings.Split(tok, ".")
	if len(parts) < 3 {
		return "", "", "", false
	}
	raw, err := base64.RawURLEncoding.DecodeString(parts[len(parts)-2])
	if err != nil {
		return "", "", "", false
	}
	var c struct {
		TenantID string `json:"tenant_id"`
		DeviceID string `json:"device_id"`
		KeyID    string `json:"key_id"`
	}
	if json.Unmarshal(raw, &c) != nil {
		return "", "", "", false
	}
	return c.TenantID, c.DeviceID, c.KeyID, true
}

// serverOf recovers the control-plane base the CLI stores as `server`: controld builds ingest as base + "/m1p/v1/ingest".
func serverOf(ingest string) string {
	if base, ok := strings.CutSuffix(ingest, "/m1p/v1/ingest"); ok {
		return base
	}
	u, err := url.Parse(ingest)
	if err != nil || u.Scheme == "" || u.Host == "" {
		return ""
	}
	return u.Scheme + "://" + u.Host
}

// postEnroll persists the ACTIVE body exactly as `mark1 enroll` does (08 §7.1), once it names this daemon's key.
func (s *Server) postEnroll(w http.ResponseWriter, r *http.Request) {
	var body activeBody
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxBody)).Decode(&body); err != nil {
		refuse(w, http.StatusBadRequest, "M1E-2001", "body: "+err.Error())
		return
	}
	if body.Status != "active" || body.DeviceToken == "" || body.ExpiresIn <= 0 {
		refuse(w, http.StatusBadRequest, "M1E-2001", "an ACTIVE enrollment body carries status=active, device_token and a positive expires_in")
		return
	}
	if _, err := uuid.Parse(body.TenantID); err != nil {
		refuse(w, http.StatusBadRequest, "M1E-2001", "tenant_id must be a UUID")
		return
	}
	if _, err := uuid.Parse(body.DeviceID); err != nil {
		refuse(w, http.StatusBadRequest, "M1E-2001", "device_id must be a UUID")
		return
	}
	key, err := receipt.OpenKey(s.keyPath())
	if errors.Is(err, identity.ErrNoKey) {
		refuse(w, http.StatusConflict, "M1E-2001", "no device key; POST /v1/enroll/keygen first")
		return
	}
	if err != nil {
		internal(w, err)
		return
	}
	tid, did, kid, ok := tokenClaims(body.DeviceToken)
	if !ok || kid != key.KeyID() || tid != body.TenantID || did != body.DeviceID {
		refuse(w, http.StatusConflict, "M1E-2001", "enrollment names another device: the token's key_id/device_id/tenant_id must match this daemon's key and the body")
		return
	}
	s.files.Lock()
	defer s.files.Unlock()
	if s.otherTenantLive(w, body.TenantID) {
		return
	}
	ts := time.Now().UTC()
	doc := enrollmentDoc{
		Version: 1, State: "active", DeviceID: body.DeviceID, TenantID: body.TenantID, DeviceToken: body.DeviceToken,
		TokenExpiresAt: ts.Add(time.Duration(body.ExpiresIn) * time.Second), TenantRootHex: body.TenantRootHex,
		Server: serverOf(body.Endpoints.Ingest), Channel: "stable", ServerMinEdge: body.ServerMinEdge,
		KeyManifestURI: body.KeyManifestURI, Endpoints: body.Endpoints, EnrolledAt: ts,
	}
	b, err := json.MarshalIndent(doc, "", "  ")
	if err == nil {
		err = writeAtomic(s.enrollmentPath(), b)
	}
	if err == nil {
		err = s.pinKeys(body.BundleSectionKeys)
	}
	if err != nil {
		internal(w, err)
		return
	}
	s.notifyEnrolled()
	writeJSON(w, map[string]any{"tenant_id": doc.TenantID, "device_id": doc.DeviceID, "enrolled_at": ts.Format(time.RFC3339)})
}

func (s *Server) getEnroll(w http.ResponseWriter, _ *http.Request) {
	out := map[string]any{"enrolled": false}
	if key, err := receipt.OpenKey(s.keyPath()); err == nil {
		out["key_id"] = key.KeyID()
	}
	doc, err := s.readEnrollment()
	switch {
	case errors.Is(err, os.ErrNotExist):
	case err != nil:
		internal(w, err)
		return
	default:
		state := doc.liveState()
		out["enrolled"], out["state"], out["tenant_id"], out["device_id"] = state == "active", state, doc.TenantID, doc.DeviceID
		out["expires_at"] = doc.TokenExpiresAt.UTC().Format(time.RFC3339)
	}
	writeJSON(w, out)
}

// deleteEnroll is the device sign-out: the document goes, the key stays (its receipts stay attributable), and the window is journalled exactly as `mark1 off` is (08 §7.6 step 4).
func (s *Server) deleteEnroll(w http.ResponseWriter, r *http.Request) {
	s.files.Lock()
	defer s.files.Unlock()
	err := os.Remove(s.enrollmentPath())
	switch {
	case errors.Is(err, os.ErrNotExist):
	case err != nil:
		internal(w, err)
		return
	default:
		if err := appendJSONL(coverage.JournalPath(s.cfg.StateDir), map[string]any{"ts": now(), "kind": "disable", "reason": coverage.ReasonMark1Off, "scope": "all"}); err != nil {
			internal(w, err)
			return
		}
		if err := s.purgePolicy(); err != nil {
			internal(w, err)
			return
		}
		s.notifyEnrolled()
	}
	s.getEnroll(w, r)
}
