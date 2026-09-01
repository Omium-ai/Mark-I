package enroll_test

// FR-ENROLL-002's ingest half, driven through the REAL route.
//
// The lifetime ceiling already had two proofs, and neither is this one:
// auth.TestTokenLifetimeCeiling asserts the MINTER refuses >24 h, and
// auth.TestExpiredTokenRejected asserts auth.Verify refuses an aged token in
// isolation. Both stop at the package boundary. The requirement is written
// about the wire ("Token older than 24 h rejected at ingest", 02 §12
// FR-ENROLL-002), and between Verify and the wire sit server.Chain's error
// mapping and ingest's handler order — a ceiling that held inside auth but
// whose verdict reached the socket as a 403, a 500 or a 200 would satisfy
// every existing test while breaking the edge's park-vs-quarantine decision
// (08 §2.4: 401 parks and keeps spooling, 403 quarantines).
//
// The tokens are hand-signed rather than minted: auth.Signer.Mint REFUSES to
// issue past the ceiling (token.go:65), so the only way to present an
// over-ceiling token to the route is to sign one the way a minting bug or a
// stolen signing key would. mintRaw is therefore itself under test — the two
// inside-ceiling cases prove the hand-rolled wire form is the one the
// production verifier accepts, so a red aged case is the clock talking and not
// a malformed token.
//
// It lives in the enroll package because enroll is the only minter (05 §3.1
// issues the first token, §3.3 the rest): the ceiling is enrollment's promise
// and ingest is merely where it is collected.

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/Omium-ai/omium-mark1/go/controld/internal/auth"
	"github.com/Omium-ai/omium-mark1/go/controld/internal/ingest"
	"github.com/Omium-ai/omium-mark1/go/controld/internal/obs"
)

// tokenSeed is the server signing seed; auth.NewSigner and
// ed25519.NewKeyFromSeed must agree on it, which the test asserts rather than
// assumes — a derivation change would otherwise turn every case 401 and read
// as a ceiling that got stricter.
var tokenSeed = []byte("enroll-ingest-ceiling-seed-32b!!")

// mintRaw writes auth's v1 device-token wire form (token.go: prefix + payload
// signed together, then the signature appended) with caller-chosen iat/exp —
// the one thing Signer.Mint will not do.
func mintRaw(t *testing.T, priv ed25519.PrivateKey, tenant, device uuid.UUID, iat, exp time.Time) string {
	t.Helper()
	payload, err := json.Marshal(map[string]any{
		"tenant_id": tenant.String(), "device_id": device.String(),
		"key_id": "ed25519:0011223344556677", "iat": iat.Unix(), "exp": exp.Unix(),
	})
	if err != nil {
		t.Fatal(err)
	}
	signed := "m1tok.v1." + base64.RawURLEncoding.EncodeToString(payload)
	sig := ed25519.Sign(priv, []byte(signed))
	return signed + "." + base64.RawURLEncoding.EncodeToString(sig)
}

// ingestRoute mounts the production ingest handler behind the production
// middleware chain and the production Ed25519 verifier. Store/PG/projector are
// nil on purpose: every case here is decided in stage 1 or stage 2, so a nil
// dependency reached would be a test that stopped measuring what it claims.
func ingestRoute(t *testing.T, pub ed25519.PublicKey) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()
	ingest.New(ingest.Deps{
		Verifier: auth.NewEd25519Verifier(pub, auth.StaticRevocations{}),
		ObsCfg:   obs.Config{ServiceName: "controld-test"},
	}).RegisterRoutes(mux)
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv
}

func TestOver24hTokenRejectedAtIngestRoute(t *testing.T) {
	signer, err := auth.NewSigner(tokenSeed)
	if err != nil {
		t.Fatal(err)
	}
	priv := ed25519.NewKeyFromSeed(tokenSeed)
	if !priv.Public().(ed25519.PublicKey).Equal(signer.Public()) {
		t.Fatal("auth.NewSigner no longer derives its key the way this test signs; re-derive mintRaw before trusting any result below")
	}
	srv := ingestRoute(t, signer.Public())
	tenant, device := uuid.New(), uuid.New()
	now := time.Now()

	cases := []struct {
		name       string
		iat, exp   time.Time
		wantStatus int
		wantCode   string
	}{
		// The control. Identical request bytes, identical signing key, a
		// lifetime inside the ceiling: whatever the aged cases return, it is
		// not "this route refuses everything". 415 is stage 1 refusing the
		// deliberately wrong Content-Type — only reachable AFTER stage 2
		// admitted the token.
		{"inside_ceiling_passes_auth", now, now.Add(23 * time.Hour), http.StatusUnsupportedMediaType, "M1E-2005"},
		// The boundary from the legal side: exactly 24 h is the ceiling, not
		// past it, so tightening the comparison to >= fails here.
		{"exactly_24h_passes_auth", now, now.Add(auth.TokenTTLCeiling), http.StatusUnsupportedMediaType, "M1E-2005"},
		// A token minted legally 25 h ago: the ordinary expiry every device
		// hits once a day. 401 M1E-1002 is the code the edge treats as
		// park-and-keep-spooling; 403 would quarantine customer data.
		{"aged_out_25h", now.Add(-25 * time.Hour), now.Add(-time.Hour), http.StatusUnauthorized, "M1E-1002"},
		// A 25-hour lifetime that has NOT yet expired — only a minting bug or
		// a compromised signer produces this, and it is exactly the case a
		// now>exp check alone waves through.
		{"over_ceiling_not_yet_expired", now, now.Add(25 * time.Hour), http.StatusUnauthorized, "M1E-1002"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			req, err := http.NewRequest(http.MethodPost, srv.URL+"/m1p/v1/ingest", strings.NewReader("{}"))
			if err != nil {
				t.Fatal(err)
			}
			req.Header.Set("Authorization", "Bearer "+mintRaw(t, priv, tenant, device, tc.iat, tc.exp))
			req.Header.Set("Content-Type", "application/json") // the stage-1 tripwire
			resp, err := http.DefaultClient.Do(req)
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = resp.Body.Close() }()
			var body struct {
				Error struct {
					Code string `json:"code"`
				} `json:"error"`
			}
			_ = json.NewDecoder(resp.Body).Decode(&body)
			if resp.StatusCode != tc.wantStatus || body.Error.Code != tc.wantCode {
				t.Fatalf("token iat=%v exp=%v: got %d %q, want %d %q",
					tc.iat.Sub(now), tc.exp.Sub(now), resp.StatusCode, body.Error.Code, tc.wantStatus, tc.wantCode)
			}
		})
	}
}
