// Package enroll drives 08 §3.1's OIDC device-code flow from the CLI side
// (08 §7.1): generate the device Ed25519 key, start, print user_code + URI,
// poll at the server's `interval`, persist the enrollment document 0600.
package enroll

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"runtime"
	"time"

	"github.com/Omium-ai/omium-mark1/go/mark1/internal/cli"
)

type Options struct {
	Tenant  string
	Channel string // stable|canary, default stable
}

type startResponse struct {
	DeviceCode      string `json:"device_code"`
	UserCode        string `json:"user_code"`
	VerificationURI string `json:"verification_uri"`
	ExpiresIn       int    `json:"expires_in"`
	Interval        int    `json:"interval"`
}

type pollResponse struct {
	Status        string `json:"status"`
	DeviceID      string `json:"device_id"`
	TenantID      string `json:"tenant_id"`
	DeviceToken   string `json:"device_token"`
	ExpiresIn     int    `json:"expires_in"`
	ServerMinEdge string `json:"server_min_edge"`
	Endpoints     struct {
		Ingest       string `json:"ingest"`
		Attach       string `json:"attach"`
		PolicyStream string `json:"policy_stream"`
	} `json:"endpoints"`
	KeyManifestURI string `json:"key_manifest_uri"`
}

// Result is §7.1's --json shape.
type Result struct {
	OK        bool   `json:"ok"`
	DeviceID  string `json:"device_id"`
	TenantID  string `json:"tenant_id"`
	State     string `json:"state"`
	ExpiresIn int    `json:"expires_in"`
}

func Run(ctx context.Context, env *cli.Env, opts Options) error {
	if opts.Channel == "" {
		opts.Channel = "stable"
	}
	if opts.Channel != "stable" && opts.Channel != "canary" {
		return cli.Failf(cli.ExitUsage, "", "--channel must be stable or canary, got %q", opts.Channel)
	}

	// §7.1 idempotence: an already-ACTIVE device re-prints its identity and
	// exits 0 — re-enrolling would orphan the receipt chain the existing
	// device key signed. ACTIVE is checked, never assumed: a doc whose token
	// passed its stored expiry, or one a device-token call stamped REVOKED
	// (cli.NoteAuthRefusal on the server's 401/M1E-1003), surfaces that state
	// and falls through to a FRESH enrollment with a NEW key below — the old
	// path treated any doc on disk as live, which made revocation unrecoverable
	// and key rotation impossible from this side.
	priorState := ""
	if doc, err := env.LoadEnrollment(); err == nil {
		if state := doc.LiveState(time.Now()); state == cli.StateActive {
			return env.Emit(Result{OK: true, DeviceID: doc.DeviceID, TenantID: doc.TenantID,
				State: state, ExpiresIn: int(time.Until(doc.TokenExpiresAt).Seconds())},
				func(w io.Writer) {
					fmt.Fprintf(w, "already enrolled: device %s (tenant %s, state %s)\n", doc.DeviceID, doc.TenantID, state)
				})
		} else {
			priorState = state
		}
	} else if !errors.Is(err, cli.ErrNotEnrolled) {
		return cli.Failf(cli.ExitRuntime, "", "reading enrollment: %v", err)
	}

	// The server locates the tenant row (its RLS routing key) from the start
	// body's `tenant` field — additive to 08 §3.1's documented shape, required
	// by controld's handleStart (M1E-2001 without it). Refusing locally beats a
	// guaranteed 400 after a network round-trip; checked after the idempotence
	// branch so a bare re-run on an enrolled device still exits 0 (§7.1).
	if opts.Tenant == "" {
		if priorState != "" {
			return cli.Failf(cli.ExitUsage, "", "previous enrollment is %s — a fresh enrollment requires --tenant <tenant-uuid> (08 §7.1)", priorState)
		}
		return cli.Failf(cli.ExitUsage, "", "--tenant is required (the tenant UUID from your Omium onboarding)")
	}

	// A revoked/expired prior identity re-enrolls under a freshly MINTED key:
	// re-presenting the dead identity's key would just re-earn the refusal.
	// Safe by m1_001's design — "a revoked device must keep existing so its
	// historical receipts stay attributable" (m1_devices' revocation-is-columns
	// comment) and m1_device_keys never deletes or overwrites a key row — so
	// the old identity's receipts verify forever; only this machine's signing
	// future changes.
	var pub ed25519.PublicKey
	var err error
	if priorState != "" {
		if !env.Quiet && !env.JSON {
			fmt.Fprintf(env.Stdout, "previous enrollment is %s — re-enrolling with a new device key\n", priorState)
		}
		pub, err = rotateDeviceKey(env)
	} else {
		pub, err = loadOrCreateDeviceKey(env)
	}
	if err != nil {
		return cli.Failf(cli.ExitRuntime, "", "device key: %v", err)
	}

	hostname, _ := os.Hostname()
	start, err := postJSON[startResponse](ctx, env, "/api/v1/enroll/device/start", map[string]any{
		"client":         "mark1-cli",
		"client_version": env.Version,
		"device_pubkey":  "ed25519:" + base64.StdEncoding.EncodeToString(pub),
		"platform":       runtime.GOOS + "-" + runtime.GOARCH,
		// tenant: the routing key controld resolves the tenant IdP with —
		// additive to §3.1's body (see the server's contract note in
		// controld/internal/enroll/handlers.go).
		"tenant": opts.Tenant,
		// hostname_hash: HMAC-SHA256 keyed by the tenant UUID string —
		// m1_001's column promises a "per-tenant HMAC of the hostname, never
		// the hostname", and per-tenant keying is what blocks cross-tenant
		// correlation of one machine. The previous key (the device pubkey)
		// travelled in this same request, so anyone holding the row could
		// invert the pseudonym by brute-forcing hostnames — a keyed hash
		// whose key rides alongside is just a hash. The "hmac-sha256:" prefix
		// is the one controld's parseHostnameHash strips — any other prefix
		// fails to decode server-side and 400s the whole flow.
		// ponytail: the post-enrollment per-tenant salt (04 §2.9, delivered
		// into identity custody) is the upgrade; the tenant UUID is the
		// enrollment-time floor — low-entropy as a secret, but per-tenant,
		// which is the property the column claims.
		"hostname_hash": "hmac-sha256:" + hmacHex([]byte(opts.Tenant), hostname),
	})
	if err != nil {
		return err
	}

	if !env.Quiet && !env.JSON {
		fmt.Fprintf(env.Stdout, "To enroll this device, visit:\n\n    %s\n\nand enter code: %s\n\n", start.VerificationURI, start.UserCode)
		fmt.Fprintf(env.Stdout, "Waiting for approval (expires in %ds)...\n", start.ExpiresIn)
	}

	poll, err := pollUntilActive(ctx, env, start)
	if err != nil {
		return err
	}

	doc := &cli.Enrollment{
		Version:        1,
		State:          cli.StateActive,
		DeviceID:       poll.DeviceID,
		TenantID:       poll.TenantID,
		DeviceToken:    poll.DeviceToken,
		TokenExpiresAt: time.Now().Add(time.Duration(poll.ExpiresIn) * time.Second),
		Server:         env.BaseURL(),
		Channel:        opts.Channel,
		ServerMinEdge:  poll.ServerMinEdge,
		KeyManifestURI: poll.KeyManifestURI,
		EnrolledAt:     time.Now().UTC(),
	}
	doc.Endpoints.Ingest = poll.Endpoints.Ingest
	doc.Endpoints.Attach = poll.Endpoints.Attach
	doc.Endpoints.PolicyStream = poll.Endpoints.PolicyStream
	if err := env.SaveEnrollment(doc); err != nil {
		return cli.Failf(cli.ExitRuntime, "", "persisting enrollment: %v", err)
	}

	return env.Emit(Result{OK: true, DeviceID: poll.DeviceID, TenantID: poll.TenantID,
		State: cli.StateActive, ExpiresIn: poll.ExpiresIn},
		func(w io.Writer) {
			fmt.Fprintf(w, "enrolled: device %s (tenant %s)\n", poll.DeviceID, poll.TenantID)
		})
}

// pollUntilActive honors §3.1's cadence contract exactly: poll at
// `interval`, 202 keeps polling, 429 (M1E-9001, "poll faster than interval")
// backs off one extra interval rather than hammering.
func pollUntilActive(ctx context.Context, env *cli.Env, start *startResponse) (*pollResponse, error) {
	interval := time.Duration(start.Interval) * time.Second
	deadline := time.Now().Add(time.Duration(start.ExpiresIn) * time.Second)
	for {
		if time.Now().After(deadline) {
			// Local expiry mirrors the server's M1E-1004: state EXPIRED is
			// terminal, the flow restarts from `start` (§3.1).
			return nil, cli.Failf(cli.ExitRefused, "M1E-1004", "device code expired before approval — rerun `mark1 enroll`")
		}
		resp, status, err := postRaw(ctx, env, "/api/v1/enroll/device/poll",
			map[string]any{"device_code": start.DeviceCode})
		if err != nil {
			return nil, cli.Failf(cli.ExitRuntime, "", "polling enrollment: %v", err)
		}
		switch status {
		case http.StatusOK:
			var pr pollResponse
			if err := json.Unmarshal(resp, &pr); err != nil {
				return nil, cli.Failf(cli.ExitRuntime, "", "malformed poll response: %v", err)
			}
			if pr.Status != "active" {
				return nil, cli.Failf(cli.ExitRuntime, "", "unexpected poll status %q", pr.Status)
			}
			return &pr, nil
		case http.StatusAccepted: // pending — keep polling at `interval`
		case http.StatusBadRequest:
			return nil, cli.Failf(cli.ExitRefused, "M1E-1004", "device code unknown or expired — rerun `mark1 enroll`")
		case http.StatusForbidden:
			return nil, cli.Failf(cli.ExitNotEnrolled, "M1E-1005", "enrollment denied at the identity provider")
		case http.StatusTooManyRequests:
			select {
			case <-ctx.Done():
				return nil, cli.Failf(cli.ExitRuntime, "", "cancelled: %v", ctx.Err())
			case <-time.After(interval):
			}
		default:
			return nil, cli.Failf(cli.ExitRuntime, "", "poll returned HTTP %d", status)
		}
		select {
		case <-ctx.Done():
			return nil, cli.Failf(cli.ExitRuntime, "", "cancelled: %v", ctx.Err())
		case <-time.After(interval):
		}
	}
}

// loadOrCreateDeviceKey is the custody floor of 04 §2.9 (0600 file under the
// state dir, created O_EXCL exactly once — overwriting would orphan every
// receipt the old key signed), byte-compatible with mark1d's
// identity.FileCustody so the daemon adopts the same key at its enroll row.
// ponytail: keychain/TPM rungs (go-keyring is pinned for them) ride the
// same seam later; the floor is never skipped-below, so it ships first.
func loadOrCreateDeviceKey(env *cli.Env) (ed25519.PublicKey, error) {
	path := env.DeviceKeyPath()
	if fi, err := os.Stat(path); err == nil {
		if runtime.GOOS != "windows" && fi.Mode().Perm()&0o077 != 0 {
			return nil, fmt.Errorf("%s has mode %o; a device key must be 0600 — refusing to use it", path, fi.Mode().Perm())
		}
		seed, err := os.ReadFile(path)
		if err != nil {
			return nil, err
		}
		if len(seed) != ed25519.SeedSize {
			return nil, fmt.Errorf("%s holds %d bytes, expected a %d-byte ed25519 seed", path, len(seed), ed25519.SeedSize)
		}
		return ed25519.NewKeyFromSeed(seed).Public().(ed25519.PublicKey), nil
	}
	seed := make([]byte, ed25519.SeedSize)
	if _, err := rand.Read(seed); err != nil {
		return nil, err
	}
	if err := os.MkdirAll(env.StateDir, 0o700); err != nil {
		return nil, err
	}
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return nil, err
	}
	if _, err := f.Write(seed); err != nil {
		f.Close()
		return nil, err
	}
	if err := f.Close(); err != nil {
		return nil, err
	}
	return ed25519.NewKeyFromSeed(seed).Public().(ed25519.PublicKey), nil
}

// rotateDeviceKey mints a NEW seed for a fresh enrollment over a dead
// identity (revoked/expired): O_EXCL temp + atomic swap via WriteFileAtomic
// (CreateTemp is O_CREATE|O_EXCL; fsync-then-rename), so no crash window
// leaves a truncated or loose-mode key file, and readers of the path only
// ever see the old complete key or the new complete key. The old key is
// dropped locally on purpose — its receipts stay verifiable server-side
// because m1_device_keys "never deletes or overwrites" (m1_001 §5) and the
// revoked device row keeps existing so those receipts stay attributable
// (m1_001 m1_devices' revocation-is-columns comment).
func rotateDeviceKey(env *cli.Env) (ed25519.PublicKey, error) {
	seed := make([]byte, ed25519.SeedSize)
	if _, err := rand.Read(seed); err != nil {
		return nil, err
	}
	if err := cli.WriteFileAtomic(env.DeviceKeyPath(), seed, 0o600); err != nil {
		return nil, err
	}
	return ed25519.NewKeyFromSeed(seed).Public().(ed25519.PublicKey), nil
}

func hmacHex(key []byte, msg string) string {
	m := hmac.New(sha256.New, key)
	m.Write([]byte(msg))
	return hex.EncodeToString(m.Sum(nil))
}

func postRaw(ctx context.Context, env *cli.Env, path string, body any) ([]byte, int, error) {
	data, err := json.Marshal(body)
	if err != nil {
		return nil, 0, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, env.BaseURL()+path, bytes.NewReader(data))
	if err != nil {
		return nil, 0, err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := env.Client().Do(req)
	if err != nil {
		return nil, 0, err
	}
	defer resp.Body.Close()
	respBody, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, 0, err
	}
	return respBody, resp.StatusCode, nil
}

func postJSON[T any](ctx context.Context, env *cli.Env, path string, body any) (*T, error) {
	respBody, status, err := postRaw(ctx, env, path, body)
	if err != nil {
		return nil, cli.Failf(cli.ExitRuntime, "", "%s: %v", path, err)
	}
	if status != http.StatusOK {
		var apiErr struct {
			Error struct {
				Code    string `json:"code"`
				Message string `json:"message"`
			} `json:"error"`
		}
		if json.Unmarshal(respBody, &apiErr) == nil && apiErr.Error.Code != "" {
			return nil, cli.Failf(cli.ExitRuntime, apiErr.Error.Code, "%s: %s", path, apiErr.Error.Message)
		}
		return nil, cli.Failf(cli.ExitRuntime, "", "%s returned HTTP %d", path, status)
	}
	var out T
	if err := json.Unmarshal(respBody, &out); err != nil {
		return nil, cli.Failf(cli.ExitRuntime, "", "%s: malformed response: %v", path, err)
	}
	return &out, nil
}
