package claudecode

// The base-URL fragment — 04 §3.1 step 6 and 10 §3.3's "fenced ANTHROPIC_BASE_URL
// fragment": the one thing in the product that puts mark1-proxy in an agent's
// path, plus the `M1-Cred-Ref` header the proxy's provenance guard admits on.
//
// Mechanism B into the same settings.json the hooks fragment fences, but under
// its own reserved key and its own §8.2 manifest, because the two are reverted
// independently and in opposite situations: `mark1 off` takes both out, and the
// CON-001 contamination rollback takes ONLY this one out — tearing out capture
// on a legal event would undo the wrong thing in the wrong direction.
//
// It is provisioned only for a detected API-key credential. That is the whole
// of CON-001's structural half: a subscription agent's config is never opened
// for write, so it has no route to the proxy to misconfigure.

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/Omium-ai/omium-mark1/go/mark1d/adapters"
)

const (
	// The hooks fragment shipped its checksum object as the bare
	// `_mark1_managed`, so the second fragment in the same file takes a
	// suffixed key rather than renaming one already on users' disks.
	baseURLManagedKey = "_mark1_managed_baseurl"
	baseURLFragment   = "baseurl"

	envKey     = "env"
	envBaseURL = "ANTHROPIC_BASE_URL"
	// Vendor-documented format for ANTHROPIC_CUSTOM_HEADERS is `Name: Value`,
	// newline-separated. The proxy strips M1-Cred-Ref before upstream (04 §3.1).
	envHeaders    = "ANTHROPIC_CUSTOM_HEADERS"
	credRefHeader = "M1-Cred-Ref" //nolint:gosec // G101 false positive: an HTTP header NAME, not a credential

	// One agent, one provisioned credential, so the ref-id is the agent name
	// rather than a minted id: re-provisioning replaces the registry line
	// instead of growing it. Guessing it buys an attacker nothing — the
	// constant-time fingerprint match and the OAuth-shape tripwire are the
	// gates that decide admission (04 §3.1 steps 3 and 5).
	credRefID = "claudecode"

	// 08 §9's 7xxx provisioning family, continuing after 7103/7104.
	CodeNotEligible = "M1E-7105"
	CodeEnvConflict = "M1E-7106"
)

var (
	// ErrNotEligible is the CON-001 boundary and the reason this fragment has
	// no force path. Every non-affirmative answer collapses into it — no key,
	// a subscription credential, a detection that errored, no proxy listening —
	// because on this path "I could not tell" and "no" must be the same answer.
	ErrNotEligible = errors.New(CodeNotEligible + ": not proxy-eligible; the base-URL fragment is provisioned only for a detected API-key credential (10 §3.3)")
	// ErrEnvConflict: the user already sets one of these variables themselves.
	// Merging into it would redirect traffic through a value we did not write,
	// and 08 §8.1 owns only the pointers it records.
	ErrEnvConflict = errors.New(CodeEnvConflict + ": the agent's settings already set this variable; Mark 1 will not overwrite a base URL or header set by the user (08 §8.1)")
)

// ProxyPortPath is where mark1-proxy publishes the port it actually bound
// (rust/mark1-proxy/src/main.rs, `write_port`). The sidecar binds :0, so this
// file is the ONLY source for the URL the fragment points at — and its absence
// means nothing is listening, which is a reason not to provision rather than a
// reason to guess.
func ProxyPortPath(stateDir string) string { return filepath.Join(stateDir, "proxy.port") }

const (
	// guardRefusalCode is 04 §3.1 step 2's frozen answer to a request carrying
	// no `M1-Cred-Ref` (08 §9).
	//
	// Taken from rust/mark1-proxy/src/router.rs:143-149 — `handle`'s
	// `Decision::Refused(_)` arm, which returns FORBIDDEN + "M1E-8001" for the
	// `Cause::CredentialAmbiguous` this probe deliberately produces (no header,
	// no credential; guard/provenance.rs decide()). The body shape is lib.rs:188 `error_body`.
	// Cited by line on purpose: if the proxy's refusal shape ever changes, this
	// gate must fail visibly at the next probe rather than start silently
	// refusing a live proxy, or silently accepting a squatter.
	guardRefusalCode = "M1E-8001"
	// probeTimeout bounds the identify call. It runs inside `mark1 enable` on
	// a loopback connection, so a second is already pathological; the budget
	// exists so a listener that accepts and then says nothing cannot hang the
	// CLI, and a timeout is a refusal like every other doubt on this path.
	probeTimeout = 2 * time.Second
	probeBodyCap = 4 << 10
)

func proxyURL(stateDir string) (string, error) {
	b, err := os.ReadFile(ProxyPortPath(stateDir))
	if err != nil {
		return "", err
	}
	port, err := strconv.Atoi(strings.TrimSpace(string(b)))
	if err != nil || port < 1 || port > 65535 {
		return "", fmt.Errorf("%s does not hold a port", ProxyPortPath(stateDir))
	}
	// Literal loopback, matching the listener's own SocketAddr: "localhost"
	// resolves through the host's name service and can be pointed elsewhere.
	url := "http://127.0.0.1:" + strconv.Itoa(port)
	if err := probeProxy(url); err != nil {
		return "", err
	}
	return url, nil
}

// probeProxy asks whatever holds the port to identify itself, before that port
// is written into the developer's agent settings.
//
// The failure it closes: `proxy.port` is written once, at bind, and the sidecar
// binds :0 — an OS ephemeral port. When the proxy dies, that port returns to
// the pool and any other local process can bind it. The file's PRESENCE then
// proves nothing at all, and the agent settings this function gates would hand
// that process the developer's `x-api-key` on the next request.
//
// WHAT THE PROBE ESTABLISHES: something is listening on that loopback port
// right now, it speaks HTTP, and it answers a credential-free GET with
// `403` and `M1E-8001` in the body — the guard's frozen refusal for a request
// with no `M1-Cred-Ref` (04 §3.1 step 2). A process that merely inherited the
// port answers a connection refusal, a different status, or nothing inside the
// budget, and each of those refuses.
//
// WHAT IT DOES NOT ESTABLISH: that the listener IS our mark1-proxy. Any process
// running as this user can imitate one 403. That is deliberately outside the
// gate rather than missing from it — the same user already reads `guard.key`
// and `registry` (both 0600, same directory), so a same-uid adversary has no
// need to squat a port. What is being excluded is the accidental case, which is
// what the exposure actually is: an unrelated local process handed a freed
// ephemeral port by the kernel.
//
// The probe carries no credential and no `M1-Cred-Ref`: it must never send the
// thing it exists to protect. Redirects are refused for the same reason the URL
// is a literal — a 302 from the squatter is not permission to go and ask
// somewhere else.
func probeProxy(url string) error {
	ctx, cancel := context.WithTimeout(context.Background(), probeTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url+"/", nil)
	if err != nil {
		return err
	}
	res, err := probeClient.Do(req)
	if err != nil {
		return fmt.Errorf("nothing answered at %s: %w", url, err)
	}
	defer func() { _ = res.Body.Close() }()
	body, _ := io.ReadAll(io.LimitReader(res.Body, probeBodyCap))
	if res.StatusCode != http.StatusForbidden || !bytes.Contains(body, []byte(guardRefusalCode)) {
		return fmt.Errorf("%s is held by something that is not a mark1-proxy guard: status %d, no %s", url, res.StatusCode, guardRefusalCode)
	}
	return nil
}

// probeClient never reuses a connection and never follows a redirect: this is
// one question asked once, and leaving a pooled connection open to a listener
// we have just decided not to trust has no upside.
var probeClient = &http.Client{
	CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	Transport: &http.Transport{
		DisableKeepAlives: true,
		Proxy:             nil, // HTTP_PROXY must not divert a loopback liveness check
		DialContext:       (&net.Dialer{Timeout: probeTimeout}).DialContext,
	},
}

// ApplyProxyPointer is the eligibility gate and the only sanctioned caller of
// ApplyBaseURL. It resolves the two facts the fragment cannot invent — is this
// an API-key credential, and is a proxy listening — and refuses without opening
// the settings file when either is missing or unreadable.
func (a *Adapter) ApplyProxyPointer() (ApplyResult, error) {
	d, err := a.Detect()
	switch {
	case err != nil:
		return ApplyResult{}, fmt.Errorf("%w: detection failed: %v", ErrNotEligible, err)
	case d.Regime != adapters.RegimeAPIKey:
		return ApplyResult{}, ErrNotEligible
	}
	cred := apiKeyCredential()
	if cred == "" {
		return ApplyResult{}, ErrNotEligible
	}
	target, state, err := a.paths()
	if err != nil {
		return ApplyResult{}, err
	}
	url, err := proxyURL(state)
	if err != nil {
		return ApplyResult{}, fmt.Errorf("%w: no proxy answered at the published port: %v", ErrNotEligible, err)
	}
	// Before the fragment, never after: a pointer naming a ref-id the guard
	// has no entry for is an agent that 403s on every request (04 §3.1 step 2).
	if err := provisionCredential(state, cred); err != nil {
		return ApplyResult{}, err
	}
	return ApplyBaseURL(target, state, url, credRefID)
}

// RevertProxyPointer detaches the agent from the proxy, leaving capture intact.
func (a *Adapter) RevertProxyPointer() (RevertResult, error) {
	_, state, err := a.paths()
	if err != nil {
		return RevertResult{}, err
	}
	return RevertBaseURL(state)
}

// ApplyBaseURL is 08 §8.3's apply over the `/env` pointers.
//
// It is not ApplyFragment with a parameter. The two fragments share the file,
// the mechanism and the manifest, not the pointer grammar: a hook entry is an
// object that carries a `_mark1` tag and slides index when the user inserts a
// handler above it, while an env var is a string at a fixed key that cannot
// carry a tag at all. Folding both into one generic would have to encode that
// difference anyway, in a place where getting it wrong is silent.
func ApplyBaseURL(settingsPath, stateDir, url, credRef string) (ApplyResult, error) {
	pre, err := os.ReadFile(settingsPath)
	if err != nil {
		if os.IsNotExist(err) {
			return ApplyResult{}, ErrNoTarget
		}
		return ApplyResult{}, err
	}
	root, env, err := openEnv(pre)
	if err != nil {
		return ApplyResult{}, err
	}

	want, err := desiredEnv(url, credRef)
	if err != nil {
		return ApplyResult{}, err
	}
	canonWant, err := canonical(want)
	if err != nil {
		return ApplyResult{}, err
	}
	desired := sum(canonWant)
	pointers := []string{"/" + envKey + "/" + envBaseURL, "/" + envKey + "/" + envHeaders}

	if raw, ok := root.get(baseURLManagedKey); ok {
		m, cur, cerr := currentEnvChecksum(raw, env)
		switch {
		case cerr != nil || cur != m.Checksum:
			// §8.3(d). No force path here, unlike the hooks fragment: repairing
			// this one means re-pointing an agent at the proxy, and that
			// decision belongs to a fresh eligibility check, not to a repair.
			return ApplyResult{}, ErrDamaged
		case m.Checksum == desired:
			return ApplyResult{Changed: false, Checksum: desired, Pointers: pointers}, nil
		}
	} else {
		for _, k := range []string{envBaseURL, envHeaders} {
			if _, exists := env.get(k); exists {
				return ApplyResult{}, fmt.Errorf("%w: /%s/%s", ErrEnvConflict, envKey, k)
			}
		}
	}

	preImage, preHash, err := priorPreImage(stateDir, baseURLFragment)
	if err != nil {
		return ApplyResult{}, err
	}

	env.set(envBaseURL, want[0])
	env.set(envHeaders, want[1])
	root.set(envKey, rawOrdered(env))
	mb, err := json.Marshal(managed{
		Version: 1, Agent: "claudecode", Fragment: baseURLFragment,
		Pointers: pointers, Checksum: desired,
	})
	if err != nil {
		return ApplyResult{}, err
	}
	root.set(baseURLManagedKey, mb)

	post, err := root.encode()
	if err != nil {
		return ApplyResult{}, err
	}
	// Manifest first, for §8.3's reason: revert keys off the manifest alone, so
	// the other order can strand a live proxy pointer nothing knows how to
	// remove — on this fragment that stranded state is a legal exposure.
	if err := writeManifest(settingsPath, stateDir, baseURLFragment, pre, post, desired, preImage, preHash); err != nil {
		return ApplyResult{}, err
	}
	if err := writeAtomic(settingsPath, post); err != nil {
		return ApplyResult{}, err
	}
	return ApplyResult{Changed: true, Checksum: desired, Pointers: pointers}, nil
}

// RevertBaseURL removes the proxy pointer. Unlike the hooks revert it has no
// verbatim path: this fragment shares its target with the hooks fragment, so
// restoring a whole-file pre_image would silently delete whichever fragment was
// applied after this one's snapshot was taken. Removal is always surgical, and
// byte-equality is then measured rather than assumed.
func RevertBaseURL(stateDir string) (RevertResult, error) {
	m, err := loadManifest(stateDir, baseURLFragment)
	if errors.Is(err, os.ErrNotExist) {
		return RevertResult{Kind: "not-provisioned", ByteEquality: true}, nil
	}
	if err != nil {
		return RevertResult{}, err
	}
	res := RevertResult{Target: m.TargetPath}

	cur, rerr := os.ReadFile(m.TargetPath)
	switch {
	case os.IsNotExist(rerr):
		res.Kind, res.ByteEquality = "target-absent", true
	case rerr != nil:
		return res, rerr
	default:
		eq, standing, err := surgicalBaseURL(m, cur)
		if err != nil {
			return res, err
		}
		res.ByteEquality, res.Retained = eq, standing
		res.Kind = "surgical"
		if len(standing) > 0 {
			res.Kind = "fragment-damaged"
		}
	}

	// Deleted last, so an interrupted revert is re-runnable (§8.4 step 4) — and
	// NOT AT ALL while a pointer of ours is still set. The manifest is the only
	// thing that makes this fragment findable: `mark1 off` globs for it, and
	// `doctor` reads it to classify. Removing it beside a live
	// ANTHROPIC_BASE_URL does not end the exposure, it ends our ability to see
	// it — every later run reports `not-provisioned` at a machine that is still
	// pointing an agent's API key at a loopback port (D-CR).
	if len(res.Retained) > 0 {
		return res, nil
	}
	if err := os.Remove(manifestPath(stateDir, baseURLFragment)); err != nil && !os.IsNotExist(err) {
		return res, err
	}
	return res, nil
}

// surgicalBaseURL deletes our two env keys and our checksum object, and reports
// whether the result is byte-identical to the file as it stood before this
// fragment was applied.
//
// It removes all of our block or none of it, and the all-or-nothing is the
// control (D-CR). The recorded checksum covers both pointers jointly, so once
// it stops matching we cannot say WHICH of the two the user took ownership of —
// and revert.go's rule for that state is already written: what we cannot verify
// is FRAGMENT-DAMAGED, and the only safe reading of "I cannot tell what is in
// there" is the one that refuses to write.
//
// The previous shape deleted our checksum object on that path anyway and kept
// the env keys. That is backwards. `ANTHROPIC_CUSTOM_HEADERS` still held the
// `M1-Cred-Ref` line we wrote, and the object being deleted was the one record
// in the file saying so — erasing our bookkeeping while leaving our footprint
// is how a pointer becomes unattributable. RevertBaseURL then deleted the
// manifest too, and `mark1 off` reported a completed surgical revert.
func surgicalBaseURL(m Manifest, cur []byte) (bool, []string, error) {
	root, env, err := openEnv(cur)
	if err != nil {
		return false, nil, err
	}
	var mg managed
	raw, hasManaged := root.get(baseURLManagedKey)
	if hasManaged {
		if err := json.Unmarshal(raw, &mg); err != nil {
			return false, nil, err
		}
	}
	found, ferr := resolveEnv(env, mg.Pointers)
	ours := false
	if hasManaged && ferr == nil {
		if canonFound, cerr := canonical(found); cerr == nil {
			ours = sum(canonFound) == mg.Checksum
		}
	}
	if !ours {
		// Not "give up": report exactly what of ours is still set, so the
		// caller can refuse to claim a clean revert and keep the manifest that
		// makes it findable. An empty list is the honest success — the user
		// took our block out by hand and there is nothing left to remove.
		if standing := standingPointers(env); len(standing) > 0 {
			return false, standing, nil
		}
		pre, perr := RestorePreImage(m)
		return perr == nil && bytes.Equal(cur, pre), nil, nil
	}

	root.del(baseURLManagedKey)
	for _, k := range []string{envBaseURL, envHeaders} {
		env.del(k)
	}
	// The `env` key survives only if the user had one. Keeping an object we
	// created leaves our footprint behind; deleting one they wrote breaks the
	// rule we do not touch what we do not own — and the pre-image is the only
	// thing that knows which this is.
	if len(env.keys) == 0 && !preHadEnv(m) {
		root.del(envKey)
	} else {
		root.set(envKey, rawOrdered(env))
	}
	post, err := root.encode()
	if err != nil {
		return false, nil, err
	}
	if err := writeAtomic(m.TargetPath, post); err != nil {
		return false, nil, err
	}
	pre, perr := RestorePreImage(m)
	return perr == nil && bytes.Equal(post, pre), nil, nil
}

// standingPointers names the fragment's own variables that are still set. It
// walks the two constants rather than manifest.pointers, so a manifest whose
// pointer list was itself truncated cannot shrink the answer.
func standingPointers(env *object) []string {
	var out []string
	for _, k := range []string{envBaseURL, envHeaders} {
		if _, ok := env.get(k); ok {
			out = append(out, "/"+envKey+"/"+k)
		}
	}
	return out
}

// BaseURLManifestPath is this fragment's §8.2 record, exported for the same
// reason ManifestPath is: `mark1 doctor` has to know which of the manifests it
// globs are ones this build can speak for.
func BaseURLManifestPath(stateDir string) string { return manifestPath(stateDir, baseURLFragment) }

// InspectBaseURL is Inspect for this fragment: classify, never write.
//
// It exists because doctor could not classify what apply wrote. Doctor globs
// `provisioned/*/*.manifest.json` and, finding no inspector that claimed this
// manifest, reported FRAGMENT-DAMAGED with "no adapter in this build can
// classify or revert this fragment" — false on both halves, and a non-zero
// `mark1 doctor` for every user whose `mark1 enable` found an API key (D-CM).
//
// The state worth having a second inspector for is the one D-CR opened:
// `_mark1_managed_baseurl` deleted while ANTHROPIC_BASE_URL is still set is not
// absence, it is a live proxy pointer nothing owns, and it is exactly why
// RevertBaseURL leaves the manifest behind rather than deleting it. MISSING
// there would report that the exposure ended.
func InspectBaseURL(stateDir string) (Status, error) {
	st := Status{Agent: "claudecode", Fragment: baseURLFragment, Mechanism: "B",
		Manifest: BaseURLManifestPath(stateDir), State: StateMissing}
	m, err := loadManifest(stateDir, baseURLFragment)
	if errors.Is(err, os.ErrNotExist) {
		st.Detail = "not provisioned"
		return st, nil
	}
	if err != nil {
		return st, err
	}
	st.Target = m.TargetPath

	cur, err := os.ReadFile(m.TargetPath)
	if os.IsNotExist(err) {
		st.Detail = "target file no longer exists"
		return st, nil
	}
	if err != nil {
		return st, err
	}
	root, env, err := openEnv(cur)
	if err != nil {
		st.State, st.Detail = StateDamaged, err.Error()
		return st, nil
	}

	if raw, ok := root.get(baseURLManagedKey); ok {
		mg, curSum, cerr := currentEnvChecksum(raw, env)
		st.Lines = envLines(env, mg.Pointers)
		switch {
		case cerr != nil || curSum != mg.Checksum:
			st.State = StateDamaged
			st.Detail = CodeDamaged + ": values at the recorded pointers no longer match their checksum"
			if len(st.Lines) == 0 {
				st.Lines = envLines(env, standingPointers(env))
			}
		case sum(cur) == m.PostImageHash:
			st.State = StateOK
		default:
			// The ordinary two-fragment install reaches this: the hooks fragment
			// was applied into the same file after this one, so the post-image is
			// stale by design. Our own bytes are verified intact by the checksum
			// above, which is what USER-EDITED means and why doctor passes it.
			st.State = StateUserEdited
			st.Detail = "fragment intact; the rest of the file changed since apply"
		}
		return st, nil
	}

	if standing := standingPointers(env); len(standing) > 0 {
		st.State, st.Lines = StateDamaged, envLines(env, standing)
		st.Detail = CodeDamaged + ": " + baseURLManagedKey + " was removed but " +
			strings.Join(standing, ", ") + " is still set — the agent is still pointed at the proxy"
		return st, nil
	}
	st.Detail = "fragment absent from the target"
	return st, nil
}

// envLines is linesAt for the `/env/<VAR>` grammar. A pointer that no longer
// resolves yields no lines rather than a fabricated one.
func envLines(env *object, pointers []string) []Line {
	vals, err := resolveEnv(env, pointers)
	if err != nil {
		return nil
	}
	out := make([]Line, 0, len(pointers))
	for i, p := range pointers {
		out = append(out, Line{Pointer: p, Value: string(vals[i])})
	}
	return out
}

func preHadEnv(m Manifest) bool {
	pre, err := RestorePreImage(m)
	if err != nil {
		return false
	}
	root, err := decodeObject(pre)
	if err != nil {
		return false
	}
	_, ok := root.get(envKey)
	return ok
}

func desiredEnv(url, credRef string) ([]json.RawMessage, error) {
	base, err := json.Marshal(url)
	if err != nil {
		return nil, err
	}
	hdr, err := json.Marshal(credRefHeader + ": " + credRef)
	if err != nil {
		return nil, err
	}
	return []json.RawMessage{base, hdr}, nil
}

// openEnv decodes the settings root and its `env` object, mirroring openTarget.
func openEnv(b []byte) (root, env *object, err error) {
	root, err = decodeObject(b)
	if err != nil {
		return nil, nil, err
	}
	raw, ok := root.get(envKey)
	if !ok || len(raw) == 0 {
		raw = json.RawMessage("{}")
	}
	env, err = decodeObject(raw)
	if err != nil {
		return nil, nil, err
	}
	return root, env, nil
}

func currentEnvChecksum(raw json.RawMessage, env *object) (managed, string, error) {
	var m managed
	if err := json.Unmarshal(raw, &m); err != nil {
		return m, "", err
	}
	found, err := resolveEnv(env, m.Pointers)
	if err != nil {
		return m, "", err
	}
	canonFound, err := canonical(found)
	if err != nil {
		return m, "", err
	}
	return m, sum(canonFound), nil
}

// resolveEnv reads the values a recorded pointer set points at. Only the
// `/env/<VAR>` shape this fragment records is understood.
func resolveEnv(env *object, pointers []string) ([]json.RawMessage, error) {
	out := make([]json.RawMessage, 0, len(pointers))
	for _, p := range pointers {
		k, ok := strings.CutPrefix(p, "/"+envKey+"/")
		if !ok || k == "" {
			return nil, fmt.Errorf("unownable pointer %q", p)
		}
		raw, ok := env.get(k)
		if !ok {
			return nil, fmt.Errorf("pointer %q: no such variable", p)
		}
		out = append(out, raw)
	}
	return out, nil
}

// provisionCredential is 10 §3.3 steps 1 and 2: fingerprint the credential
// under the device-local guard key, and record `ref-id → fingerprint` in the
// registry the proxy's guard loads at startup. The credential bytes never leave
// this function.
//
// Step 3 — registering the fingerprint server-side via POST /enroll/fingerprints
// — is NOT done here: it needs the device token the enroll client holds, and the
// local guard admits without it. Its absence costs server-side attestation of
// the provisioning, not admission control.
func provisionCredential(stateDir, credential string) error {
	key, err := guardKey(stateDir)
	if err != nil {
		return err
	}
	mac := hmac.New(sha256.New, key)
	if _, err := mac.Write([]byte(credential)); err != nil {
		return err
	}
	return putRegistryLine(stateDir, credRefID, hex.EncodeToString(mac.Sum(nil)))
}

// guardKey reads, or on first use mints, the device-local key the proxy
// fingerprints under (`<state>/guard.key`). O_EXCL rather than stat-then-write:
// two provisioners racing must converge on ONE key, or the guard verifies
// against a fingerprint computed under a key it no longer holds and fails
// closed on every request.
func guardKey(stateDir string) ([]byte, error) {
	path := filepath.Join(stateDir, "guard.key")
	if b, err := os.ReadFile(path); err == nil && len(b) > 0 {
		return b, nil
	}
	if err := os.MkdirAll(stateDir, 0o700); err != nil {
		return nil, err
	}
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		return nil, err
	}
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		if os.IsExist(err) {
			return os.ReadFile(path)
		}
		return nil, err
	}
	defer func() { _ = f.Close() }()
	if _, err := f.Write(key); err != nil {
		return nil, err
	}
	return key, f.Close()
}

// putRegistryLine writes `<ref> <fingerprint-hex>` into `<state>/registry`,
// replacing any line for the same ref. The format is the proxy's reader, not a
// choice: space-separated, 64 hex chars, `#` comments (guard/provenance.rs).
func putRegistryLine(stateDir, ref, fingerprint string) error {
	path := filepath.Join(stateDir, "registry")
	old, err := os.ReadFile(path)
	if err != nil && !os.IsNotExist(err) {
		return err
	}
	var out bytes.Buffer
	for _, line := range strings.Split(string(old), "\n") {
		if strings.TrimSpace(line) == "" || strings.HasPrefix(strings.TrimSpace(line), ref+" ") {
			continue
		}
		out.WriteString(line)
		out.WriteByte('\n')
	}
	out.WriteString(ref + " " + fingerprint + "\n")
	if err := os.MkdirAll(stateDir, 0o700); err != nil {
		return err
	}
	return writeAtomicMode(path, out.Bytes(), 0o600)
}
