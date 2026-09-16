// The fixture is a per-test miniature Sigstore instance minting bundles in release.yml's exact shape: actions/attest-build-provenance@v2 on a private repo (Fulcio leaf with the workflow SAN + GitHub OIDC issuer, RFC 3161 timestamp, no Rekor entry, DSSE over an in-toto/SLSA v1 statement).
package verifyrelease

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/hex"
	"encoding/json"
	"errors"
	"math/big"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/digitorus/timestamp"

	"github.com/Omium-ai/omium-mark1/go/mark1/internal/cli"
)

const (
	goodSAN = BuilderWorkflow + "@refs/tags/edge/v0.1.0"
	commit  = "3f2a9c1d4e5b6a7f8091a2b3c4d5e6f708192a3b"
)

type instance struct {
	fulcioInt    *x509.Certificate
	fulcioIntKey *ecdsa.PrivateKey
	tsaLeaf      *x509.Certificate
	tsaKey       *ecdsa.PrivateKey
	trustedRoot  []byte
}

func mustKey(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

func mustCert(t *testing.T, tmpl, parent *x509.Certificate, pub any, signer *ecdsa.PrivateKey) *x509.Certificate {
	t.Helper()
	serial, _ := rand.Int(rand.Reader, big.NewInt(1<<62))
	tmpl.SerialNumber = serial
	der, err := x509.CreateCertificate(rand.Reader, tmpl, parent, pub, signer)
	if err != nil {
		t.Fatal(err)
	}
	c, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func newInstance(t *testing.T) *instance {
	t.Helper()
	now := time.Now()
	ca := func(cn string, eku []x509.ExtKeyUsage) *x509.Certificate {
		return &x509.Certificate{
			Subject:   pkix.Name{Organization: []string{"GitHub, Inc."}, CommonName: cn},
			NotBefore: now.Add(-time.Hour), NotAfter: now.Add(24 * time.Hour),
			IsCA: true, BasicConstraintsValid: true,
			KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign, ExtKeyUsage: eku,
		}
	}
	rootKey := mustKey(t)
	rootTmpl := ca("Internal Services Root", nil)
	root := mustCert(t, rootTmpl, rootTmpl, &rootKey.PublicKey, rootKey)
	fulcioKey := mustKey(t)
	fulcioInt := mustCert(t, ca("Fulcio Intermediate", []x509.ExtKeyUsage{x509.ExtKeyUsageCodeSigning}), root, &fulcioKey.PublicKey, rootKey)
	tsaIntKey := mustKey(t)
	tsaInt := mustCert(t, ca("TSA intermediate", []x509.ExtKeyUsage{x509.ExtKeyUsageTimeStamping}), root, &tsaIntKey.PublicKey, rootKey)
	tsaKey := mustKey(t)
	ekuCritical, _ := asn1.Marshal([]asn1.ObjectIdentifier{{1, 3, 6, 1, 5, 5, 7, 3, 8}})
	tsaLeaf := mustCert(t, &x509.Certificate{
		Subject:   pkix.Name{Organization: []string{"GitHub, Inc."}, CommonName: "TSA Timestamping"},
		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(24 * time.Hour),
		KeyUsage:        x509.KeyUsageDigitalSignature,
		ExtraExtensions: []pkix.Extension{{Id: asn1.ObjectIdentifier{2, 5, 29, 37}, Critical: true, Value: ekuCritical}},
	}, tsaInt, &tsaKey.PublicKey, tsaIntKey)

	chain := func(certs ...*x509.Certificate) []map[string]any {
		var out []map[string]any
		for _, c := range certs {
			out = append(out, map[string]any{"rawBytes": c.Raw})
		}
		return out
	}
	tr, _ := json.Marshal(map[string]any{
		"mediaType": "application/vnd.dev.sigstore.trustedroot+json;version=0.1",
		"certificateAuthorities": []map[string]any{{
			"uri": "fulcio.githubapp.com", "certChain": map[string]any{"certificates": chain(fulcioInt, root)},
			"validFor": map[string]any{"start": now.Add(-time.Hour).UTC().Format(time.RFC3339)},
		}},
		"timestampAuthorities": []map[string]any{{
			"uri": "timestamp.githubapp.com", "certChain": map[string]any{"certificates": chain(tsaLeaf, tsaInt, root)},
			"validFor": map[string]any{"start": now.Add(-time.Hour).UTC().Format(time.RFC3339)},
		}},
	})
	return &instance{fulcioInt: fulcioInt, fulcioIntKey: fulcioKey, tsaLeaf: tsaLeaf, tsaKey: tsaKey, trustedRoot: tr}
}

type attestOpts struct {
	san, issuer string
	tamperSig   bool
	noTimestamp bool
	tsOverOther bool      // the TSA timestamped some other signature
	fulcio      *instance // signs the leaf; defaults to the receiver (an untrusted CA otherwise)
	tsa         *instance // signs the timestamp; same default
}

// attest mints one bundle over artifact the way the workflow's publish job does.
func (in *instance) attest(t *testing.T, artifact []byte, o attestOpts) []byte {
	t.Helper()
	if o.san == "" {
		o.san = goodSAN
	}
	if o.issuer == "" {
		o.issuer = OIDCIssuer
	}
	if o.fulcio == nil {
		o.fulcio = in
	}
	if o.tsa == nil {
		o.tsa = in
	}
	now := time.Now()
	sanURL, _ := url.Parse(o.san)
	issuerDER, _ := asn1.Marshal(o.issuer)
	commitDER, _ := asn1.Marshal(commit)
	leafKey := mustKey(t)
	leaf := mustCert(t, &x509.Certificate{
		URIs: []*url.URL{sanURL}, NotBefore: now.Add(-time.Minute), NotAfter: now.Add(9 * time.Minute),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageCodeSigning},
		ExtraExtensions: []pkix.Extension{
			{Id: oidIssuerV2, Value: issuerDER},
			{Id: oidSourceDigest, Value: commitDER},
		},
	}, o.fulcio.fulcioInt, &leafKey.PublicKey, o.fulcio.fulcioIntKey)

	digest := sha256.Sum256(artifact)
	payload, _ := json.Marshal(map[string]any{
		"_type":         statementType,
		"subject":       []map[string]any{{"name": "mark1-0.1.0-x86_64-unknown-linux-gnu.tar.gz", "digest": map[string]string{"sha256": hex.EncodeToString(digest[:])}}},
		"predicateType": predicateType,
		"predicate": map[string]any{
			"buildDefinition": map[string]any{
				"buildType": "https://actions.github.io/buildtypes/workflow/v1",
				"externalParameters": map[string]any{"workflow": map[string]string{
					"ref": "refs/tags/edge/v0.1.0", "repository": "https://github.com/Omium-ai/omium-mark1", "path": ".github/workflows/release.yml",
				}},
				"internalParameters":   map[string]any{"github": map[string]string{"event_name": "push", "runner_environment": "github-hosted"}},
				"resolvedDependencies": []map[string]any{{"uri": "git+https://github.com/Omium-ai/omium-mark1@refs/tags/edge/v0.1.0", "digest": map[string]string{"gitCommit": commit}}},
			},
			"runDetails": map[string]any{"builder": map[string]string{"id": o.san}},
		},
	})
	pae := []byte("DSSEv1 " + itoa(len(payloadType)) + " " + payloadType + " " + itoa(len(payload)) + " ")
	h := sha256.Sum256(append(pae, payload...))
	sig, err := ecdsa.SignASN1(rand.Reader, leafKey, h[:])
	if err != nil {
		t.Fatal(err)
	}
	sigH := sha256.Sum256(sig)
	if o.tsOverOther {
		sigH = sha256.Sum256([]byte("a signature the TSA saw, but not this one"))
	}
	tsr, err := (&timestamp.Timestamp{HashAlgorithm: crypto.SHA256, HashedMessage: sigH[:], Time: now,
		Policy: asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 57264, 2}, AddTSACertificate: true}).
		CreateResponseWithOpts(o.tsa.tsaLeaf, o.tsa.tsaKey, crypto.SHA256)
	if err != nil {
		t.Fatal(err)
	}
	if o.tamperSig {
		sig[len(sig)-1] ^= 0x01
	}
	var timestamps []map[string]any
	if !o.noTimestamp {
		timestamps = []map[string]any{{"signedTimestamp": tsr}}
	}
	b, _ := json.Marshal(map[string]any{
		"mediaType": "application/vnd.dev.sigstore.bundle.v0.3+json",
		"verificationMaterial": map[string]any{
			"certificate":               map[string]any{"rawBytes": leaf.Raw},
			"tlogEntries":               []any{},
			"timestampVerificationData": map[string]any{"rfc3161Timestamps": timestamps},
		},
		"dsseEnvelope": map[string]any{"payload": payload, "payloadType": payloadType, "signatures": []map[string]any{{"sig": sig, "keyid": ""}}},
	})
	return b
}

func itoa(n int) string { return big.NewInt(int64(n)).String() }

// run writes artifact + bundle + trusted root to disk and runs the command as main.go would, returning exit code and --json stdout.
func run(t *testing.T, in *instance, artifact, bundle []byte) (int, map[string]any) {
	t.Helper()
	dir := t.TempDir()
	art := filepath.Join(dir, "mark1-0.1.0-x86_64-unknown-linux-gnu.tar.gz")
	for name, data := range map[string][]byte{art: artifact, art + ".sigstore.json": bundle, filepath.Join(dir, "tr.json"): in.trustedRoot} {
		if err := os.WriteFile(name, data, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	var out bytes.Buffer
	env := &cli.Env{JSON: true, Stdout: &out, Stderr: &bytes.Buffer{}}
	err := Run(env, Options{Artifact: art, TrustedRoot: filepath.Join(dir, "tr.json")})
	code := 0
	if err != nil {
		var ee *cli.ExitError
		if !errors.As(err, &ee) {
			t.Fatalf("not an ExitError: %v", err)
		}
		code = ee.Code
		env.EmitError(ee)
	}
	var obj map[string]any
	if err := json.Unmarshal(out.Bytes(), &obj); err != nil {
		t.Fatalf("stdout is not one JSON object: %q", out.String())
	}
	return code, obj
}

func TestValidProvenanceVerifies(t *testing.T) {
	in := newInstance(t)
	artifact := []byte("edge tarball bytes")
	code, obj := run(t, in, artifact, in.attest(t, artifact, attestOpts{}))
	if code != cli.ExitOK || obj["ok"] != true {
		t.Fatalf("exit %d, %v", code, obj)
	}
	d := sha256.Sum256(artifact)
	if obj["sha256"] != hex.EncodeToString(d[:]) || obj["builder"] != goodSAN || obj["commit"] != commit || obj["tsa"] != "timestamp.githubapp.com" {
		t.Fatalf("result does not report what was verified: %v", obj)
	}
}

func TestBundleForAnotherArtifactIsADigestMismatch(t *testing.T) {
	in := newInstance(t)
	bundle := in.attest(t, []byte("the bytes that were built"), attestOpts{})
	code, obj := run(t, in, []byte("the bytes that were built, then tampered"), bundle)
	assertDefect(t, code, obj, "digest_mismatch")
}

func TestWrongBuilderIdentityIsRefused(t *testing.T) {
	in := newInstance(t)
	artifact := []byte("edge tarball bytes")
	for name, o := range map[string]attestOpts{
		"other repo":     {san: "https://github.com/evil/omium-mark1/.github/workflows/release.yml@refs/tags/edge/v0.1.0"},
		"other workflow": {san: "https://github.com/Omium-ai/omium-mark1/.github/workflows/ci.yml@refs/tags/edge/v0.1.0"},
		"branch ref":     {san: BuilderWorkflow + "@refs/heads/main"},
		"nested ref":     {san: BuilderWorkflow + "@refs/tags/edge/v0.1.0/evil"},
		"other issuer":   {issuer: "https://accounts.google.com"},
	} {
		code, obj := run(t, in, artifact, in.attest(t, artifact, o))
		if code != cli.ExitVerify {
			t.Errorf("%s: exit %d, want %d", name, code, cli.ExitVerify)
		}
		assertDefect(t, code, obj, "builder_identity")
	}
}

func TestBrokenSignatureUntrustedCAAndMissingTimestampAreRefused(t *testing.T) {
	in := newInstance(t)
	artifact := []byte("edge tarball bytes")
	code, obj := run(t, in, artifact, in.attest(t, artifact, attestOpts{tamperSig: true}))
	assertDefect(t, code, obj, "signature_invalid")

	code, obj = run(t, in, artifact, in.attest(t, artifact, attestOpts{fulcio: newInstance(t)}))
	assertDefect(t, code, obj, "certificate_untrusted")

	code, obj = run(t, in, artifact, in.attest(t, artifact, attestOpts{noTimestamp: true}))
	assertDefect(t, code, obj, "no_timestamp")

	code, obj = run(t, in, artifact, in.attest(t, artifact, attestOpts{tsOverOther: true}))
	assertDefect(t, code, obj, "no_timestamp")

	code, obj = run(t, in, artifact, in.attest(t, artifact, attestOpts{tsa: newInstance(t)}))
	assertDefect(t, code, obj, "no_timestamp")
}

func TestAuthorityValidityWindowEndBinds(t *testing.T) {
	in := newInstance(t)
	artifact := []byte("edge tarball bytes")
	bundle := in.attest(t, artifact, attestOpts{})
	var tr map[string]any
	if err := json.Unmarshal(in.trustedRoot, &tr); err != nil {
		t.Fatal(err)
	}
	for _, key := range []string{"certificateAuthorities", "timestampAuthorities"} {
		for _, a := range tr[key].([]any) {
			a.(map[string]any)["validFor"].(map[string]any)["end"] = time.Now().Add(-30 * time.Minute).UTC().Format(time.RFC3339)
		}
	}
	in.trustedRoot, _ = json.Marshal(tr)
	code, obj := run(t, in, artifact, bundle)
	if code != cli.ExitVerify {
		t.Fatalf("exit %d with every authority expired before the signature, want %d: %v", code, cli.ExitVerify, obj)
	}
}

// gh attestation download writes one bundle per line; the one naming this artifact decides.
func TestJSONLPicksTheBundleNamingTheArtifact(t *testing.T) {
	in := newInstance(t)
	artifact := []byte("edge tarball bytes")
	other := in.attest(t, []byte("a sibling triple's tarball"), attestOpts{})
	good := in.attest(t, artifact, attestOpts{})
	code, obj := run(t, in, artifact, bytes.Join([][]byte{other, good}, []byte("\n")))
	if code != cli.ExitOK || obj["ok"] != true {
		t.Fatalf("exit %d, %v", code, obj)
	}
}

func TestMissingProvenanceIsAVerificationFailure(t *testing.T) {
	dir := t.TempDir()
	art := filepath.Join(dir, "x")
	if err := os.WriteFile(art, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	err := Run(&cli.Env{Stdout: &bytes.Buffer{}, Stderr: &bytes.Buffer{}}, Options{Artifact: art})
	var ee *cli.ExitError
	if !errors.As(err, &ee) || ee.Code != cli.ExitVerify || !strings.HasPrefix(ee.Msg, "provenance_missing") {
		t.Fatalf("an artifact without provenance must not verify: %v", err)
	}
}

// The embedded snapshot must parse and name both instances, or the default path verifies against nothing.
func TestEmbeddedTrustedRootsCoverBothInstances(t *testing.T) {
	roots, err := loadRoots("")
	if err != nil {
		t.Fatal(err)
	}
	uris := map[string]bool{}
	for _, r := range roots {
		for _, ca := range r.CertificateAuthorities {
			uris[ca.URI] = true
		}
		for _, ca := range r.TimestampAuthorities {
			uris[ca.URI] = true
		}
	}
	for _, want := range []string{"fulcio.githubapp.com", "timestamp.githubapp.com", "https://fulcio.sigstore.dev"} {
		if !uris[want] {
			t.Errorf("embedded trusted roots lack %s: %v", want, uris)
		}
	}
}

func assertDefect(t *testing.T, code int, obj map[string]any, kind string) {
	t.Helper()
	if code != cli.ExitVerify || obj["ok"] != false {
		t.Fatalf("want exit %d (verification failure) for %s, got exit %d: %v", cli.ExitVerify, kind, code, obj)
	}
	e, _ := obj["error"].(map[string]any)
	if e["code"] != "verification_failure" || !strings.HasPrefix(e["message"].(string), kind+": ") {
		t.Fatalf("want error.code verification_failure with a %q message, got %v", kind, e)
	}
}

// FR-POLICY-009's finding was release.yml's notes naming a command that did not exist; both ends of that link are pinned here.
func TestReleaseNotesAndCLIAgreeOnVerifyRelease(t *testing.T) {
	for path, want := range map[string]string{
		"../../cmd/main.go":                         "verifyrelease.Run(",
		"../../../../.github/workflows/release.yml": "mark1 verify-release",
	} {
		src, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Contains(src, []byte(want)) {
			t.Errorf("%s no longer mentions %q", path, want)
		}
	}
}
