// Package verifyrelease is `mark1 verify-release` (09 §11.2, FR-POLICY-009): stdlib x509 + digitorus/timestamp, because sigstore-go compiles the OTel metric/auto-sdk packages tools/ci/otel_gate.sh forbids (CON-005) plus the whole gRPC stack.
// ponytail: trust anchors are an embedded TUF-fetched snapshot, not a TUF client — GitHub rotates Fulcio/TSA intermediates ~6-monthly, so an old binary needs --trusted-root (gh attestation trusted-root) for a newer release; go-tuf/v2 is the upgrade.
// ponytail: only RFC 3161 timestamps establish signing time; Rekor-only (public-good) bundles are refused as no_timestamp until the Rekor v2 checkpoint rung lands. SCTs are not checked.
package verifyrelease

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	_ "embed"
	"encoding/asn1"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"regexp"
	"time"

	"github.com/digitorus/pkcs7"
	"github.com/digitorus/timestamp"

	"github.com/Omium-ai/omium-mark1/go/mark1/internal/cli"
)

// BuilderWorkflow is the pinned builder identity (the Fulcio SAN less the ref); release.yml runs on edge/v* tags only.
const (
	BuilderWorkflow = "https://github.com/Omium-ai/omium-mark1/.github/workflows/release.yml"
	OIDCIssuer      = "https://token.actions.githubusercontent.com"
	statementType   = "https://in-toto.io/Statement/v1"
	predicateType   = "https://slsa.dev/provenance/v1"
	payloadType     = "application/vnd.in-toto+json"
)

var builderIdentity = regexp.MustCompile(`^` + regexp.QuoteMeta(BuilderWorkflow) + `@refs/tags/edge/v[^/]+$`)

// Fulcio certificate extensions (sigstore/fulcio docs/oid-info.md).
var (
	oidIssuerV2     = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 57264, 1, 8}
	oidIssuerV1     = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 57264, 1, 1}
	oidSourceDigest = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 57264, 1, 13}
)

//go:embed trusted_roots.jsonl
var embeddedRoots []byte

type Options struct {
	Artifact    string
	Provenance  string // default <artifact>.sigstore.json; a .jsonl of bundles works
	TrustedRoot string // trusted_root.json[l]; default the embedded snapshot
}

// Defect is one verification failure: the artifact must not be executed.
type Defect struct{ Kind, Detail string }

func (d *Defect) Error() string { return d.Kind + ": " + d.Detail }

func defect(kind, format string, a ...any) *Defect {
	return &Defect{Kind: kind, Detail: fmt.Sprintf(format, a...)}
}

// Result is the --json object on success.
type Result struct {
	OK       bool   `json:"ok"`
	Artifact string `json:"artifact"`
	SHA256   string `json:"sha256"`
	Builder  string `json:"builder"`
	Issuer   string `json:"issuer"`
	Commit   string `json:"commit,omitempty"`
	SignedAt string `json:"signed_at"`
	TSA      string `json:"tsa"`
}

func Run(env *cli.Env, opts Options) error {
	digest, err := fileSHA256(opts.Artifact)
	if err != nil {
		return cli.Failf(cli.ExitUsage, "", "artifact %s: %v", opts.Artifact, err)
	}
	prov := opts.Provenance
	if prov == "" {
		prov = opts.Artifact + ".sigstore.json"
	}
	bundles, err := readLines(prov)
	if err != nil {
		return cli.Failf(cli.ExitVerify, "", "provenance_missing: %v", err)
	}
	roots, err := loadRoots(opts.TrustedRoot)
	if err != nil {
		return cli.Failf(cli.ExitRuntime, "", "trusted root: %v", err)
	}
	res, err := verify(digest, bundles, roots)
	if err != nil {
		var d *Defect
		if errors.As(err, &d) {
			return cli.Failf(cli.ExitVerify, "", "%s", d.Error())
		}
		return cli.Failf(cli.ExitRuntime, "", "%v", err)
	}
	res.Artifact = opts.Artifact
	return env.Emit(res, func(w io.Writer) {
		_, _ = fmt.Fprintf(w, "verified: %s\n  sha256:  %s\n  builder: %s\n  commit:  %s\n  signed:  %s (%s)\n",
			res.Artifact, res.SHA256, res.Builder, res.Commit, res.SignedAt, res.TSA)
	})
}

// verify runs the checks over the first bundle naming digest; a *Defect is the verdict, any other error is the verifier's own failure.
func verify(digest [32]byte, bundles [][]byte, roots []trustedRoot) (*Result, error) {
	hexDigest := hex.EncodeToString(digest[:])
	var b *bundle
	for _, raw := range bundles {
		cand, err := parseBundle(raw)
		if err != nil {
			return nil, defect("provenance_unparseable", "%v", err)
		}
		if cand.statement.names(hexDigest) {
			b = cand
			break
		}
	}
	if b == nil {
		return nil, defect("digest_mismatch", "no provenance statement names sha256:%s", hexDigest)
	}
	if b.statement.Type != statementType || b.statement.PredicateType != predicateType {
		return nil, defect("predicate_type", "%s %s is not SLSA provenance v1", b.statement.Type, b.statement.PredicateType)
	}

	leaf, err := x509.ParseCertificate(b.leafDER)
	if err != nil {
		return nil, defect("provenance_unparseable", "leaf certificate: %v", err)
	}
	san := ""
	if len(leaf.URIs) > 0 {
		san = leaf.URIs[0].String()
	}
	issuer := extString(leaf, oidIssuerV2)
	if issuer == "" {
		issuer = extRaw(leaf, oidIssuerV1)
	}
	if !builderIdentity.MatchString(san) || issuer != OIDCIssuer {
		return nil, defect("builder_identity", "signed by %q (issuer %q), want %s@refs/tags/edge/v* from %s", san, issuer, BuilderWorkflow, OIDCIssuer)
	}

	pae := fmt.Sprintf("DSSEv1 %d %s %d ", len(payloadType), payloadType, len(b.payload))
	if err := leaf.CheckSignature(sigAlg(leaf.PublicKey), append([]byte(pae), b.payload...), b.sig); err != nil {
		return nil, defect("signature_invalid", "DSSE signature: %v", err)
	}

	signedAt, tsa, err := observedTime(b.timestamps, b.sig, roots)
	if err != nil {
		return nil, defect("no_timestamp", "%v", err)
	}

	var chain []*x509.Certificate
	for _, der := range b.chainDER {
		if c, err := x509.ParseCertificate(der); err == nil {
			chain = append(chain, c)
		}
	}
	if err := chainsToTrustedCA(leaf, chain, signedAt, roots); err != nil {
		return nil, defect("certificate_untrusted", "%v", err)
	}
	return &Result{
		OK: true, SHA256: hexDigest, Builder: san, Issuer: issuer,
		Commit: extString(leaf, oidSourceDigest), SignedAt: signedAt.UTC().Format(time.RFC3339), TSA: tsa,
	}, nil
}

// bundle is the subset of a Sigstore bundle (v0.2/v0.3) this verifier reads.
type bundle struct {
	leafDER    []byte
	chainDER   [][]byte
	timestamps [][]byte
	payload    []byte
	sig        []byte
	statement  statement
}

type statement struct {
	Type          string `json:"_type"`
	PredicateType string `json:"predicateType"`
	Subject       []struct {
		Name   string            `json:"name"`
		Digest map[string]string `json:"digest"`
	} `json:"subject"`
}

func (s statement) names(hexDigest string) bool {
	for _, subj := range s.Subject {
		if subj.Digest["sha256"] == hexDigest {
			return true
		}
	}
	return false
}

func parseBundle(raw []byte) (*bundle, error) {
	var doc struct {
		VerificationMaterial struct {
			Certificate          *struct{ RawBytes []byte } `json:"certificate"`
			X509CertificateChain *struct {
				Certificates []struct{ RawBytes []byte } `json:"certificates"`
			} `json:"x509CertificateChain"`
			TimestampVerificationData struct {
				RFC3161Timestamps []struct{ SignedTimestamp []byte } `json:"rfc3161Timestamps"`
			} `json:"timestampVerificationData"`
		} `json:"verificationMaterial"`
		DSSEEnvelope *struct {
			Payload     []byte                 `json:"payload"`
			PayloadType string                 `json:"payloadType"`
			Signatures  []struct{ Sig []byte } `json:"signatures"`
		} `json:"dsseEnvelope"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		return nil, err
	}
	env := doc.DSSEEnvelope
	if env == nil || env.PayloadType != payloadType || len(env.Signatures) != 1 {
		return nil, errors.New("bundle has no in-toto DSSE envelope with exactly one signature")
	}
	b := &bundle{payload: env.Payload, sig: env.Signatures[0].Sig}
	vm := doc.VerificationMaterial
	switch {
	case vm.Certificate != nil:
		b.leafDER = vm.Certificate.RawBytes
	case vm.X509CertificateChain != nil && len(vm.X509CertificateChain.Certificates) > 0:
		b.leafDER = vm.X509CertificateChain.Certificates[0].RawBytes
		for _, c := range vm.X509CertificateChain.Certificates[1:] {
			b.chainDER = append(b.chainDER, c.RawBytes)
		}
	default:
		return nil, errors.New("bundle carries no signing certificate")
	}
	for _, ts := range vm.TimestampVerificationData.RFC3161Timestamps {
		b.timestamps = append(b.timestamps, ts.SignedTimestamp)
	}
	if err := json.Unmarshal(b.payload, &b.statement); err != nil {
		return nil, fmt.Errorf("in-toto statement: %w", err)
	}
	return b, nil
}

// trustedRoot is the subset of a Sigstore trusted_root.json this verifier reads; certChain is leaf-first, root last.
type trustedRoot struct {
	CertificateAuthorities []authority `json:"certificateAuthorities"`
	TimestampAuthorities   []authority `json:"timestampAuthorities"`
}

type authority struct {
	URI       string `json:"uri"`
	CertChain struct {
		Certificates []struct{ RawBytes []byte } `json:"certificates"`
	} `json:"certChain"`
	ValidFor struct {
		Start time.Time `json:"start"`
		End   time.Time `json:"end"`
	} `json:"validFor"`
}

func (a authority) validAt(t time.Time) bool {
	return !t.Before(a.ValidFor.Start) && (a.ValidFor.End.IsZero() || !t.After(a.ValidFor.End))
}

// pools splits the chain into stdlib verify inputs: root (last), intermediates, and a leaf when the first is not a CA.
func (a authority) pools() (roots, inter *x509.CertPool, leaf *x509.Certificate) {
	roots, inter = x509.NewCertPool(), x509.NewCertPool()
	n := len(a.CertChain.Certificates)
	for i, c := range a.CertChain.Certificates {
		cert, err := x509.ParseCertificate(c.RawBytes)
		if err != nil {
			continue
		}
		switch {
		case i == n-1:
			roots.AddCert(cert)
		case i == 0 && !cert.IsCA:
			leaf = cert
		default:
			inter.AddCert(cert)
		}
	}
	return roots, inter, leaf
}

func loadRoots(path string) ([]trustedRoot, error) {
	lines := splitLines(embeddedRoots)
	if path != "" {
		var err error
		if lines, err = readLines(path); err != nil {
			return nil, err
		}
	}
	var roots []trustedRoot
	for _, l := range lines {
		var tr trustedRoot
		if err := json.Unmarshal(l, &tr); err != nil {
			return nil, err
		}
		roots = append(roots, tr)
	}
	if len(roots) == 0 {
		return nil, errors.New("no trusted root documents")
	}
	return roots, nil
}

// observedTime is the instant of the first RFC 3161 timestamp a trusted TSA signed over exactly this DSSE signature.
func observedTime(timestamps [][]byte, sig []byte, roots []trustedRoot) (time.Time, string, error) {
	var errs []error
	for _, tsr := range timestamps {
		ts, err := timestamp.ParseResponse(tsr)
		if err != nil {
			errs = append(errs, err)
			continue
		}
		if ts.HashAlgorithm != crypto.SHA256 && ts.HashAlgorithm != crypto.SHA384 && ts.HashAlgorithm != crypto.SHA512 {
			errs = append(errs, fmt.Errorf("timestamp uses %v", ts.HashAlgorithm))
			continue
		}
		h := ts.HashAlgorithm.New()
		h.Write(sig)
		if !bytes.Equal(h.Sum(nil), ts.HashedMessage) {
			errs = append(errs, errors.New("timestamp does not cover this signature"))
			continue
		}
		for _, tr := range roots {
			for _, tsa := range tr.TimestampAuthorities {
				if err := verifyTSA(ts, tsa); err != nil {
					errs = append(errs, fmt.Errorf("%s: %w", tsa.URI, err))
					continue
				}
				return ts.Time, tsa.URI, nil
			}
		}
	}
	if len(timestamps) == 0 {
		return time.Time{}, "", errors.New("bundle carries no RFC 3161 timestamp (Rekor-only bundles are not supported yet)")
	}
	return time.Time{}, "", fmt.Errorf("no trusted TSA signed this timestamp: %w", errors.Join(errs...))
}

// verifyTSA is timestamp-authority's VerifyTimestampResponse in miniature: CMS signature by the TSA leaf, then its chain at the timestamp's own instant.
func verifyTSA(ts *timestamp.Timestamp, tsa authority) error {
	if !tsa.validAt(ts.Time) {
		return errors.New("outside the authority's validity window")
	}
	p7, err := pkcs7.Parse(ts.RawToken)
	if err != nil {
		return err
	}
	roots, inter, leaf := tsa.pools()
	if leaf != nil {
		p7.Certificates = append(p7.Certificates, leaf)
	}
	if err := p7.Verify(); err != nil {
		return err
	}
	signer := p7.GetOnlySigner()
	if signer == nil || signer.IsCA {
		return errors.New("timestamp has no single end-entity signer")
	}
	for _, c := range p7.Certificates {
		inter.AddCert(c)
	}
	_, err = signer.Verify(x509.VerifyOptions{
		Roots: roots, Intermediates: inter, CurrentTime: ts.Time,
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageTimeStamping},
	})
	return err
}

func chainsToTrustedCA(leaf *x509.Certificate, chain []*x509.Certificate, at time.Time, roots []trustedRoot) error {
	var errs []error
	for _, tr := range roots {
		for _, ca := range tr.CertificateAuthorities {
			if !ca.validAt(at) {
				continue
			}
			rootPool, inter, _ := ca.pools()
			for _, c := range chain {
				inter.AddCert(c)
			}
			_, err := leaf.Verify(x509.VerifyOptions{
				Roots: rootPool, Intermediates: inter, CurrentTime: at,
				KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageCodeSigning},
			})
			if err == nil {
				return nil
			}
			errs = append(errs, fmt.Errorf("%s: %w", ca.URI, err))
		}
	}
	return fmt.Errorf("leaf certificate chains to no trusted Fulcio CA valid at %s: %w", at.UTC().Format(time.RFC3339), errors.Join(errs...))
}

func sigAlg(pub crypto.PublicKey) x509.SignatureAlgorithm {
	switch k := pub.(type) {
	case *ecdsa.PublicKey:
		switch k.Curve {
		case elliptic.P384():
			return x509.ECDSAWithSHA384
		case elliptic.P521():
			return x509.ECDSAWithSHA512
		}
		return x509.ECDSAWithSHA256
	case ed25519.PublicKey:
		return x509.PureEd25519
	case *rsa.PublicKey:
		return x509.SHA256WithRSA
	}
	return x509.UnknownSignatureAlgorithm
}

// extString reads a Fulcio extension whose value is a DER UTF8String.
func extString(c *x509.Certificate, oid asn1.ObjectIdentifier) string {
	for _, e := range c.Extensions {
		if e.Id.Equal(oid) {
			var s string
			if _, err := asn1.Unmarshal(e.Value, &s); err == nil {
				return s
			}
		}
	}
	return ""
}

// extRaw reads the deprecated .1.1 issuer, which Fulcio wrote as raw bytes.
func extRaw(c *x509.Certificate, oid asn1.ObjectIdentifier) string {
	for _, e := range c.Extensions {
		if e.Id.Equal(oid) {
			return string(e.Value)
		}
	}
	return ""
}

func fileSHA256(path string) ([32]byte, error) {
	var out [32]byte
	f, err := os.Open(path)
	if err != nil {
		return out, err
	}
	defer func() { _ = f.Close() }()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return out, err
	}
	copy(out[:], h.Sum(nil))
	return out, nil
}

func readLines(path string) ([][]byte, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	lines := splitLines(data)
	if len(lines) == 0 {
		return nil, fmt.Errorf("%s is empty", path)
	}
	return lines, nil
}

func splitLines(data []byte) [][]byte {
	var out [][]byte
	for _, l := range bytes.Split(data, []byte{'\n'}) {
		if len(bytes.TrimSpace(l)) > 0 {
			out = append(out, l)
		}
	}
	return out
}
