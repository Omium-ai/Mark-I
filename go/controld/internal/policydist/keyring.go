// The key manifest (08 §3.5 /.well-known/mark1-keys; ADR-0004): every
// server-published key with its role, window and -- after a rotation -- the
// retiring key's cross-signature on it. Published as a transparency-log leaf
// beside the bundles it signs, so one log head covers both.
//
// Two invariants are refusals, never warnings. R5 (10 §8.3): the update/log
// key is distinct from every bundle section key -- a forged update is fleet
// RCE and must not become reachable through a section key compromise. And a
// rotation is only ever the retiring key endorsing its successor: a key that
// endorses itself, or is endorsed by a key outside its own role, is a new
// trust root smuggled in as a rotation.

package policydist

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"

	"github.com/Omium-ai/omium-mark1/go/controld/internal/querychoke"
	"github.com/Omium-ai/omium-mark1/go/controld/internal/receipts"
)

const KeyManifestSchema = "mark1-keys.v1"

// ManifestKey is one published key; the JSON shape is tools/verifier's
// KeyRecord plus `section` for bundle keys.
type ManifestKey struct {
	Section   string            `json:"section,omitempty"`
	KeyID     string            `json:"key_id"`
	PubkeyHex string            `json:"pubkey_hex"`
	NotBefore string            `json:"not_before,omitempty"`
	NotAfter  string            `json:"not_after,omitempty"`
	CrossSig  *ManifestCrossSig `json:"cross_sig,omitempty"`
}

type ManifestCrossSig struct {
	ByKeyID      string `json:"by_key_id"`
	SignatureHex string `json:"signature_hex"`
}

type KeyManifest struct {
	Schema            string        `json:"schema"`
	ServerChainKeys   []ManifestKey `json:"server_chain_keys"`
	BundleSectionKeys []ManifestKey `json:"bundle_section_keys"`
	UpdateKeys        []ManifestKey `json:"update_keys"`
}

// ManifestReject names why a manifest is refused; Kind is the conformance
// vectors' vocabulary, shared with the edge (rust/mark1-policy RotationReject).
type ManifestReject struct {
	Kind   string
	Detail string
}

func (e *ManifestReject) Error() string {
	return "policydist: key manifest refused (" + e.Kind + "): " + e.Detail
}

func refuse(kind, format string, a ...any) *ManifestReject {
	return &ManifestReject{Kind: kind, Detail: fmt.Sprintf(format, a...)}
}

// BundleRole is the cross-sign role string for a section key.
func BundleRole(section string) receipts.KeyRole { return receipts.KeyRole("bundle:" + section) }

func manifestKeyOf(section string, s SectionSigner) ManifestKey {
	return ManifestKey{Section: section, KeyID: s.KeyID(), PubkeyHex: hex.EncodeToString(s.Public())}
}

// ManifestKeys lists this ring, cross-signed per section by prev when this
// ring is prev's successor. prev's own keys are listed too: a rotated-out key
// is never unpublished (every bundle it signed must verify forever).
func (k *Keyring) ManifestKeys(prev *Keyring) ([]ManifestKey, error) {
	out := make([]ManifestKey, 0, 2*len(SectionNames))
	for _, name := range SectionNames {
		cur := manifestKeyOf(name, k.byName[name])
		if prev != nil && prev.byName[name].KeyID() != cur.KeyID {
			old := prev.byName[name]
			sig, err := receipts.CrossSign(old, BundleRole(name), k.byName[name].Public())
			if err != nil {
				return nil, err
			}
			cur.CrossSig = &ManifestCrossSig{ByKeyID: old.KeyID(), SignatureHex: hex.EncodeToString(sig)}
			out = append(out, manifestKeyOf(name, old))
		}
		out = append(out, cur)
	}
	return out, nil
}

// BuildKeyManifest assembles and validates the manifest for one ring (prev
// nil outside a rotation), the update/log key, and the server chain keys as
// the receipts table publishes them.
func BuildKeyManifest(ring, prev *Keyring, update SectionSigner, serverChain []ManifestKey) (*KeyManifest, error) {
	sections, err := ring.ManifestKeys(prev)
	if err != nil {
		return nil, err
	}
	m := &KeyManifest{
		Schema: KeyManifestSchema, ServerChainKeys: serverChain,
		BundleSectionKeys: sections, UpdateKeys: []ManifestKey{manifestKeyOf("", update)},
	}
	if err := ValidateKeyManifest(m); err != nil {
		return nil, err
	}
	return m, nil
}

// ValidateKeyManifest is the publish-side twin of the edge's manifest intake:
// derived ids, the six sections present, R5, and every cross-signature a
// genuine hand-over within one role.
func ValidateKeyManifest(m *KeyManifest) error {
	if m.Schema != KeyManifestSchema {
		return refuse("schema", "schema %q, want %q", m.Schema, KeyManifestSchema)
	}
	pubs := map[string]ed25519.PublicKey{}
	decode := func(list []ManifestKey, role string) error {
		for _, k := range list {
			pub, err := hex.DecodeString(k.PubkeyHex)
			if err != nil || len(pub) != ed25519.PublicKeySize {
				return refuse("key_id_mismatch", "%s key %s: pubkey_hex is not 32 bytes", role, k.KeyID)
			}
			if got := receipts.DeriveKeyID(pub); got != k.KeyID {
				return refuse("key_id_mismatch", "%s key named %s derives to %s", role, k.KeyID, got)
			}
			pubs[k.KeyID] = pub
		}
		return nil
	}
	if err := decode(m.ServerChainKeys, "server_chain"); err != nil {
		return err
	}
	if err := decode(m.BundleSectionKeys, "bundle"); err != nil {
		return err
	}
	if err := decode(m.UpdateKeys, "update"); err != nil {
		return err
	}
	bySection := map[string]map[string]bool{}
	for _, k := range m.BundleSectionKeys {
		if !knownSection(k.Section) {
			return refuse("unknown_section", "bundle key %s names section %q", k.KeyID, k.Section)
		}
		if bySection[k.Section] == nil {
			bySection[k.Section] = map[string]bool{}
		}
		bySection[k.Section][k.KeyID] = true
	}
	for _, name := range SectionNames {
		if len(bySection[name]) == 0 {
			return refuse("missing_section", "no key published for section %q", name)
		}
	}
	for _, u := range m.UpdateKeys {
		for _, b := range m.BundleSectionKeys {
			if u.KeyID == b.KeyID {
				return refuse("update_equals_bundle", "update key %s is also the %s section key (boot refusal R5)", u.KeyID, b.Section)
			}
		}
	}
	for _, c := range m.ServerChainKeys {
		for _, b := range m.BundleSectionKeys {
			if c.KeyID == b.KeyID {
				return refuse("chain_equals_bundle", "server chain key %s is also the %s section key", c.KeyID, b.Section)
			}
		}
	}
	inRole := func(list []ManifestKey, id string) bool {
		for _, k := range list {
			if k.KeyID == id {
				return true
			}
		}
		return false
	}
	check := func(k ManifestKey, role receipts.KeyRole, peers []ManifestKey) error {
		if k.CrossSig == nil {
			return nil
		}
		by := k.CrossSig.ByKeyID
		switch {
		case by == k.KeyID:
			return refuse("self_signed", "key %s cross-signs itself", k.KeyID)
		case !inRole(peers, by):
			return refuse("unknown_signer", "key %s is cross-signed by %s, which is not published for role %s", k.KeyID, by, role)
		}
		sig, err := hex.DecodeString(k.CrossSig.SignatureHex)
		if err != nil || !receipts.VerifyCrossSign(pubs[by], role, pubs[k.KeyID], sig) {
			return refuse("bad_cross_signature", "cross-signature on %s by %s does not verify", k.KeyID, by)
		}
		return nil
	}
	for _, k := range m.ServerChainKeys {
		if err := check(k, receipts.RoleServerChain, m.ServerChainKeys); err != nil {
			return err
		}
	}
	for _, k := range m.UpdateKeys {
		if err := check(k, receipts.RoleUpdate, m.UpdateKeys); err != nil {
			return err
		}
	}
	for _, k := range m.BundleSectionKeys {
		var peers []ManifestKey
		for _, p := range m.BundleSectionKeys {
			if p.Section == k.Section {
				peers = append(peers, p)
			}
		}
		if err := check(k, BundleRole(k.Section), peers); err != nil {
			return err
		}
	}
	return nil
}

// CanonicalManifest is the logged form: receipts.CanonicalJSON over the
// manifest, so the leaf preimage is one serialisation in every language.
func CanonicalManifest(m *KeyManifest) ([]byte, error) {
	raw, err := json.Marshal(m)
	if err != nil {
		return nil, err
	}
	v, err := receipts.DecodePayload(raw)
	if err != nil {
		return nil, err
	}
	text, err := receipts.CanonicalJSON(v)
	if err != nil {
		return nil, err
	}
	return []byte(text), nil
}

// ManifestPublished reports where a manifest landed in one tenant's log.
type ManifestPublished struct {
	Body       []byte
	BodySHA256 [32]byte
	Inclusion  *Inclusion
}

// PublishKeyManifest validates m and appends it to the tenant's log as a
// `key_manifest` leaf, keeping the logged bytes in key_manifests -- one
// transaction, exactly as a bundle publication (05 §4.1).
func (s *Store) PublishKeyManifest(ctx context.Context, tenant querychoke.TenantID, m *KeyManifest) (ManifestPublished, error) {
	if s.headSigner == nil {
		return ManifestPublished{}, errors.New("policydist: no log head signing key configured; this process cannot publish")
	}
	if err := ValidateKeyManifest(m); err != nil {
		return ManifestPublished{}, err
	}
	body, err := CanonicalManifest(m)
	if err != nil {
		return ManifestPublished{}, err
	}
	out := ManifestPublished{Body: body, BodySHA256: sha256.Sum256(body)}
	err = s.db.WithTenant(ctx, tenant, func(tx pgx.Tx) error {
		incl, _, err := s.appendLeaf(ctx, tx, tenant, LeafKindKeyManifest, out.BodySHA256)
		if err != nil {
			return err
		}
		proofJSON, err := inclusionJSON(incl)
		if err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `
			INSERT INTO key_manifests (tenant_id, tlog_index, body, body_sha256, tlog_proof)
			VALUES ($1, $2, $3, $4, $5)`,
			tenant.UUID(), i64(incl.LeafIndex), string(body), out.BodySHA256[:], proofJSON); err != nil {
			return err
		}
		out.Inclusion = incl
		return nil
	})
	if err != nil {
		return ManifestPublished{}, err
	}
	return out, nil
}
