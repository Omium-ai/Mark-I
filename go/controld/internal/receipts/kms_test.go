package receipts

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"errors"
	"testing"
)

// fakeKMS is the test double: keys are addressed by alias, the private half
// never leaves the map, and the only verbs are the two KMSAPI has.
type fakeKMS struct {
	keys  map[string]ed25519.PrivateKey
	signs int
}

func newFakeKMS(aliases ...string) *fakeKMS {
	f := &fakeKMS{keys: map[string]ed25519.PrivateKey{}}
	for i, a := range aliases {
		f.keys[a] = ed25519.NewKeyFromSeed(bytes.Repeat([]byte{byte(0x60 + i)}, 32))
	}
	return f
}

func (f *fakeKMS) Sign(_ context.Context, ref string, msg []byte) ([]byte, error) {
	k, ok := f.keys[ref]
	if !ok {
		return nil, errors.New("AccessDeniedException")
	}
	f.signs++
	return ed25519.Sign(k, msg), nil
}

func (f *fakeKMS) PublicKey(_ context.Context, ref string) ([]byte, error) {
	k, ok := f.keys[ref]
	if !ok {
		return nil, errors.New("NotFoundException")
	}
	return k.Public().(ed25519.PublicKey), nil
}

func TestKMSSignerBehindTheSameSeam(t *testing.T) {
	kms := newFakeKMS("alias/mark1-sign-chain-v1")
	ks, err := NewKMSSigner(context.Background(), kms, "alias/mark1-sign-chain-v1")
	if err != nil {
		t.Fatal(err)
	}
	var s SignerLike = ks
	msg := []byte(DomainPrefix + `{"a":1}`)
	sig, err := s.Sign(msg)
	if err != nil {
		t.Fatal(err)
	}
	if !Verify(s.Public(), sig, msg) || s.KeyID() != DeriveKeyID(s.Public()) {
		t.Fatal("kms signature does not verify under the derived key id")
	}
	if kms.signs != 1 {
		t.Fatalf("expected exactly one kms:Sign call, got %d", kms.signs)
	}
	if _, err := NewKMSSigner(context.Background(), kms, "alias/nope"); err == nil {
		t.Fatal("an unknown key ref must fail at construction, not at first sign")
	}
}

func TestCrossSignBindsRoleAndRefusesSelf(t *testing.T) {
	old, _ := NewSigner(bytes.Repeat([]byte{1}, 32))
	next, _ := NewSigner(bytes.Repeat([]byte{2}, 32))
	sig, err := CrossSign(old, RoleServerChain, next.Public())
	if err != nil {
		t.Fatal(err)
	}
	if !VerifyCrossSign(old.Public(), RoleServerChain, next.Public(), sig) {
		t.Fatal("cross-signature does not verify")
	}
	if VerifyCrossSign(old.Public(), RoleUpdate, next.Public(), sig) {
		t.Fatal("a server-chain cross-signature replayed as an update-key endorsement")
	}
	if VerifyCrossSign(next.Public(), RoleServerChain, next.Public(), sig) {
		t.Fatal("verified under the successor itself")
	}
	if _, err := CrossSign(old, RoleServerChain, old.Public()); err == nil {
		t.Fatal("self cross-signing was accepted")
	}
}
