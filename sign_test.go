package main

import (
	"crypto/ed25519"
	"path/filepath"
	"strings"
	"testing"
)

func signedLog(t *testing.T, n int) (path string, pub ed25519.PublicKey) {
	t.Helper()

	pub, priv, err := generateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	path = filepath.Join(t.TempDir(), "signed.log")

	l, err := OpenLog(path, false)
	if err != nil {
		t.Fatal(err)
	}
	l.WithSigner(priv)

	for i := 0; i < n; i++ {
		if _, err := l.Append(Action{Direction: "call", Method: "tools/call", Tool: "read_file"}, nil, nil); err != nil {
			t.Fatal(err)
		}
	}
	if err := l.Close(); err != nil {
		t.Fatal(err)
	}
	return path, pub
}

func TestSignedLogVerifiesWithKey(t *testing.T) {
	path, pub := signedLog(t, 4)

	res, err := VerifyLog(path, pub)
	if err != nil {
		t.Fatal(err)
	}
	if !res.Intact {
		t.Fatalf("expected intact, got %q at %v", res.Problem, res.BrokenAt)
	}
	if res.SignaturesVerified != 4 {
		t.Errorf("SignaturesVerified = %d, want 4", res.SignaturesVerified)
	}
	if !strings.Contains(res.Guarantee, "every signature validates") {
		t.Errorf("guarantee should state signatures validated, got %q", res.Guarantee)
	}
}

// TestFullChainRebuildIsDetected is the attack signing exists to stop. An
// attacker with write access edits an entry and recomputes every hash after it,
// producing a chain that is internally perfect.
func TestFullChainRebuildIsDetected(t *testing.T) {
	path, pub := signedLog(t, 5)

	entries := readEntries(t, path)
	entries[1].Action.Tool = "exfiltrate"
	prev := entries[0].Hash
	for i := 1; i < len(entries); i++ {
		entries[i].PrevHash = prev
		entries[i].Hash = computeHash(&entries[i])
		prev = entries[i].Hash
	}
	writeEntries(t, path, entries)

	// Without the key the rebuild is undetectable, which is why an unsigned
	// log is not evidence.
	unsigned, err := VerifyLog(path, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !unsigned.Intact {
		t.Error("hash checks alone should not catch a full rebuild; if they now do, update the documented guarantee")
	}

	res, err := VerifyLog(path, pub)
	if err != nil {
		t.Fatal(err)
	}
	if res.Intact {
		t.Fatal("a rebuilt chain was not detected despite signatures")
	}
	if !strings.Contains(res.Problem, "signature") {
		t.Errorf("problem should name the signature, got %q", res.Problem)
	}
}

func TestWrongKeyIsRejected(t *testing.T) {
	path, _ := signedLog(t, 3)
	other, _, err := generateKeyPair()
	if err != nil {
		t.Fatal(err)
	}

	res, err := VerifyLog(path, other)
	if err != nil {
		t.Fatal(err)
	}
	if res.Intact {
		t.Error("a log verified against an unrelated key")
	}
}

// TestMixedSigningIsRejected covers inserting unsigned entries into a log that
// presents itself as signed.
func TestMixedSigningIsRejected(t *testing.T) {
	path, pub := signedLog(t, 3)

	entries := readEntries(t, path)
	entries[1].Sig = ""
	entries[1].KeyID = ""
	writeEntries(t, path, entries)

	res, err := VerifyLog(path, pub)
	if err != nil {
		t.Fatal(err)
	}
	if res.Intact {
		t.Error("a log mixing signed and unsigned entries was accepted")
	}
}

func TestUnsignedLogStatesWeakerGuarantee(t *testing.T) {
	path := tempLog(t)
	appendN(t, path, 3, false)

	res, err := VerifyLog(path, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !res.Intact {
		t.Fatal("expected an intact unsigned chain")
	}
	if !strings.Contains(res.Guarantee, "Unsigned") {
		t.Errorf("guarantee should lead with Unsigned, got %q", res.Guarantee)
	}
	if !strings.Contains(res.Guarantee, "rebuilt") {
		t.Errorf("guarantee should warn about rebuilding, got %q", res.Guarantee)
	}
}

// TestSignedLogWithoutKeyDoesNotClaimVerification guards against the report
// implying signatures were checked when no key was supplied.
func TestSignedLogWithoutKeyDoesNotClaimVerification(t *testing.T) {
	path, _ := signedLog(t, 3)

	res, err := VerifyLog(path, nil)
	if err != nil {
		t.Fatal(err)
	}
	if res.SignaturesVerified != 0 {
		t.Errorf("SignaturesVerified = %d with no key supplied, want 0", res.SignaturesVerified)
	}
	if res.Signed != 3 {
		t.Errorf("Signed = %d, want 3", res.Signed)
	}
	if !strings.Contains(res.Guarantee, "not checked") {
		t.Errorf("guarantee must say signatures were not checked, got %q", res.Guarantee)
	}
}

func TestKeyRoundTripsThroughPEM(t *testing.T) {
	dir := t.TempDir()
	keyPath := filepath.Join(dir, "adjent.key")
	pubPath := filepath.Join(dir, "adjent.pub")

	pub, priv, err := generateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	if err := savePrivateKey(keyPath, priv); err != nil {
		t.Fatal(err)
	}
	if err := savePublicKey(pubPath, pub); err != nil {
		t.Fatal(err)
	}

	loadedPriv, err := loadPrivateKey(keyPath)
	if err != nil {
		t.Fatal(err)
	}
	loadedPub, err := loadPublicKey(pubPath)
	if err != nil {
		t.Fatal(err)
	}

	sig := signEntryHash(loadedPriv, "deadbeef")
	if !verifyEntrySignature(loadedPub, "deadbeef", sig) {
		t.Error("signature from a round-tripped key did not verify")
	}
	if keyID(loadedPub) != keyID(pub) {
		t.Error("key id changed across a round trip")
	}
}

// TestSavePrivateKeyRefusesToOverwrite: silently replacing a signing key would
// orphan every log signed with the old one.
func TestSavePrivateKeyRefusesToOverwrite(t *testing.T) {
	path := filepath.Join(t.TempDir(), "adjent.key")
	_, priv, _ := generateKeyPair()

	if err := savePrivateKey(path, priv); err != nil {
		t.Fatal(err)
	}
	if err := savePrivateKey(path, priv); err == nil {
		t.Error("overwriting an existing signing key was allowed")
	}
}
