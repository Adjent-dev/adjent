package main

import (
	"crypto/ed25519"
	"path/filepath"
	"strings"
	"testing"
)

func checkpointFor(t *testing.T, path string, priv ed25519.PrivateKey, pub ed25519.PublicKey) *Checkpoint {
	t.Helper()
	res, err := VerifyLog(path, pub)
	if err != nil {
		t.Fatal(err)
	}
	if !res.Intact {
		t.Fatalf("log not intact before checkpointing: %s", res.Problem)
	}
	return NewCheckpoint("test-log", uint64(res.Entries), res.Head, priv)
}

func signedLogWithKey(t *testing.T, n int) (string, ed25519.PublicKey, ed25519.PrivateKey) {
	t.Helper()
	pub, priv, err := generateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "cp.log")
	l, err := OpenLog(path, false)
	if err != nil {
		t.Fatal(err)
	}
	l.WithSigner(priv)
	for i := 0; i < n; i++ {
		if _, err := l.Append(Action{Direction: "call", Method: "tools/call", Tool: "act"}, nil, nil); err != nil {
			t.Fatal(err)
		}
	}
	if err := l.Close(); err != nil {
		t.Fatal(err)
	}
	return path, pub, priv
}

// TestCheckpointDetectsTruncation is the whole point of this file. Truncation is
// invisible to the chain alone; a checkpoint is the independent claim about
// length that makes it visible.
func TestCheckpointDetectsTruncation(t *testing.T) {
	path, pub, priv := signedLogWithKey(t, 6)
	cp := checkpointFor(t, path, priv, pub)

	writeEntries(t, path, readEntries(t, path)[:3])

	res, err := VerifyLog(path, pub)
	if err != nil {
		t.Fatal(err)
	}
	if !res.Intact {
		t.Fatal("truncated chain should still verify on its own; that is why checkpoints exist")
	}

	got := checkAgainstCheckpoint(res.entries, cp, pub, "")
	if got.Consistent {
		t.Fatal("checkpoint did not detect truncation")
	}
	if !strings.Contains(got.Problem, "removed from the end") {
		t.Errorf("problem should name the truncation, got %q", got.Problem)
	}
	if !got.Verified {
		t.Error("checkpoint signature should have been verified")
	}
}

func TestCheckpointAcceptsAppendedEntries(t *testing.T) {
	path, pub, priv := signedLogWithKey(t, 3)
	cp := checkpointFor(t, path, priv, pub)

	// A log legitimately grows after a checkpoint is taken.
	l, err := OpenLog(path, false)
	if err != nil {
		t.Fatal(err)
	}
	l.WithSigner(priv)
	for i := 0; i < 4; i++ {
		if _, err := l.Append(Action{Direction: "call", Method: "tools/list"}, nil, nil); err != nil {
			t.Fatal(err)
		}
	}
	l.Close()

	res, err := VerifyLog(path, pub)
	if err != nil {
		t.Fatal(err)
	}
	got := checkAgainstCheckpoint(res.entries, cp, pub, "")
	if !got.Consistent {
		t.Errorf("growth after a checkpoint was rejected: %s", got.Problem)
	}
	if got.LogSize != 7 {
		t.Errorf("LogSize = %d, want 7", got.LogSize)
	}
}

// TestCheckpointDetectsRewriteBelowCheckpoint covers an attacker who holds the
// signing key. They can rebuild the chain, but they cannot alter a checkpoint
// already published elsewhere.
func TestCheckpointDetectsRewriteBelowCheckpoint(t *testing.T) {
	path, pub, priv := signedLogWithKey(t, 5)
	cp := checkpointFor(t, path, priv, pub)

	entries := readEntries(t, path)
	entries[1].Action.Tool = "exfiltrate"
	prev := entries[0].Hash
	for i := 1; i < len(entries); i++ {
		entries[i].PrevHash = prev
		entries[i].Hash = computeHash(&entries[i])
		entries[i].Sig = signEntryHash(priv, entries[i].Hash)
		prev = entries[i].Hash
	}
	writeEntries(t, path, entries)

	res, err := VerifyLog(path, pub)
	if err != nil {
		t.Fatal(err)
	}
	if !res.Intact {
		t.Fatal("a rebuild by the key holder should pass signature checks; that is the gap checkpoints close")
	}

	got := checkAgainstCheckpoint(res.entries, cp, pub, "")
	if got.Consistent {
		t.Fatal("checkpoint did not detect a rewrite by the key holder")
	}
	if !strings.Contains(got.Problem, "rewritten") {
		t.Errorf("problem should name the rewrite, got %q", got.Problem)
	}
}

func TestCheckpointSignatureIsChecked(t *testing.T) {
	path, pub, priv := signedLogWithKey(t, 3)
	cp := checkpointFor(t, path, priv, pub)

	res, _ := VerifyLog(path, pub)

	// Claiming a longer log than was signed for.
	forged := *cp
	forged.Size = 99
	if got := checkAgainstCheckpoint(res.entries, &forged, pub, ""); got.Consistent {
		t.Error("a checkpoint with a tampered size was accepted")
	}

	other, _, _ := generateKeyPair()
	if got := checkAgainstCheckpoint(res.entries, cp, other, ""); got.Consistent {
		t.Error("a checkpoint verified against an unrelated key")
	}
}

func TestCheckpointWithoutKeyDoesNotClaimVerification(t *testing.T) {
	path, pub, priv := signedLogWithKey(t, 3)
	cp := checkpointFor(t, path, priv, pub)

	res, _ := VerifyLog(path, pub)
	got := checkAgainstCheckpoint(res.entries, cp, nil, "")

	if !got.Consistent {
		t.Errorf("unexpected mismatch: %s", got.Problem)
	}
	if got.Verified {
		t.Error("reported the checkpoint signature as verified when no key was supplied")
	}
}

func TestCheckpointRoundTripsThroughFile(t *testing.T) {
	path, pub, priv := signedLogWithKey(t, 2)
	cp := checkpointFor(t, path, priv, pub)

	out := filepath.Join(t.TempDir(), "adjent.checkpoint")
	if err := writeCheckpoint(out, cp); err != nil {
		t.Fatal(err)
	}
	loaded, err := readCheckpoint(out)
	if err != nil {
		t.Fatal(err)
	}
	if !loaded.verifySignature(pub) {
		t.Error("checkpoint signature did not survive a round trip")
	}
	if loaded.Head != cp.Head || loaded.Size != cp.Size {
		t.Error("checkpoint contents changed across a round trip")
	}
}

func TestCheckpointFieldBoundariesAreUnambiguous(t *testing.T) {
	_, priv, _ := generateKeyPair()
	a := NewCheckpoint("ab", 1, "c", priv)
	b := &Checkpoint{Origin: "a", Size: 1, Head: "bc", Time: a.Time}

	if string(checkpointBytes(a)) == string(checkpointBytes(b)) {
		t.Error("checkpoints with different field boundaries share signing input")
	}
}

// TestGuaranteeNarrowsWithAVerifiedCheckpoint: leaving the unqualified
// truncation caveat in place would understate what a checkpoint proved.
func TestGuaranteeNarrowsWithAVerifiedCheckpoint(t *testing.T) {
	path, pub, priv := signedLogWithKey(t, 4)
	cp := checkpointFor(t, path, priv, pub)

	res, err := VerifyLog(path, pub)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(res.Guarantee, "deleted from the end") {
		t.Fatalf("expected the truncation caveat before refinement, got %q", res.Guarantee)
	}

	res.Checkpoint = checkAgainstCheckpoint(res.entries, cp, pub, "")
	res.refineGuarantee()

	if strings.Contains(res.Guarantee, "deleted from the end") {
		t.Errorf("truncation caveat survived a verified checkpoint: %q", res.Guarantee)
	}
	// Same key for entries and checkpoint, so the claim must stay conditional.
	if !strings.Contains(res.Guarantee, "same key as the entries") {
		t.Errorf("guarantee must qualify a same-key checkpoint, got %q", res.Guarantee)
	}
	if strings.Contains(res.Guarantee, "even by the holder of the entry key") {
		t.Errorf("guarantee overclaims key-compromise resistance with a same-key checkpoint: %q", res.Guarantee)
	}
}

// TestIndependentCheckpointKeyStrengthensGuarantee is the case that actually
// survives key compromise: the adversary who can rewrite entries cannot mint a
// replacement checkpoint.
func TestIndependentCheckpointKeyStrengthensGuarantee(t *testing.T) {
	path, pub, priv := signedLogWithKey(t, 4)

	cpPub, cpPriv, err := generateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	res, err := VerifyLog(path, pub)
	if err != nil {
		t.Fatal(err)
	}
	cp := NewCheckpoint("test-log", uint64(res.Entries), res.Head, cpPriv)

	res.Checkpoint = checkAgainstCheckpoint(res.entries, cp, cpPub, "test-log")
	res.Checkpoint.IndependentKey = true
	res.refineGuarantee()

	if !res.Checkpoint.Consistent {
		t.Fatalf("independently signed checkpoint rejected: %s", res.Checkpoint.Problem)
	}
	if !strings.Contains(res.Guarantee, "even by the holder of the entry key") {
		t.Errorf("guarantee should claim key-compromise resistance here, got %q", res.Guarantee)
	}
	_ = priv
}

func TestCheckpointOriginIsBound(t *testing.T) {
	path, pub, priv := signedLogWithKey(t, 3)
	cp := checkpointFor(t, path, priv, pub) // origin "test-log"

	res, _ := VerifyLog(path, pub)
	if got := checkAgainstCheckpoint(res.entries, cp, pub, "some-other-log"); got.Consistent {
		t.Error("a checkpoint for a different origin was accepted")
	}
	if got := checkAgainstCheckpoint(res.entries, cp, pub, "test-log"); !got.Consistent {
		t.Errorf("matching origin rejected: %s", got.Problem)
	}
}

// TestGuaranteeUnchangedWhenCheckpointUnverified guards the reverse error.
func TestGuaranteeUnchangedWhenCheckpointUnverified(t *testing.T) {
	path, pub, priv := signedLogWithKey(t, 4)
	cp := checkpointFor(t, path, priv, pub)

	res, _ := VerifyLog(path, pub)
	res.Checkpoint = checkAgainstCheckpoint(res.entries, cp, nil, "") // no key
	res.refineGuarantee()

	if !strings.Contains(res.Guarantee, "deleted from the end") {
		t.Errorf("an unverified checkpoint must not narrow the guarantee, got %q", res.Guarantee)
	}
}

// TestCheckpointVerifiesEntriesWithTheEntryKey guards against confusing the two
// keys. The checkpoint is signed by one key while entries are signed by another,
// so verifying entries with the checkpoint key would fail on every valid log.
func TestCheckpointUsesSeparateKeysCorrectly(t *testing.T) {
	path, entryPub, entryPriv := signedLogWithKey(t, 4)
	_, cpPriv, err := generateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	if keyID(entryPriv.Public().(ed25519.PublicKey)) == keyID(cpPriv.Public().(ed25519.PublicKey)) {
		t.Fatal("test needs two distinct keys")
	}

	res, err := VerifyLog(path, entryPub)
	if err != nil {
		t.Fatal(err)
	}
	if !res.Intact {
		t.Fatalf("log should verify with its own entry key: %s", res.Problem)
	}
	if res.SignaturesVerified != 4 {
		t.Errorf("SignaturesVerified = %d, want 4", res.SignaturesVerified)
	}
}
