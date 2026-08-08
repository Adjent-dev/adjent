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

	got := checkAgainstCheckpoint(res.entries, cp, pub)
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
	got := checkAgainstCheckpoint(res.entries, cp, pub)
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

	got := checkAgainstCheckpoint(res.entries, cp, pub)
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
	if got := checkAgainstCheckpoint(res.entries, &forged, pub); got.Consistent {
		t.Error("a checkpoint with a tampered size was accepted")
	}

	other, _, _ := generateKeyPair()
	if got := checkAgainstCheckpoint(res.entries, cp, other); got.Consistent {
		t.Error("a checkpoint verified against an unrelated key")
	}
}

func TestCheckpointWithoutKeyDoesNotClaimVerification(t *testing.T) {
	path, pub, priv := signedLogWithKey(t, 3)
	cp := checkpointFor(t, path, priv, pub)

	res, _ := VerifyLog(path, pub)
	got := checkAgainstCheckpoint(res.entries, cp, nil)

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

	res.Checkpoint = checkAgainstCheckpoint(res.entries, cp, pub)
	res.refineGuarantee()

	if strings.Contains(res.Guarantee, "deleted from the end") {
		t.Errorf("truncation caveat survived a verified checkpoint: %q", res.Guarantee)
	}
	if !strings.Contains(res.Guarantee, "including by the holder of the key") {
		t.Errorf("refined guarantee should state the key holder is covered, got %q", res.Guarantee)
	}
}

// TestGuaranteeUnchangedWhenCheckpointUnverified guards the reverse error.
func TestGuaranteeUnchangedWhenCheckpointUnverified(t *testing.T) {
	path, pub, priv := signedLogWithKey(t, 4)
	cp := checkpointFor(t, path, priv, pub)

	res, _ := VerifyLog(path, pub)
	res.Checkpoint = checkAgainstCheckpoint(res.entries, cp, nil) // no key
	res.refineGuarantee()

	if !strings.Contains(res.Guarantee, "deleted from the end") {
		t.Errorf("an unverified checkpoint must not narrow the guarantee, got %q", res.Guarantee)
	}
}
