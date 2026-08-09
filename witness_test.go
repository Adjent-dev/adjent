package main

import (
	"crypto/ed25519"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// TestWitnessSurvivesTotalOperatorCompromise is the strongest claim the system
// makes. The attacker holds every key the operator holds: entry key and
// checkpoint key. They can rebuild and re-sign anything. They cannot forge the
// witness countersignature, so the truncation is still caught.
func TestWitnessSurvivesTotalOperatorCompromise(t *testing.T) {
	path, entryPub, entryPriv := signedLogWithKey(t, 6)

	opPub, opPriv, _ := generateKeyPair() // operator's checkpoint key
	wPub, wPriv, _ := generateKeyPair()   // witness key, held elsewhere

	res, err := VerifyLog(path, entryPub)
	if err != nil {
		t.Fatal(err)
	}
	cp := NewCheckpoint("prod", uint64(res.Entries), res.Head, opPriv)
	cp.Countersign(wPriv)

	// Attacker with both operator keys truncates and re-signs everything.
	entries := readEntries(t, path)[:3]
	prev := genesisHash
	for i := range entries {
		entries[i].PrevHash = prev
		entries[i].Hash = computeHash(&entries[i])
		entries[i].Sig = signEntryHash(entryPriv, entries[i].Hash)
		prev = entries[i].Hash
	}
	writeEntries(t, path, entries)

	after, err := VerifyLog(path, entryPub)
	if err != nil {
		t.Fatal(err)
	}
	if !after.Intact {
		t.Fatal("a rebuild with the entry key should pass entry verification")
	}

	// The attacker also mints a replacement checkpoint with the operator key.
	forged := NewCheckpoint("prod", uint64(after.Entries), after.Head, opPriv)
	if got := checkAgainstCheckpoint(after.entries, forged, opPub, "prod"); !got.Consistent {
		t.Fatal("the forged checkpoint should satisfy operator-key verification; that is the gap witnesses close")
	}

	// They cannot produce a witness signature over it.
	got := checkAgainstCheckpoint(after.entries, forged, opPub, "prod")
	got.applyWitnesses(forged, []ed25519.PublicKey{wPub})
	if got.Witnessed != 0 {
		t.Error("a forged checkpoint carried a valid witness signature")
	}

	// Against the genuine witnessed checkpoint, the truncation surfaces.
	real := checkAgainstCheckpoint(after.entries, cp, opPub, "prod")
	real.applyWitnesses(cp, []ed25519.PublicKey{wPub})
	if real.Consistent {
		t.Fatal("truncation was not detected against the witnessed checkpoint")
	}
	if real.Witnessed != 1 {
		t.Errorf("Witnessed = %d, want 1", real.Witnessed)
	}
}

// TestUnnamedWitnessIsIgnored: anyone can append a countersignature, so one the
// verifier did not ask for must count for nothing.
func TestUnnamedWitnessIsIgnored(t *testing.T) {
	_, opPriv, _ := generateKeyPair()
	_, strangerPriv, _ := generateKeyPair()
	trustedPub, trustedPriv, _ := generateKeyPair()

	cp := NewCheckpoint("prod", 3, "abc", opPriv)
	cp.Countersign(strangerPriv)

	res := &CheckpointResult{}
	res.applyWitnesses(cp, []ed25519.PublicKey{trustedPub})
	if res.Witnessed != 0 {
		t.Error("a countersignature from an untrusted key was counted")
	}

	cp.Countersign(trustedPriv)
	res = &CheckpointResult{}
	res.applyWitnesses(cp, []ed25519.PublicKey{trustedPub})
	if res.Witnessed != 1 {
		t.Errorf("Witnessed = %d, want 1", res.Witnessed)
	}
}

// TestWitnessTimeIsSigned: an unauthenticated timestamp could be edited to
// suggest a witness saw the log at a different moment.
func TestWitnessTimeIsSigned(t *testing.T) {
	_, opPriv, _ := generateKeyPair()
	wPub, wPriv, _ := generateKeyPair()

	cp := NewCheckpoint("prod", 3, "abc", opPriv)
	cp.Countersign(wPriv)

	cp.Witnesses[0].Time = cp.Witnesses[0].Time.Add(-48 * 3600 * 1e9)
	if _, ok := cp.verifyWitness(wPub); ok {
		t.Error("an edited witness timestamp still verified")
	}
}

func TestWitnessCannotBeReusedAcrossCheckpoints(t *testing.T) {
	_, opPriv, _ := generateKeyPair()
	wPub, wPriv, _ := generateKeyPair()

	a := NewCheckpoint("prod", 3, "aaa", opPriv)
	a.Countersign(wPriv)

	b := NewCheckpoint("prod", 3, "bbb", opPriv)
	b.Witnesses = a.Witnesses // lift the signature onto a different head

	if _, ok := b.verifyWitness(wPub); ok {
		t.Error("a witness signature was reusable on a different checkpoint")
	}
}

func TestPublishPostsTheCheckpoint(t *testing.T) {
	var got Checkpoint
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		json.Unmarshal(body, &got)
		w.WriteHeader(http.StatusCreated)
	}))
	defer srv.Close()

	_, priv, _ := generateKeyPair()
	cp := NewCheckpoint("prod", 5, "deadbeef", priv)

	if err := publishCheckpoint(srv.URL, cp); err != nil {
		t.Fatalf("publish failed: %v", err)
	}
	if got.Head != "deadbeef" || got.Size != 5 {
		t.Errorf("destination received %+v", got)
	}
}

// TestPublishFailureIsAnError: an operator who believes a checkpoint was
// published when it was not is worse off than one who knows it was not.
func TestPublishFailureIsAnError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "nope", http.StatusInternalServerError)
	}))
	defer srv.Close()

	_, priv, _ := generateKeyPair()
	err := publishCheckpoint(srv.URL, NewCheckpoint("prod", 1, "x", priv))
	if err == nil {
		t.Fatal("a rejected publish reported success")
	}
	if !strings.Contains(err.Error(), "500") {
		t.Errorf("error should name the status, got %v", err)
	}
}

// TestRequiredWitnessMissingIsRejected: asking for a witness must be a
// requirement. A verifier who requested independent attestation and got none
// must not be told the checkpoint is fine.
func TestRequiredWitnessMissingIsRejected(t *testing.T) {
	path, entryPub, _ := signedLogWithKey(t, 3)
	opPub, opPriv, _ := generateKeyPair()
	wPub, _, _ := generateKeyPair()

	res, _ := VerifyLog(path, entryPub)
	cp := NewCheckpoint("prod", uint64(res.Entries), res.Head, opPriv) // no witness

	got := checkAgainstCheckpoint(res.entries, cp, opPub, "prod")
	if !got.Consistent {
		t.Fatalf("precondition: checkpoint should match the log, got %s", got.Problem)
	}

	got.applyWitnesses(cp, []ed25519.PublicKey{wPub})
	if got.Consistent {
		t.Fatal("a checkpoint with no required countersignature was accepted")
	}
	if !strings.Contains(got.Problem, "countersignature") {
		t.Errorf("problem should name the missing witness, got %q", got.Problem)
	}
}

func TestNoWitnessRequestedStaysConsistent(t *testing.T) {
	path, entryPub, _ := signedLogWithKey(t, 3)
	opPub, opPriv, _ := generateKeyPair()

	res, _ := VerifyLog(path, entryPub)
	cp := NewCheckpoint("prod", uint64(res.Entries), res.Head, opPriv)

	got := checkAgainstCheckpoint(res.entries, cp, opPub, "prod")
	got.applyWitnesses(cp, nil)
	if !got.Consistent {
		t.Errorf("requesting no witness must not reject: %s", got.Problem)
	}
}
