package main

import (
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

// These vectors are published in the Adjent Record Format specification at
// github.com/Adjent-dev/spec. They are duplicated here on purpose: this test is
// what stops the implementation and the specification drifting apart, and it can
// only do that if a change to either one breaks it.

const (
	specEmptyPayloadHash = "dd5e855e7e410b27dea3470bbc39e8e2680b69d7a9c4f4c6361cfd9c3aac5ff5"
	specPayloadHashA1B2  = "c569f517e1a63b329ada94dcd75f2789342bdb7f2a786e78440c50ea1ff22ae9"
	specPublicKeyHex     = "03a107bff3ce10be1d70dd18e74bc09967e4d6309ba50d5f1ddc8664125531b8"
	specKeyID            = "56475aa75463474c"

	specEntry0 = `{"seq":0,"time":"2026-08-09T12:00:00Z","action":{"direction":"call","method":"tools/call","tool":"read_file","rpc_id":"1","upstream":"https://example.com/mcp","status":200,"bytes":74},"payload_hash":"c569f517e1a63b329ada94dcd75f2789342bdb7f2a786e78440c50ea1ff22ae9","prev_hash":"0000000000000000000000000000000000000000000000000000000000000000","hash":"059fa8b869ac61d40320a04b2cab49c7027d6547f05ccd50ba0e1bddd411c6e8","sig":"d19d2d8a54d1e7dcc7f8864beac63a2b05dcf032b5a286790549fcf997ae59e7573c21b3689adca79bce1aa433054a954ba3b045770ceeee7ba8a08eee05a308","key_id":"56475aa75463474c"}`
	specEntry1 = `{"seq":1,"time":"2026-08-09T12:00:01Z","action":{"direction":"call","method":"tools/list","status":200,"bytes":40},"payload_hash":"dd5e855e7e410b27dea3470bbc39e8e2680b69d7a9c4f4c6361cfd9c3aac5ff5","prev_hash":"059fa8b869ac61d40320a04b2cab49c7027d6547f05ccd50ba0e1bddd411c6e8","hash":"31c44afd408c461ba5c06c348c6bd11db59304a15ebbf479b77032597c356ef1","sig":"099178f066a7b9e0f89eac14d82632f3c2cf77f054d1a93adcfcf327c142dfec43eded9596c8a44dd2f57c938032793ab726d6ae486a88fc6351dd15c95c500b","key_id":"56475aa75463474c"}`
)

func TestSpecPayloadHashVectors(t *testing.T) {
	if got := hashPayload(nil, nil); got != specEmptyPayloadHash {
		t.Errorf("empty payload hash = %s, spec says %s", got, specEmptyPayloadHash)
	}
	if got := hashPayload([]byte(`{"a":1}`), []byte(`{"b":2}`)); got != specPayloadHashA1B2 {
		t.Errorf("payload hash = %s, spec says %s", got, specPayloadHashA1B2)
	}
}

func TestSpecKeyIDVector(t *testing.T) {
	raw, err := hex.DecodeString(specPublicKeyHex)
	if err != nil {
		t.Fatal(err)
	}
	if got := keyID(ed25519.PublicKey(raw)); got != specKeyID {
		t.Errorf("key_id = %s, spec says %s", got, specKeyID)
	}
}

// TestSpecChainVector is the conformance test proper: the published chain must
// verify, and its hashes must be reproducible from the entry contents alone.
func TestSpecChainVector(t *testing.T) {
	raw, err := hex.DecodeString(specPublicKeyHex)
	if err != nil {
		t.Fatal(err)
	}
	pub := ed25519.PublicKey(raw)

	path := filepath.Join(t.TempDir(), "spec.log")
	if err := os.WriteFile(path, []byte(specEntry0+"\n"+specEntry1+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	res, err := VerifyLog(path, pub)
	if err != nil {
		t.Fatal(err)
	}
	if !res.Intact {
		t.Fatalf("the published chain failed verification at %v: %s", res.BrokenAt, res.Problem)
	}
	if res.Entries != 2 {
		t.Errorf("Entries = %d, want 2", res.Entries)
	}
	if res.SignaturesVerified != 2 {
		t.Errorf("SignaturesVerified = %d, want 2", res.SignaturesVerified)
	}
	if res.KeyID != specKeyID {
		t.Errorf("KeyID = %s, want %s", res.KeyID, specKeyID)
	}
}

// TestSpecVectorSurvivesTrailingNewlineAbsence covers the requirement that a
// verifier not depend on a trailing line feed.
func TestSpecVectorSurvivesTrailingNewlineAbsence(t *testing.T) {
	raw, _ := hex.DecodeString(specPublicKeyHex)
	path := filepath.Join(t.TempDir(), "spec.log")
	if err := os.WriteFile(path, []byte(specEntry0+"\n"+specEntry1), 0o600); err != nil {
		t.Fatal(err)
	}

	res, err := VerifyLog(path, ed25519.PublicKey(raw))
	if err != nil {
		t.Fatal(err)
	}
	if !res.Intact || res.Entries != 2 {
		t.Errorf("chain without a trailing newline did not verify: intact=%v entries=%d", res.Intact, res.Entries)
	}
}

// Checkpoint vector, also published in the specification.
const specCheckpoint = `{"origin":"example-log","size":2,"head":"31c44afd408c461ba5c06c348c6bd11db59304a15ebbf479b77032597c356ef1","time":"2026-08-09T12:05:00Z","key_id":"56475aa75463474c","sig":"32dace99ebc27676b1ab8752995ccd512a66eb3c6ec59e076cdd32cce3488fbe185e47b47d89a1e52a008ac0cc2994ed1cbf31be25fc2ba64819eaaefd87a906"}`

func TestSpecCheckpointVector(t *testing.T) {
	raw, err := hex.DecodeString(specPublicKeyHex)
	if err != nil {
		t.Fatal(err)
	}
	pub := ed25519.PublicKey(raw)

	var cp Checkpoint
	if err := json.Unmarshal([]byte(specCheckpoint), &cp); err != nil {
		t.Fatal(err)
	}
	if !cp.verifySignature(pub) {
		t.Fatal("the published checkpoint vector does not verify")
	}

	// It must also agree with the published chain, since it names its head.
	path := filepath.Join(t.TempDir(), "spec.log")
	if err := os.WriteFile(path, []byte(specEntry0+"\n"+specEntry1+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	res, err := VerifyLog(path, pub)
	if err != nil {
		t.Fatal(err)
	}
	if got := checkAgainstCheckpoint(res.entries, &cp, pub, ""); !got.Consistent {
		t.Fatalf("published checkpoint disagrees with the published chain: %s", got.Problem)
	}
}
