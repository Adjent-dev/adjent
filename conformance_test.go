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
	specEmptyPayloadHash = "374708fff7719dd5979ec875d56cd2286f6d3cf7ec317a3b25632aab28ec37bb"
	specPayloadHashA1B2  = "b5a6830bd0e0529cd4a3d4cc171e5392c7c1d38d6fc481cada45beebb9ae5399"
	specPublicKeyHex     = "03a107bff3ce10be1d70dd18e74bc09967e4d6309ba50d5f1ddc8664125531b8"
	specKeyID            = "56475aa75463474c"

	specEntry0 = `{"seq":0,"time":"2026-08-09T12:00:00Z","action":{"direction":"call","method":"tools/call","tool":"read_file","rpc_id":"1","upstream":"https://example.com/mcp","status":200,"bytes":74},"payload_hash":"b5a6830bd0e0529cd4a3d4cc171e5392c7c1d38d6fc481cada45beebb9ae5399","prev_hash":"0000000000000000000000000000000000000000000000000000000000000000","hash":"ba8d7ee17055eeba056ec5ac793ce9b22f7487d60a4702147c084390741e8ba0","sig":"9c8bae9040cd1e9bd7cb64b7db51af9760545cb7c8876448dcc1659ced7eecc60936fb50734bbe69d3dd3a6600b44f7b1903e063c30b76bd38b88e780bb37502","key_id":"56475aa75463474c"}`
	specEntry1 = `{"seq":1,"time":"2026-08-09T12:00:01Z","action":{"direction":"call","method":"tools/list","status":200,"bytes":40},"payload_hash":"374708fff7719dd5979ec875d56cd2286f6d3cf7ec317a3b25632aab28ec37bb","prev_hash":"ba8d7ee17055eeba056ec5ac793ce9b22f7487d60a4702147c084390741e8ba0","hash":"9c980918e691dd3afef05872b4c67cbe51251e93a627314d7386a6224ad5f9c1","sig":"52b5158b800cc904c5967d83dd432d4f49c19e2a48f550b635e3811ed4ccfcd69f1df46406422dfc8f2d2b29d91cc334e467666636903ef9d648d1c69c8f9a0b","key_id":"56475aa75463474c"}`
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
const specCheckpoint = `{"origin":"example-log","size":2,"head":"9c980918e691dd3afef05872b4c67cbe51251e93a627314d7386a6224ad5f9c1","time":"2026-08-09T12:05:00Z","key_id":"56475aa75463474c","sig":"3349351f4cd7616b7858cbb2a64cac935a26e5b6e49a12fb013e0d97df133307d3ac5def9f1931748937bcd378046537a6f515e3f4cfbf7430137ca0b7a9f80b"}`

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
	if got := checkAgainstCheckpoint(res.entries, &cp, pub); !got.Consistent {
		t.Fatalf("published checkpoint disagrees with the published chain: %s", got.Problem)
	}
}
