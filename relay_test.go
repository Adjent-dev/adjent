package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
)

// TestLargeBodyRelayedIntact is the regression for the worst defect this code
// had: bodies over the cap were truncated in transit, so the server received
// something the client never sent.
func TestLargeBodyRelayedIntact(t *testing.T) {
	const size = 6 << 20 // above the old 4 MiB cap

	payload := bytes.Repeat([]byte("x"), size)
	var received []byte
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		received, _ = io.ReadAll(r.Body)
		w.Write([]byte(`{"ok":true}`))
	}))
	defer upstream.Close()

	path := tempLog(t)
	l, _ := OpenLog(path, false)
	target, _ := normalizeTarget(upstream.URL)
	front := httptest.NewServer(&recordingProxy{upstream: target, log: l, client: upstream.Client()})
	defer front.Close()

	resp, err := http.Post(front.URL+"/mcp", "application/json", bytes.NewReader(payload))
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	l.Close()

	if len(received) != size {
		t.Fatalf("upstream received %d bytes, client sent %d; the proxy altered the request", len(received), size)
	}
	if !bytes.Equal(received, payload) {
		t.Fatal("upstream received different bytes than were sent")
	}
}

// TestPayloadHashCoversWhatWasRelayed: the commitment must describe the traffic
// that actually happened, not a prefix of it.
func TestPayloadHashCoversWhatWasRelayed(t *testing.T) {
	reqBody := bytes.Repeat([]byte("a"), 5<<20)
	respBody := bytes.Repeat([]byte("b"), 5<<20)

	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.Copy(io.Discard, r.Body)
		w.Write(respBody)
	}))
	defer upstream.Close()

	path := tempLog(t)
	l, _ := OpenLog(path, true) // retain, so storage is capped while the hash is not
	target, _ := normalizeTarget(upstream.URL)
	front := httptest.NewServer(&recordingProxy{upstream: target, log: l, client: upstream.Client()})
	defer front.Close()

	resp, err := http.Post(front.URL+"/mcp", "application/json", bytes.NewReader(reqBody))
	if err != nil {
		t.Fatal(err)
	}
	got, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	l.Close()

	if !bytes.Equal(got, respBody) {
		t.Fatalf("client received %d bytes, upstream sent %d", len(got), len(respBody))
	}

	entries := readEntries(t, path)
	want := combinePayloadHash(
		bodyDigest{Len: uint64(len(reqBody)), Digest: sha256.Sum256(reqBody)},
		bodyDigest{Len: uint64(len(respBody)), Digest: sha256.Sum256(respBody)},
	)
	if entries[0].PayloadHash != want {
		t.Errorf("payload_hash = %s, want %s (commitment must cover the full bodies)",
			entries[0].PayloadHash, want)
	}
	if entries[0].Payload == nil || !entries[0].Payload.Partial {
		t.Error("stored bodies were capped but the entry does not say so")
	}

	// A partial payload must not be recomputed against the full-body hash.
	res, err := VerifyLog(path, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !res.Intact {
		t.Errorf("a correctly partial record failed verification: %s", res.Problem)
	}
}

// TestOversizeRequestIsRefusedNotTruncated: past the relay limit the request is
// rejected and recorded as never having reached the server.
func TestOversizeRequestIsRefusedNotTruncated(t *testing.T) {
	var reached bool
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		reached = true
	}))
	defer upstream.Close()

	path := tempLog(t)
	l, _ := OpenLog(path, false)
	target, _ := normalizeTarget(upstream.URL)
	front := httptest.NewServer(&recordingProxy{upstream: target, log: l, client: upstream.Client()})
	defer front.Close()

	resp, err := http.Post(front.URL+"/mcp", "application/json",
		bytes.NewReader(bytes.Repeat([]byte("z"), maxRelay+1024)))
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	l.Close()

	if resp.StatusCode != http.StatusRequestEntityTooLarge {
		t.Errorf("status = %d, want 413", resp.StatusCode)
	}
	if reached {
		t.Error("a truncated request was forwarded upstream")
	}
	entries := readEntries(t, path)
	if len(entries) != 1 || entries[0].Action.Err == "" {
		t.Error("the refusal was not recorded")
	}
}

func TestHashingRelayMatchesBufferedHash(t *testing.T) {
	body := bytes.Repeat([]byte("stream"), 100000)
	var sink bytes.Buffer
	c := &hashingRelay{dst: &sink, limit: 1024}
	c.run(bytes.NewReader(body))

	if !bytes.Equal(sink.Bytes(), body) {
		t.Fatal("relayed bytes differ from the source")
	}
	d := c.digest()
	if d.Len != uint64(len(body)) {
		t.Errorf("Len = %d, want %d", d.Len, len(body))
	}
	want := sha256.Sum256(body)
	if hex.EncodeToString(d.Digest[:]) != hex.EncodeToString(want[:]) {
		t.Error("streamed digest differs from the buffered digest")
	}
	if !c.truncated || len(c.stored) != 1024 {
		t.Errorf("storage cap not applied: truncated=%v stored=%d", c.truncated, len(c.stored))
	}
}
