package main

import (
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

// TestEventStreamRelayedAndHashed covers the SSE path, which had no coverage.
func TestEventStreamRelayedAndHashed(t *testing.T) {
	var body strings.Builder
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		w.WriteHeader(http.StatusOK)
		f, _ := w.(http.Flusher)
		for i := 0; i < 5; i++ {
			chunk := fmt.Sprintf("event: message\ndata: {\"n\":%d}\n\n", i)
			body.WriteString(chunk)
			fmt.Fprint(w, chunk)
			if f != nil {
				f.Flush()
			}
		}
	}))
	defer upstream.Close()

	path := tempLog(t)
	l, _ := OpenLog(path, false)
	target, _ := normalizeTarget(upstream.URL)
	front := httptest.NewServer(&recordingProxy{upstream: target, log: l, client: upstream.Client()})
	defer front.Close()

	resp, err := http.Post(front.URL+"/mcp", "application/json",
		strings.NewReader(`{"jsonrpc":"2.0","method":"tools/call","params":{"name":"watch"}}`))
	if err != nil {
		t.Fatal(err)
	}
	var got strings.Builder
	sc := bufio.NewScanner(resp.Body)
	for sc.Scan() {
		got.WriteString(sc.Text())
		got.WriteString("\n")
	}
	resp.Body.Close()
	l.Close()

	if !strings.Contains(got.String(), `{"n":4}`) {
		t.Errorf("last event did not reach the client, got %q", got.String())
	}

	entries := readEntries(t, path)
	if len(entries) != 1 {
		t.Fatalf("recorded %d entries, want 1", len(entries))
	}
	if entries[0].Action.Direction != "call/stream" {
		t.Errorf("Direction = %q, want call/stream", entries[0].Action.Direction)
	}

	// The commitment must cover the whole stream, not a prefix of it.
	sum := sha256.Sum256([]byte(body.String()))
	want := combinePayloadHash(
		digestOf([]byte(`{"jsonrpc":"2.0","method":"tools/call","params":{"name":"watch"}}`)),
		bodyDigest{Len: uint64(body.Len()), Digest: sum},
	)
	if entries[0].PayloadHash != want {
		t.Errorf("payload_hash does not cover the full stream\n got %s\nwant %s (stream sha %s)",
			entries[0].PayloadHash, want, hex.EncodeToString(sum[:]))
	}
}

// TestStreamIsNotBufferedBeforeRelay: buffering an open stream would stall the
// agent until the server closed it, which for SSE may be never.
func TestStreamIsNotBufferedBeforeRelay(t *testing.T) {
	release := make(chan struct{})
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		w.WriteHeader(http.StatusOK)
		f, _ := w.(http.Flusher)
		fmt.Fprint(w, "data: first\n\n")
		if f != nil {
			f.Flush()
		}
		<-release // hold the stream open
		fmt.Fprint(w, "data: last\n\n")
	}))
	defer upstream.Close()

	path := tempLog(t)
	l, _ := OpenLog(path, false)
	target, _ := normalizeTarget(upstream.URL)
	front := httptest.NewServer(&recordingProxy{upstream: target, log: l, client: upstream.Client()})
	defer front.Close()

	resp, err := http.Post(front.URL+"/mcp", "application/json", strings.NewReader(`{"method":"sub"}`))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	first := make(chan string, 1)
	go func() {
		buf := make([]byte, 64)
		n, _ := resp.Body.Read(buf)
		first <- string(buf[:n])
	}()

	select {
	case got := <-first:
		if !strings.Contains(got, "first") {
			t.Errorf("unexpected first chunk %q", got)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("first event never arrived; the proxy is buffering the stream")
	}
	close(release)
	l.Close()
}

// TestConcurrentRecordingKeepsChainIntact: the chain is a shared mutable
// sequence, so parallel requests are where ordering would break.
func TestConcurrentRecordingKeepsChainIntact(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"jsonrpc":"2.0","result":{}}`))
	}))
	defer upstream.Close()

	pub, priv, _ := generateKeyPair()
	path := tempLog(t)
	l, _ := OpenLog(path, false)
	l.WithSigner(priv)

	target, _ := normalizeTarget(upstream.URL)
	front := httptest.NewServer(&recordingProxy{upstream: target, log: l, client: upstream.Client()})
	defer front.Close()

	const workers, each = 16, 20

	var wg sync.WaitGroup
	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func(w int) {
			defer wg.Done()
			for i := 0; i < each; i++ {
				body := fmt.Sprintf(`{"jsonrpc":"2.0","id":%d,"method":"tools/call","params":{"name":"t%d"}}`, i, w)
				resp, err := http.Post(front.URL+"/mcp", "application/json", strings.NewReader(body))
				if err != nil {
					t.Errorf("worker %d: %v", w, err)
					return
				}
				resp.Body.Close()
			}
		}(w)
	}
	wg.Wait()
	if err := l.Close(); err != nil {
		t.Fatal(err)
	}

	res, err := VerifyLog(path, pub)
	if err != nil {
		t.Fatal(err)
	}
	if !res.Intact {
		t.Fatalf("concurrent recording broke the chain at %v: %s", res.BrokenAt, res.Problem)
	}
	if res.Entries != workers*each {
		t.Errorf("Entries = %d, want %d; entries were lost or duplicated", res.Entries, workers*each)
	}
	if res.SignaturesVerified != workers*each {
		t.Errorf("SignaturesVerified = %d, want %d", res.SignaturesVerified, workers*each)
	}
}
