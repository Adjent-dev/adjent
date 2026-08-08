package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func tempLog(t *testing.T) string {
	t.Helper()
	return filepath.Join(t.TempDir(), "adjent.log")
}

func appendN(t *testing.T, path string, n int, retain bool) {
	t.Helper()
	l, err := OpenLog(path, retain)
	if err != nil {
		t.Fatalf("OpenLog: %v", err)
	}
	defer l.Close()

	for i := 0; i < n; i++ {
		_, err := l.Append(
			Action{Direction: "call", Method: "tools/call", Tool: "read_file", Status: 200},
			[]byte(`{"jsonrpc":"2.0","method":"tools/call"}`),
			[]byte(`{"jsonrpc":"2.0","result":{}}`),
		)
		if err != nil {
			t.Fatalf("Append %d: %v", i, err)
		}
	}
}

// readEntries loads a log as raw entries so tests can tamper with it the way an
// attacker with file access would.
func readEntries(t *testing.T, path string) []Entry {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("reading log: %v", err)
	}
	var out []Entry
	for _, line := range strings.Split(strings.TrimSpace(string(data)), "\n") {
		if line == "" {
			continue
		}
		var e Entry
		if err := json.Unmarshal([]byte(line), &e); err != nil {
			t.Fatalf("parsing log line: %v", err)
		}
		out = append(out, e)
	}
	return out
}

func writeEntries(t *testing.T, path string, entries []Entry) {
	t.Helper()
	var b strings.Builder
	for _, e := range entries {
		line, err := json.Marshal(e)
		if err != nil {
			t.Fatalf("encoding entry: %v", err)
		}
		b.Write(line)
		b.WriteByte('\n')
	}
	if err := os.WriteFile(path, []byte(b.String()), 0o600); err != nil {
		t.Fatalf("writing log: %v", err)
	}
}

func TestChainVerifiesWhenUntouched(t *testing.T) {
	path := tempLog(t)
	appendN(t, path, 5, false)

	res, err := VerifyLog(path)
	if err != nil {
		t.Fatalf("VerifyLog: %v", err)
	}
	if !res.Intact {
		t.Fatalf("expected an intact chain, got problem at %v: %s", res.BrokenAt, res.Problem)
	}
	if res.Entries != 5 {
		t.Errorf("Entries = %d, want 5", res.Entries)
	}
}

// TestChainSurvivesReopen covers the case that matters in production: the
// process restarts and must continue the existing chain rather than starting a
// new one or corrupting the link.
func TestChainSurvivesReopen(t *testing.T) {
	path := tempLog(t)
	appendN(t, path, 3, false)
	appendN(t, path, 3, false)

	res, err := VerifyLog(path)
	if err != nil {
		t.Fatalf("VerifyLog: %v", err)
	}
	if !res.Intact {
		t.Fatalf("chain broke across reopen at %v: %s", res.BrokenAt, res.Problem)
	}
	if res.Entries != 6 {
		t.Errorf("Entries = %d, want 6", res.Entries)
	}
}

func TestModifiedEntryIsDetected(t *testing.T) {
	path := tempLog(t)
	appendN(t, path, 5, false)

	entries := readEntries(t, path)
	// Change what an agent appears to have done, leaving everything else
	// including the stored hash untouched.
	entries[2].Action.Tool = "delete_everything"
	writeEntries(t, path, entries)

	res, err := VerifyLog(path)
	if err != nil {
		t.Fatalf("VerifyLog: %v", err)
	}
	if res.Intact {
		t.Fatal("a modified entry was not detected")
	}
	if res.BrokenAt == nil || *res.BrokenAt != 2 {
		t.Errorf("BrokenAt = %v, want 2", res.BrokenAt)
	}
}

// TestRehashedEntryIsStillDetected is the important one. A naive design lets an
// attacker edit an entry and recompute its hash. The chain must still break,
// because every later entry commits to the old hash.
func TestRehashedEntryIsStillDetected(t *testing.T) {
	path := tempLog(t)
	appendN(t, path, 5, false)

	entries := readEntries(t, path)
	entries[1].Action.Tool = "exfiltrate"
	entries[1].Hash = computeHash(&entries[1]) // attacker repairs the entry
	writeEntries(t, path, entries)

	res, err := VerifyLog(path)
	if err != nil {
		t.Fatalf("VerifyLog: %v", err)
	}
	if res.Intact {
		t.Fatal("a re-hashed entry was not detected")
	}
	// Entry 1 now verifies on its own, so the break surfaces at entry 2, which
	// still points at the original hash of entry 1.
	if res.BrokenAt == nil || *res.BrokenAt != 2 {
		t.Errorf("BrokenAt = %v, want 2", res.BrokenAt)
	}
}

func TestRemovedEntryIsDetected(t *testing.T) {
	path := tempLog(t)
	appendN(t, path, 5, false)

	entries := readEntries(t, path)
	entries = append(entries[:2], entries[3:]...) // delete entry 2
	writeEntries(t, path, entries)

	res, err := VerifyLog(path)
	if err != nil {
		t.Fatalf("VerifyLog: %v", err)
	}
	if res.Intact {
		t.Fatal("a removed entry was not detected")
	}
}

func TestSubstitutedPayloadIsDetected(t *testing.T) {
	path := tempLog(t)
	appendN(t, path, 3, true)

	entries := readEntries(t, path)
	if entries[1].Payload == nil {
		t.Fatal("expected bodies to be retained")
	}
	entries[1].Payload.Request = json.RawMessage(`{"jsonrpc":"2.0","method":"something/else"}`)
	writeEntries(t, path, entries)

	res, err := VerifyLog(path)
	if err != nil {
		t.Fatalf("VerifyLog: %v", err)
	}
	if res.Intact {
		t.Fatal("a substituted body was not detected")
	}
	if !strings.Contains(res.Problem, "bodies") {
		t.Errorf("problem should name the payload, got %q", res.Problem)
	}
}

// TestTruncationIsNotDetected documents a real limitation rather than asserting
// a capability. Deleting entries from the end leaves a shorter chain that still
// verifies. Closing this gap requires anchoring the head hash somewhere the
// operator does not control, which is the Verify stage of this project.
//
// If this test ever starts failing, the limitation has been fixed and the
// claims in log.go, the README, and the verify output all need updating.
func TestTruncationIsNotDetected(t *testing.T) {
	path := tempLog(t)
	appendN(t, path, 5, false)

	entries := readEntries(t, path)
	writeEntries(t, path, entries[:3])

	res, err := VerifyLog(path)
	if err != nil {
		t.Fatalf("VerifyLog: %v", err)
	}
	if !res.Intact {
		t.Fatal("a truncated log unexpectedly failed verification; if this is a real fix, update the documented limitation")
	}
	if res.Entries != 3 {
		t.Errorf("Entries = %d, want 3", res.Entries)
	}
}

func TestBodiesAreNotStoredByDefault(t *testing.T) {
	path := tempLog(t)
	appendN(t, path, 2, false)

	for _, e := range readEntries(t, path) {
		if e.Payload != nil {
			t.Errorf("entry %d stored a body when retention was off", e.Seq)
		}
		if e.PayloadHash == "" {
			t.Errorf("entry %d has no payload hash, so the bodies are not committed to", e.Seq)
		}
	}
}

func TestHashCommitsToEveryField(t *testing.T) {
	base := Entry{
		Seq: 1, PrevHash: genesisHash, PayloadHash: "abc",
		Action: Action{Direction: "call", Method: "tools/call", Tool: "read", Status: 200, Bytes: 10},
	}
	original := computeHash(&base)

	mutations := map[string]func(*Entry){
		"seq":       func(e *Entry) { e.Seq = 2 },
		"prev hash": func(e *Entry) { e.PrevHash = "ffff" },
		"payload":   func(e *Entry) { e.PayloadHash = "def" },
		"direction": func(e *Entry) { e.Action.Direction = "reply" },
		"method":    func(e *Entry) { e.Action.Method = "tools/list" },
		"tool":      func(e *Entry) { e.Action.Tool = "write" },
		"status":    func(e *Entry) { e.Action.Status = 500 },
		"bytes":     func(e *Entry) { e.Action.Bytes = 11 },
		"error":     func(e *Entry) { e.Action.Err = "boom" },
	}

	for name, mutate := range mutations {
		e := base
		mutate(&e)
		if computeHash(&e) == original {
			t.Errorf("changing %s did not change the hash, so that field is not committed to", name)
		}
	}
}

// TestFieldBoundariesAreUnambiguous guards the length-prefixing. Without it,
// two different entries could hash identically by shifting characters across a
// field boundary, letting one be substituted for the other undetected.
func TestFieldBoundariesAreUnambiguous(t *testing.T) {
	a := Entry{Seq: 1, PrevHash: genesisHash, Action: Action{Method: "ab", Tool: "c"}}
	b := Entry{Seq: 1, PrevHash: genesisHash, Action: Action{Method: "a", Tool: "bc"}}

	if computeHash(&a) == computeHash(&b) {
		t.Error("entries with different field boundaries hash identically")
	}
}

func TestProxyRecordsAndForwards(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"jsonrpc":"2.0","id":1,"result":{"content":"hello"}}`))
	}))
	defer upstream.Close()

	path := tempLog(t)
	l, err := OpenLog(path, false)
	if err != nil {
		t.Fatal(err)
	}

	target, _ := normalizeTarget(upstream.URL)
	front := httptest.NewServer(&recordingProxy{
		upstream: target,
		log:      l,
		client:   upstream.Client(),
	})
	defer front.Close()

	body := `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"read_file"}}`
	resp, err := http.Post(front.URL+"/mcp", "application/json", strings.NewReader(body))
	if err != nil {
		t.Fatalf("proxied request failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("status = %d, want 200", resp.StatusCode)
	}
	if err := l.Close(); err != nil {
		t.Fatal(err)
	}

	entries := readEntries(t, path)
	if len(entries) != 1 {
		t.Fatalf("recorded %d entries, want 1", len(entries))
	}
	got := entries[0].Action
	if got.Method != "tools/call" {
		t.Errorf("Method = %q, want tools/call", got.Method)
	}
	if got.Tool != "read_file" {
		t.Errorf("Tool = %q, want read_file", got.Tool)
	}
	if got.Status != http.StatusOK {
		t.Errorf("Status = %d, want 200", got.Status)
	}

	res, err := VerifyLog(path)
	if err != nil || !res.Intact {
		t.Errorf("recorded log did not verify: %v %+v", err, res)
	}
}

// TestProxyRecordsEvenWhenUpstreamFails covers the case an audit cares about
// most. A failed action is still an action, and a recorder that only writes on
// success produces a log that flatters the operator.
func TestProxyRecordsEvenWhenUpstreamFails(t *testing.T) {
	dead := httptest.NewServer(http.NewServeMux())
	deadURL := dead.URL
	dead.Close()

	path := tempLog(t)
	l, err := OpenLog(path, false)
	if err != nil {
		t.Fatal(err)
	}

	target, _ := normalizeTarget(deadURL)
	front := httptest.NewServer(&recordingProxy{
		upstream: target,
		log:      l,
		client:   http.DefaultClient,
	})
	defer front.Close()

	resp, err := http.Post(front.URL+"/mcp", "application/json",
		strings.NewReader(`{"jsonrpc":"2.0","id":9,"method":"tools/list"}`))
	if err != nil {
		t.Fatalf("request to proxy failed: %v", err)
	}
	resp.Body.Close()

	if err := l.Close(); err != nil {
		t.Fatal(err)
	}

	entries := readEntries(t, path)
	if len(entries) != 1 {
		t.Fatalf("recorded %d entries, want 1", len(entries))
	}
	if entries[0].Action.Err == "" {
		t.Error("a failed upstream call was recorded without an error")
	}
	if entries[0].Action.Method != "tools/list" {
		t.Errorf("Method = %q, want tools/list", entries[0].Action.Method)
	}
}

func TestResolvePath(t *testing.T) {
	cases := []struct{ upstream, incoming, want string }{
		// An upstream with a path names the endpoint exactly, so /mcp must not
		// become /mcp/mcp when the agent mirrors the URL.
		{"/mcp", "/mcp", "/mcp"},
		{"/mcp", "/", "/mcp"},
		{"/mcp", "/anything", "/mcp"},
		// A bare origin relays whatever the agent asked for.
		{"", "/mcp", "/mcp"},
		{"/", "/mcp", "/mcp"},
	}
	for _, c := range cases {
		if got := resolvePath(c.upstream, c.incoming); got != c.want {
			t.Errorf("resolvePath(%q, %q) = %q, want %q", c.upstream, c.incoming, got, c.want)
		}
	}
}
