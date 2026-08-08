package main

import (
	"strings"
	"testing"
)

func TestNormalizeTarget(t *testing.T) {
	cases := []struct {
		in      string
		want    string
		wantErr bool
	}{
		{in: "https://example.com/mcp", want: "https://example.com/mcp"},
		{in: "http://localhost:8080/mcp", want: "http://localhost:8080/mcp"},
		// A bare host is assumed to be HTTPS rather than rejected, because
		// typing the scheme every time is friction and HTTPS is the safe guess.
		{in: "example.com/mcp", want: "https://example.com/mcp"},
		{in: "example.com", want: "https://example.com"},
		{in: "", wantErr: true},
		{in: "https://", wantErr: true},
	}

	for _, c := range cases {
		got, err := normalizeTarget(c.in)
		if c.wantErr {
			if err == nil {
				t.Errorf("normalizeTarget(%q): expected an error, got %q", c.in, got)
			}
			continue
		}
		if err != nil {
			t.Errorf("normalizeTarget(%q): unexpected error %v", c.in, err)
			continue
		}
		if got.String() != c.want {
			t.Errorf("normalizeTarget(%q) = %q, want %q", c.in, got.String(), c.want)
		}
	}
}

func TestWellKnownCandidates(t *testing.T) {
	u, err := normalizeTarget("https://example.com/mcp")
	if err != nil {
		t.Fatal(err)
	}

	got := wellKnownCandidates(u)
	want := []string{
		"https://example.com/.well-known/oauth-protected-resource/mcp",
		"https://example.com/.well-known/oauth-protected-resource",
	}

	if len(got) != len(want) {
		t.Fatalf("got %d candidates %v, want %d", len(got), got, len(want))
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("candidate %d = %q, want %q", i, got[i], want[i])
		}
	}
}

// TestWellKnownCandidatesRootPath covers a server mounted at the origin, where
// there is no path segment to append and only the root form applies.
func TestWellKnownCandidatesRootPath(t *testing.T) {
	u, err := normalizeTarget("https://example.com")
	if err != nil {
		t.Fatal(err)
	}

	got := wellKnownCandidates(u)
	if len(got) != 1 {
		t.Fatalf("got %d candidates %v, want 1", len(got), got)
	}
	if got[0] != "https://example.com/.well-known/oauth-protected-resource" {
		t.Errorf("got %q", got[0])
	}
}

func TestASMetadataCandidatesCoverBothConventions(t *testing.T) {
	got := asMetadataCandidates("https://auth.example.com/tenant1")

	var hasRFC8414, hasOIDC bool
	for _, c := range got {
		if strings.Contains(c, "oauth-authorization-server") {
			hasRFC8414 = true
		}
		if strings.Contains(c, "openid-configuration") {
			hasOIDC = true
		}
	}

	if !hasRFC8414 {
		t.Error("expected an RFC 8414 candidate")
	}
	if !hasOIDC {
		t.Error("expected an OpenID Connect discovery candidate")
	}

	// RFC 8414 places the well-known segment before the issuer path, which is
	// the form most easily got wrong.
	want := "https://auth.example.com/.well-known/oauth-authorization-server/tenant1"
	if got[0] != want {
		t.Errorf("first candidate = %q, want %q", got[0], want)
	}
}

func TestContainsFoldIsCaseInsensitive(t *testing.T) {
	methods := []string{"plain", "s256"}
	if !containsFold(methods, "S256") {
		t.Error("expected S256 to match s256")
	}
	if containsFold(methods, "S512") {
		t.Error("did not expect S512 to match")
	}
	if containsFold(nil, "S256") {
		t.Error("did not expect a match in an empty list")
	}
}

func TestFinalizeVerdicts(t *testing.T) {
	cases := []struct {
		name             string
		checks           []Check
		wantConformant   bool
		wantInconclusive bool
	}{
		{
			name:           "all passing",
			checks:         []Check{{Severity: SevMust, Status: StatusPass}},
			wantConformant: true,
		},
		{
			name:           "MUST failure is non-conformant",
			checks:         []Check{{Severity: SevMust, Status: StatusFail}},
			wantConformant: false,
		},
		{
			name:           "SHOULD failure does not break conformance",
			checks:         []Check{{Severity: SevShould, Status: StatusFail}},
			wantConformant: true,
		},
		{
			name:           "a deliberate skip does not make the run inconclusive",
			checks:         []Check{{Severity: SevMust, Status: StatusSkip}},
			wantConformant: true,
		},
		{
			name:             "an incomplete MUST check makes the run inconclusive",
			checks:           []Check{{Severity: SevMust, Status: StatusUnknown}},
			wantConformant:   true,
			wantInconclusive: true,
		},
		{
			name:           "an incomplete SHOULD check is not enough to be inconclusive",
			checks:         []Check{{Severity: SevShould, Status: StatusUnknown}},
			wantConformant: true,
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			r := &Report{Checks: c.checks}
			r.finalize()

			if r.Conformant != c.wantConformant {
				t.Errorf("Conformant = %v, want %v", r.Conformant, c.wantConformant)
			}
			if r.Inconclusive != c.wantInconclusive {
				t.Errorf("Inconclusive = %v, want %v", r.Inconclusive, c.wantInconclusive)
			}
		})
	}
}

func TestWrapBreaksOnWordBoundaries(t *testing.T) {
	lines := wrap("the quick brown fox jumps over the lazy dog", 15)

	if len(lines) < 2 {
		t.Fatalf("expected the text to wrap, got %v", lines)
	}
	for _, l := range lines {
		if len(l) > 15 {
			t.Errorf("line %q exceeds the requested width", l)
		}
	}
	if strings.Join(lines, " ") != "the quick brown fox jumps over the lazy dog" {
		t.Errorf("wrapping lost or altered words: %v", lines)
	}
}

func TestWrapHandlesEmptyInput(t *testing.T) {
	if got := wrap("", 20); got != nil {
		t.Errorf("wrap(\"\") = %v, want nil", got)
	}
}

func TestMarkerCoversEveryStatus(t *testing.T) {
	seen := map[string]bool{}
	for _, s := range []Status{StatusPass, StatusFail, StatusWarn, StatusSkip, StatusUnknown} {
		label, _ := marker(s)
		if label == "" {
			t.Errorf("status %q has no label", s)
		}
		if seen[label] {
			t.Errorf("status %q reuses the label %q", s, label)
		}
		seen[label] = true
	}
}
