package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"
)

// The tests below stand up fake MCP servers in-process. Nothing here touches
// infrastructure belonging to anyone else, which is the same constraint the
// tool itself operates under.

type asOptions struct {
	pkceMethods  []string
	registration bool
	serve        bool
}

func newAuthServer(t *testing.T, opt asOptions) *httptest.Server {
	t.Helper()

	mux := http.NewServeMux()
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	if !opt.serve {
		return srv
	}

	mux.HandleFunc("/.well-known/oauth-authorization-server", func(w http.ResponseWriter, r *http.Request) {
		meta := authServerMetadata{
			Issuer:                        srv.URL,
			AuthorizationEndpoint:         srv.URL + "/authorize",
			TokenEndpoint:                 srv.URL + "/token",
			CodeChallengeMethodsSupported: opt.pkceMethods,
		}
		if opt.registration {
			meta.RegistrationEndpoint = srv.URL + "/register"
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(meta)
	})

	return srv
}

type resourceOptions struct {
	servePRM      bool
	resource      string // empty means "derive from the server's own URL"
	authServers   []string
	challenge     bool
	challengeCode int
}

func newResourceServer(t *testing.T, opt resourceOptions) *httptest.Server {
	t.Helper()

	mux := http.NewServeMux()
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	mux.HandleFunc("/.well-known/oauth-protected-resource/mcp", func(w http.ResponseWriter, r *http.Request) {
		if !opt.servePRM {
			http.NotFound(w, r)
			return
		}
		resource := opt.resource
		if resource == "" {
			resource = srv.URL + "/mcp"
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(protectedResourceMetadata{
			Resource:             resource,
			AuthorizationServers: opt.authServers,
		})
	})

	mux.HandleFunc("/mcp", func(w http.ResponseWriter, r *http.Request) {
		code := opt.challengeCode
		if code == 0 {
			code = http.StatusUnauthorized
		}
		if opt.challenge {
			w.Header().Set("WWW-Authenticate",
				fmt.Sprintf(`Bearer resource_metadata="%s/.well-known/oauth-protected-resource/mcp"`, srv.URL))
		}
		w.WriteHeader(code)
	})

	return srv
}

func scan(t *testing.T, target string) *Report {
	t.Helper()

	u, err := normalizeTarget(target)
	if err != nil {
		t.Fatalf("normalizeTarget(%q): %v", target, err)
	}

	report := &Report{Target: u.String(), Spec: specRev, Scanned: time.Now().UTC()}
	s := &scanner{
		client: &http.Client{Timeout: 5 * time.Second},
		target: u,
		report: report,
	}
	s.run()
	report.finalize()
	return report
}

// find returns the check with the given ID, failing the test if it is absent.
func find(t *testing.T, r *Report, id string) Check {
	t.Helper()
	for _, c := range r.Checks {
		if c.ID == id {
			return c
		}
	}
	t.Fatalf("no check with ID %q in report (have %d checks)", id, len(r.Checks))
	return Check{}
}

func TestFullyConformantServer(t *testing.T) {
	as := newAuthServer(t, asOptions{serve: true, pkceMethods: []string{"S256"}, registration: true})
	rs := newResourceServer(t, resourceOptions{
		servePRM:    true,
		authServers: []string{as.URL},
		challenge:   true,
	})

	r := scan(t, rs.URL+"/mcp")

	if !r.Conformant {
		t.Errorf("expected conformant, got not conformant")
	}
	if r.Inconclusive {
		t.Errorf("expected a conclusive result")
	}

	for _, id := range []string{"PRM", "PRM-RESOURCE", "WWW-AUTH", "AS-METADATA", "PKCE", "DCR"} {
		if got := find(t, r, id).Status; got != StatusPass {
			t.Errorf("check %s: got %s, want pass", id, got)
		}
	}

	// Resource indicator enforcement is never claimed, on any server.
	if got := find(t, r, "RFC8707").Status; got != StatusSkip {
		t.Errorf("RFC8707: got %s, want skip", got)
	}
}

func TestMissingProtectedResourceMetadata(t *testing.T) {
	rs := newResourceServer(t, resourceOptions{servePRM: false, challenge: true})

	r := scan(t, rs.URL+"/mcp")

	if r.Conformant {
		t.Errorf("expected non-conformant when RFC 9728 metadata is absent")
	}
	if r.Inconclusive {
		t.Errorf("a reachable server that omits metadata is a finding, not an inconclusive run")
	}
	if got := find(t, r, "PRM").Status; got != StatusFail {
		t.Errorf("PRM: got %s, want fail", got)
	}
	// Without metadata there is no authorization server to look up, but the
	// server answered us, so this is out of scope rather than unknown.
	if got := find(t, r, "AS-METADATA").Status; got != StatusSkip {
		t.Errorf("AS-METADATA: got %s, want skip", got)
	}
}

func TestMetadataMissingAuthorizationServers(t *testing.T) {
	rs := newResourceServer(t, resourceOptions{
		servePRM:    true,
		authServers: nil,
		challenge:   true,
	})

	r := scan(t, rs.URL+"/mcp")

	if r.Conformant {
		t.Errorf("expected non-conformant when authorization_servers is missing")
	}
	if got := find(t, r, "PRM").Status; got != StatusFail {
		t.Errorf("PRM: got %s, want fail", got)
	}
}

func TestResourceIdentifierMismatch(t *testing.T) {
	as := newAuthServer(t, asOptions{serve: true, pkceMethods: []string{"S256"}, registration: true})
	rs := newResourceServer(t, resourceOptions{
		servePRM:    true,
		resource:    "https://someone-elses-host.example.com/mcp",
		authServers: []string{as.URL},
		challenge:   true,
	})

	r := scan(t, rs.URL+"/mcp")

	if got := find(t, r, "PRM-RESOURCE").Status; got != StatusWarn {
		t.Errorf("PRM-RESOURCE: got %s, want warn", got)
	}
	// A mismatched identifier is a SHOULD, so it must not fail the build.
	if !r.Conformant {
		t.Errorf("a SHOULD-level warning must not make the server non-conformant")
	}
}

func TestAuthorizationServerWithoutS256(t *testing.T) {
	as := newAuthServer(t, asOptions{serve: true, pkceMethods: []string{"plain"}})
	rs := newResourceServer(t, resourceOptions{
		servePRM:    true,
		authServers: []string{as.URL},
		challenge:   true,
	})

	r := scan(t, rs.URL+"/mcp")

	if r.Conformant {
		t.Errorf("expected non-conformant without PKCE S256")
	}
	if got := find(t, r, "PKCE").Status; got != StatusFail {
		t.Errorf("PKCE: got %s, want fail", got)
	}
	if got := find(t, r, "DCR").Status; got != StatusWarn {
		t.Errorf("DCR: got %s, want warn when no registration endpoint is advertised", got)
	}
}

func TestAuthorizationServerWithoutMetadata(t *testing.T) {
	as := newAuthServer(t, asOptions{serve: false})
	rs := newResourceServer(t, resourceOptions{
		servePRM:    true,
		authServers: []string{as.URL},
		challenge:   true,
	})

	r := scan(t, rs.URL+"/mcp")

	if r.Conformant {
		t.Errorf("expected non-conformant when the advertised AS publishes no metadata")
	}
	if got := find(t, r, "AS-METADATA").Status; got != StatusFail {
		t.Errorf("AS-METADATA: got %s, want fail", got)
	}
}

func TestChallengeWithoutResourceMetadataPointer(t *testing.T) {
	as := newAuthServer(t, asOptions{serve: true, pkceMethods: []string{"S256"}, registration: true})
	rs := newResourceServer(t, resourceOptions{
		servePRM:    true,
		authServers: []string{as.URL},
		challenge:   false, // returns 401 but advertises nothing
	})

	r := scan(t, rs.URL+"/mcp")

	if got := find(t, r, "WWW-AUTH").Status; got != StatusFail {
		t.Errorf("WWW-AUTH: got %s, want fail", got)
	}
	// SHOULD-level, so the overall verdict stays conformant.
	if !r.Conformant {
		t.Errorf("a SHOULD-level failure must not make the server non-conformant")
	}
}

func TestEndpointNotChallenging(t *testing.T) {
	as := newAuthServer(t, asOptions{serve: true, pkceMethods: []string{"S256"}, registration: true})
	rs := newResourceServer(t, resourceOptions{
		servePRM:      true,
		authServers:   []string{as.URL},
		challengeCode: http.StatusOK,
	})

	r := scan(t, rs.URL+"/mcp")

	if got := find(t, r, "WWW-AUTH").Status; got != StatusWarn {
		t.Errorf("WWW-AUTH: got %s, want warn when the endpoint does not return 401", got)
	}
}

// TestUnreachableServerIsInconclusive guards the distinction the tool exists to
// make: a server we cannot reach has not been shown to be non-conformant.
func TestUnreachableServerIsInconclusive(t *testing.T) {
	// Bind and immediately close, so the port is almost certainly refusing.
	dead := httptest.NewServer(http.NewServeMux())
	target := dead.URL + "/mcp"
	dead.Close()

	r := scan(t, target)

	if !r.Inconclusive {
		t.Fatalf("expected an inconclusive run for an unreachable server")
	}
	if got := find(t, r, "PRM").Status; got != StatusUnknown {
		t.Errorf("PRM: got %s, want unknown", got)
	}
	if got := find(t, r, "AS-METADATA").Status; got != StatusUnknown {
		t.Errorf("AS-METADATA: got %s, want unknown", got)
	}
	if r.Summary.Fail != 0 {
		t.Errorf("an unreachable server must produce no findings, got %d failures", r.Summary.Fail)
	}
}

func TestPlaintextRemoteHostFails(t *testing.T) {
	u, _ := url.Parse("http://remote.example.com/mcp")
	report := &Report{Target: u.String()}
	s := &scanner{client: &http.Client{Timeout: time.Second}, target: u, report: report}
	s.checkTransport()

	if got := find(t, report, "TLS").Status; got != StatusFail {
		t.Errorf("TLS: got %s, want fail for a plaintext remote host", got)
	}
}

func TestPlaintextLocalhostWarnsOnly(t *testing.T) {
	for _, host := range []string{"localhost", "127.0.0.1"} {
		u, _ := url.Parse("http://" + host + ":8080/mcp")
		report := &Report{Target: u.String()}
		s := &scanner{client: &http.Client{Timeout: time.Second}, target: u, report: report}
		s.checkTransport()

		if got := find(t, report, "TLS").Status; got != StatusWarn {
			t.Errorf("TLS for %s: got %s, want warn", host, got)
		}
	}
}
