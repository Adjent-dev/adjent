package main

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
)

// protectedResourceMetadata is the subset of RFC 9728 we care about.
type protectedResourceMetadata struct {
	Resource               string   `json:"resource"`
	AuthorizationServers   []string `json:"authorization_servers"`
	ScopesSupported        []string `json:"scopes_supported"`
	BearerMethodsSupported []string `json:"bearer_methods_supported"`
}

// authServerMetadata is the subset of RFC 8414 we care about.
type authServerMetadata struct {
	Issuer                        string   `json:"issuer"`
	AuthorizationEndpoint         string   `json:"authorization_endpoint"`
	TokenEndpoint                 string   `json:"token_endpoint"`
	RegistrationEndpoint          string   `json:"registration_endpoint"`
	CodeChallengeMethodsSupported []string `json:"code_challenge_methods_supported"`
	GrantTypesSupported           []string `json:"grant_types_supported"`
}

type scanner struct {
	client *http.Client
	target *url.URL
	report *Report
	// unreachable is set once we establish the target does not answer at all,
	// so downstream checks report "unknown" rather than implying a finding.
	unreachable bool
}

// run executes every check in order. Later checks reuse what earlier ones
// discovered, so order matters.
func (s *scanner) run() {
	s.checkTransport()
	prm := s.checkProtectedResourceMetadata()
	s.checkUnauthorizedChallenge()
	if prm == nil {
		status, detail := StatusSkip, "Cannot locate the authorization server without protected resource metadata."
		if s.unreachable {
			status = StatusUnknown
			detail = "Not attempted, because the server could not be reached."
		}
		s.report.add(Check{
			ID:       "AS-METADATA",
			Title:    "Authorization server metadata",
			Severity: SevMust,
			Status:   status,
			Detail:   detail,
			Ref:      "RFC 8414",
		})
		return
	}
	s.checkAuthorizationServer(prm)
	s.checkResourceIndicators()
}

// checkTransport verifies HTTPS. Localhost is exempt, matching the spec's
// carve-out for local development servers.
func (s *scanner) checkTransport() {
	host := s.target.Hostname()
	local := host == "localhost" || host == "127.0.0.1" || host == "::1"

	switch {
	case s.target.Scheme == "https":
		s.report.add(Check{
			ID: "TLS", Title: "HTTPS transport", Severity: SevMust, Status: StatusPass,
			Detail: "Server is served over HTTPS.",
			Ref:    "MCP Authorization",
		})
	case local:
		s.report.add(Check{
			ID: "TLS", Title: "HTTPS transport", Severity: SevMust, Status: StatusWarn,
			Detail: "Plaintext HTTP allowed for localhost only. A deployed server MUST use HTTPS.",
			Ref:    "MCP Authorization",
		})
	default:
		s.report.add(Check{
			ID: "TLS", Title: "HTTPS transport", Severity: SevMust, Status: StatusFail,
			Detail: "Remote MCP servers MUST be served over HTTPS. Bearer tokens sent over plaintext are trivially interceptable.",
			Ref:    "MCP Authorization",
		})
	}
}

// checkProtectedResourceMetadata is the headline check of the 2026-07-28 spec:
// servers MUST publish RFC 9728 metadata so clients can discover which
// authorization server to use, instead of guessing.
//
// RFC 9728 defines a path-aware well-known location. For https://host/mcp the
// document lives at https://host/.well-known/oauth-protected-resource/mcp,
// with the root form as a fallback.
func (s *scanner) checkProtectedResourceMetadata() *protectedResourceMetadata {
	// reached records whether any candidate URL produced an HTTP response at
	// all. A server that answers 404 is telling us it does not publish the
	// document; a server we cannot reach is telling us nothing, and reporting
	// the two identically would turn a flaky network into a false accusation.
	var reached bool
	var lastErr error

	for _, candidate := range wellKnownCandidates(s.target) {
		body, status, err := s.get(candidate)
		if err != nil {
			lastErr = err
			continue
		}
		reached = true
		if status != http.StatusOK {
			continue
		}

		var prm protectedResourceMetadata
		if err := json.Unmarshal(body, &prm); err != nil {
			s.report.add(Check{
				ID: "PRM", Title: "Protected resource metadata (RFC 9728)", Severity: SevMust, Status: StatusFail,
				Detail: fmt.Sprintf("Found a document at %s but it is not valid JSON: %v", candidate, err),
				Ref:    "RFC 9728 §3",
			})
			return nil
		}

		var problems []string
		if prm.Resource == "" {
			problems = append(problems, "missing required field \"resource\"")
		}
		if len(prm.AuthorizationServers) == 0 {
			problems = append(problems, "missing \"authorization_servers\", so clients cannot discover where to authenticate")
		}

		if len(problems) > 0 {
			s.report.add(Check{
				ID: "PRM", Title: "Protected resource metadata (RFC 9728)", Severity: SevMust, Status: StatusFail,
				Detail: fmt.Sprintf("Served at %s but incomplete: %s.", candidate, strings.Join(problems, "; ")),
				Ref:    "RFC 9728 §3",
			})
			// Incomplete metadata cannot be followed any further, so report it
			// as absent rather than handing downstream checks a document they
			// cannot use.
			return nil
		}

		s.report.add(Check{
			ID: "PRM", Title: "Protected resource metadata (RFC 9728)", Severity: SevMust, Status: StatusPass,
			Detail: fmt.Sprintf("Published at %s, advertising authorization server(s): %s.",
				candidate, strings.Join(prm.AuthorizationServers, ", ")),
			Ref: "RFC 9728 §3",
		})
		s.checkResourceMatchesTarget(&prm)
		return &prm
	}

	if !reached {
		s.unreachable = true
		s.report.add(Check{
			ID: "PRM", Title: "Protected resource metadata (RFC 9728)", Severity: SevMust, Status: StatusUnknown,
			Detail: fmt.Sprintf("Could not reach the server: %v. This is a connectivity problem and says nothing about the server's conformance.", lastErr),
			Ref:    "RFC 9728 §3",
		})
		return nil
	}

	s.report.add(Check{
		ID: "PRM", Title: "Protected resource metadata (RFC 9728)", Severity: SevMust, Status: StatusFail,
		Detail: "No metadata document found. As of the 2026-07-28 spec revision, remote MCP servers MUST publish this so clients can discover the authorization server. Serve it at " +
			wellKnownCandidates(s.target)[0] + ".",
		Ref: "RFC 9728 §3",
	})
	return nil
}

// checkResourceMatchesTarget catches a subtle misconfiguration: if the declared
// canonical resource identifier does not match the URL clients actually call,
// audience-restricted tokens will be issued for the wrong resource.
func (s *scanner) checkResourceMatchesTarget(prm *protectedResourceMetadata) {
	declared, err := url.Parse(prm.Resource)
	if err != nil {
		s.report.add(Check{
			ID: "PRM-RESOURCE", Title: "Canonical resource identifier", Severity: SevShould, Status: StatusWarn,
			Detail: fmt.Sprintf("Declared resource %q is not a valid URI.", prm.Resource),
			Ref:    "RFC 9728 §3.1",
		})
		return
	}

	if strings.EqualFold(declared.Host, s.target.Host) {
		s.report.add(Check{
			ID: "PRM-RESOURCE", Title: "Canonical resource identifier", Severity: SevShould, Status: StatusPass,
			Detail: fmt.Sprintf("Declared resource %q matches the scanned host.", prm.Resource),
			Ref:    "RFC 9728 §3.1",
		})
		return
	}

	s.report.add(Check{
		ID: "PRM-RESOURCE", Title: "Canonical resource identifier", Severity: SevShould, Status: StatusWarn,
		Detail: fmt.Sprintf("Declared resource %q does not match the scanned host %q. Clients requesting a token for this resource may receive one with the wrong audience.",
			prm.Resource, s.target.Host),
		Ref: "RFC 9728 §3.1",
	})
}

// checkUnauthorizedChallenge makes one ordinary unauthenticated request, the
// same request any MCP client makes before it has a token, and reads the
// challenge. RFC 9728 §5.1 says the 401 should point at the metadata document.
func (s *scanner) checkUnauthorizedChallenge() {
	resp, err := s.head(s.target.String())
	if err != nil {
		s.report.add(Check{
			ID: "WWW-AUTH", Title: "401 challenge points to metadata", Severity: SevShould, Status: StatusUnknown,
			Detail: fmt.Sprintf("Could not reach the endpoint: %v", err),
			Ref:    "RFC 9728 §5.1",
		})
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusUnauthorized {
		s.report.add(Check{
			ID: "WWW-AUTH", Title: "401 challenge points to metadata", Severity: SevShould, Status: StatusWarn,
			Detail: fmt.Sprintf("Unauthenticated request returned %d, not 401. Either this endpoint requires no authorization, or it does not challenge correctly. adjent does not probe further to find out which.",
				resp.StatusCode),
			Ref: "RFC 9728 §5.1",
		})
		return
	}

	challenge := resp.Header.Get("WWW-Authenticate")
	if strings.Contains(strings.ToLower(challenge), "resource_metadata") {
		s.report.add(Check{
			ID: "WWW-AUTH", Title: "401 challenge points to metadata", Severity: SevShould, Status: StatusPass,
			Detail: "401 response carries a WWW-Authenticate header advertising resource_metadata.",
			Ref:    "RFC 9728 §5.1",
		})
		return
	}

	s.report.add(Check{
		ID: "WWW-AUTH", Title: "401 challenge points to metadata", Severity: SevShould, Status: StatusFail,
		Detail: "401 response does not advertise resource_metadata in WWW-Authenticate, so clients must guess where to authenticate.",
		Ref:    "RFC 9728 §5.1",
	})
}

// checkAuthorizationServer follows the advertised authorization server and
// verifies the parts of RFC 8414 metadata that the MCP spec depends on.
func (s *scanner) checkAuthorizationServer(prm *protectedResourceMetadata) {
	if prm == nil || len(prm.AuthorizationServers) == 0 {
		s.report.add(Check{
			ID: "AS-METADATA", Title: "Authorization server metadata", Severity: SevMust, Status: StatusSkip,
			Detail: "No authorization server was advertised, so there is nothing to look up.",
			Ref:    "RFC 8414",
		})
		return
	}
	issuer := prm.AuthorizationServers[0]

	var meta *authServerMetadata
	var found string
	for _, candidate := range asMetadataCandidates(issuer) {
		body, status, err := s.get(candidate)
		if err != nil || status != http.StatusOK {
			continue
		}
		var m authServerMetadata
		if err := json.Unmarshal(body, &m); err != nil {
			continue
		}
		meta, found = &m, candidate
		break
	}

	if meta == nil {
		s.report.add(Check{
			ID: "AS-METADATA", Title: "Authorization server metadata", Severity: SevMust, Status: StatusFail,
			Detail: fmt.Sprintf("Advertised authorization server %s publishes no discoverable metadata (tried RFC 8414 and OpenID Connect discovery).", issuer),
			Ref:    "RFC 8414",
		})
		return
	}

	s.report.add(Check{
		ID: "AS-METADATA", Title: "Authorization server metadata", Severity: SevMust, Status: StatusPass,
		Detail: fmt.Sprintf("Discovered at %s.", found),
		Ref:    "RFC 8414",
	})

	// PKCE with S256 is mandatory under OAuth 2.1. Without it, an intercepted
	// authorization code can be redeemed by an attacker.
	if containsFold(meta.CodeChallengeMethodsSupported, "S256") {
		s.report.add(Check{
			ID: "PKCE", Title: "PKCE S256 supported", Severity: SevMust, Status: StatusPass,
			Detail: "Authorization server advertises the S256 code challenge method.",
			Ref:    "OAuth 2.1 / RFC 7636",
		})
	} else {
		detail := "Authorization server does not advertise S256 in code_challenge_methods_supported. OAuth 2.1 requires PKCE with S256."
		if len(meta.CodeChallengeMethodsSupported) > 0 {
			detail += " Advertised instead: " + strings.Join(meta.CodeChallengeMethodsSupported, ", ") + "."
		}
		s.report.add(Check{
			ID: "PKCE", Title: "PKCE S256 supported", Severity: SevMust, Status: StatusFail,
			Detail: detail,
			Ref:    "OAuth 2.1 / RFC 7636",
		})
	}

	if meta.RegistrationEndpoint != "" {
		s.report.add(Check{
			ID: "DCR", Title: "Dynamic client registration", Severity: SevShould, Status: StatusPass,
			Detail: "Registration endpoint advertised, so MCP clients can onboard without manual credential exchange.",
			Ref:    "RFC 7591",
		})
	} else {
		s.report.add(Check{
			ID: "DCR", Title: "Dynamic client registration", Severity: SevShould, Status: StatusWarn,
			Detail: "No registration_endpoint advertised. Every client will need credentials issued by hand.",
			Ref:    "RFC 7591",
		})
	}
}

// checkResourceIndicators is deliberately honest about its limits. RFC 8707 is
// a client-side obligation, and servers have no standard metadata field
// announcing enforcement. Confirming it would mean requesting tokens with a
// mismatched resource parameter to see whether they are rejected, which is an active
// authorization test adjent will not run against a server without permission.
func (s *scanner) checkResourceIndicators() {
	s.report.add(Check{
		ID: "RFC8707", Title: "Resource indicators enforced", Severity: SevMust, Status: StatusSkip,
		Detail: "Not verifiable from published metadata. Confirm manually that your authorization server binds the \"resource\" parameter into the token audience, and that this server rejects tokens issued for a different audience. Without it, a malicious server can replay your users' tokens elsewhere.",
		Ref:    "RFC 8707",
	})
}

// --- helpers ---

// wellKnownCandidates returns the RFC 9728 locations to try, most specific first.
func wellKnownCandidates(u *url.URL) []string {
	origin := u.Scheme + "://" + u.Host
	path := strings.TrimSuffix(u.Path, "/")

	candidates := []string{}
	if path != "" {
		candidates = append(candidates, origin+"/.well-known/oauth-protected-resource"+path)
	}
	return append(candidates, origin+"/.well-known/oauth-protected-resource")
}

// asMetadataCandidates covers both RFC 8414 and OpenID Connect discovery, since
// authorization servers in the wild publish under either.
func asMetadataCandidates(issuer string) []string {
	issuer = strings.TrimSuffix(issuer, "/")
	u, err := url.Parse(issuer)
	if err != nil {
		return nil
	}
	origin := u.Scheme + "://" + u.Host
	path := strings.TrimSuffix(u.Path, "/")

	return []string{
		origin + "/.well-known/oauth-authorization-server" + path,
		issuer + "/.well-known/oauth-authorization-server",
		issuer + "/.well-known/openid-configuration",
		origin + "/.well-known/openid-configuration" + path,
	}
}

func containsFold(haystack []string, needle string) bool {
	for _, h := range haystack {
		if strings.EqualFold(h, needle) {
			return true
		}
	}
	return false
}

func (s *scanner) get(rawURL string) ([]byte, int, error) {
	req, err := http.NewRequest(http.MethodGet, rawURL, nil)
	if err != nil {
		return nil, 0, err
	}
	req.Header.Set("User-Agent", userAgent)
	req.Header.Set("Accept", "application/json")

	resp, err := s.client.Do(req)
	if err != nil {
		return nil, 0, err
	}
	defer resp.Body.Close()

	// Metadata documents are small; cap the read so a hostile or broken server
	// cannot make us consume unbounded memory.
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	return body, resp.StatusCode, err
}

func (s *scanner) head(rawURL string) (*http.Response, error) {
	req, err := http.NewRequest(http.MethodGet, rawURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", userAgent)
	req.Header.Set("Accept", "application/json, text/event-stream")
	return s.client.Do(req)
}
