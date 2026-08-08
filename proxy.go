package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// maxBody caps how much of a request or response is read into memory. Bodies
// larger than this are still forwarded in full; only the recorded copy is
// truncated, and the entry says so.
const maxBody = 4 << 20 // 4 MiB

// recordingProxy forwards MCP traffic to an upstream server and writes an entry
// to the chain for every exchange.
//
// It sits in the path deliberately. A recorder that the acting system can skip
// records only the actions that system chose to disclose, which is not evidence
// of anything.
type recordingProxy struct {
	upstream *url.URL
	log      *Log
	client   *http.Client
	verbose  bool
}

// jsonrpcRequest is the part of a JSON-RPC message the recorder understands.
// Everything else is forwarded untouched.
type jsonrpcRequest struct {
	Method string          `json:"method"`
	ID     json.RawMessage `json:"id"`
	Params struct {
		Name string `json:"name"`
	} `json:"params"`
}

func (p *recordingProxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	started := time.Now()

	body, truncated, err := readCapped(r.Body, maxBody)
	if err != nil {
		p.record(Action{
			Direction: "call",
			Upstream:  p.upstream.String(),
			Err:       fmt.Sprintf("reading request: %v", err),
		}, nil, nil)
		http.Error(w, "adjent: could not read request", http.StatusBadRequest)
		return
	}

	action := Action{
		Direction: "call",
		Upstream:  p.upstream.String(),
		Bytes:     len(body),
	}
	describe(&action, body)
	if truncated {
		action.Err = "request body exceeded the recording limit and was recorded truncated"
	}

	target := *p.upstream
	target.Path = resolvePath(p.upstream.Path, r.URL.Path)
	target.RawQuery = r.URL.RawQuery

	outReq, err := http.NewRequestWithContext(r.Context(), r.Method, target.String(), bytes.NewReader(body))
	if err != nil {
		action.Err = fmt.Sprintf("building upstream request: %v", err)
		p.record(action, body, nil)
		http.Error(w, "adjent: could not build upstream request", http.StatusBadGateway)
		return
	}
	copyHeaders(outReq.Header, r.Header)

	resp, err := p.client.Do(outReq)
	if err != nil {
		action.Err = fmt.Sprintf("upstream request failed: %v", err)
		p.record(action, body, nil)
		http.Error(w, "adjent: upstream unreachable", http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()

	action.Status = resp.StatusCode
	copyHeaders(w.Header(), resp.Header)

	// A server-sent event stream stays open for as long as the server wishes.
	// Buffering it would stall the agent, so it is relayed as it arrives and
	// the entry records the exchange without a response body.
	if isEventStream(resp.Header.Get("Content-Type")) {
		w.WriteHeader(resp.StatusCode)
		n := stream(w, resp.Body)
		action.Direction = "call/stream"
		if action.Err == "" {
			action.Err = ""
		}
		p.record(action, body, nil)
		p.trace(action, started, n)
		return
	}

	respBody, respTruncated, err := readCapped(resp.Body, maxBody)
	if err != nil {
		action.Err = fmt.Sprintf("reading upstream response: %v", err)
		p.record(action, body, nil)
		http.Error(w, "adjent: could not read upstream response", http.StatusBadGateway)
		return
	}
	if respTruncated && action.Err == "" {
		action.Err = "response body exceeded the recording limit and was recorded truncated"
	}

	p.record(action, body, respBody)

	w.WriteHeader(resp.StatusCode)
	_, _ = w.Write(respBody)
	p.trace(action, started, len(respBody))
}

// describe extracts the method and, for a tool invocation, the tool name. These
// are retained even when bodies are not, because "which tool did this agent
// call" is the question an audit actually asks.
func describe(a *Action, body []byte) {
	trimmed := bytes.TrimSpace(body)
	if len(trimmed) == 0 {
		return
	}
	if trimmed[0] == '[' {
		a.Method = "batch"
		return
	}

	var req jsonrpcRequest
	if err := json.Unmarshal(trimmed, &req); err != nil {
		return
	}
	a.Method = req.Method
	a.RPCID = strings.Trim(string(req.ID), `"`)
	if req.Method == "tools/call" {
		a.Tool = req.Params.Name
	}
}

func (p *recordingProxy) record(a Action, req, resp []byte) {
	if _, err := p.log.Append(a, req, resp); err != nil {
		// A failure to record is reported loudly rather than swallowed. An
		// audit trail that silently stops recording is indistinguishable from
		// one where nothing happened.
		fmt.Fprintf(stderr, "adjent: FAILED TO RECORD: %v\n", err)
	}
}

func (p *recordingProxy) trace(a Action, started time.Time, respBytes int) {
	if !p.verbose {
		return
	}
	label := a.Method
	if a.Tool != "" {
		label = a.Method + " " + a.Tool
	}
	if label == "" {
		label = "(no method)"
	}
	fmt.Fprintf(stderr, "  %-28s %3d  %5dB  %s\n",
		label, a.Status, respBytes, time.Since(started).Round(time.Millisecond))
}

// copyHeaders forwards headers verbatim, minus the hop-by-hop ones that belong
// to a single connection and must not be relayed.
func copyHeaders(dst, src http.Header) {
	for k, vs := range src {
		if hopByHop[strings.ToLower(k)] {
			continue
		}
		for _, v := range vs {
			dst.Add(k, v)
		}
	}
}

var hopByHop = map[string]bool{
	"connection":          true,
	"keep-alive":          true,
	"proxy-authenticate":  true,
	"proxy-authorization": true,
	"te":                  true,
	"trailer":             true,
	"transfer-encoding":   true,
	"upgrade":             true,
}

func isEventStream(contentType string) bool {
	return strings.HasPrefix(strings.ToLower(strings.TrimSpace(contentType)), "text/event-stream")
}

// stream relays a response as it arrives, flushing after each chunk so the
// agent sees events at the moment the server emits them.
func stream(w http.ResponseWriter, r io.Reader) int {
	flusher, _ := w.(http.Flusher)
	buf := make([]byte, 32*1024)
	total := 0

	for {
		n, err := r.Read(buf)
		if n > 0 {
			written, werr := w.Write(buf[:n])
			total += written
			if flusher != nil {
				flusher.Flush()
			}
			if werr != nil {
				return total
			}
		}
		if err != nil {
			return total
		}
	}
}

// resolvePath decides which path an incoming request is forwarded to.
//
// An upstream given with a path, such as https://server.example.com/mcp, names
// the endpoint exactly, so every request goes there whatever path the agent
// used. This is what people expect when they mirror the server's URL into their
// agent config, and it avoids forwarding /mcp to /mcp/mcp.
//
// An upstream given as a bare origin has no endpoint of its own, so the
// incoming path is preserved and the proxy behaves as a transparent relay.
func resolvePath(upstreamPath, incomingPath string) string {
	if upstreamPath != "" && upstreamPath != "/" {
		return upstreamPath
	}
	return incomingPath
}
