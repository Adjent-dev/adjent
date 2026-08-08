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

// maxBody caps the recorded copy only. Larger bodies still forward in full and
// the entry notes the truncation.
const maxBody = 4 << 20 // 4 MiB

// recordingProxy forwards MCP traffic and writes an entry per exchange. It sits
// in the path deliberately: a recorder the acting system can skip captures only
// what that system chose to disclose.
type recordingProxy struct {
	upstream *url.URL
	log      *Log
	client   *http.Client
	verbose  bool
}

// jsonrpcRequest is the part the recorder reads. The rest forwards untouched.
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

	// SSE stays open indefinitely; buffering would stall the agent.
	if isEventStream(resp.Header.Get("Content-Type")) {
		w.WriteHeader(resp.StatusCode)
		n := stream(w, resp.Body)
		action.Direction = "call/stream"
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

// describe extracts method and tool name, retained even when bodies are not:
// "which tool did this agent call" is what an audit asks.
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
		// Loud on purpose: a trail that silently stops recording looks the
		// same as one where nothing happened.
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

// copyHeaders forwards everything except hop-by-hop headers.
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

// stream relays chunks as they arrive, flushing so events are not delayed.
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

// resolvePath picks the forwarding path. An upstream with a path names the
// endpoint exactly, which avoids sending /mcp to /mcp/mcp when the agent config
// mirrors the server URL. A bare origin relays the incoming path instead.
func resolvePath(upstreamPath, incomingPath string) string {
	if upstreamPath != "" && upstreamPath != "/" {
		return upstreamPath
	}
	return incomingPath
}
