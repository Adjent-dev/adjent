package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"hash"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

const (
	// maxRelay is the largest request body that will be relayed. A request
	// above it is refused rather than shortened: a proxy that alters traffic is
	// worse than one that rejects it, and forwarding a prefix while recording
	// the whole would make the record describe an action that never occurred.
	maxRelay = 32 << 20 // 32 MiB

	// maxStore bounds how much of a body is kept under --retain-bodies. The
	// commitment always covers the full body regardless.
	maxStore = 4 << 20 // 4 MiB
)

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

	body, oversize, err := readCapped(r.Body, maxRelay)
	if err != nil {
		p.record(Action{
			Direction: "call",
			Upstream:  p.upstream.String(),
			Err:       fmt.Sprintf("reading request: %v", err),
		}, bodyDigest{}, bodyDigest{}, nil, nil)
		http.Error(w, "adjent: could not read request", http.StatusBadRequest)
		return
	}

	action := Action{
		Direction: "call",
		Upstream:  p.upstream.String(),
		Bytes:     len(body),
	}
	describe(&action, body)

	// Refused rather than relayed short. The record says the action did not
	// reach the server, which is true.
	if oversize {
		action.Err = fmt.Sprintf("request body exceeded the %d byte relay limit and was refused", maxRelay)
		p.record(action, digestOf(body), bodyDigest{}, nil, nil)
		http.Error(w, "adjent: request body too large to relay and record", http.StatusRequestEntityTooLarge)
		p.trace(action, started, 0)
		return
	}

	reqDigest := digestOf(body)

	target := *p.upstream
	target.Path = resolvePath(p.upstream.Path, r.URL.Path)
	target.RawQuery = r.URL.RawQuery

	outReq, err := http.NewRequestWithContext(r.Context(), r.Method, target.String(), bytes.NewReader(body))
	if err != nil {
		action.Err = fmt.Sprintf("building upstream request: %v", err)
		p.record(action, reqDigest, bodyDigest{}, body, nil)
		http.Error(w, "adjent: could not build upstream request", http.StatusBadGateway)
		return
	}
	copyHeaders(outReq.Header, r.Header)

	resp, err := p.client.Do(outReq)
	if err != nil {
		action.Err = fmt.Sprintf("upstream request failed: %v", err)
		p.record(action, reqDigest, bodyDigest{}, body, nil)
		http.Error(w, "adjent: upstream unreachable", http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()

	action.Status = resp.StatusCode
	copyHeaders(w.Header(), resp.Header)

	// A response is relayed in full whatever its size, because refusing one
	// after the upstream has already acted would hide an action that happened.
	// Hashing as it passes keeps the commitment over the whole body without
	// holding it.
	w.WriteHeader(resp.StatusCode)
	capture := &hashingRelay{dst: w, limit: maxStore}
	if isEventStream(resp.Header.Get("Content-Type")) {
		action.Direction = "call/stream"
	}
	capture.run(resp.Body)

	if capture.truncated {
		action.Err = appendErr(action.Err, "response exceeded the retention limit; the commitment still covers the whole body")
	}

	p.record(action, reqDigest, capture.digest(), body, capture.stored)
	p.trace(action, started, int(capture.n))
}

// hashingRelay copies a body to the client while digesting all of it and
// keeping at most limit bytes for storage.
type hashingRelay struct {
	dst       io.Writer
	limit     int
	h         hash.Hash
	n         uint64
	stored    []byte
	truncated bool
}

func (c *hashingRelay) run(src io.Reader) {
	c.h = sha256.New()
	flusher, _ := c.dst.(http.Flusher)
	buf := make([]byte, 32*1024)

	for {
		n, err := src.Read(buf)
		if n > 0 {
			chunk := buf[:n]
			c.h.Write(chunk)
			c.n += uint64(n)

			if room := c.limit - len(c.stored); room > 0 {
				if len(chunk) <= room {
					c.stored = append(c.stored, chunk...)
				} else {
					c.stored = append(c.stored, chunk[:room]...)
					c.truncated = true
				}
			} else if c.limit >= 0 {
				c.truncated = true
			}

			if _, werr := c.dst.Write(chunk); werr != nil {
				return
			}
			if flusher != nil {
				flusher.Flush()
			}
		}
		if err != nil {
			return
		}
	}
}

func (c *hashingRelay) digest() bodyDigest {
	var d bodyDigest
	d.Len = c.n
	copy(d.Digest[:], c.h.Sum(nil))
	return d
}

func appendErr(existing, msg string) string {
	if existing == "" {
		return msg
	}
	return existing + "; " + msg
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

func (p *recordingProxy) record(a Action, reqD, respD bodyDigest, storeReq, storeResp []byte) {
	if _, err := p.log.AppendDigests(a, reqD, respD, storeReq, storeResp); err != nil {
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

// resolvePath picks the forwarding path. An upstream with a path names the
// endpoint exactly, which avoids sending /mcp to /mcp/mcp when the agent config
// mirrors the server URL. A bare origin relays the incoming path instead.
func resolvePath(upstreamPath, incomingPath string) string {
	if upstreamPath != "" && upstreamPath != "/" {
		return upstreamPath
	}
	return incomingPath
}
