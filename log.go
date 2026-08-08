package main

import (
	"bufio"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"sync"
	"time"
)

// A record log is an append-only chain. Every entry carries the hash of the
// entry before it, so altering or removing anything in the middle breaks every
// link that follows and verification fails at the exact point of the change.
//
// What this construction does NOT defend against is truncation of the most
// recent entries. An attacker who can delete the tail of the file leaves a
// chain that still verifies, just a shorter one. Detecting that requires
// publishing the head hash somewhere the attacker does not control, which is
// what the Verify stage of this project is for. Until that exists, this file
// format is honest about the gap rather than implying a guarantee it cannot
// make.

const (
	// hashLen is the byte length of a SHA-256 digest.
	hashLen = 32
	// genesisHash is the PrevHash of the first entry in a chain.
	genesisHash = "0000000000000000000000000000000000000000000000000000000000000000"
)

// Entry is one recorded action. It is written to disk as a single line of JSON
// so the log can be appended to, tailed, and truncated at a line boundary
// without a parser holding the whole file in memory.
type Entry struct {
	Seq  uint64    `json:"seq"`
	Time time.Time `json:"time"`

	// Action describes what happened, in terms the log itself understands.
	Action Action `json:"action"`

	// PayloadHash commits to the full request and response bodies even when
	// those bodies are not stored, so a party holding the payloads can prove
	// they match what was recorded.
	PayloadHash string `json:"payload_hash"`

	// Payload is present only when recording was configured to retain bodies.
	// The default omits it, because an agent's traffic routinely carries
	// credentials and personal data that a record keeper should never hold.
	Payload *Payload `json:"payload,omitempty"`

	PrevHash string `json:"prev_hash"`
	Hash     string `json:"hash"`
}

// Action is the metadata retained for every recorded call, whether or not
// bodies are stored.
type Action struct {
	Direction string `json:"direction"`
	Method    string `json:"method,omitempty"`
	Tool      string `json:"tool,omitempty"`
	RPCID     string `json:"rpc_id,omitempty"`
	Upstream  string `json:"upstream,omitempty"`
	Status    int    `json:"status,omitempty"`
	Bytes     int    `json:"bytes,omitempty"`
	Err       string `json:"error,omitempty"`
}

// Payload holds bodies verbatim. Retaining it is opt-in.
type Payload struct {
	Request  json.RawMessage `json:"request,omitempty"`
	Response json.RawMessage `json:"response,omitempty"`
}

// computeHash derives an entry's hash from its contents and its predecessor.
//
// Every field is length-prefixed before hashing. Plain concatenation would let
// two different entries produce identical input, for example a method of "ab"
// with tool "c" versus method "a" with tool "bc", which would let one entry be
// substituted for another without breaking the chain.
func computeHash(e *Entry) string {
	h := sha256.New()

	var num [8]byte
	binary.BigEndian.PutUint64(num[:], e.Seq)
	h.Write(num[:])

	binary.BigEndian.PutUint64(num[:], uint64(e.Time.UTC().UnixNano()))
	h.Write(num[:])

	writeField := func(s string) {
		binary.BigEndian.PutUint64(num[:], uint64(len(s)))
		h.Write(num[:])
		h.Write([]byte(s))
	}

	writeField(e.PrevHash)
	writeField(e.PayloadHash)
	writeField(e.Action.Direction)
	writeField(e.Action.Method)
	writeField(e.Action.Tool)
	writeField(e.Action.RPCID)
	writeField(e.Action.Upstream)
	writeField(e.Action.Err)

	binary.BigEndian.PutUint64(num[:], uint64(e.Action.Status))
	h.Write(num[:])
	binary.BigEndian.PutUint64(num[:], uint64(e.Action.Bytes))
	h.Write(num[:])

	return hex.EncodeToString(h.Sum(nil))
}

// hashPayload commits to the bodies of a call. Absent bodies hash as empty
// rather than being skipped, so "no response" is distinguishable from a
// response that happened not to be recorded.
func hashPayload(req, resp []byte) string {
	h := sha256.New()
	var num [8]byte

	binary.BigEndian.PutUint64(num[:], uint64(len(req)))
	h.Write(num[:])
	h.Write(req)

	binary.BigEndian.PutUint64(num[:], uint64(len(resp)))
	h.Write(num[:])
	h.Write(resp)

	return hex.EncodeToString(h.Sum(nil))
}

// Log appends entries to a file, maintaining the chain across process restarts
// by reading back the last entry on open.
type Log struct {
	mu       sync.Mutex
	file     *os.File
	writer   *bufio.Writer
	lastHash string
	seq      uint64
	// retain controls whether request and response bodies are stored. The
	// hash commitment is written either way.
	retain bool
}

// OpenLog opens or creates a log at path and positions the chain at its end.
func OpenLog(path string, retain bool) (*Log, error) {
	last, seq, err := tailChain(path)
	if err != nil {
		return nil, err
	}

	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		return nil, fmt.Errorf("opening log: %w", err)
	}

	return &Log{
		file:     f,
		writer:   bufio.NewWriter(f),
		lastHash: last,
		seq:      seq,
		retain:   retain,
	}, nil
}

// tailChain reads an existing log to find the head of the chain. A log that
// does not yet exist starts at genesis.
func tailChain(path string) (lastHash string, nextSeq uint64, err error) {
	f, err := os.Open(path)
	if os.IsNotExist(err) {
		return genesisHash, 0, nil
	}
	if err != nil {
		return "", 0, fmt.Errorf("reading log: %w", err)
	}
	defer f.Close()

	lastHash = genesisHash
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64*1024), 16*1024*1024)

	for sc.Scan() {
		line := sc.Bytes()
		if len(line) == 0 {
			continue
		}
		var e Entry
		if err := json.Unmarshal(line, &e); err != nil {
			return "", 0, fmt.Errorf("log is corrupt at entry %d: %w", nextSeq, err)
		}
		lastHash = e.Hash
		nextSeq = e.Seq + 1
	}
	if err := sc.Err(); err != nil {
		return "", 0, fmt.Errorf("reading log: %w", err)
	}
	return lastHash, nextSeq, nil
}

// Append seals one action into the chain and flushes it to disk. It flushes on
// every write deliberately: a record that is lost in a buffer when the process
// is killed is a record that never existed, and an audit trail with gaps at
// exactly the moments things went wrong is worse than none.
func (l *Log) Append(a Action, req, resp []byte) (*Entry, error) {
	l.mu.Lock()
	defer l.mu.Unlock()

	e := &Entry{
		Seq:         l.seq,
		Time:        time.Now().UTC(),
		Action:      a,
		PayloadHash: hashPayload(req, resp),
		PrevHash:    l.lastHash,
	}
	if l.retain {
		e.Payload = &Payload{
			Request:  rawOrNil(req),
			Response: rawOrNil(resp),
		}
	}
	e.Hash = computeHash(e)

	line, err := json.Marshal(e)
	if err != nil {
		return nil, fmt.Errorf("encoding entry: %w", err)
	}
	if _, err := l.writer.Write(append(line, '\n')); err != nil {
		return nil, fmt.Errorf("writing entry: %w", err)
	}
	if err := l.writer.Flush(); err != nil {
		return nil, fmt.Errorf("flushing entry: %w", err)
	}
	if err := l.file.Sync(); err != nil {
		return nil, fmt.Errorf("syncing log: %w", err)
	}

	l.lastHash = e.Hash
	l.seq++
	return e, nil
}

// Head returns the hash of the most recent entry. Publishing this value
// somewhere outside the operator's control is what would close the truncation
// gap described at the top of this file.
func (l *Log) Head() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.lastHash
}

func (l *Log) Close() error {
	l.mu.Lock()
	defer l.mu.Unlock()
	if err := l.writer.Flush(); err != nil {
		l.file.Close()
		return err
	}
	return l.file.Close()
}

// rawOrNil avoids storing invalid JSON in a json.RawMessage field, which would
// make the whole entry unparseable on read back.
func rawOrNil(b []byte) json.RawMessage {
	if len(b) == 0 || !json.Valid(b) {
		return nil
	}
	return json.RawMessage(b)
}

// VerifyResult reports what verification established about a log.
type VerifyResult struct {
	Path    string `json:"path"`
	Entries int    `json:"entries"`
	Head    string `json:"head"`
	Intact  bool   `json:"intact"`
	// Problem describes the first break found, and BrokenAt is the sequence
	// number where it was found. Verification stops at the first break because
	// everything after it is unverifiable by definition.
	Problem  string `json:"problem,omitempty"`
	BrokenAt *int   `json:"broken_at,omitempty"`
	// PayloadsChecked counts entries whose retained bodies were confirmed
	// against their recorded hash.
	PayloadsChecked int `json:"payloads_checked"`
}

// VerifyLog walks a log from genesis and confirms that every entry links to its
// predecessor and that every recorded hash matches a recomputation.
func VerifyLog(path string) (*VerifyResult, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("opening log: %w", err)
	}
	defer f.Close()

	res := &VerifyResult{Path: path, Intact: true, Head: genesisHash}

	prev := genesisHash
	var expectedSeq uint64

	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64*1024), 16*1024*1024)

	for sc.Scan() {
		line := sc.Bytes()
		if len(line) == 0 {
			continue
		}

		var e Entry
		if err := json.Unmarshal(line, &e); err != nil {
			return brokenAt(res, int(expectedSeq), fmt.Sprintf("entry is not valid JSON: %v", err)), nil
		}

		if e.Seq != expectedSeq {
			return brokenAt(res, int(expectedSeq),
				fmt.Sprintf("sequence jumps to %d where %d was expected, so an entry was removed or reordered", e.Seq, expectedSeq)), nil
		}
		if e.PrevHash != prev {
			return brokenAt(res, int(e.Seq),
				"entry does not link to its predecessor, so the chain was altered at or before this point"), nil
		}
		if got := computeHash(&e); got != e.Hash {
			return brokenAt(res, int(e.Seq),
				"entry hash does not match its contents, so this entry was modified after it was written"), nil
		}

		if e.Payload != nil {
			if hashPayload(e.Payload.Request, e.Payload.Response) != e.PayloadHash {
				return brokenAt(res, int(e.Seq),
					"stored bodies do not match the hash recorded for them, so a payload was substituted"), nil
			}
			res.PayloadsChecked++
		}

		prev = e.Hash
		expectedSeq = e.Seq + 1
		res.Entries++
		res.Head = e.Hash
	}
	if err := sc.Err(); err != nil {
		return nil, fmt.Errorf("reading log: %w", err)
	}

	return res, nil
}

func brokenAt(res *VerifyResult, seq int, problem string) *VerifyResult {
	res.Intact = false
	res.Problem = problem
	res.BrokenAt = &seq
	return res
}

// readCapped reads at most limit bytes, reporting whether the source had more.
// Bodies are capped so a large upload cannot exhaust memory in the proxy.
func readCapped(r io.Reader, limit int64) (body []byte, truncated bool, err error) {
	b, err := io.ReadAll(io.LimitReader(r, limit+1))
	if err != nil {
		return nil, false, err
	}
	if int64(len(b)) > limit {
		return b[:limit], true, nil
	}
	return b, false, nil
}
