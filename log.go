package main

import (
	"bufio"
	"crypto/ed25519"
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

// An append-only chain: each entry carries the hash of its predecessor, so any
// edit or removal breaks every link after it.
//
// Two gaps remain by construction. Tail truncation leaves a shorter chain that
// still verifies. A holder of the signing key can rewrite history. Both need the
// head published where the operator cannot reach it; see describeGuarantee.

const (
	// genesisHash is the PrevHash of the first entry in a chain.
	genesisHash = "0000000000000000000000000000000000000000000000000000000000000000"
)

// Entry is one recorded action, stored as a single JSON line so the log can be
// appended and tailed without reading it whole.
type Entry struct {
	Seq  uint64    `json:"seq"`
	Time time.Time `json:"time"`

	Action Action `json:"action"`

	// PayloadHash commits to the bodies even when they are not stored, so a
	// party holding the originals can prove they match.
	PayloadHash string `json:"payload_hash"`

	// Payload is set only under --retain-bodies. Agent traffic carries
	// credentials and personal data a record keeper should not hold.
	Payload *Payload `json:"payload,omitempty"`

	PrevHash string `json:"prev_hash"`
	Hash     string `json:"hash"`

	// Ed25519 signature over Hash. Without it, write access is enough to rebuild
	// the chain, so an unsigned log is good faith rather than evidence.
	Sig   string `json:"sig,omitempty"`
	KeyID string `json:"key_id,omitempty"`
}

// Action is the metadata retained whether or not bodies are stored.
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

// Payload holds bodies verbatim. Opt-in.
type Payload struct {
	Request  json.RawMessage `json:"request,omitempty"`
	Response json.RawMessage `json:"response,omitempty"`
	// Partial marks a stored body as a prefix of what was relayed. PayloadHash
	// still commits to the whole, so a verifier must not recompute from these.
	Partial bool `json:"partial,omitempty"`
}

// computeHash covers the entry and its predecessor. Fields are length-prefixed:
// plain concatenation would let ("ab","c") and ("a","bc") collide.
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

// bodyDigest is the length and SHA-256 of one body, computed while the body is
// being relayed rather than after it has been buffered.
type bodyDigest struct {
	Len    uint64
	Digest [sha256.Size]byte
}

func digestOf(b []byte) bodyDigest {
	return bodyDigest{Len: uint64(len(b)), Digest: sha256.Sum256(b)}
}

// combinePayloadHash commits to both bodies through their digests rather than
// their contents, so a response can be hashed as it streams past instead of
// being held in memory first. Lengths are included so that two bodies cannot be
// swapped for others with the same digests at different sizes.
//
// The commitment must always cover exactly what was relayed. Hashing a
// truncated copy of a body that was forwarded in full would produce a record of
// something that never happened.
func combinePayloadHash(req, resp bodyDigest) string {
	h := sha256.New()
	var num [8]byte

	binary.BigEndian.PutUint64(num[:], req.Len)
	h.Write(num[:])
	h.Write(req.Digest[:])

	binary.BigEndian.PutUint64(num[:], resp.Len)
	h.Write(num[:])
	h.Write(resp.Digest[:])

	return hex.EncodeToString(h.Sum(nil))
}

// hashPayload is the buffered form, used where both bodies are already in hand.
func hashPayload(req, resp []byte) string {
	return combinePayloadHash(digestOf(req), digestOf(resp))
}

// Log appends to a file, resuming the chain across restarts.
type Log struct {
	mu       sync.Mutex
	file     *os.File
	writer   *bufio.Writer
	lastHash string
	seq      uint64
	retain   bool

	// Optional. Unsigned entries verify to a weaker guarantee.
	signer ed25519.PrivateKey
	keyID  string
}

// WithSigner attaches a signing key so every subsequent entry is signed.
func (l *Log) WithSigner(priv ed25519.PrivateKey) *Log {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.signer = priv
	l.keyID = keyID(priv.Public().(ed25519.PublicKey))
	return l
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

// tailChain finds the head of an existing chain, or genesis if absent.
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

// Append seals one action into the chain and fsyncs it. Syncing per entry is
// deliberate: a record lost in a buffer on kill is a gap at exactly the moment
// something went wrong.
func (l *Log) Append(a Action, req, resp []byte) (*Entry, error) {
	return l.AppendDigests(a, digestOf(req), digestOf(resp), req, resp)
}

// AppendDigests seals an action whose bodies were hashed as they were relayed.
// store holds whatever subset of the bodies is being retained, which may be
// shorter than what the digests cover.
func (l *Log) AppendDigests(a Action, reqD, respD bodyDigest, storeReq, storeResp []byte) (*Entry, error) {
	l.mu.Lock()
	defer l.mu.Unlock()

	e := &Entry{
		Seq:         l.seq,
		Time:        time.Now().UTC(),
		Action:      a,
		PayloadHash: combinePayloadHash(reqD, respD),
		PrevHash:    l.lastHash,
	}
	if l.retain {
		e.Payload = &Payload{
			Request:  rawOrNil(storeReq),
			Response: rawOrNil(storeResp),
			Partial:  uint64(len(storeReq)) != reqD.Len || uint64(len(storeResp)) != respD.Len,
		}
	}
	e.Hash = computeHash(e)
	if l.signer != nil {
		e.Sig = signEntryHash(l.signer, e.Hash)
		e.KeyID = l.keyID
	}

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

// Head is the most recent entry hash. Publishing it outside the operator's
// control is what would close the truncation gap.
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

// rawOrNil keeps invalid JSON out of RawMessage, which would make the entry
// unparseable on read back.
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
	// Verification stops at the first break; everything after is unverifiable.
	Problem         string `json:"problem,omitempty"`
	BrokenAt        *int   `json:"broken_at,omitempty"`
	PayloadsChecked int    `json:"payloads_checked"`

	// When Signed and SignaturesVerified differ, the log claims signatures
	// nobody has validated.
	Signed             int    `json:"signed"`
	SignaturesVerified int    `json:"signatures_verified"`
	KeyID              string `json:"key_id,omitempty"`

	// Guarantee states what was actually proved, so no reader infers more.
	Guarantee string `json:"guarantee"`

	// Checkpoint is set when the chain was compared against one.
	Checkpoint *CheckpointResult `json:"checkpoint,omitempty"`

	// entries backs checkpoint comparison without a second pass over the file.
	entries []Entry
}

// VerifyLog walks a log from genesis and confirms that every entry links to its
// predecessor and that every recorded hash matches a recomputation. Passing a
// public key additionally verifies each signature, which is what distinguishes
// evidence from bookkeeping.
func VerifyLog(path string, pub ed25519.PublicKey) (*VerifyResult, error) {
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

		// Recomputing from stored bodies is only meaningful when both were
		// retained whole. A record that kept a prefix commits to the full body,
		// so a mismatch there would be the expected result, not tampering.
		if e.Payload != nil && !e.Payload.Partial {
			if hashPayload(e.Payload.Request, e.Payload.Response) != e.PayloadHash {
				return brokenAt(res, int(e.Seq),
					"stored bodies do not match the hash recorded for them, so a payload was substituted"), nil
			}
			res.PayloadsChecked++
		}

		if e.Sig != "" {
			res.Signed++
			if res.KeyID == "" {
				res.KeyID = e.KeyID
			} else if e.KeyID != res.KeyID {
				return brokenAt(res, int(e.Seq),
					fmt.Sprintf("entry is signed by key %s where earlier entries used %s, so the log was written by more than one signer", e.KeyID, res.KeyID)), nil
			}
			if pub != nil {
				if !verifyEntrySignature(pub, e.Hash, e.Sig) {
					return brokenAt(res, int(e.Seq),
						"signature does not validate against the supplied public key, so this entry was not written by the holder of that key"), nil
				}
				res.SignaturesVerified++
			}
		}

		prev = e.Hash
		expectedSeq = e.Seq + 1
		res.Entries++
		res.Head = e.Hash
		res.entries = append(res.entries, e)
	}
	if err := sc.Err(); err != nil {
		return nil, fmt.Errorf("reading log: %w", err)
	}

	// Mixed signing is worse than none: unsigned entries can be inserted while
	// the log presents itself as signed.
	if res.Signed > 0 && res.Signed != res.Entries {
		return brokenAt(res, res.Signed,
			fmt.Sprintf("only %d of %d entries are signed, so unsigned entries may have been inserted into a log that appears signed", res.Signed, res.Entries)), nil
	}

	res.Guarantee = describeGuarantee(res, pub != nil)
	return res, nil
}

// describeGuarantee names the attacker each outcome does not stop.
func describeGuarantee(res *VerifyResult, haveKey bool) string {
	switch {
	case res.Signed == 0:
		return "Unsigned. This shows the file was not edited carelessly, and nothing more. " +
			"Anyone able to write to it could have rebuilt every entry from genesis and produced a chain that verifies. " +
			"Run adjent keygen and record with --key to make this evidence."
	case !haveKey:
		return fmt.Sprintf("Signed by key %s, but no public key was supplied, so the signatures were not checked. "+
			"Pass --pubkey to verify them. Until then this proves no more than an unsigned log.", res.KeyID)
	default:
		return fmt.Sprintf("Signed by key %s and every signature validates. "+
			"Rewriting this log requires the private key, not merely write access to the file. "+
			"It remains possible for the holder of that key to rewrite history, and for entries to be deleted from the end.", res.KeyID)
	}
}

// refineGuarantee narrows the stated guarantee once a checkpoint has been
// compared. A verified checkpoint rules out truncation and rewriting up to its
// size, including by the key holder, so leaving the unqualified caveat in place
// would understate what was proved.
func (r *VerifyResult) refineGuarantee() {
	c := r.Checkpoint
	if c == nil || !c.Consistent || !c.Verified || r.SignaturesVerified == 0 {
		return
	}
	base := fmt.Sprintf(
		"Signed by key %s, every signature validates, and the first %d entries match a checkpoint "+
			"signed at an earlier time. ", r.KeyID, c.Size)

	// The checkpoint is only independent evidence if the adversary who could
	// rewrite entries could not also mint a replacement checkpoint. Validating
	// both with one key does not establish that.
	if c.Witnessed > 0 {
		base += fmt.Sprintf("The checkpoint carries %d countersignature(s) from witnesses you named, "+
			"so a party other than the operator attested to this head. Nothing recorded up to that "+
			"point has been removed or rewritten even if every key the operator holds is compromised.",
			c.Witnessed)
	} else if c.IndependentKey {
		base += "The checkpoint is signed by a separate key, so nothing recorded up to that point " +
			"has been removed or rewritten even by the holder of the entry key."
	} else {
		base += "The checkpoint is signed by the same key as the entries, so this holds only if you " +
			"obtained the checkpoint through a channel that key holder cannot influence. Sign " +
			"checkpoints with a separate key to remove that assumption."
	}

	r.Guarantee = base + " Entries appended after the checkpoint carry only the weaker signature " +
		"guarantee until a later checkpoint covers them."
}

func brokenAt(res *VerifyResult, seq int, problem string) *VerifyResult {
	res.Intact = false
	res.Problem = problem
	res.BrokenAt = &seq
	return res
}

// readCapped reads at most limit bytes, reporting whether more remained.
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
