package main

import (
	"crypto/ed25519"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"os"
	"time"
)

// A checkpoint is a signed statement that at a given moment the log held a
// given number of entries ending in a given hash.
//
// It is what makes tail truncation detectable. A chain alone cannot reveal that
// entries were removed from the end, because the file carries no independent
// claim about how long it should be. A checkpoint is that claim, and once it has
// left the operator's machine they cannot retract it.
//
// The detection is only as good as the distribution. A checkpoint sitting beside
// the log it describes proves nothing, since an adversary rewriting one will
// rewrite the other. Section 3 of the roadmap covers publishing them.

type Checkpoint struct {
	Origin string    `json:"origin"`
	Size   uint64    `json:"size"`
	Head   string    `json:"head"`
	Time   time.Time `json:"time"`
	KeyID  string    `json:"key_id"`
	Sig    string    `json:"sig"`
}

// checkpointBytes is the signed representation. Fields are length-prefixed for
// the same reason as entry hashes: without it, moving characters across a
// boundary could produce two checkpoints with identical signing input.
func checkpointBytes(c *Checkpoint) []byte {
	var out []byte
	var num [8]byte

	binary.BigEndian.PutUint64(num[:], c.Size)
	out = append(out, num[:]...)

	binary.BigEndian.PutUint64(num[:], uint64(c.Time.UTC().UnixNano()))
	out = append(out, num[:]...)

	appendField := func(s string) {
		binary.BigEndian.PutUint64(num[:], uint64(len(s)))
		out = append(out, num[:]...)
		out = append(out, s...)
	}
	appendField(c.Origin)
	appendField(c.Head)

	return out
}

// NewCheckpoint records the current extent of a log and signs it.
func NewCheckpoint(origin string, size uint64, head string, priv ed25519.PrivateKey) *Checkpoint {
	c := &Checkpoint{
		Origin: origin,
		Size:   size,
		Head:   head,
		Time:   time.Now().UTC(),
		KeyID:  keyID(priv.Public().(ed25519.PublicKey)),
	}
	c.Sig = hexSign(priv, checkpointBytes(c))
	return c
}

func (c *Checkpoint) verifySignature(pub ed25519.PublicKey) bool {
	return hexVerify(pub, checkpointBytes(c), c.Sig)
}

func writeCheckpoint(path string, c *Checkpoint) error {
	data, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		return fmt.Errorf("encoding checkpoint: %w", err)
	}
	return os.WriteFile(path, append(data, '\n'), 0o644)
}

func readCheckpoint(path string) (*Checkpoint, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading checkpoint: %w", err)
	}
	var c Checkpoint
	if err := json.Unmarshal(data, &c); err != nil {
		return nil, fmt.Errorf("parsing checkpoint: %w", err)
	}
	return &c, nil
}

// CheckpointResult reports whether a log is consistent with a prior checkpoint.
type CheckpointResult struct {
	Size       uint64 `json:"checkpoint_size"`
	LogSize    int    `json:"log_size"`
	Consistent bool   `json:"consistent"`
	Problem    string `json:"problem,omitempty"`
	Verified   bool   `json:"signature_verified"`
}

// checkAgainstCheckpoint compares a verified chain to a checkpoint.
//
// A log may legitimately have grown since the checkpoint was taken, so more
// entries than the checkpoint claims is fine provided the entry at the recorded
// position still carries the recorded hash. Fewer entries means the tail was
// removed, which is the case a chain cannot detect on its own.
func checkAgainstCheckpoint(entries []Entry, c *Checkpoint, pub ed25519.PublicKey) *CheckpointResult {
	res := &CheckpointResult{Size: c.Size, LogSize: len(entries)}

	if pub != nil {
		if !c.verifySignature(pub) {
			res.Problem = "checkpoint signature does not validate, so this checkpoint was not issued by the holder of that key"
			return res
		}
		res.Verified = true
	}

	if uint64(len(entries)) < c.Size {
		res.Problem = fmt.Sprintf(
			"checkpoint records %d entries but the log holds %d, so %d entries were removed from the end",
			c.Size, len(entries), c.Size-uint64(len(entries)))
		return res
	}

	if c.Size == 0 {
		res.Consistent = true
		return res
	}

	if got := entries[c.Size-1].Hash; got != c.Head {
		res.Problem = fmt.Sprintf(
			"entry %d hashes to %s but the checkpoint recorded %s, so history was rewritten at or before that point",
			c.Size-1, short(got), short(c.Head))
		return res
	}

	res.Consistent = true
	return res
}

func short(hash string) string {
	if len(hash) <= 16 {
		return hash
	}
	return hash[:16] + "..."
}
