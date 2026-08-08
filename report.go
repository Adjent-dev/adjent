package main

import "time"

// Severity mirrors the language the specs use. A MUST failure means the server
// is non-conformant; a SHOULD failure is a real weakness but not a violation.
type Severity string

const (
	SevMust   Severity = "MUST"
	SevShould Severity = "SHOULD"
	SevInfo   Severity = "INFO"
)

type Status string

const (
	StatusPass Status = "pass"
	StatusFail Status = "fail"
	StatusWarn Status = "warn"
	// StatusSkip is used when a check cannot be answered by reading published
	// metadata. adjent never probes for exploitability, so some questions are
	// deliberately left unanswered rather than guessed at. A skip is a known
	// and permanent limit of the method, not a problem with this run.
	StatusSkip Status = "skip"
	// StatusUnknown means the check could not be completed, usually because the
	// server was unreachable. Unlike a skip, this says nothing about the server
	// and means the run itself is inconclusive.
	StatusUnknown Status = "unknown"
)

type Check struct {
	ID       string   `json:"id"`
	Title    string   `json:"title"`
	Severity Severity `json:"severity"`
	Status   Status   `json:"status"`
	Detail   string   `json:"detail"`
	Ref      string   `json:"ref,omitempty"`
}

type Report struct {
	Target  string    `json:"target"`
	Spec    string    `json:"spec"`
	Scanned time.Time `json:"scanned"`
	Checks  []Check   `json:"checks"`
	// Conformant is meaningful only when Inconclusive is false.
	Conformant bool `json:"conformant"`
	// Inconclusive reports that a required check could not be completed, so no
	// verdict about the server is available in either direction.
	Inconclusive bool    `json:"inconclusive"`
	Summary      Summary `json:"summary"`
}

type Summary struct {
	Pass    int `json:"pass"`
	Fail    int `json:"fail"`
	Warn    int `json:"warn"`
	Skip    int `json:"skip"`
	Unknown int `json:"unknown"`
}

func (r *Report) add(c Check) {
	r.Checks = append(r.Checks, c)
}

// finalize computes the summary. Only MUST-level checks affect the verdict, so
// warnings and skips never fail a build. A MUST-level check that could not be
// completed makes the whole run inconclusive, because calling a server
// conformant on the strength of checks that never ran would be worse than
// reporting nothing at all.
func (r *Report) finalize() {
	r.Conformant = true
	for _, c := range r.Checks {
		switch c.Status {
		case StatusPass:
			r.Summary.Pass++
		case StatusFail:
			r.Summary.Fail++
			if c.Severity == SevMust {
				r.Conformant = false
			}
		case StatusWarn:
			r.Summary.Warn++
		case StatusSkip:
			r.Summary.Skip++
		case StatusUnknown:
			r.Summary.Unknown++
			if c.Severity == SevMust {
				r.Inconclusive = true
			}
		}
	}
}
