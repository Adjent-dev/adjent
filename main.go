package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"
)

const (
	version   = "0.1.0"
	specRev   = "2026-07-28"
	userAgent = "adjent/" + version + " (+https://github.com/adjent-dev/adjent; MCP authorization conformance checker)"
)

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}

	switch os.Args[1] {
	case "check":
		os.Exit(runCheck(os.Args[2:]))
	case "version", "-v", "--version":
		fmt.Printf("adjent %s (MCP authorization spec %s)\n", version, specRev)
	case "help", "-h", "--help":
		usage()
	default:
		fmt.Fprintf(os.Stderr, "adjent: unknown command %q\n\n", os.Args[1])
		usage()
		os.Exit(2)
	}
}

func usage() {
	fmt.Fprint(os.Stderr, `adjent: check an MCP server against the `+specRev+` authorization spec

USAGE
  adjent check <url> [flags]

FLAGS
  --json           machine-readable output, for CI
  --timeout <dur>  per-request timeout (default 10s)

EXIT CODES
  0  conformant, no MUST-level failures
  1  non-conformant
  2  usage error
  3  inconclusive, a required check could not be completed

adjent only reads metadata a server publishes about itself. It never probes
for exploitability. Point it at servers you operate, or have permission to test.
`)
}

func runCheck(args []string) int {
	fs := flag.NewFlagSet("check", flag.ExitOnError)
	asJSON := fs.Bool("json", false, "machine-readable output")
	timeout := fs.Duration("timeout", 10*time.Second, "per-request timeout")
	_ = fs.Parse(args)

	if fs.NArg() != 1 {
		fmt.Fprint(os.Stderr, "adjent: expected exactly one server URL\n\n")
		usage()
		return 2
	}

	target, err := normalizeTarget(fs.Arg(0))
	if err != nil {
		fmt.Fprintf(os.Stderr, "adjent: %v\n", err)
		return 2
	}

	report := &Report{
		Target:  target.String(),
		Spec:    specRev,
		Scanned: time.Now().UTC(),
	}

	s := &scanner{
		client: &http.Client{
			Timeout: *timeout,
			// Metadata discovery follows redirects, but a runaway redirect
			// chain is a bug on the server's side, not something to chase.
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				if len(via) >= 5 {
					return fmt.Errorf("stopped after 5 redirects")
				}
				return nil
			},
		},
		target: target,
		report: report,
	}

	s.run()
	report.finalize()

	if *asJSON {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		_ = enc.Encode(report)
	} else {
		renderText(report)
	}

	switch {
	case report.Inconclusive:
		return 3
	case !report.Conformant:
		return 1
	}
	return 0
}

func normalizeTarget(raw string) (*url.URL, error) {
	if !strings.Contains(raw, "://") {
		raw = "https://" + raw
	}
	u, err := url.Parse(raw)
	if err != nil {
		return nil, fmt.Errorf("could not parse %q as a URL: %w", raw, err)
	}
	if u.Host == "" {
		return nil, fmt.Errorf("no host in %q", raw)
	}
	return u, nil
}

// --- rendering ---

const (
	dim    = "\033[2m"
	bold   = "\033[1m"
	red    = "\033[31m"
	green  = "\033[32m"
	yellow = "\033[33m"
	blue   = "\033[34m"
	reset  = "\033[0m"
)

// color returns the escape code, or an empty string when output is redirected
// or NO_COLOR is set, so piped and CI output stays clean.
func color(c string) string {
	if os.Getenv("NO_COLOR") != "" {
		return ""
	}
	if fi, err := os.Stdout.Stat(); err == nil && fi.Mode()&os.ModeCharDevice == 0 {
		return ""
	}
	return c
}

func renderText(r *Report) {
	fmt.Printf("\n%sadjent%s  %s\n", color(bold), color(reset), r.Target)
	fmt.Printf("%sMCP authorization spec %s%s\n\n", color(dim), r.Spec, color(reset))

	for _, c := range r.Checks {
		mark, hue := marker(c.Status)
		fmt.Printf("  %s%s%s  %s %s(%s)%s\n",
			color(hue), mark, color(reset), c.Title, color(dim), c.Severity, color(reset))
		for _, line := range wrap(c.Detail, 72) {
			fmt.Printf("      %s%s%s\n", color(dim), line, color(reset))
		}
		if c.Ref != "" {
			fmt.Printf("      %sref: %s%s\n", color(dim), c.Ref, color(reset))
		}
		fmt.Println()
	}

	fmt.Printf("  %s%d passed  %d failed  %d warnings  %d not checked  %d unknown%s\n",
		color(dim), r.Summary.Pass, r.Summary.Fail, r.Summary.Warn, r.Summary.Skip, r.Summary.Unknown, color(reset))

	switch {
	case r.Inconclusive:
		fmt.Printf("  %s%sInconclusive%s. A required check could not be completed, so this run reports no verdict.\n\n",
			color(bold), color(yellow), color(reset))
	case r.Conformant:
		fmt.Printf("  %s%sConformant%s. No MUST-level failures.\n\n", color(bold), color(green), color(reset))
	default:
		fmt.Printf("  %s%sNot conformant%s. MUST-level requirements are unmet.\n\n", color(bold), color(red), color(reset))
	}
}

func marker(s Status) (string, string) {
	switch s {
	case StatusPass:
		return "PASS", green
	case StatusFail:
		return "FAIL", red
	case StatusWarn:
		return "WARN", yellow
	case StatusUnknown:
		return "UNKN", yellow
	default:
		return "SKIP", blue
	}
}

// wrap breaks text on word boundaries so long explanations stay readable in a
// terminal without depending on a formatting library.
func wrap(text string, width int) []string {
	words := strings.Fields(text)
	if len(words) == 0 {
		return nil
	}

	var lines []string
	line := words[0]
	for _, w := range words[1:] {
		if len(line)+1+len(w) > width {
			lines = append(lines, line)
			line = w
			continue
		}
		line += " " + w
	}
	return append(lines, line)
}
