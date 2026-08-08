package main

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"
)

const (
	version   = "0.1.0"
	specRev   = "2026-07-28"
	userAgent = "adjent/" + version + " (+https://github.com/adjent-dev/adjent; MCP authorization conformance checker)"
)

// stderr is a variable so tests can capture diagnostic output.
var stderr io.Writer = os.Stderr

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}

	switch os.Args[1] {
	case "check":
		os.Exit(runCheck(os.Args[2:]))
	case "record":
		os.Exit(runRecord(os.Args[2:]))
	case "verify":
		os.Exit(runVerify(os.Args[2:]))
	case "keygen":
		os.Exit(runKeygen(os.Args[2:]))
	case "checkpoint":
		os.Exit(runCheckpoint(os.Args[2:]))
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
	fmt.Fprint(os.Stderr, `adjent: evidence for what autonomous software does

USAGE
  adjent check  <url>            check an MCP server against the `+specRev+` auth spec
  adjent record --upstream <url> record agent traffic into a tamper-evident log
  adjent verify <log>            verify that a recorded log has not been altered
  adjent keygen                  create an Ed25519 signing key
  adjent checkpoint <log>        sign a statement of how long the log is now

CHECK FLAGS
  --json           machine-readable output, for CI
  --timeout <dur>  per-request timeout (default 10s)

RECORD FLAGS
  --upstream <url>  MCP server to forward to (required)
  --listen <addr>   address to listen on (default 127.0.0.1:8722)
  --log <path>      log file to append to (default adjent.log)
  --key <path>      Ed25519 private key to sign entries with
  --retain-bodies   store request and response bodies, not only their hashes
  --verbose         print each call as it is recorded

VERIFY FLAGS
  --pubkey <path>             public key to check entry signatures against
  --checkpoint <path>         earlier checkpoint to detect truncation against
  --checkpoint-pubkey <path>  key the checkpoint was signed with, if different
  --origin <name>             origin the checkpoint must name
  --json                      machine-readable output

CHECKPOINT FLAGS
  --key <path>     Ed25519 private key to sign with (required)
  --out <path>     checkpoint to write (default adjent.checkpoint)
  --origin <name>  identifier for this log (default the log path)

KEYGEN FLAGS
  --key <path>     private key to write (default adjent.key)
  --pubkey <path>  public key to write (default adjent.pub)

EXIT CODES
  0  success, or a conformant server, or an intact log
  1  a MUST-level failure, or a log that has been altered
  2  usage error
  3  inconclusive, a required check could not be completed

check only reads metadata a server publishes about itself. It never probes for
exploitability. Point it at servers you operate, or have permission to test.

record stores only metadata by default, because agent traffic routinely carries
credentials and personal data that a record keeper should not hold.

An unsigned log shows only that nobody edited it carelessly. Anyone able to
write to the file could rebuild it. Sign with --key to make it evidence.

Signing does not reveal entries deleted from the end. Take checkpoints and keep
them somewhere the operator cannot reach, then verify against one.
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

func runRecord(args []string) int {
	fs := flag.NewFlagSet("record", flag.ExitOnError)
	upstream := fs.String("upstream", "", "MCP server to forward to")
	listen := fs.String("listen", "127.0.0.1:8722", "address to listen on")
	logPath := fs.String("log", "adjent.log", "log file to append to")
	keyPath := fs.String("key", "", "Ed25519 private key to sign entries with")
	retain := fs.Bool("retain-bodies", false, "store bodies, not only their hashes")
	verbose := fs.Bool("verbose", false, "print each call as it is recorded")
	_ = fs.Parse(args)

	if *upstream == "" {
		fmt.Fprint(os.Stderr, "adjent: --upstream is required\n\n")
		usage()
		return 2
	}

	target, err := normalizeTarget(*upstream)
	if err != nil {
		fmt.Fprintf(os.Stderr, "adjent: %v\n", err)
		return 2
	}

	log, err := OpenLog(*logPath, *retain)
	if err != nil {
		fmt.Fprintf(os.Stderr, "adjent: %v\n", err)
		return 2
	}
	defer log.Close()

	signing := "unsigned; anyone with write access could rebuild this log"
	if *keyPath != "" {
		priv, err := loadPrivateKey(*keyPath)
		if err != nil {
			fmt.Fprintf(os.Stderr, "adjent: %v\n", err)
			return 2
		}
		log.WithSigner(priv)
		signing = "signed by key " + keyID(priv.Public().(ed25519.PublicKey))
	}

	proxy := &recordingProxy{
		upstream: target,
		log:      log,
		client:   &http.Client{Timeout: 0}, // no timeout: MCP streams stay open
		verbose:  *verbose,
	}

	srv := &http.Server{
		Addr:              *listen,
		Handler:           proxy,
		ReadHeaderTimeout: 10 * time.Second,
	}

	fmt.Fprintf(stderr, "\nadjent record\n")
	fmt.Fprintf(stderr, "  listening   http://%s\n", *listen)
	fmt.Fprintf(stderr, "  forwarding  %s\n", target)
	fmt.Fprintf(stderr, "  recording   %s\n", *logPath)
	fmt.Fprintf(stderr, "  signing     %s\n", signing)
	if *retain {
		fmt.Fprintf(stderr, "  bodies      retained in full\n")
	} else {
		fmt.Fprintf(stderr, "  bodies      hashed, not stored\n")
	}
	fmt.Fprintf(stderr, "\nPoint your agent at the listening address instead of the server.\n\n")

	// Shut down on signal so the final entry is flushed and the listener
	// released, rather than leaving a half-written log behind.
	stop := make(chan os.Signal, 1)
	signal.Notify(stop, os.Interrupt, syscall.SIGTERM)

	errc := make(chan error, 1)
	go func() {
		err := srv.ListenAndServe()
		if err == http.ErrServerClosed {
			err = nil
		}
		errc <- err
	}()

	select {
	case err := <-errc:
		if err != nil {
			fmt.Fprintf(os.Stderr, "adjent: %v\n", err)
			return 1
		}
	case <-stop:
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		_ = srv.Shutdown(ctx)
		fmt.Fprintf(stderr, "\nrecorded through %s\n", log.Head())
	}
	return 0
}

func runKeygen(args []string) int {
	fs := flag.NewFlagSet("keygen", flag.ExitOnError)
	keyPath := fs.String("key", "adjent.key", "private key to write")
	pubPath := fs.String("pubkey", "adjent.pub", "public key to write")
	_ = fs.Parse(args)

	pub, priv, err := generateKeyPair()
	if err != nil {
		fmt.Fprintf(os.Stderr, "adjent: %v\n", err)
		return 1
	}
	if err := savePrivateKey(*keyPath, priv); err != nil {
		fmt.Fprintf(os.Stderr, "adjent: %v\n", err)
		return 1
	}
	if err := savePublicKey(*pubPath, pub); err != nil {
		fmt.Fprintf(os.Stderr, "adjent: %v\n", err)
		return 1
	}

	fmt.Printf("\nkey %s\n", keyID(pub))
	fmt.Printf("  private  %s  (mode 0600, never share or commit this)\n", *keyPath)
	fmt.Printf("  public   %s  (give this to anyone who needs to verify)\n\n", *pubPath)
	return 0
}

func runVerify(args []string) int {
	fs := flag.NewFlagSet("verify", flag.ExitOnError)
	asJSON := fs.Bool("json", false, "machine-readable output")
	pubPath := fs.String("pubkey", "", "public key to check signatures against")
	cpPath := fs.String("checkpoint", "", "earlier checkpoint to detect truncation against")
	cpPubPath := fs.String("checkpoint-pubkey", "", "key the checkpoint was signed with, if different")
	origin := fs.String("origin", "", "origin the checkpoint must name")
	_ = fs.Parse(args)

	if fs.NArg() != 1 {
		fmt.Fprint(os.Stderr, "adjent: expected exactly one log file\n\n")
		usage()
		return 2
	}

	var pub ed25519.PublicKey
	if *pubPath != "" {
		var err error
		if pub, err = loadPublicKey(*pubPath); err != nil {
			fmt.Fprintf(os.Stderr, "adjent: %v\n", err)
			return 2
		}
	}

	res, err := VerifyLog(fs.Arg(0), pub)
	if err != nil {
		fmt.Fprintf(os.Stderr, "adjent: %v\n", err)
		return 2
	}

	// Only compare against a checkpoint once the chain itself verifies. On a
	// broken chain the parsed entries are incomplete, and comparing them would
	// report a truncation that is really the earlier failure.
	if *cpPath != "" && res.Intact {
		cp, err := readCheckpoint(*cpPath)
		if err != nil {
			fmt.Fprintf(os.Stderr, "adjent: %v\n", err)
			return 2
		}
		cpPub := pub
		independent := false
		if *cpPubPath != "" {
			if cpPub, err = loadPublicKey(*cpPubPath); err != nil {
				fmt.Fprintf(os.Stderr, "adjent: %v\n", err)
				return 2
			}
			independent = !cpPub.Equal(pub)
		}

		res.Checkpoint = checkAgainstCheckpoint(res.entries, cp, cpPub, *origin)
		res.Checkpoint.IndependentKey = independent
		res.refineGuarantee()
	}

	if *asJSON {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		_ = enc.Encode(res)
	} else {
		renderVerify(res)
	}

	if !res.Intact {
		return 1
	}
	if res.Checkpoint != nil && !res.Checkpoint.Consistent {
		return 1
	}
	return 0
}

func runCheckpoint(args []string) int {
	fs := flag.NewFlagSet("checkpoint", flag.ExitOnError)
	keyPath := fs.String("key", "", "Ed25519 private key to sign with")
	outPath := fs.String("out", "adjent.checkpoint", "checkpoint to write")
	origin := fs.String("origin", "", "identifier for this log")
	_ = fs.Parse(args)

	if fs.NArg() != 1 {
		fmt.Fprint(os.Stderr, "adjent: expected exactly one log file\n\n")
		usage()
		return 2
	}
	if *keyPath == "" {
		fmt.Fprint(os.Stderr, "adjent: --key is required; an unsigned checkpoint proves nothing\n\n")
		usage()
		return 2
	}

	logPath := fs.Arg(0)
	priv, err := loadPrivateKey(*keyPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "adjent: %v\n", err)
		return 2
	}

	// Checkpointing a chain that does not verify would attest to a broken log.
	res, err := VerifyLog(logPath, priv.Public().(ed25519.PublicKey))
	if err != nil {
		fmt.Fprintf(os.Stderr, "adjent: %v\n", err)
		return 2
	}
	if !res.Intact {
		fmt.Fprintf(os.Stderr, "adjent: refusing to checkpoint a log that fails verification at entry %d: %s\n",
			*res.BrokenAt, res.Problem)
		return 1
	}

	name := *origin
	if name == "" {
		name = logPath
	}
	cp := NewCheckpoint(name, uint64(res.Entries), res.Head, priv)
	if err := writeCheckpoint(*outPath, cp); err != nil {
		fmt.Fprintf(os.Stderr, "adjent: %v\n", err)
		return 1
	}

	fmt.Printf("\ncheckpoint %s\n", *outPath)
	fmt.Printf("  origin  %s\n", cp.Origin)
	fmt.Printf("  size    %d entries\n", cp.Size)
	fmt.Printf("  head    %s\n", cp.Head)
	fmt.Printf("  signed  key %s\n\n", cp.KeyID)
	fmt.Printf("  Publish this where you cannot reach it. A checkpoint kept beside the log\n")
	fmt.Printf("  it describes proves nothing, since whoever rewrites one rewrites the other.\n\n")
	return 0
}

func renderVerify(r *VerifyResult) {
	fmt.Printf("\n%sadjent verify%s  %s\n\n", color(bold), color(reset), r.Path)
	fmt.Printf("  %sentries%s     %d\n", color(dim), color(reset), r.Entries)
	fmt.Printf("  %shead%s        %s\n", color(dim), color(reset), r.Head)
	if r.PayloadsChecked > 0 {
		fmt.Printf("  %sbodies%s      %d matched their recorded hash\n",
			color(dim), color(reset), r.PayloadsChecked)
	}
	switch {
	case r.SignaturesVerified > 0:
		fmt.Printf("  %ssignatures%s  %d of %d verified against key %s\n",
			color(dim), color(reset), r.SignaturesVerified, r.Entries, r.KeyID)
	case r.Signed > 0:
		fmt.Printf("  %ssignatures%s  %d present, %snone checked%s\n",
			color(dim), color(reset), r.Signed, color(yellow), color(reset))
	default:
		fmt.Printf("  %ssignatures%s  %snone%s\n", color(dim), color(reset), color(yellow), color(reset))
	}
	fmt.Println()

	if !r.Intact {
		fmt.Printf("  %s%sAltered%s at entry %d.\n", color(bold), color(red), color(reset), *r.BrokenAt)
		for _, line := range wrap(r.Problem, 72) {
			fmt.Printf("  %s%s%s\n", color(dim), line, color(reset))
		}
		fmt.Println()
		return
	}

	// The headline is qualified by what was actually proved, so a passing run
	// never reads as a stronger claim than the evidence supports.
	hue := yellow
	if r.SignaturesVerified > 0 {
		hue = green
	}
	fmt.Printf("  %s%sIntact%s. Every entry links to the one before it.\n",
		color(bold), color(hue), color(reset))
	for _, line := range wrap(r.Guarantee, 72) {
		fmt.Printf("  %s%s%s\n", color(dim), line, color(reset))
	}
	renderCheckpoint(r.Checkpoint)
	fmt.Println()
}

func renderCheckpoint(c *CheckpointResult) {
	if c == nil {
		return
	}
	fmt.Println()
	if !c.Consistent {
		fmt.Printf("  %s%sCheckpoint mismatch%s.\n", color(bold), color(red), color(reset))
		for _, line := range wrap(c.Problem, 72) {
			fmt.Printf("  %s%s%s\n", color(dim), line, color(reset))
		}
		return
	}
	fmt.Printf("  %s%sConsistent%s with a checkpoint of %d entries.\n",
		color(bold), color(green), color(reset), c.Size)
	if c.Verified {
		fmt.Printf("  %sNo entry recorded at that checkpoint has been removed or rewritten.%s\n",
			color(dim), color(reset))
	} else {
		fmt.Printf("  %sThe checkpoint signature was not checked; pass --pubkey to validate it.%s\n",
			color(dim), color(reset))
	}
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
