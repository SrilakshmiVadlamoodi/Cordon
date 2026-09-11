// Package behaviorreport turns a run's captured syscall events into a
// plain-text diagnosis for a developer (features/behavior-report/intent.md).
//
// The taxonomy here is deliberately crude — two rules, two severities —
// per that intent doc ("severity tiers may be crude here; the real
// taxonomy is Phase 2 work") and INTENT.md §2's signal-to-noise
// requirement: it must not flag an ordinary native build. See
// DECISIONS.md 2026-09-05 "behavior-report MVP: two rules, and where
// 'high severity' is drawn".
package behaviorreport

import (
	"fmt"
	"io"
	"sort"
	"strings"

	"github.com/SrilakshmiVadlamoodi/cordon/internal/syscallcapture"
)

// Severity is coarse on purpose for the MVP.
type Severity int

const (
	Medium Severity = iota
	High
)

func (s Severity) String() string {
	if s == High {
		return "HIGH"
	}
	return "MEDIUM"
}

// Finding is one thing worth telling the developer about.
type Finding struct {
	Severity Severity
	Title    string
	// Detail is already-wrapped plain text, indented by the renderer.
	Detail string
}

// Report is the whole diagnosis: findings plus an honest account of what
// was and wasn't seen.
type Report struct {
	Findings []Finding

	// Raw observation tallies, shown as-is.
	OpenCount    int
	ConnectCount int
	ExecCount    int

	// UnobservedDescendants is copied straight from
	// syscallcapture.Result — separate processes the install forked that
	// were not traced (features/syscall-capture-tree).
	UnobservedDescendants int
}

// Collector is the cheap onEvent sink: it only appends. All
// classification happens later, in Generate, off the ptrace hot path
// (onEvent is called synchronously from inside syscallcapture's tracer
// loop and blocks the tracee until it returns).
type Collector struct {
	Events []syscallcapture.Event
}

// OnEvent is the func to hand to syscallcapture.Run.
func (c *Collector) OnEvent(e syscallcapture.Event) {
	c.Events = append(c.Events, e)
}

// credentialPathMarkers are substrings that mark a path as a well-known
// secret store. Matched as plain substrings against the resolved path —
// crude but adequate for the MVP, and each has no legitimate reason to
// be opened by a package install. `.npmrc` is the loosest of these: a
// project-local `.npmrc` holding only registry config, no token, would
// match too — a known false-positive shape this rule does not
// distinguish, tracked for Phase 2's allowlist work (see
// testdata/corpus/credential-read-no-network/README.md). `/.env` has the
// same shape of imprecision: it also matches `/.envrc` (a direnv config
// file, not a dotenv secrets file) — a known, accepted false-positive
// class in the same family as `.npmrc`, not fixed here for the same
// reason (see DECISIONS.md, ".env credential marker was missing").
var credentialPathMarkers = []string{
	"/.ssh/id_rsa",
	"/.ssh/id_ed25519",
	"/.ssh/id_ecdsa",
	"/.ssh/id_dsa",
	"/.aws/credentials",
	"/.config/gcloud/credentials.db",
	"/.npmrc",
	"/.netrc",
	"/.git-credentials",
	"/.docker/config.json",
	"/.gnupg/",
	"/.bash_history",
	"/.zsh_history",
	"/.env",
}

// Generate runs the rules over the events and the descendant count.
func Generate(events []syscallcapture.Event, unobservedDescendants int) Report {
	r := Report{UnobservedDescendants: unobservedDescendants}

	var credentialPaths []string
	var connectAddrs []string
	seenCredPath := map[string]bool{}
	seenAddr := map[string]bool{}

	for _, e := range events {
		switch e.Syscall {
		case "openat":
			r.OpenCount++
			if m := matchCredentialMarker(e.Path); m != "" && !seenCredPath[e.Path] {
				seenCredPath[e.Path] = true
				credentialPaths = append(credentialPaths, e.Path)
			}
		case "connect":
			r.ConnectCount++
			if e.Addr != "" && !seenAddr[e.Addr] {
				seenAddr[e.Addr] = true
				connectAddrs = append(connectAddrs, e.Addr)
			}
		case "execve":
			r.ExecCount++
		}
	}

	// Rule 1 — credential-read: HIGH, one finding per distinct secret
	// path opened. Fires regardless of whether the open succeeded or
	// whether any network activity followed: the attempt alone is the
	// signal.
	for _, p := range credentialPaths {
		r.Findings = append(r.Findings, Finding{
			Severity: High,
			Title:    "Credential file read",
			Detail: fmt.Sprintf(
				"The install opened a file matching a known secret path:\n  %s\n"+
					"A package install has no legitimate reason to read this.", p),
		})
	}

	// Rule 2 — network egress: each distinct connect target is a MEDIUM
	// finding on its own (a legitimate native build fetches headers, so
	// this is not alarming by itself). If a credential file was *also*
	// read this run, add one HIGH "possible credential exfiltration"
	// finding correlating the two — Cordon cannot prove data flowed from
	// the file to the socket, only that both happened.
	for _, a := range connectAddrs {
		r.Findings = append(r.Findings, Finding{
			Severity: Medium,
			Title:    "Network connection",
			Detail: fmt.Sprintf(
				"The install opened a network connection to:\n  %s\n"+
					"Shown as IP:port — the hostname the install asked for is not captured.", a),
		})
	}
	if len(credentialPaths) > 0 && len(connectAddrs) > 0 {
		r.Findings = append(r.Findings, Finding{
			Severity: High,
			Title:    "Possible credential exfiltration",
			Detail: fmt.Sprintf(
				"A credential file was read AND a network connection was made in the same run:\n"+
					"  read:    %s\n"+
					"  connect: %s\n"+
					"Cordon cannot confirm the file's contents were sent — only that both happened.",
				strings.Join(credentialPaths, ", "), strings.Join(connectAddrs, ", ")),
		})
	}

	// Highest severity first; stable within a severity so output is
	// deterministic for a given event order.
	sort.SliceStable(r.Findings, func(i, j int) bool {
		return r.Findings[i].Severity > r.Findings[j].Severity
	})
	return r
}

func matchCredentialMarker(path string) string {
	for _, m := range credentialPathMarkers {
		if strings.Contains(path, m) {
			return m
		}
	}
	return ""
}

// WriteText renders the report as plain text to w (features/behavior-
// report/intent.md: "plain text to stdout only").
func (r Report) WriteText(w io.Writer) {
	fmt.Fprintln(w, "=== Cordon behavior report ===")
	fmt.Fprintln(w)

	if len(r.Findings) == 0 {
		fmt.Fprintln(w, "No findings.")
	} else {
		fmt.Fprintf(w, "FINDINGS (%d)\n\n", len(r.Findings))
		// Cap the rendered list. The report crosses a pipe with a fixed
		// buffer and is read only after the writer exits, so an
		// unbounded render (a run that connects to hundreds of distinct
		// hosts) could deadlock. Highest-severity findings sort first, so
		// the cap only ever drops lower-severity tail entries.
		const maxRendered = 100
		shown := r.Findings
		if len(shown) > maxRendered {
			shown = shown[:maxRendered]
		}
		for _, f := range shown {
			fmt.Fprintf(w, "  [%s] %s\n", f.Severity, f.Title)
			for _, line := range strings.Split(f.Detail, "\n") {
				fmt.Fprintf(w, "    %s\n", line)
			}
			fmt.Fprintln(w)
		}
		if len(r.Findings) > maxRendered {
			fmt.Fprintf(w, "  ... and %d more finding(s) not shown.\n\n", len(r.Findings)-maxRendered)
		}
	}

	fmt.Fprintln(w, "OBSERVED")
	fmt.Fprintf(w, "  %d file open(s), %d network connection(s), %d program execution(s)\n",
		r.OpenCount, r.ConnectCount, r.ExecCount)
	fmt.Fprintln(w)

	fmt.Fprintln(w, "WHAT CORDON DID NOT OBSERVE")
	fmt.Fprintln(w, "  - Only file opens, network connects, and program executions are traced.")
	fmt.Fprintln(w, "    What a program does with an open file (read vs. write, how much) is not")
	fmt.Fprintln(w, "    captured, and connection targets are shown as IP:port, not the hostname")
	fmt.Fprintln(w, "    the program resolved.")
	if r.UnobservedDescendants > 0 {
		fmt.Fprintf(w, "  - %d other process(es) were launched during this run and were NOT traced\n",
			r.UnobservedDescendants)
		fmt.Fprintln(w, "    (the process-tree gap, features/syscall-capture-tree). This is a lower")
		fmt.Fprintln(w, "    bound.")
	} else {
		fmt.Fprintln(w, "  - No separate processes were launched by the install this run; if any had")
		fmt.Fprintln(w, "    been, their syscalls would not have been traced.")
	}
	fmt.Fprintln(w, "  - Detection is best-effort by design (INTENT.md §1): a determined package")
	fmt.Fprintln(w, "    can act through syscalls Cordon does not watch, or through a child process.")
}
