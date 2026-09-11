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

// maxRenderedFindings caps both the Findings and Suppressed render loops
// in WriteText. The report crosses a pipe with a fixed buffer and is
// read only after the writer exits (sandbox.Run's cmd.Wait then
// io.ReadAll), so an unbounded render of either list — hundreds of
// distinct connect targets, or a developer allowlisting many distinct
// paths under one broad marker like /.gnupg/ — could deadlock it.
const maxRenderedFindings = 100

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

	// confidence is an internal secondary sort key, never rendered —
	// see markerConfidence and the sort in Generate. Unexported
	// deliberately: only Generate should ever set it, so a caller
	// outside this package cannot construct a Finding that jumps the
	// queue.
	confidence markerConfidence
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

	// Suppressed lists Rule 1 findings that matched a credential-path
	// marker but were withheld because the path is in the developer's
	// own .cordon-allowlist. Named explicitly (title + path), not just
	// counted: a suppression is a deliberate developer decision, unlike
	// UnobservedDescendants, so the report should make it trivial to
	// audit that decision against what actually happened this run
	// (features/allowlist-mechanism/intent.md).
	Suppressed []SuppressedFinding

	// AllowlistIgnored is the number of lines in .cordon-allowlist that
	// were present but invalid (relative path, or no file exists there)
	// and were therefore dropped rather than applied — see
	// Allowlist.Ignored. Surfaced so a developer whose allowlist entry
	// silently did nothing (a typo, a moved file) can tell why.
	AllowlistIgnored int
}

// SuppressedFinding records one Rule 1 finding that would have been
// reported HIGH but was withheld because Path is in the allowlist.
type SuppressedFinding struct {
	Title string
	Path  string
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

// markerConfidence classifies how strongly a credentialMarker's own
// existence implies secret material, independent of Severity — see
// features/finding-confidence/intent.md. It is used only as a secondary
// sort key among findings that are already HIGH; it never changes
// whether something is HIGH, MEDIUM, or a finding at all.
type markerConfidence int

const (
	// heuristicConfidence markers are path-only signals that can
	// legitimately hold no secret at all — Cordon cannot see file
	// contents (it traces openat, never read), so these are exactly the
	// known false-positive shapes already on record (.npmrc without a
	// token, DECISIONS.md 2026-09-05; a non-secret .env, DECISIONS.md
	// 2026-09-11). heuristicConfidence is the zero value deliberately:
	// a Finding built without setting confidence (nothing outside this
	// file does, but future code should default to the more skeptical
	// reading, not the more alarming one) reads as heuristic, not
	// definite.
	heuristicConfidence markerConfidence = iota
	// definiteConfidence markers have no legitimate "config only, no
	// secret" reading — the file's sole documented purpose is storing
	// credential material (a private key; a cloud provider's literal
	// access-key file; git's or netrc's plaintext credential store).
	definiteConfidence
)

// credentialMarker pairs a path substring with how strongly its mere
// existence implies secret material.
type credentialMarker struct {
	pattern    string
	confidence markerConfidence
}

// credentialMarkers are substrings that mark a path as a well-known
// secret store, matched as plain substrings against the resolved path —
// crude but adequate for the MVP, and each has no legitimate reason to
// be opened by a package install. All fire the same HIGH severity;
// confidence only orders multiple simultaneous HIGHs, it never changes
// whether one fires (features/finding-confidence/intent.md).
//
// `.npmrc` is heuristicConfidence: a project-local `.npmrc` holding only
// registry config, no token, matches too — a known false-positive shape
// this rule does not distinguish (tracked for Phase 2's allowlist work,
// shipped as [[allowlist-mechanism]]; see
// testdata/corpus/credential-read-no-network/README.md history).
// `/.env` is the same shape of imprecision for the same reason
// (DECISIONS.md, ".env credential marker was missing") — and also
// matches `/.envrc` (a direnv config file, not a dotenv secrets file),
// an accepted false-positive class in the same family. Shell history
// files are heuristic for a different reason: they can hold an
// accidentally-typed secret, but their designed purpose is a command
// log, not a credential store.
//
// `/.netrc` is classified definiteConfidence here even though it wasn't
// named explicitly in features/finding-confidence/intent.md's examples:
// like `/.git-credentials`, its file format (machine/login/password
// stanzas) has no legitimate "config only" reading the way `.npmrc`'s
// registry-URL-only case does — its sole documented purpose is storing
// plaintext credentials. `/.docker/config.json` is kept definiteConfidence
// per that doc's explicit list, with a caveat worth flagging for a future
// revisit: many modern Docker configs hold only a `credsStore` pointer to
// an external credential helper, with no embedded secret in the file
// itself — closer to `.npmrc`'s shape than to a private key's. Not
// reclassified here without discussion, since the approved design named
// it definite explicitly.
var credentialMarkers = []credentialMarker{
	{"/.ssh/id_rsa", definiteConfidence},
	{"/.ssh/id_ed25519", definiteConfidence},
	{"/.ssh/id_ecdsa", definiteConfidence},
	{"/.ssh/id_dsa", definiteConfidence},
	{"/.aws/credentials", definiteConfidence},
	{"/.config/gcloud/credentials.db", definiteConfidence},
	{"/.npmrc", heuristicConfidence},
	{"/.netrc", definiteConfidence},
	{"/.git-credentials", definiteConfidence},
	{"/.docker/config.json", definiteConfidence},
	{"/.gnupg/", heuristicConfidence},
	{"/.bash_history", heuristicConfidence},
	{"/.zsh_history", heuristicConfidence},
	{"/.env", heuristicConfidence},
}

// Generate runs the rules over the events and the descendant count.
// allow suppresses Rule 1's standalone finding for any path it covers
// (features/allowlist-mechanism/intent.md) but has no effect on Rule 2's
// exfil-correlation check below, which considers every matched
// credential path regardless of allowlist status — allowlisting says
// "reading this file alone isn't alarming," not "ignore this file even
// in combination with a network connection this run."
func Generate(events []syscallcapture.Event, unobservedDescendants int, allow Allowlist) Report {
	r := Report{UnobservedDescendants: unobservedDescendants, AllowlistIgnored: allow.Ignored}

	var credentialPaths []string
	var connectAddrs []string
	// credentialConfidence carries each matched path's confidence
	// alongside credentialPaths, keyed by path — a secondary sort key
	// for Rule 1's Findings (features/finding-confidence/intent.md), not
	// used by the exfil-correlation check below, which treats every
	// matched path identically regardless of confidence.
	credentialConfidence := map[string]markerConfidence{}
	seenCredPath := map[string]bool{}
	seenAddr := map[string]bool{}

	for _, e := range events {
		switch e.Syscall {
		case "openat":
			r.OpenCount++
			if conf, matched := matchCredentialMarker(e.Path); matched && !seenCredPath[e.Path] {
				seenCredPath[e.Path] = true
				credentialPaths = append(credentialPaths, e.Path)
				credentialConfidence[e.Path] = conf
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
	// signal. An allowlisted path is withheld from Findings and recorded
	// in Suppressed instead — it is NOT removed from credentialPaths
	// itself, so the exfil-correlation check below still sees it.
	for _, p := range credentialPaths {
		if allow.allows(p) {
			r.Suppressed = append(r.Suppressed, SuppressedFinding{Title: "Credential file read", Path: p})
			continue
		}
		r.Findings = append(r.Findings, Finding{
			Severity: High,
			Title:    "Credential file read",
			Detail: fmt.Sprintf(
				"The install opened a file matching a known secret path:\n  %s\n"+
					"A package install has no legitimate reason to read this.", p),
			confidence: credentialConfidence[p],
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
	// credentialPaths here is the FULL matched set, allowlisted entries
	// included — see Generate's doc comment for why this correlation is
	// not subject to the allowlist the way the standalone Rule 1 finding
	// above is.
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

	// Highest severity first, then by confidence rank within a severity
	// (features/finding-confidence/intent.md) — stable beyond that, so
	// output is deterministic for a given event order whenever severity
	// and rank tie.
	sort.SliceStable(r.Findings, func(i, j int) bool {
		fi, fj := r.Findings[i], r.Findings[j]
		if fi.Severity != fj.Severity {
			return fi.Severity > fj.Severity
		}
		return fi.confidenceRank() < fj.confidenceRank()
	})
	return r
}

// confidenceRank orders findings within the same Severity: the
// exfil-correlation finding is always the single strongest signal
// Cordon can produce, independent of which marker's confidence
// triggered the credential-read half of it, so it ranks first
// regardless of confidence. Among ordinary findings, definiteConfidence
// ranks ahead of heuristicConfidence. This has no effect across
// severities — Generate's sort already checks Severity first — so a
// MEDIUM "Network connection" finding's zero-value confidence never
// competes with a HIGH's.
func (f Finding) confidenceRank() int {
	if f.Title == "Possible credential exfiltration" {
		return 0
	}
	if f.confidence == definiteConfidence {
		return 1
	}
	return 2
}

func matchCredentialMarker(path string) (conf markerConfidence, matched bool) {
	for _, m := range credentialMarkers {
		if strings.Contains(path, m.pattern) {
			return m.confidence, true
		}
	}
	return heuristicConfidence, false
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
		shown := r.Findings
		if len(shown) > maxRenderedFindings {
			shown = shown[:maxRenderedFindings]
		}
		for _, f := range shown {
			fmt.Fprintf(w, "  [%s] %s\n", f.Severity, f.Title)
			for _, line := range strings.Split(f.Detail, "\n") {
				fmt.Fprintf(w, "    %s\n", line)
			}
			fmt.Fprintln(w)
		}
		if len(r.Findings) > maxRenderedFindings {
			fmt.Fprintf(w, "  ... and %d more finding(s) not shown.\n\n", len(r.Findings)-maxRenderedFindings)
		}
	}

	if len(r.Suppressed) > 0 {
		fmt.Fprintf(w, "SUPPRESSED BY ALLOWLIST (%d)\n\n", len(r.Suppressed))
		// Same cap and rationale as Findings above: this crosses the same
		// fixed-size pipe, read only after the writer exits, so an
		// unbounded render (a developer allowlisting many distinct paths
		// under one broad marker, e.g. /.gnupg/) could deadlock it exactly
		// as an uncapped Findings list could.
		shown := r.Suppressed
		if len(shown) > maxRenderedFindings {
			shown = shown[:maxRenderedFindings]
		}
		for _, s := range shown {
			fmt.Fprintf(w, "  [%s] %s\n", s.Title, s.Path)
		}
		if len(r.Suppressed) > maxRenderedFindings {
			fmt.Fprintf(w, "  ... and %d more suppressed entry(ies) not shown.\n", len(r.Suppressed)-maxRenderedFindings)
		}
		fmt.Fprintln(w, "  A finding above was withheld because its exact path is listed in this")
		fmt.Fprintf(w, "  project's %s. This does not affect any 'Possible credential\n", AllowlistFileName)
		fmt.Fprintln(w, "  exfiltration' finding, which still considers this path if it was also")
		fmt.Fprintln(w, "  involved in a network connection this run.")
		fmt.Fprintln(w)
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
	if r.AllowlistIgnored > 0 {
		fmt.Fprintf(w, "  - %d entry(ies) in %s were ignored (not an absolute path to\n", r.AllowlistIgnored, AllowlistFileName)
		fmt.Fprintln(w, "    a file that exists) and treated as NOT allowlisted -- any matching path")
		fmt.Fprintln(w, "    stays flagged as usual.")
	}
}
