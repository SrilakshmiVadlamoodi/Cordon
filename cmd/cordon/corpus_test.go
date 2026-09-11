//go:build linux

package main_test

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// buildFixture compiles one standalone fixture file
// (testdata/corpus/<group>/<file>.go) into destDir and returns its path.
// destDir must be inside the project dir the run will use, so the binary
// is visible through the sandbox's bind mount. Fixture files are built
// individually, not as a directory package, because each group directory
// holds several independent, self-contained "package main" files sharing
// no other declarations — `go build` only compiles the files explicitly
// named on its command line, so passing one file ignores its siblings.
func buildFixture(t *testing.T, group, file, destDir string) string {
	t.Helper()
	src, err := filepath.Abs(filepath.Join("..", "..", "testdata", "corpus", group, file+".go"))
	if err != nil {
		t.Fatal(err)
	}
	bin := filepath.Join(destDir, "fixture-"+group+"-"+file)
	out, err := exec.Command("go", "build", "-o", bin, src).CombinedOutput()
	if err != nil {
		t.Fatalf("building fixture %s/%s: %v\n%s", group, file, err, out)
	}
	return bin
}

// runCorpusFixture runs one corpus fixture through the real cordon binary
// and returns just the behavior-report section of stdout.
func runCorpusFixture(t *testing.T, cordonBin, group, file string, plant func(projectDir string)) string {
	t.Helper()
	projectDir := t.TempDir()
	if plant != nil {
		plant(projectDir)
	}
	fixtureBin := buildFixture(t, group, file, projectDir)

	cmd := exec.Command(cordonBin, "run", fixtureBin)
	cmd.Dir = projectDir // cordon uses cwd as the project dir; sandbox maps $HOME to it
	out, _ := cmd.CombinedOutput()

	marker := "=== Cordon behavior report ==="
	i := strings.Index(string(out), marker)
	if i < 0 {
		t.Fatalf("%s/%s: no behavior report in output:\n%s", group, file, out)
	}
	return string(out)[i:]
}

func plantSSHKey(projectDir string) {
	_ = os.MkdirAll(filepath.Join(projectDir, ".ssh"), 0o700)
	_ = os.WriteFile(filepath.Join(projectDir, ".ssh", "id_rsa"), []byte("FAKE-PRIVATE-KEY\n"), 0o600)
}

func plantAWSCreds(projectDir string) {
	_ = os.MkdirAll(filepath.Join(projectDir, ".aws"), 0o700)
	_ = os.WriteFile(filepath.Join(projectDir, ".aws", "credentials"), []byte("FAKE-AWS-KEY\n"), 0o600)
}

func plantNpmrc(projectDir string) {
	_ = os.WriteFile(filepath.Join(projectDir, ".npmrc"),
		[]byte("//registry.npmjs.org/:_authToken=FAKE-TOKEN\n"), 0o600)
}

func plantDotEnv(projectDir string) {
	_ = os.WriteFile(filepath.Join(projectDir, ".env"),
		[]byte("API_KEY=FAKE-KEY\n"), 0o600)
}

func plantKnownHosts(projectDir string) {
	_ = os.MkdirAll(filepath.Join(projectDir, ".ssh"), 0o700)
	_ = os.WriteFile(filepath.Join(projectDir, ".ssh", "known_hosts"),
		[]byte("github.com ssh-ed25519 AAAA...\n"), 0o644)
}

// plantSSHKeyPreAllowlisted plants the SSH key AND authors
// .cordon-allowlist to allow it, both before the fixture process starts
// — the intended, legitimate use of the mechanism.
func plantSSHKeyPreAllowlisted(projectDir string) {
	plantSSHKey(projectDir)
	entry := filepath.Join(projectDir, ".ssh", "id_rsa")
	_ = os.WriteFile(filepath.Join(projectDir, ".cordon-allowlist"), []byte(entry+"\n"), 0o644)
}

// plantMalformedAllowlist plants two credential files, but authors
// .cordon-allowlist with a RELATIVE (invalid) entry for one and a valid
// absolute entry for the other — exercising fail-safe parsing.
func plantMalformedAllowlist(projectDir string) {
	plantSSHKey(projectDir)
	plantAWSCreds(projectDir)
	lines := ".ssh/id_rsa\n" + filepath.Join(projectDir, ".aws", "credentials") + "\n"
	_ = os.WriteFile(filepath.Join(projectDir, ".cordon-allowlist"), []byte(lines), 0o644)
}

// ruleAssertion names a finding that MUST appear in the report.
type ruleAssertion struct {
	titleSubstr  string
	detailSubstr string // "" = don't check
}

// expectedMiss names a finding that MUST NOT appear — a documented,
// asserted non-detection, not just an absent check. reason is required:
// the test fails loudly if a case supplies an empty one, so a miss can
// never be added silently.
type expectedMiss struct {
	titleSubstr string
	reason      string
}

type corpusCase struct {
	name  string
	group string
	file  string
	plant func(projectDir string)

	wantHit  []ruleAssertion
	wantMiss []expectedMiss

	// wantContain/wantAbsent are plain substring checks with no special
	// semantics (unlike wantMiss, which asserts a documented detection
	// gap and requires a reason) — used for report structure that isn't
	// itself a rule finding, e.g. the SUPPRESSED BY ALLOWLIST section or
	// the allowlist-ignored-entries count.
	wantContain []string
	wantAbsent  []string

	// wantOrder asserts RELATIVE ORDER, not presence — each pair's first
	// substring's index in the report must be lower than its second's.
	// This is a distinct claim from wantHit (which only proves a finding
	// is present somewhere) and wantMiss (which only proves one is
	// absent): a case can pass every wantHit in its table entry — both
	// findings genuinely there — while still rendering them in the
	// wrong order, and wantHit has no way to catch that. wantOrder
	// exists specifically for features/finding-confidence's claim, which
	// only makes sense as an ordering statement: among two-or-more HIGH
	// findings, the definite-confidence one (or the exfil-correlation
	// finding, unconditionally) must render first. A fixture proving
	// this deliberately opens the LOWER-priority marker first
	// (`definite-before-heuristic.go`), so a pass here rules out the
	// specific failure mode a naive presence check would miss: passing
	// by accident because insertion order happened to already match the
	// required display order.
	wantOrder [][2]string

	noHigh        bool // assert no "[HIGH]" anywhere in the report
	noMedium      bool // assert no "[MEDIUM]" anywhere in the report
	wantEmpty     bool // assert the literal "No findings." line
	minUnobserved int  // if > 0, assert unobservedCount(t, report) >= this
	firstIsHigh   bool // assert the first finding line is a HIGH

	// benign is an explicit label for features/false-positive-rate: this
	// fixture models legitimate install behavior that should never
	// produce a HIGH finding. Deliberately NOT inferred from noHigh or
	// the absence of a HIGH wantHit — inference would wrongly fold in
	// cases that are non-HIGH for an unrelated reason (an
	// allowlist-suppressed finding, a documented detection miss) into a
	// "clean" population they don't belong to. Only a case explicitly
	// marked benign counts toward the false-positive rate.
	benign bool
}

// corpusCases is the single table both TestCorpus_BehaviorReport and
// TestCorpus_FalsePositiveRate iterate — one ground truth, so the
// published false-positive count can never drift from what the corpus
// actually asserts elsewhere.
var corpusCases = []corpusCase{
	// --- benign-local-io ---
	{
		name:      "noop-install: no findings",
		group:     "benign-local-io",
		file:      "noop-install",
		wantEmpty: true,
		noHigh:    true,
		noMedium:  true,
		benign:    true,
	},
	{
		name:     "local-file-writes: no high/medium",
		group:    "benign-local-io",
		file:     "local-file-writes",
		noHigh:   true,
		noMedium: true,
		benign:   true,
	},

	// --- network-egress ---
	{
		name:  "bare-connect: medium, not escalated",
		group: "network-egress",
		file:  "bare-connect",
		wantHit: []ruleAssertion{
			{titleSubstr: "[MEDIUM] Network connection", detailSubstr: "203.0.113.7:443"},
		},
		noHigh: true,
		benign: true,
	},
	{
		name:  "multi-host-connect: three distinct MEDIUMs, no escalation",
		group: "network-egress",
		file:  "multi-host-connect",
		wantHit: []ruleAssertion{
			{titleSubstr: "203.0.113.30:443"},
			{titleSubstr: "203.0.113.31:443"},
			{titleSubstr: "203.0.113.32:80"},
		},
		noHigh: true,
		benign: true,
	},

	// --- native-build-style ---
	{
		name:  "faux-node-gyp: medium egress, no high, descendants reported",
		group: "native-build-style",
		file:  "faux-node-gyp",
		wantHit: []ruleAssertion{
			{titleSubstr: "[MEDIUM] Network connection", detailSubstr: "203.0.113.11:443"},
		},
		noHigh:        true,
		minUnobserved: 2,
		benign:        true,
	},
	{
		name:     "temp-artifact-build: high /tmp churn, still no finding",
		group:    "native-build-style",
		file:     "temp-artifact-build",
		noHigh:   true,
		noMedium: true,
		benign:   true,
	},

	// --- credential-read ---
	{
		name:  "direct-read-and-exfil: two highs at the top",
		group: "credential-read",
		file:  "direct-read-and-exfil",
		plant: plantSSHKey,
		wantHit: []ruleAssertion{
			{titleSubstr: "[HIGH] Credential file read", detailSubstr: "id_rsa"},
			{titleSubstr: "[HIGH] Possible credential exfiltration", detailSubstr: "203.0.113.21:443"},
		},
		firstIsHigh: true,
	},
	{
		name:  "direct-read-no-network: high, no exfil, no medium",
		group: "credential-read",
		file:  "direct-read-no-network",
		plant: plantNpmrc,
		wantHit: []ruleAssertion{
			{titleSubstr: "[HIGH] Credential file read", detailSubstr: ".npmrc"},
		},
		noMedium: true,
		wantMiss: []expectedMiss{
			{titleSubstr: "Possible credential exfiltration",
				reason: "no network connection was made in this run, so Rule 2's escalation correlation has nothing to pair with — this is the ordinary non-escalation case, not a detection gap"},
		},
	},
	{
		name:  "multi-secret: two distinct HIGHs, deduped, no network",
		group: "credential-read",
		file:  "multi-secret",
		plant: func(dir string) { plantSSHKey(dir); plantAWSCreds(dir) },
		wantHit: []ruleAssertion{
			{titleSubstr: "[HIGH] Credential file read", detailSubstr: "id_rsa"},
			{titleSubstr: "[HIGH] Credential file read", detailSubstr: "credentials"},
		},
		noMedium: true,
	},

	// --- credential-marker-gap (the .env fix, proven) ---
	{
		name:  "dotenv-read: .env now recognized as a credential marker",
		group: "credential-marker-gap",
		file:  "dotenv-read",
		plant: plantDotEnv,
		wantHit: []ruleAssertion{
			{titleSubstr: "[HIGH] Credential file read", detailSubstr: ".env"},
		},
	},

	// --- credential-read-gap (expected miss) ---
	{
		name:  "subprocess-read: credential read in a forked child is NOT detected",
		group: "credential-read-gap",
		file:  "subprocess-read",
		plant: plantSSHKey,
		wantMiss: []expectedMiss{
			{titleSubstr: "Credential file read",
				reason: "syscall-capture's tracing scope covers only the single directly-launched process and its own OS threads (features/syscall-capture/intent.md 'Scope split', DECISIONS.md 2026-09-04); a forked child's own openat is auto-attached-and-released, never read. Closing this requires features/syscall-capture-tree, not yet built."},
		},
		minUnobserved: 1,
	},

	// --- marker-precision (false-positive hedge) ---
	{
		name:     "known-hosts: adjacent to a marker, not a match",
		group:    "marker-precision",
		file:     "known-hosts",
		plant:    plantKnownHosts,
		noHigh:   true,
		noMedium: true,
		benign:   true,
	},
	{
		name:     "generic-config: adjacent to the gcloud marker, not a match",
		group:    "marker-precision",
		file:     "generic-config",
		noHigh:   true,
		noMedium: true,
		benign:   true,
	},

	// --- escalation-volume ---
	{
		name:  "multi-secret-multi-host: dedup and ordering hold at volume",
		group: "escalation-volume",
		file:  "multi-secret-multi-host",
		plant: func(dir string) { plantSSHKey(dir); plantAWSCreds(dir); plantNpmrc(dir) },
		wantHit: []ruleAssertion{
			{titleSubstr: "id_rsa"},
			{titleSubstr: "credentials"},
			{titleSubstr: ".npmrc"},
			{titleSubstr: "203.0.113.40:443"},
			{titleSubstr: "203.0.113.41:443"},
			{titleSubstr: "203.0.113.42:443"},
		},
		firstIsHigh: true,
	},

	// --- allowlist-mechanism ---
	{
		name:  "pre-authored-suppresses: standalone finding suppressed, named in report",
		group: "allowlist-mechanism",
		file:  "pre-authored-suppresses",
		plant: plantSSHKeyPreAllowlisted,
		wantContain: []string{
			"SUPPRESSED BY ALLOWLIST (1)",
			"[Credential file read]",
		},
		noHigh:   true,
		noMedium: true,
	},
	{
		name:  "still-correlates-with-network: allowlisting does not suppress exfil correlation",
		group: "allowlist-mechanism",
		file:  "still-correlates-with-network",
		plant: plantSSHKeyPreAllowlisted,
		wantHit: []ruleAssertion{
			{titleSubstr: "[HIGH] Possible credential exfiltration", detailSubstr: "203.0.113.50:443"},
			{titleSubstr: "[MEDIUM] Network connection"},
		},
		wantContain: []string{"SUPPRESSED BY ALLOWLIST (1)"},
		wantAbsent:  []string{"[HIGH] Credential file read"},
		firstIsHigh: true,
	},
	{
		name:  "self-write-too-late: mid-run allowlist edit has no effect on this run (3b regression)",
		group: "allowlist-mechanism",
		file:  "self-write-too-late",
		plant: plantSSHKey, // no allowlist planted ahead of time -- the fixture writes its own
		wantHit: []ruleAssertion{
			{titleSubstr: "[HIGH] Credential file read", detailSubstr: "id_rsa"},
		},
		wantAbsent: []string{"SUPPRESSED BY ALLOWLIST"},
	},
	{
		name:  "malformed-entries-ignored: invalid entry stays flagged, valid entry suppresses",
		group: "allowlist-mechanism",
		file:  "malformed-entries-ignored",
		plant: plantMalformedAllowlist,
		wantHit: []ruleAssertion{
			{titleSubstr: "[HIGH] Credential file read", detailSubstr: "id_rsa"},
		},
		wantContain: []string{
			"SUPPRESSED BY ALLOWLIST (1)",
			"1 entry(ies) in .cordon-allowlist were ignored",
		},
		wantAbsent: []string{"SUPPRESSED BY ALLOWLIST (2)"},
	},

	// --- finding-confidence ---
	{
		name:  "definite-before-heuristic: id_rsa outranks .npmrc despite opening second",
		group: "finding-confidence",
		file:  "definite-before-heuristic",
		plant: func(dir string) { plantNpmrc(dir); plantSSHKey(dir) },
		wantHit: []ruleAssertion{
			{titleSubstr: "[HIGH] Credential file read", detailSubstr: "id_rsa"},
			{titleSubstr: "[HIGH] Credential file read", detailSubstr: ".npmrc"},
		},
		wantOrder: [][2]string{{"id_rsa", ".npmrc"}},
	},
	{
		name:  "exfil-ranks-first-even-with-heuristic-marker: correlation outranks a heuristic credential-read",
		group: "finding-confidence",
		file:  "exfil-ranks-first-even-with-heuristic-marker",
		plant: plantNpmrc,
		wantHit: []ruleAssertion{
			{titleSubstr: "[HIGH] Possible credential exfiltration", detailSubstr: "203.0.113.60:443"},
			{titleSubstr: "[HIGH] Credential file read", detailSubstr: ".npmrc"},
		},
		wantOrder: [][2]string{{"Possible credential exfiltration", "[HIGH] Credential file read"}},
	},
}

func TestCorpus_BehaviorReport(t *testing.T) {
	requireUserNS(t)
	cordonBin := buildCordon(t)

	for _, c := range corpusCases {
		c := c
		t.Run(c.name, func(t *testing.T) {
			r := runCorpusFixture(t, cordonBin, c.group, c.file, c.plant)

			for _, want := range c.wantHit {
				mustContain(t, r, want.titleSubstr)
				if want.detailSubstr != "" {
					mustContain(t, r, want.detailSubstr)
				}
			}

			for _, miss := range c.wantMiss {
				if miss.reason == "" {
					t.Fatalf("expectedMiss for %q has no reason — a documented miss must say why, not just assert absence", miss.titleSubstr)
				}
				mustNotContain(t, r, miss.titleSubstr)
				t.Logf("confirmed expected miss %q: %s", miss.titleSubstr, miss.reason)
			}

			for _, s := range c.wantContain {
				mustContain(t, r, s)
			}
			for _, s := range c.wantAbsent {
				mustNotContain(t, r, s)
			}

			for _, pair := range c.wantOrder {
				earlier, later := pair[0], pair[1]
				ei, li := strings.Index(r, earlier), strings.Index(r, later)
				if ei < 0 {
					t.Errorf("wantOrder: %q not found in report:\n%s", earlier, r)
				} else if li < 0 {
					t.Errorf("wantOrder: %q not found in report:\n%s", later, r)
				} else if ei >= li {
					t.Errorf("wantOrder: %q (at %d) should appear before %q (at %d):\n%s", earlier, ei, later, li, r)
				}
			}

			if c.noHigh {
				mustNotContain(t, r, "[HIGH]")
			}
			if c.noMedium {
				mustNotContain(t, r, "[MEDIUM]")
			}
			if c.wantEmpty {
				mustContain(t, r, "No findings.")
			}
			if c.minUnobserved > 0 {
				if n := unobservedCount(t, r); n < c.minUnobserved {
					t.Errorf("unobserved-descendant count = %d, want >= %d; report:\n%s", n, c.minUnobserved, r)
				}
			}
			if c.firstIsHigh {
				if fi := strings.Index(r, "FINDINGS"); fi >= 0 {
					after := r[fi:]
					firstBracket := strings.Index(after, "[")
					if firstBracket < 0 || !strings.HasPrefix(after[firstBracket:], "[HIGH]") {
						t.Errorf("first finding is not HIGH; report:\n%s", r)
					}
				}
			}
		})
	}
}

// TestCorpus_FalsePositiveRate computes and logs Cordon's false-positive
// rate on its own synthetic corpus (features/false-positive-rate/
// intent.md): the fraction of benign-labeled corpusCases (see
// corpusCase.benign) that produce an unexpected HIGH finding. It shares
// corpusCases with TestCorpus_BehaviorReport rather than keeping a
// separate list, so this number can never silently drift from what the
// rest of the corpus actually asserts.
//
// This is emphatically NOT a measurement against real npm/pip registry
// packages -- every fixture here is synthetic and self-authored
// (DECISIONS.md 2026-09-05, corpus-expansion/intent.md). The number this
// test logs describes exactly one thing: how Cordon's own rules classify
// the specific benign archetypes this project deliberately built to
// represent legitimate install behavior. See README.md's own caveats
// before citing this number anywhere else.
func TestCorpus_FalsePositiveRate(t *testing.T) {
	requireUserNS(t)
	cordonBin := buildCordon(t)

	var total, falsePositives int
	for _, c := range corpusCases {
		if !c.benign {
			continue
		}
		total++
		r := runCorpusFixture(t, cordonBin, c.group, c.file, c.plant)
		if strings.Contains(r, "[HIGH]") {
			falsePositives++
			t.Errorf("benign-labeled fixture %q produced a HIGH finding (false positive):\n%s", c.name, r)
		}
	}

	if total == 0 {
		t.Fatal("no corpusCase is labeled benign -- the false-positive-rate metric has nothing to measure; " +
			"this almost certainly means the benign label was lost, not that the corpus genuinely has none")
	}
	t.Logf("false-positive rate on Cordon's synthetic benign-archetype corpus (testdata/corpus/, "+
		"NOT a measurement against real registry packages): %d/%d benign-labeled fixtures produced "+
		"an unexpected HIGH finding", falsePositives, total)
}

// TestCorpus_DelayedProcess_DoesNotOutliveTheRun is a dedicated test, not
// a table row: its assertion is on a host-visible side effect (a marker
// file's absence, checked after a wait) rather than report text, so it
// doesn't fit corpusCase's report-only schema. See
// testdata/corpus/delayed-process/group.md for the full investigation
// this fixture is built on.
func TestCorpus_DelayedProcess_DoesNotOutliveTheRun(t *testing.T) {
	requireUserNS(t)
	cordonBin := buildCordon(t)

	projectDir := t.TempDir()
	fixtureBin := buildFixture(t, "delayed-process", "detached-descendant", projectDir)

	cmd := exec.Command(cordonBin, "run", fixtureBin)
	cmd.Dir = projectDir
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Logf("cordon run output:\n%s", out) // non-zero exit is not itself a failure here
	}

	marker := filepath.Join(projectDir, "marker-file")
	if _, err := os.Stat(marker); err == nil {
		t.Fatalf("marker-file exists immediately after cordon run returned; the detached descendant's delayed write should have been cut off by namespace teardown")
	}

	// The descendant's own sleep is 2s; wait well past it and check again.
	time.Sleep(3 * time.Second)
	if _, err := os.Stat(marker); err == nil {
		t.Fatalf("marker-file exists after waiting past the descendant's delay — namespace teardown did not kill it as DECISIONS.md's investigation found")
	}
}

// unobservedCount pulls N out of the report's
// "N other process(es) were launched ... NOT traced" line, or -1 if the
// zero-case line is present instead.
func unobservedCount(t *testing.T, report string) int {
	t.Helper()
	const marker = " other process(es) were launched during this run and were NOT traced"
	i := strings.Index(report, marker)
	if i < 0 {
		if strings.Contains(report, "No separate processes were launched by the install this run") {
			return 0
		}
		t.Fatalf("report has neither the descendant-count line nor the zero-case line:\n%s", report)
	}
	// Walk back from the marker to the start of the number.
	j := i
	for j > 0 && report[j-1] >= '0' && report[j-1] <= '9' {
		j--
	}
	n := 0
	for _, c := range report[j:i] {
		n = n*10 + int(c-'0')
	}
	return n
}

func mustContain(t *testing.T, haystack, needle string) {
	t.Helper()
	if !strings.Contains(haystack, needle) {
		t.Errorf("report missing %q:\n%s", needle, haystack)
	}
}

func mustNotContain(t *testing.T, haystack, needle string) {
	t.Helper()
	if strings.Contains(haystack, needle) {
		t.Errorf("report unexpectedly contains %q:\n%s", needle, haystack)
	}
}
