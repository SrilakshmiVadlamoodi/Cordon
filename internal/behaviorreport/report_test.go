package behaviorreport_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/SrilakshmiVadlamoodi/cordon/internal/behaviorreport"
	"github.com/SrilakshmiVadlamoodi/cordon/internal/syscallcapture"
)

func ev(syscall, path, addr string) syscallcapture.Event {
	return syscallcapture.Event{Syscall: syscall, Path: path, Addr: addr}
}

func severities(r behaviorreport.Report) []string {
	var out []string
	for _, f := range r.Findings {
		out = append(out, f.Severity.String()+":"+f.Title)
	}
	return out
}

func TestGenerate_QuietRun_NoFindings(t *testing.T) {
	r := behaviorreport.Generate([]syscallcapture.Event{
		ev("openat", "/home/u/proj/package.json", ""),
		ev("openat", "/home/u/proj/build/x.js", ""),
	}, 0, behaviorreport.Allowlist{})
	if len(r.Findings) != 0 {
		t.Fatalf("want no findings, got %v", severities(r))
	}
	if r.OpenCount != 2 {
		t.Fatalf("OpenCount = %d, want 2", r.OpenCount)
	}
}

func TestGenerate_CredentialRead_IsHigh(t *testing.T) {
	r := behaviorreport.Generate([]syscallcapture.Event{
		ev("openat", "/home/u/proj/.ssh/id_rsa", ""),
	}, 0, behaviorreport.Allowlist{})
	if got := severities(r); len(got) != 1 || got[0] != "HIGH:Credential file read" {
		t.Fatalf("findings = %v, want one HIGH credential-read", got)
	}
}

func TestGenerate_BareConnect_IsMediumNotEscalated(t *testing.T) {
	r := behaviorreport.Generate([]syscallcapture.Event{
		ev("connect", "", "203.0.113.7:443"),
	}, 0, behaviorreport.Allowlist{})
	got := severities(r)
	if len(got) != 1 || got[0] != "MEDIUM:Network connection" {
		t.Fatalf("findings = %v, want a single MEDIUM network connection", got)
	}
}

func TestGenerate_CredentialReadPlusConnect_Escalates(t *testing.T) {
	r := behaviorreport.Generate([]syscallcapture.Event{
		ev("openat", "/home/u/proj/.ssh/id_rsa", ""),
		ev("connect", "", "203.0.113.21:443"),
	}, 0, behaviorreport.Allowlist{})
	got := severities(r)
	// Highest severity first: the two HIGHs (credential read, exfil
	// correlation) before the MEDIUM connection.
	want := []string{
		"HIGH:Credential file read",
		"HIGH:Possible credential exfiltration",
		"MEDIUM:Network connection",
	}
	if len(got) != len(want) {
		t.Fatalf("findings = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("findings[%d] = %q, want %q (full: %v)", i, got[i], want[i], got)
		}
	}
}

func TestGenerate_DotEnvRead_IsHigh(t *testing.T) {
	r := behaviorreport.Generate([]syscallcapture.Event{
		ev("openat", "/home/u/proj/.env", ""),
	}, 0, behaviorreport.Allowlist{})
	if got := severities(r); len(got) != 1 || got[0] != "HIGH:Credential file read" {
		t.Fatalf("findings = %v, want one HIGH credential-read for .env", got)
	}
}

func TestGenerate_CredentialReadNoConnect_DoesNotEscalate(t *testing.T) {
	r := behaviorreport.Generate([]syscallcapture.Event{
		ev("openat", "/home/u/proj/.npmrc", ""),
	}, 0, behaviorreport.Allowlist{})
	got := severities(r)
	if len(got) != 1 || got[0] != "HIGH:Credential file read" {
		t.Fatalf("findings = %v, want one HIGH credential-read, no exfil finding", got)
	}
}

func TestGenerate_DuplicatePathsAndAddrsCollapse(t *testing.T) {
	r := behaviorreport.Generate([]syscallcapture.Event{
		ev("openat", "/home/u/proj/.ssh/id_rsa", ""),
		ev("openat", "/home/u/proj/.ssh/id_rsa", ""),
		ev("connect", "", "203.0.113.21:443"),
		ev("connect", "", "203.0.113.21:443"),
	}, 0, behaviorreport.Allowlist{})
	// One credential-read, one connect, one exfil correlation — not two of each.
	if got := severities(r); len(got) != 3 {
		t.Fatalf("findings = %v, want exactly 3 (deduped)", got)
	}
}

// allowlistFor builds an Allowlist containing exactly path, via the real
// LoadAllowlist parser (not by poking at unexported fields) — path must
// exist on disk since LoadAllowlist's fail-safe validation requires it.
func allowlistFor(t *testing.T, path string) behaviorreport.Allowlist {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("planted\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	return behaviorreport.LoadAllowlist(strings.NewReader(path + "\n"))
}

func TestGenerate_AllowlistedPath_SuppressesStandaloneFinding(t *testing.T) {
	path := filepath.Join(t.TempDir(), ".ssh", "id_rsa")
	allow := allowlistFor(t, path)

	r := behaviorreport.Generate([]syscallcapture.Event{
		ev("openat", path, ""),
	}, 0, allow)

	if len(r.Findings) != 0 {
		t.Fatalf("allowlisted path should produce no Findings, got %v", severities(r))
	}
	if len(r.Suppressed) != 1 || r.Suppressed[0].Path != path || r.Suppressed[0].Title != "Credential file read" {
		t.Fatalf("Suppressed = %v, want one entry naming %q", r.Suppressed, path)
	}
}

func TestGenerate_AllowlistedPath_StillCorrelatesWithConnect(t *testing.T) {
	path := filepath.Join(t.TempDir(), ".ssh", "id_rsa")
	allow := allowlistFor(t, path)

	r := behaviorreport.Generate([]syscallcapture.Event{
		ev("openat", path, ""),
		ev("connect", "", "203.0.113.21:443"),
	}, 0, allow)

	// The standalone "Credential file read" is suppressed, but the
	// exfil-correlation HIGH still fires: allowlisting suppresses the
	// standalone alert, not this run's read+connect signal in
	// combination (features/allowlist-mechanism/intent.md).
	got := severities(r)
	want := []string{"HIGH:Possible credential exfiltration", "MEDIUM:Network connection"}
	if len(got) != len(want) {
		t.Fatalf("findings = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("findings[%d] = %q, want %q (full: %v)", i, got[i], want[i], got)
		}
	}
	if len(r.Suppressed) != 1 {
		t.Fatalf("Suppressed = %v, want exactly one entry", r.Suppressed)
	}
}

func TestLoadAllowlist_InvalidEntriesAreIgnoredNotApplied(t *testing.T) {
	dir := t.TempDir()
	validPath := filepath.Join(dir, ".ssh", "id_rsa")
	if err := os.MkdirAll(filepath.Dir(validPath), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(validPath, []byte("key\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	missingPath := filepath.Join(dir, ".aws", "credentials") // never created

	input := strings.Join([]string{
		"# a comment line",
		"",
		"relative/.ssh/id_rsa", // relative -- must be ignored
		missingPath,            // absolute but no file there -- must be ignored
		validPath,              // absolute, exists -- must be applied
	}, "\n")

	allow := behaviorreport.LoadAllowlist(strings.NewReader(input))
	if allow.Ignored != 2 {
		t.Fatalf("Ignored = %d, want 2 (the relative line and the nonexistent-file line)", allow.Ignored)
	}

	suppressed := behaviorreport.Generate([]syscallcapture.Event{
		ev("openat", validPath, ""),
	}, 0, allow)
	if len(suppressed.Findings) != 0 || len(suppressed.Suppressed) != 1 {
		t.Fatalf("the valid entry should suppress: findings=%v suppressed=%v", suppressed.Findings, suppressed.Suppressed)
	}

	notSuppressed := behaviorreport.Generate([]syscallcapture.Event{
		ev("openat", missingPath, ""),
	}, 0, allow)
	if len(notSuppressed.Findings) != 1 || len(notSuppressed.Suppressed) != 0 {
		t.Fatalf("the nonexistent-file entry must NOT suppress -- path should stay flagged: findings=%v suppressed=%v",
			notSuppressed.Findings, notSuppressed.Suppressed)
	}
}

func TestReport_WriteText_UnobservedLineReflectsCount(t *testing.T) {
	var withDesc, without strings.Builder
	behaviorreport.Generate(nil, 3, behaviorreport.Allowlist{}).WriteText(&withDesc)
	behaviorreport.Generate(nil, 0, behaviorreport.Allowlist{}).WriteText(&without)

	if !strings.Contains(withDesc.String(), "3 other process(es) were launched during this run and were NOT traced") {
		t.Errorf("report with 3 descendants missing the specific count line:\n%s", withDesc.String())
	}
	if strings.Contains(without.String(), "were launched during this run and were NOT traced") {
		t.Errorf("report with 0 descendants should not claim processes were launched:\n%s", without.String())
	}
	if !strings.Contains(without.String(), "No separate processes were launched by the install this run") {
		t.Errorf("report with 0 descendants missing the zero-case line:\n%s", without.String())
	}
}

func TestReport_WriteText_NoFindingsRendersCleanly(t *testing.T) {
	var b strings.Builder
	behaviorreport.Generate([]syscallcapture.Event{ev("openat", "/x", "")}, 0, behaviorreport.Allowlist{}).WriteText(&b)
	out := b.String()
	if !strings.Contains(out, "No findings.") {
		t.Errorf("missing 'No findings.':\n%s", out)
	}
	if !strings.Contains(out, "WHAT CORDON DID NOT OBSERVE") {
		t.Errorf("missing the not-observed section even on a clean run:\n%s", out)
	}
}

func TestReport_WriteText_SuppressedSectionNamesPathAndTitle(t *testing.T) {
	path := filepath.Join(t.TempDir(), ".ssh", "id_rsa")
	allow := allowlistFor(t, path)

	var b strings.Builder
	behaviorreport.Generate([]syscallcapture.Event{
		ev("openat", path, ""),
	}, 0, allow).WriteText(&b)
	out := b.String()

	if !strings.Contains(out, "SUPPRESSED BY ALLOWLIST (1)") {
		t.Errorf("missing suppressed-by-allowlist section header:\n%s", out)
	}
	if !strings.Contains(out, "[Credential file read] "+path) {
		t.Errorf("suppressed section does not name the path:\n%s", out)
	}
	if strings.Contains(out, "[HIGH] Credential file read") {
		t.Errorf("a suppressed finding must not also appear in FINDINGS:\n%s", out)
	}
}

func TestReport_WriteText_AllowlistIgnoredCountSurfaced(t *testing.T) {
	allow := behaviorreport.LoadAllowlist(strings.NewReader("not/absolute\n"))
	if allow.Ignored != 1 {
		t.Fatalf("Ignored = %d, want 1", allow.Ignored)
	}

	var b strings.Builder
	behaviorreport.Generate(nil, 0, allow).WriteText(&b)
	out := b.String()
	if !strings.Contains(out, "1 entry(ies) in .cordon-allowlist were ignored") {
		t.Errorf("missing the ignored-entries line:\n%s", out)
	}
}
