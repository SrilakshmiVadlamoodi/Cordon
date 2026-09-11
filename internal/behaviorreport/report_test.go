package behaviorreport_test

import (
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
	}, 0)
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
	}, 0)
	if got := severities(r); len(got) != 1 || got[0] != "HIGH:Credential file read" {
		t.Fatalf("findings = %v, want one HIGH credential-read", got)
	}
}

func TestGenerate_BareConnect_IsMediumNotEscalated(t *testing.T) {
	r := behaviorreport.Generate([]syscallcapture.Event{
		ev("connect", "", "203.0.113.7:443"),
	}, 0)
	got := severities(r)
	if len(got) != 1 || got[0] != "MEDIUM:Network connection" {
		t.Fatalf("findings = %v, want a single MEDIUM network connection", got)
	}
}

func TestGenerate_CredentialReadPlusConnect_Escalates(t *testing.T) {
	r := behaviorreport.Generate([]syscallcapture.Event{
		ev("openat", "/home/u/proj/.ssh/id_rsa", ""),
		ev("connect", "", "203.0.113.21:443"),
	}, 0)
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
	}, 0)
	if got := severities(r); len(got) != 1 || got[0] != "HIGH:Credential file read" {
		t.Fatalf("findings = %v, want one HIGH credential-read for .env", got)
	}
}

func TestGenerate_CredentialReadNoConnect_DoesNotEscalate(t *testing.T) {
	r := behaviorreport.Generate([]syscallcapture.Event{
		ev("openat", "/home/u/proj/.npmrc", ""),
	}, 0)
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
	}, 0)
	// One credential-read, one connect, one exfil correlation — not two of each.
	if got := severities(r); len(got) != 3 {
		t.Fatalf("findings = %v, want exactly 3 (deduped)", got)
	}
}

func TestReport_WriteText_UnobservedLineReflectsCount(t *testing.T) {
	var withDesc, without strings.Builder
	behaviorreport.Generate(nil, 3).WriteText(&withDesc)
	behaviorreport.Generate(nil, 0).WriteText(&without)

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
	behaviorreport.Generate([]syscallcapture.Event{ev("openat", "/x", "")}, 0).WriteText(&b)
	out := b.String()
	if !strings.Contains(out, "No findings.") {
		t.Errorf("missing 'No findings.':\n%s", out)
	}
	if !strings.Contains(out, "WHAT CORDON DID NOT OBSERVE") {
		t.Errorf("missing the not-observed section even on a clean run:\n%s", out)
	}
}
