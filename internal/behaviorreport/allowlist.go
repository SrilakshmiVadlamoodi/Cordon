package behaviorreport

import (
	"bufio"
	"io"
	"os"
	"path/filepath"
	"strings"
)

// AllowlistFileName is the project-root file a developer authors to mark
// specific, exact paths as known-safe for Rule 1 (credential-read). See
// features/allowlist-mechanism/intent.md.
const AllowlistFileName = ".cordon-allowlist"

// Allowlist holds developer-approved exact paths whose standalone
// Rule 1 finding should be suppressed. It has no bearing on Rule 2's
// exfil-correlation check: allowlisting a path says "reading this file
// alone isn't alarming," not "ignore this file even in combination with
// a network connection this run" — see Generate.
//
// Granularity is exact path only, by design (features/allowlist-
// mechanism/intent.md, "Why not globs"): both known false positives
// (.npmrc without a token, a non-secret .env) are content problems
// Cordon cannot observe (it traces openat, never read), so a path
// *pattern* loose enough to cover a legitimate file is loose enough to
// cover a malicious one at a similarly-shaped path. Allowlist is a
// value type (not built with exported fields) so a caller cannot
// construct one from an arbitrary map and bypass LoadAllowlist's
// fail-safe validation.
type Allowlist struct {
	paths map[string]bool
	// Ignored counts lines that were present and non-comment but failed
	// validation (not an absolute path, or no file exists there) and
	// were therefore dropped rather than applied. A dropped entry can
	// only leave a path MORE exposed (still reported as a finding),
	// never less — fail-safe means fail-flagged, not fail-open.
	Ignored int
}

func (a Allowlist) allows(path string) bool {
	// A nil map read (not write) is safe in Go and returns the zero
	// value, so this needs no separate nil check.
	return a.paths[path]
}

// LoadAllowlist parses .cordon-allowlist content from r: one path per
// line, blank lines and lines starting with '#' ignored. A line is
// accepted only if, after filepath.Clean, it is an absolute path AND a
// regular file actually exists there right now (checked via os.Stat,
// rejecting directories explicitly — os.Stat alone does not distinguish
// a file from a directory, and a directory entry could never match an
// openat path anyway) — matching the same resolved-path string Rule 1
// already compares against (Event.Path via matchCredentialMarker). Any
// other line (relative, malformed, a directory, or naming a path that
// doesn't exist) is silently dropped from the effective allowlist and
// counted in Ignored: this is deliberately fail-safe, not fail-open — an
// invalid entry never suppresses a finding, it just does nothing.
func LoadAllowlist(r io.Reader) Allowlist {
	paths := map[string]bool{}
	ignored := 0

	scanner := bufio.NewScanner(r)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		clean := filepath.Clean(line)
		if !filepath.IsAbs(clean) {
			ignored++
			continue
		}
		info, err := os.Stat(clean)
		if err != nil || info.IsDir() {
			ignored++
			continue
		}
		paths[clean] = true
	}
	return Allowlist{paths: paths, Ignored: ignored}
}

// LoadAllowlistFile opens <projectDir>/.cordon-allowlist and parses it
// via LoadAllowlist. A missing file is not an error — it means no
// entries, the default, zero-friction state (INTENT.md §2) — and
// returns a zero-value Allowlist that allows nothing.
func LoadAllowlistFile(projectDir string) Allowlist {
	f, err := os.Open(filepath.Join(projectDir, AllowlistFileName))
	if err != nil {
		return Allowlist{}
	}
	defer f.Close()
	return LoadAllowlist(f)
}
