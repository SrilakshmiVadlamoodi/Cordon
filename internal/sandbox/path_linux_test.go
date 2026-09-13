//go:build linux

package sandbox

import (
	"reflect"
	"testing"
)

// TestExtraPathDirs_ExcludesAlreadyCoveredDirectories is a fast, in-package
// unit test for the pure PATH-diffing logic env-path-forwarding adds —
// separate from the slower, namespace-requiring end-to-end proof in
// sandbox_test.go that the resulting directories actually get bind-mounted
// and resolved inside a real sandbox run.
func TestExtraPathDirs_ExcludesAlreadyCoveredDirectories(t *testing.T) {
	cases := []struct {
		name       string
		callerPath string
		want       []string
	}{
		{
			name:       "exact roSystemDirs entries excluded",
			callerPath: "/usr/bin:/bin",
			want:       nil,
		},
		{
			name:       "defaultPath entries excluded",
			callerPath: "/usr/local/sbin:/sbin",
			want:       nil,
		},
		{
			name:       "nested under a roSystemDirs entry excluded",
			callerPath: "/usr/lib/node_modules/.bin",
			want:       nil,
		},
		{
			name:       "genuinely new directory kept",
			callerPath: "/opt/hostedtoolcache/node/20.0.0/x64/bin",
			want:       []string{"/opt/hostedtoolcache/node/20.0.0/x64/bin"},
		},
		{
			name:       "order preserved, duplicates within callerPath collapsed",
			callerPath: "/opt/a:/opt/b:/opt/a",
			want:       []string{"/opt/a", "/opt/b"},
		},
		{
			name:       "empty segments from a leading/trailing/doubled colon ignored",
			callerPath: ":/opt/a::/opt/b:",
			want:       []string{"/opt/a", "/opt/b"},
		},
		{
			name:       "empty caller PATH yields nothing to forward",
			callerPath: "",
			want:       nil,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := extraPathDirs(tc.callerPath)
			if !reflect.DeepEqual(got, tc.want) {
				t.Errorf("extraPathDirs(%q) = %#v, want %#v", tc.callerPath, got, tc.want)
			}
		})
	}
}

func TestUnderAny(t *testing.T) {
	roots := []string{"/usr", "/bin"}
	cases := []struct {
		dir  string
		want bool
	}{
		{"/usr", true},
		{"/usr/bin", true},
		{"/usr/local/bin", true},
		{"/bin", true},
		{"/opt/bin", false},
		{"/usrx", false}, // must not match on bare string prefix without a separator
	}
	for _, tc := range cases {
		if got := underAny(tc.dir, roots); got != tc.want {
			t.Errorf("underAny(%q, %v) = %v, want %v", tc.dir, roots, got, tc.want)
		}
	}
}
