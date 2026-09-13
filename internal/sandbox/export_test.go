//go:build linux

package sandbox

// CheckUserNamespacesAvailableForTest exposes checkUserNamespacesAvailable
// to sandbox_test (an external test package) so helpers_test.go's
// requireUserNS can share the exact same check Run itself uses, rather than
// keeping a second, hand-copied copy of the same two sysctl reads. Exported
// only because Go's export_test.go idiom requires it to cross the package
// boundary into _test; not part of this package's real public API.
func CheckUserNamespacesAvailableForTest() error {
	return checkUserNamespacesAvailable()
}
