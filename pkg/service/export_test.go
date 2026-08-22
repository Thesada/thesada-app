package service

// Test-only seam. export_test.go compiles into the test binary and nowhere
// else, so this cannot be reached from production code.

// SetVerifyBurnHook installs f in the window between the challenge burn and
// the verified update, and returns a function restoring the previous value.
func SetVerifyBurnHook(f func()) func() {
	prev := testHookAfterBurn
	testHookAfterBurn = f
	return func() { testHookAfterBurn = prev }
}
