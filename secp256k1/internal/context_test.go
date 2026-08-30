package internal

import "testing"

// TestContext exercises the shared context end to end: it proves the vendored
// C sources compile, link, and run. Note this file must stay free of
// `import "C"` — cgo is not permitted in _test.go files.
func TestContext(t *testing.T) {
	if context() == nil {
		t.Fatal("context() returned nil")
	}
	if context() != context() {
		t.Fatal("context() handed out two different contexts")
	}
}
