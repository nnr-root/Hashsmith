package smith

import (
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"syscall"
	"testing"
)

// makeFIFO creates a named pipe, used to prove that nothing in the wordlist
// path consumes bytes from a non-seekable source.
func makeFIFO(path string) error { return syscall.Mkfifo(path, 0o600) }

var (
	testBinOnce sync.Once
	testBinPath string
	testBinErr  error
)

// buildTestBinary compiles the CLI once per test run and returns its path.
// End-to-end tests need the real binary because the defects they pin live in
// argument handling and stream routing, which an in-process call cannot see.
func buildTestBinary(t *testing.T) string {
	t.Helper()
	testBinOnce.Do(func() {
		dir, err := os.MkdirTemp("", "hashsmith-e2e")
		if err != nil {
			testBinErr = err
			return
		}
		testBinPath = filepath.Join(dir, "hashsmith")
		cmd := exec.Command("go", "build", "-o", testBinPath, "hashsmith-go/cmd/hashsmith")
		if out, err := cmd.CombinedOutput(); err != nil {
			testBinErr = err
			t.Logf("build output:\n%s", out)
		}
	})
	if testBinErr != nil {
		t.Fatalf("building test binary: %v", testBinErr)
	}
	return testBinPath
}
