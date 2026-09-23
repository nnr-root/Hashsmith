package smith

import (
	"errors"
	"os"
	"os/exec"
	"strings"
	"testing"
)

// gpu.go is not behind a build tag, so the failure-handling seam is testable
// in the default build even though no backend is compiled in.

// A dispatch failure must never be reported as "the GPU ran and found
// nothing". A driver error, a lost device or a refused allocation is
// indistinguishable from an exhausted keyspace once it reaches the user as
// "Not found", and they stop looking.
func TestGPUDispatchFailureIsNotSilentlyANegative(t *testing.T) {
	takeGPUDispatchError() // clear
	if gpuDispatchFailed() {
		t.Fatal("a failure is recorded before anything ran")
	}

	recordGPUDispatchFailure(errors.New("device lost"))
	if !gpuDispatchFailed() {
		t.Error("a recorded dispatch failure was not reported")
	}
	// The check must PEEK: the caller still needs the error for its message.
	if !gpuDispatchFailed() {
		t.Error("checking for a failure consumed it; the fallback message would lose the reason")
	}

	reason := gpuFallbackReason("md5")
	if !strings.Contains(reason, "device lost") {
		t.Errorf("fallback reason %q does not name the dispatch error", reason)
	}
	// Taking it clears it, so the next run starts clean.
	if gpuDispatchFailed() {
		t.Error("the dispatch error survived being taken")
	}

	// With nothing recorded, the reason falls back to the backend's own.
	recordGPUDispatchFailure(nil)
	if gpuDispatchFailed() {
		t.Error("recording a nil error registered a failure")
	}
}

// --gpu with a salt must decline the GPU rather than hash the bare candidate.
// No kernel takes a salt, so running one anyway produced digests for the wrong
// input and reported the correct password as not found.
func TestGPUSaltedRunFallsBackAndStillCracks(t *testing.T) {
	bin := buildTestBinary(t)
	// md5("abc" + "1234"), the salted construction the GPU path cannot do.
	const target = "a141c47927929bc2d1fb6d336a256df4"
	out := runCLI(t, bin, "-N", "crack", "-t", "md5", target,
		"-s", "1234", "-S", "suffix", "-M", "brute", "-C", "abc",
		"-n", "3", "-x", "3", "--gpu", "--no-pot")
	if !strings.Contains(out, "abc") {
		t.Errorf("a salted --gpu run did not recover the password:\n%s", out)
	}
	// It must also SAY it fell back, rather than quietly doing something else.
	if !strings.Contains(out, "salt") {
		t.Errorf("the run did not explain why the GPU was declined:\n%s", out)
	}
}

// runCLI runs the built binary and returns its combined output.
func runCLI(t *testing.T, bin string, args ...string) string {
	t.Helper()
	cmd := exec.Command(bin, args...)
	cmd.Env = append(os.Environ(), "NO_COLOR=1", "TERM=dumb", "HOME="+t.TempDir())
	out, _ := cmd.CombinedOutput()
	return string(out)
}
