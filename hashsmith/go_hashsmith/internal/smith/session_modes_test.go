package smith

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestSessionModeListIsSharedNotCopied is the point of consolidating the two
// lists. They were a map and an inline || chain, with a comment instructing
// readers to keep them in step — which is not a thing a compiler can check.
func TestSessionModeListIsSharedNotCopied(t *testing.T) {
	for _, m := range []string{"brute", "mask", "markov", "hybrid", "combinator", "prince"} {
		if !sessionCheckpointModes[m] {
			t.Errorf("%s should be checkpointed", m)
		}
	}
	for _, m := range []string{"dict", "", "nonsense"} {
		if sessionCheckpointModes[m] {
			t.Errorf("%s should not be checkpointed", m)
		}
	}
}

// TestSessionRefusalIsAnnouncedForDict pins the behaviour that was missing: a
// run asked to be resumable and silently given no checkpoint is the worst
// outcome available, because the operator only finds out when they try to
// resume — which is after an interrupt, which is exactly when the work is
// already gone.
func TestSessionRefusalIsAnnouncedForDict(t *testing.T) {
	wl := filepath.Join(t.TempDir(), "w.txt")
	if err := os.WriteFile(wl, []byte("alpha\nbeta\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	target, err := hashText("not-in-the-list", "md5", "", "")
	if err != nil {
		t.Fatal(err)
	}

	out := captureStderr(t, func() error {
		return runCrack([]string{"-t", "md5", "-M", "dict", "-w", wl,
			"--session", "dict-session-test", "--no-pot", target})
	})

	if !strings.Contains(out, "not checkpointed for -M dict") {
		t.Errorf("a dict run with --session said nothing about the missing checkpoint:\n%s", out)
	}
	// The message has to leave the operator somewhere to go, not just say no.
	if !strings.Contains(out, "--skip") {
		t.Errorf("the refusal does not name the alternative:\n%s", out)
	}
}

// TestSessionIsSilentForACheckpointedMode is the other half: a mode that DOES
// checkpoint must not print the warning, or the message becomes noise every
// resumable run scrolls past.
func TestSessionIsSilentForACheckpointedMode(t *testing.T) {
	target, err := hashText("zz", "md5", "", "")
	if err != nil {
		t.Fatal(err)
	}
	out := captureStderr(t, func() error {
		return runCrack([]string{"-t", "md5", "-M", "brute", "-C", "abz", "-n", "2", "-x", "2",
			"--session", "brute-session-test", "--no-pot", target})
	})
	if strings.Contains(out, "not checkpointed") {
		t.Errorf("a brute run with --session warned about a checkpoint it does have:\n%s", out)
	}
}
