package smith

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestWordlistLinesAreCandidatesVerbatim pins what a wordlist line means.
//
// Hashsmith used to trim each line and drop the ones that came out empty,
// which cost it two kinds of password: one with leading or trailing spaces,
// and the empty one. The second mattered most — an account with no password
// is the weakest finding there is, and Hashsmith verified it, stopped the
// run, and then reported "Not found", because found-ness was carried by the
// password being non-empty.
func TestWordlistLinesAreCandidatesVerbatim(t *testing.T) {
	dir := t.TempDir()
	list := filepath.Join(dir, "words.txt")
	// A blank line, a word with a trailing space, one with a leading space,
	// and an ordinary one.
	if err := os.WriteFile(list, []byte("\nsecret \n leading\nplain\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	// The reader and the counter must agree about which lines exist, because
	// the count is what --skip and --limit slice.
	n, err := countWordlistLines(list)
	if err != nil {
		t.Fatal(err)
	}
	if n != 4 {
		t.Errorf("counted %d lines, want 4", n)
	}

	for _, want := range []string{"", "secret ", " leading", "plain"} {
		target, err := hashText(want, "md5", "", "prefix")
		if err != nil {
			t.Fatalf("%q: %v", want, err)
		}
		res, err := dictAttack(t.Context(), list, 0, 0, 1, new(int64), nil,
			func(c string) bool { ok, _ := verifyCandidate(c, target, "md5", "", "prefix"); return ok },
			target, "md5", "", "prefix")
		if err != nil {
			t.Fatalf("%q: %v", want, err)
		}
		if !res.found {
			t.Errorf("%q: not found", want)
			continue
		}
		if res.password != want {
			t.Errorf("found %q, want %q", res.password, want)
		}
	}

	// And a password that is not in the list is still not found, so the
	// change did not make everything match.
	target, _ := hashText("absent", "md5", "", "prefix")
	res, err := dictAttack(t.Context(), list, 0, 0, 1, new(int64), nil,
		func(c string) bool { ok, _ := verifyCandidate(c, target, "md5", "", "prefix"); return ok },
		target, "md5", "", "prefix")
	if err != nil {
		t.Fatal(err)
	}
	if res.found {
		t.Errorf("reported %q for a password the list does not hold", res.password)
	}
}

// TestEmptyPasswordIsReportedLegibly pins that the terminal names what was
// found rather than printing nothing after "Found: ".
func TestEmptyPasswordIsReportedLegibly(t *testing.T) {
	dir := t.TempDir()
	list := filepath.Join(dir, "words.txt")
	if err := os.WriteFile(list, []byte("\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	target, _ := hashText("", "md5", "", "prefix")
	out := captureStderr(t, func() error {
		return runCrack([]string{"-t", "md5", "-w", list, "--no-pot", "-p", "1", target})
	})
	if !strings.Contains(out, "the empty password") {
		t.Errorf("the empty password was not named in the output:\n%s", out)
	}
}
