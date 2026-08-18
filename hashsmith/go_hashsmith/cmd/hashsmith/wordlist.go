package main

import (
	"bufio"
	_ "embed"
	"io"
	"os"
	"strings"
)

// embeddedCommonWordlist is the bundled common.txt, compiled directly into the
// binary via go:embed. Because it lives inside the executable, dictionary
// attacks work from any working directory and even when the package is
// pip-installed without the external wordlists/ directory.
//
//go:embed common.txt
var embeddedCommonWordlist string

// defaultWordlistLabel is shown to the user when the built-in list is used.
const defaultWordlistLabel = "built-in common.txt"

// openWordlist returns a reader for the requested wordlist. An empty path
// selects the embedded common.txt, so callers can omit -w / --wordlist and
// still get a working default. The returned label describes the source for
// user-facing messages.
func openWordlist(path string) (io.ReadCloser, string, error) {
	if strings.TrimSpace(path) == "" {
		return io.NopCloser(strings.NewReader(embeddedCommonWordlist)), defaultWordlistLabel, nil
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, "", err
	}
	return f, path, nil
}

// wordlistCountable reports whether a wordlist can be pre-counted for the
// progress bar without harm. Non-regular inputs — pipes, FIFOs, process
// substitution (/dev/fd/N), stdin — are one-shot streams: reading them to count
// lines would consume the data before the attack runs, so they are skipped (the
// progress bar is simply left indeterminate). The embedded default re-reads from
// memory and is always countable.
func wordlistCountable(path string) bool {
	if strings.TrimSpace(path) == "" {
		return true
	}
	info, err := os.Stat(path)
	if err != nil {
		return false
	}
	return info.Mode().IsRegular()
}

// countWordlistLines counts the non-empty lines of a wordlist (embedded default
// when path is empty) so the progress bar can show an accurate total. It returns
// -1 for non-seekable inputs, which must not be read twice (see wordlistCountable).
func countWordlistLines(path string) (int64, error) {
	if !wordlistCountable(path) {
		return -1, nil
	}
	rc, _, err := openWordlist(path)
	if err != nil {
		return -1, err
	}
	defer rc.Close()

	var n int64
	scanner := bufio.NewScanner(rc)
	scanner.Buffer(make([]byte, 1<<20), 1<<20)
	for scanner.Scan() {
		if strings.TrimSpace(scanner.Text()) != "" {
			n++
		}
	}
	return n, scanner.Err()
}
