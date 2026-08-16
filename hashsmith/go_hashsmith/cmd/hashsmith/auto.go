package main

import (
	"bufio"
	"errors"
	"flag"
	"io"
	"os"
	"runtime"
	"strings"

	"github.com/fatih/color"
)

// runAuto powers the John-the-Ripper-style shortcut:
//
//	hashsmith <hash>          # detect the type and crack it
//	hashsmith hashes.txt      # crack every hash in a file
//	hashsmith <hash> -w list  # optional flags after the target
//
// The target (a literal hash or a file containing one hash per line) is the
// first positional argument; any remaining args are the same flags accepted by
// the `crack` command. When -t is omitted the hash type is auto-detected.
func runAuto(target string, flagArgs []string) error {
	fs := flag.NewFlagSet("auto", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	typ := fs.String("t", "", "hash type (omit or 'auto' to auto-detect)")
	mode := fs.String("M", "dict", "attack mode: dict|brute")
	wordlist := fs.String("w", "", "wordlist path (defaults to built-in common.txt)")
	wordlistLong := fs.String("wordlist", "", "alias for -w")
	charset := fs.String("C", "abcdefghijklmnopqrstuvwxyz0123456789", "charset (brute mode)")
	minLen := fs.Int("n", 1, "min length (brute)")
	maxLen := fs.Int("x", 4, "max length (brute)")
	salt := fs.String("s", "", "salt")
	saltMode := fs.String("S", "prefix", "salt mode: prefix|suffix")
	workers := fs.Int("p", 0, "parallel workers (0 = NumCPU)")
	outFile := fs.String("o", "", "write result to file")
	copyResult := fs.Bool("c", false, "copy result to clipboard")
	useRules := fs.Bool("r", false, "enable mangling rules in dict mode")
	if err := fs.Parse(flagArgs); err != nil {
		return err
	}

	wl := *wordlist
	if wl == "" {
		wl = *wordlistLong
	}
	w := *workers
	if w < 1 {
		w = runtime.NumCPU()
	}

	targets, fromFile, err := resolveAutoTargets(target)
	if err != nil {
		return err
	}
	if len(targets) == 0 {
		return errors.New("no hashes found to crack")
	}

	for i, h := range targets {
		if fromFile || len(targets) > 1 {
			color.New(themeAttr, color.Bold).Fprintf(os.Stderr,
				"\n══ Hash %d/%d: %s\n", i+1, len(targets), h)
		}
		if err := crackWithDetection(h, *typ, *mode, wl, *charset,
			*minLen, *maxLen, w, *salt, *saltMode, *outFile, *copyResult, *useRules); err != nil {
			// Report and continue so one bad line doesn't abort the whole file.
			clrRed.Fprintf(os.Stderr, "  error: %v\n", err)
		}
	}
	return nil
}

// resolveAutoTargets turns the positional argument into a list of hashes. If it
// is a readable file, every non-empty, non-comment line becomes a target;
// otherwise the argument itself is treated as a single literal hash. The bool
// reports whether the hashes came from a file.
func resolveAutoTargets(arg string) ([]string, bool, error) {
	info, statErr := os.Stat(arg)
	if statErr == nil && !info.IsDir() {
		f, err := os.Open(arg)
		if err != nil {
			return nil, false, err
		}
		defer f.Close()

		var hashes []string
		scanner := bufio.NewScanner(f)
		scanner.Buffer(make([]byte, 1<<20), 1<<20)
		for scanner.Scan() {
			line := strings.TrimSpace(scanner.Text())
			if line == "" || strings.HasPrefix(line, "#") {
				continue
			}
			hashes = append(hashes, line)
		}
		if err := scanner.Err(); err != nil {
			return nil, true, err
		}
		return hashes, true, nil
	}
	return []string{strings.TrimSpace(arg)}, false, nil
}

// looksLikeAutoTarget decides whether a bare, non-command argument should be
// treated as a crack target. It is intentionally conservative — only an
// existing file or a string that detection directly recognises as a hash
// qualifies — so genuine command typos still produce an "unknown command"
// error instead of silently launching an attack.
//
// Speculative Base58/Base64 decoding is deliberately NOT used here: ordinary
// words are valid Base58, which would misroute typos. Encoded hashes are still
// normalized when passed explicitly to `crack -H`.
func looksLikeAutoTarget(arg string) bool {
	if arg == "" || strings.HasPrefix(arg, "-") {
		return false
	}
	if info, err := os.Stat(arg); err == nil && !info.IsDir() {
		return true
	}
	return len(detectHashTypes(strings.TrimSpace(arg))) > 0
}
