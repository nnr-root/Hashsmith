package smith

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
)

// ── Unified positional input handling ──────────────────────────────────────────
//
// Every command takes its input(s) as positional arguments — no -i/-f flags.
// A single argument may be:
//
//   • inline text                    →  hashsmith hash -t md5 "secret"
//   • "-" meaning standard input     →  cat words.txt | hashsmith hash -t md5 -
//   • a file path (one input per line)  →  hashsmith crack hashes.txt
//
// Multiple positional arguments are accepted and flattened together, so
// `hashsmith hash -t md5 a b c` gives three inputs.
//
// ── One argument is one input ──────────────────────────────────────────────────
//
// This layer does NOT rewrite what the user typed. It does not split on commas,
// and it does not trim surrounding whitespace. Both behaviours used to be
// unconditional, and both silently corrupted real data:
//
//   • Hashcat's own canonical records for -m 10300, 21600, 30601, 34000, 35000
//     and 70000 contain commas, so they were split into fragments and every
//     fragment was rejected as a malformed hash.
//   • Surrounding whitespace is the entire point of quoted-printable's "=20",
//     and it is legal inside a password, so stripping it makes those inputs
//     unrepresentable.
//
// The comma-list convenience is still available, but it is now opt-in with
// --split, because a convenience must never be able to corrupt a payload that
// the user did not ask to have split.
//
// A leading "-" in a payload is handled by the flag package's own "--"
// terminator: `hashsmith encode -t base64 -- -hello`.

// inputOpts controls how a positional argument becomes one or more inputs.
// The zero value is the safe default: no splitting, no trimming, no stdin.
type inputOpts struct {
	// split enables separator-splitting of a single argument (--split).
	split bool
	// sep is the separator used when split is set. Empty means ",".
	sep string
	// trim strips surrounding whitespace from each resulting input. Off by
	// default; crack and identify set it because a hash never carries
	// meaningful edge whitespace, while codec payloads routinely do.
	trim bool
	// stdin lets the literal argument "-" mean standard input.
	stdin bool
	// noFile disables treating an existing path as a file of inputs. Used by
	// callers whose argument is definitionally literal text.
	noFile bool
	// whole makes a file ONE input rather than one per line.
	//
	// The line-per-input default is right for a list of hashes and wrong for
	// anything whose representation spans lines: a PEM block, a hex dump, a
	// wrapped MIME body. Those decode to nothing useful line by line, because
	// each line is a fragment of one value rather than a value.
	whole bool
}

// targetInputOpts is the profile for hash targets (crack, identify, auto):
// whitespace around a hash is noise, "-" reads a hash list from a pipe, and a
// path is a file of hashes.
func targetInputOpts() inputOpts { return inputOpts{trim: true, stdin: true} }

// payloadInputOpts is the profile for codec and hashing payloads (encode,
// decode, hash): the bytes the user gave are the bytes that get processed.
func payloadInputOpts() inputOpts { return inputOpts{stdin: true} }

// gatherInputs flattens every positional argument using the safe defaults.
func gatherInputs(positional []string) ([]string, error) {
	return gatherInputsOpts(positional, targetInputOpts())
}

// gatherInputsOpts flattens every positional argument under the given profile.
func gatherInputsOpts(positional []string, opts inputOpts) ([]string, error) {
	var out []string
	for _, arg := range positional {
		items, err := collectInputsOpts(arg, opts)
		if err != nil {
			return nil, err
		}
		out = append(out, items...)
	}
	if len(out) == 0 {
		return nil, errors.New("no input provided — pass text (\"...\"), \"-\" for standard input, or a file path")
	}
	return out, nil
}

// collectInputs resolves one positional argument using the safe defaults.
func collectInputs(arg string) ([]string, error) {
	return collectInputsOpts(arg, inputOpts{})
}

// collectInputsOpts resolves one positional argument into one or more inputs.
func collectInputsOpts(arg string, opts inputOpts) ([]string, error) {
	if arg == "" {
		return nil, nil
	}
	// "-" is standard input, one input per line, like every other Unix tool.
	if opts.stdin && arg == "-" {
		return readInputLinesFrom(os.Stdin, "standard input")
	}
	// A readable file → one input per non-empty, non-comment line.
	//
	// This substitution is SAID OUT LOUD, because it is silent otherwise and
	// the failure it causes is not obvious. macOS matches filenames without
	// regard to case, so `encode -t base85 Hashsmith`, run in a directory
	// holding a binary called "hashsmith", encoded twenty megabytes of
	// executable instead of the nine characters the user typed — and printed
	// twenty-five million characters with no indication why. Someone encoding
	// a secret deserves to know their argument became a file.
	if !opts.noFile {
		if info, err := os.Stat(arg); err == nil && !info.IsDir() {
			if opts.whole {
				body, rerr := os.ReadFile(arg)
				if rerr != nil {
					return nil, rerr
				}
				noteFileSubstitution(arg, info.Size(), 1)
				return []string{string(body)}, nil
			}
			lines, rerr := readInputLines(arg)
			if rerr == nil {
				noteFileSubstitution(arg, info.Size(), len(lines))
			}
			return lines, rerr
		}
	}
	// Opt-in separator splitting.
	if opts.split {
		sep := opts.sep
		if sep == "" {
			sep = ","
		}
		if strings.Contains(arg, sep) {
			var out []string
			for _, p := range strings.Split(arg, sep) {
				// Elements of an explicitly requested list are always trimmed:
				// "a, b, c" means three inputs, not "a", " b", " c". This is
				// safe precisely because splitting is now opt-in — a payload
				// that must keep its spaces simply is not passed --split.
				p = strings.TrimSpace(p)
				if p != "" {
					out = append(out, p)
				}
			}
			return out, nil
		}
	}
	if opts.trim {
		if arg = strings.TrimSpace(arg); arg == "" {
			return nil, nil
		}
	}
	// Otherwise a single literal input, byte for byte as the user gave it.
	return []string{arg}, nil
}

// maxInputLine bounds one line of a file of inputs. The old 1 MiB ceiling
// rejected perfectly ordinary payloads outright; a record or a base64 blob can
// legitimately be far larger than that, and failing on it is never the helpful
// answer.
const maxInputLine = 64 << 20

// readInputLines returns every non-empty, non-comment (#) line of a file.
func readInputLines(path string) ([]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	lines, err := readInputLinesFrom(f, path)
	if err != nil {
		return nil, err
	}
	return lines, nil
}

// readInputLinesFrom reads one input per line from r. label names the source in
// error messages.
func readInputLinesFrom(r io.Reader, label string) ([]string, error) {
	var lines []string
	scanner := bufio.NewScanner(r)
	scanner.Buffer(make([]byte, 64<<10), maxInputLine)
	for scanner.Scan() {
		line := strings.TrimRight(scanner.Text(), "\r")
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		lines = append(lines, line)
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	if len(lines) == 0 {
		return nil, errors.New("no inputs found in " + label)
	}
	return lines, nil
}

// withLiteral turns off file substitution, so an argument that happens to
// name an existing file is still taken as the text the user typed.
func withLiteral(o inputOpts, literal bool) inputOpts {
	if literal {
		o.noFile = true
	}
	return o
}

// withWhole makes each file one input. It is the plumbing behind --whole, for
// the codecs whose representation spans lines.
func withWhole(o inputOpts, whole bool) inputOpts {
	if whole {
		o.whole = true
	}
	return o
}

// withSplit turns on separator splitting when sep is non-empty. It is the
// plumbing behind the --split flag, which restores the old comma-list
// convenience for callers that actually want it.
func withSplit(o inputOpts, sep string) inputOpts {
	if sep != "" {
		o.split, o.sep = true, sep
	}
	return o
}

// fileSubstitutionNotice is where the "read as a file" notice goes. It is a
// var so tests can capture it without touching os.Stderr.
var fileSubstitutionNotice io.Writer = os.Stderr

// noteFileSubstitution tells the user that a positional argument was read as a
// file rather than taken as literal text.
func noteFileSubstitution(path string, size int64, lines int) {
	if fileSubstitutionNotice == nil {
		return
	}
	word := "inputs"
	if lines == 1 {
		word = "input"
	}
	fmt.Fprintf(fileSubstitutionNotice,
		"Reading %s as a file (%s, %d %s) — pass --string to use it as literal text\n",
		path, humanSizeShort(size), lines, word)
}

// humanSizeShort renders a byte count compactly for that notice.
func humanSizeShort(n int64) string {
	switch {
	case n >= 1<<20:
		return fmt.Sprintf("%.1f MiB", float64(n)/(1<<20))
	case n >= 1<<10:
		return fmt.Sprintf("%.1f KiB", float64(n)/(1<<10))
	default:
		return fmt.Sprintf("%d B", n)
	}
}
