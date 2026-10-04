package smith

import (
	"errors"
	"flag"
	"fmt"
	"os"
	"strings"
)

// runCoordinate is the `hashsmith coordinate` subcommand entry point.
func runCoordinate(args []string) error {
	fs := flag.NewFlagSet("coordinate", flag.ContinueOnError)
	typ := fs.String("t", "", "hash type")
	mode := fs.String("M", "mask", "attack mode: mask|brute|dict")
	mask := fs.String("mask", "", "mask (mode mask)")
	cs1 := fs.String("1", "", "custom charset 1 (mode mask)")
	cs2 := fs.String("2", "", "custom charset 2 (mode mask)")
	cs3 := fs.String("3", "", "custom charset 3 (mode mask)")
	cs4 := fs.String("4", "", "custom charset 4 (mode mask)")
	charset := fs.String("C", "abcdefghijklmnopqrstuvwxyz0123456789", "charset (mode brute)")
	minLen := fs.Int("n", 1, "min length (mode brute)")
	maxLen := fs.Int("x", 4, "max length (mode brute)")
	wordlist := fs.String("w", "", "wordlist path (mode dict; must exist at this exact path on every worker)")
	salt := fs.String("s", "", "salt")
	saltMode := fs.String("S", "prefix", "salt mode: prefix|suffix")
	workersFlag := fs.String("workers", "", "comma-separated worker URLs, e.g. http://host1:8745,http://host2:8745")
	token := fs.String("token", "", "shared-secret token (must match every worker's --token)")
	chunkSize := fs.Int64("chunk-size", 0, "candidates per chunk; required, no default -- there is no safe universal size across hash types whose speed differs by many orders of magnitude. Run `hashsmith benchmark -t <type>` first and pick roughly (seconds per chunk you want) x (that rate)")
	if err := parseArgsFlexible(fs, args); err != nil {
		return err
	}

	if *typ == "" {
		return errors.New("-t is required")
	}
	if *workersFlag == "" {
		return errors.New("--workers is required")
	}
	if *token == "" {
		return errors.New("--token is required")
	}
	if *chunkSize <= 0 {
		return fmt.Errorf("--chunk-size is required and must be > 0 -- run `hashsmith benchmark -t %s` first and pick a size that takes roughly 5-30 seconds per chunk", *typ)
	}
	targets := fs.Args()
	if len(targets) != 1 {
		return fmt.Errorf("coordinate takes exactly one target hash, got %d", len(targets))
	}
	target := targets[0]
	workerURLs := strings.Split(*workersFlag, ",")

	total, err := coordinatorKeyspace(*mode, *mask, *cs1, *cs2, *cs3, *cs4, *charset, *minLen, *maxLen, *wordlist)
	if err != nil {
		return err
	}

	base := chunkRequest{
		Type: *typ, Target: target, Salt: *salt, SaltMode: *saltMode, Mode: *mode,
		Mask: *mask, Charset1: *cs1, Charset2: *cs2, Charset3: *cs3, Charset4: *cs4,
		Charset: *charset, MinLen: *minLen, MaxLen: *maxLen, Wordlist: *wordlist,
	}

	chunks := splitKeyspace(total, *chunkSize)
	if len(chunks) == 0 {
		fmt.Fprintln(os.Stderr, "Not found")
		exitCode = 1
		return nil
	}
	queue := newChunkQueue(chunks)
	result := runCoordinatorLoop(workerURLs, *token, base, queue)
	switch {
	case result.found:
		emitStdoutResult(nil, target, result.password)
		fmt.Fprintf(os.Stderr, "Found: %s\n", result.password)
		exitCode = 0
	case result.incomplete:
		fmt.Fprintln(os.Stderr, "Error: every worker failed before the keyspace was fully covered -- this is NOT a confirmed \"not found\"")
		exitCode = 2
	default:
		fmt.Fprintln(os.Stderr, "Not found")
		exitCode = 1
	}
	return nil
}
