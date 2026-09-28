package smith

import (
	"errors"
	"fmt"
	"io"
	"os"
	"runtime"
	"sort"
	"strings"
	"sync"
)

// ── The library surface ───────────────────────────────────────────────────────
//
// Everything in this package is unexported except what is here and Main. That
// is deliberate: the implementation is 78,000 lines spread over 336 files, and
// exporting it wholesale would turn every internal rename into a breaking
// change for anyone who imported it.
//
// The package at the module root wraps these with documented types. This file
// exists because that package cannot see unexported identifiers, not because
// it is a second API.

// ── Identification ────────────────────────────────────────────────────────────

// IdentifyRecord returns the candidate type names for a record, in the order
// cracking should try them. An empty result means nothing recognised it.
func IdentifyRecord(record string) []string { return detectHashTypes(record) }

// ── Hashing ───────────────────────────────────────────────────────────────────

// HashPassword produces a hash of the given type. saltMode is "prefix",
// "suffix" or "" and applies only to the plain digest types; formats that
// carry their salt inside the record (bcrypt, Argon2, scrypt, the MSSQL
// family) place it themselves and ignore it.
func HashPassword(password, typ, salt, saltMode string) (string, error) {
	return hashText(password, typ, salt, saltMode)
}

// ── Verification ──────────────────────────────────────────────────────────────

// VerifyPassword reports whether password produces record under the given
// type. An empty typ asks the identification engine, and the record is
// accepted if ANY candidate type verifies it — which is what the CLI does, and
// why a caller who knows the type should say so.
func VerifyPassword(password, record, typ, salt, saltMode string) (bool, error) {
	if typ != "" {
		return verifyCandidate(password, record, typ, salt, saltMode)
	}
	types := detectHashTypes(record)
	if len(types) == 0 {
		return false, errors.New("no type recognises this record; pass one explicitly")
	}
	var firstErr error
	for _, candidate := range types {
		ok, err := verifyCandidate(password, record, candidate, salt, saltMode)
		if err != nil {
			if firstErr == nil {
				firstErr = err
			}
			continue
		}
		if ok {
			return true, nil
		}
	}
	if firstErr != nil {
		return false, firstErr
	}
	return false, nil
}

// ── Cracking ──────────────────────────────────────────────────────────────────

// CrackWith tries each candidate against the record and returns the first that
// verifies.
//
// This is a parallel loop over VerifyPassword and nothing more. It does not
// use the sessions, potfile, rule engine, mask enumeration, progress reporting
// or GPU dispatch that the crack subcommand has, because all of those own the
// process in ways a library caller did not ask for. The per-candidate cost is
// identical — it is the same verifier — so for a wordlist held in memory this
// is the whole of what the engine would do.
//
// workers of zero means one per CPU.
func CrackWith(record, typ, salt, saltMode string, candidates []string, workers int) (string, bool, error) {
	if workers <= 0 {
		workers = runtime.NumCPU()
	}
	if workers > len(candidates) {
		workers = len(candidates)
	}
	if workers < 1 {
		return "", false, nil
	}
	if typ == "" {
		types := detectHashTypes(record)
		if len(types) == 0 {
			return "", false, errors.New("no type recognises this record; pass one explicitly")
		}
		typ = types[0]
	}

	type result struct {
		password string
		index    int
	}
	var (
		mu    sync.Mutex
		best  = result{index: -1}
		first error
		wg    sync.WaitGroup
	)
	next := make(chan int)
	stop := make(chan struct{})
	var stopOnce sync.Once

	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := range next {
				ok, err := verifyCandidate(candidates[i], record, typ, salt, saltMode)
				if err != nil {
					mu.Lock()
					if first == nil {
						first = err
					}
					mu.Unlock()
					continue
				}
				if !ok {
					continue
				}
				// The FIRST candidate in the supplied order wins, not the
				// first a worker happens to finish. A caller who ordered
				// their wordlist by likelihood gets the answer they ordered.
				mu.Lock()
				if best.index < 0 || i < best.index {
					best = result{password: candidates[i], index: i}
				}
				mu.Unlock()
				stopOnce.Do(func() { close(stop) })
			}
		}()
	}

feed:
	for i := range candidates {
		select {
		case next <- i:
		case <-stop:
			break feed
		}
	}
	close(next)
	wg.Wait()

	if best.index >= 0 {
		return best.password, true, nil
	}
	return "", false, first
}

// ── Codecs ────────────────────────────────────────────────────────────────────

// Encode applies a codec. shift is the Caesar shift, key the string a keyed
// codec needs, and rails the rail-fence or scytale count; each codec reads
// only what it uses.
func Encode(text, typ string, shift int, key string, rails int) (string, error) {
	return encodeText(text, typ, shift, key, rails)
}

// Decode reverses a codec, refusing any result larger than limit. A limit of
// zero or less uses the default ceiling, which matters for the compression
// codecs: a few hundred bytes of zstd is an instruction to allocate megabytes.
func Decode(text, typ string, shift int, key string, rails, limit int) (string, error) {
	if limit <= 0 {
		limit = maxDecodedSize
	}
	return decodeTextLimited(text, typ, shift, key, rails, limit)
}

// CodecNames returns every codec name, with its one-line description.
func CodecNames() [][2]string {
	var out [][2]string
	for _, group := range codecCatalogue {
		out = append(out, group.items...)
	}
	return out
}

// CanonicalCodec resolves a codec alias to the name the catalogue uses.
func CanonicalCodec(typ string) string { return canonicalCodecType(typ) }

// MagicChain is one decode chain magic found, with the value it produced.
type MagicChain struct {
	Value      string
	Chain      []string
	Score      float64
	Identified string
}

// MagicDecode searches for decode chains that turn input into something
// meaningful, best first. depth of zero uses the default.
//
// Codecs that need a key or a parameter are not tried: guessing one and
// reporting the noise as a finding is worse than declining, and so is trying a
// compression format that has no signature to check.
func MagicDecode(input string, depth int) []MagicChain {
	found := magicDecode(input, depth)
	out := make([]MagicChain, 0, len(found))
	for _, c := range found {
		out = append(out, MagicChain{
			Value:      c.value,
			Chain:      append([]string(nil), c.chain...),
			Score:      c.score,
			Identified: c.identified,
		})
	}
	return out
}

// ── Hash types ────────────────────────────────────────────────────────────────

// HashTypeNames returns every -t name the registry knows, sorted.
func HashTypeNames() []string {
	out := append([]string(nil), universalHashRegistry.order...)
	sort.Strings(out)
	return out
}

// CanonicalHashType resolves a type alias to the registry's own name.
func CanonicalHashType(typ string) string { return canonicalHashType(typ) }

// ── Extraction ────────────────────────────────────────────────────────────────

// extractStdout serialises stdout capture.
//
// The extractors print their records: they were written as subcommands and
// their result is a stream, not a return value. Capturing os.Stdout around one
// is the faithful way to call it from a library without rewriting all eighty-
// nine, and the roadmap already names the underlying debt — there is no format
// module interface, so a format's behaviour lives in hand-edited switches
// rather than in a value something can call.
//
// The consequence a caller must know: this redirects the PROCESS's stdout for
// the duration, so anything else writing to stdout concurrently is captured
// too. The mutex keeps two extractions from colliding with each other; it
// cannot keep the rest of the program out.
var extractStdout sync.Mutex

// ExtractorNames returns every extractor name with the container it reads.
func ExtractorNames() [][2]string {
	out := make([][2]string, 0, len(universalExtractorRegistry))
	for _, d := range universalExtractorRegistry {
		out = append(out, [2]string{d.name, d.input})
	}
	return out
}

// RunExtractor runs a named extractor over a file and returns the records it
// produced, one per line, with the progress note it writes to stderr
// discarded.
func RunExtractor(name, path string) ([]string, error) {
	var def *extractorDefinition
	for i := range universalExtractorRegistry {
		d := &universalExtractorRegistry[i]
		if d.name == name {
			def = d
			break
		}
		for _, alias := range d.aliases {
			if alias == name {
				def = d
				break
			}
		}
		if def != nil {
			break
		}
	}
	if def == nil {
		return nil, fmt.Errorf("no extractor named %q", name)
	}
	return captureRecords(func() error { return def.run([]string{"-f", path}) })
}

// ExtractFromFile identifies the container from its first bytes and runs the
// extractor that reads it. It reports what it recognised, so a caller can tell
// a confident identification from a structural guess.
func ExtractFromFile(path string) (records []string, extractor string, err error) {
	def, _, _, ok := sniffContainer(path)
	if !ok {
		return nil, "", fmt.Errorf("nothing recognised %s; name an extractor explicitly", path)
	}
	got, err := captureRecords(func() error { return def.run([]string{"-f", path}) })
	return got, def.name, err
}

// captureRecords runs an extractor with stdout redirected to a pipe and
// returns the lines it printed.
func captureRecords(run func() error) ([]string, error) {
	extractStdout.Lock()
	defer extractStdout.Unlock()

	r, w, err := os.Pipe()
	if err != nil {
		return nil, err
	}
	savedOut, savedErr := os.Stdout, os.Stderr
	devNull, err := os.OpenFile(os.DevNull, os.O_WRONLY, 0)
	if err != nil {
		r.Close()
		w.Close()
		return nil, err
	}
	os.Stdout, os.Stderr = w, devNull

	// The pipe's buffer is finite, so the reader must run while the writer
	// does. Draining after the extractor returns deadlocks on any output
	// larger than that buffer, which for a keystore full of records is not a
	// hypothetical.
	done := make(chan []byte, 1)
	go func() {
		b, _ := io.ReadAll(r)
		done <- b
	}()

	runErr := run()

	w.Close()
	os.Stdout, os.Stderr = savedOut, savedErr
	devNull.Close()
	out := <-done
	r.Close()

	if runErr != nil {
		return nil, runErr
	}
	var records []string
	for _, line := range strings.Split(string(out), "\n") {
		if line = strings.TrimSpace(line); line != "" {
			records = append(records, line)
		}
	}
	return records, nil
}
