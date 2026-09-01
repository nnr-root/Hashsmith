package main

// ── `hashsmith wordlists` ────────────────────────────────────────────────────
//
// Two jobs, deliberately separated by a flag:
//
//   - The default listing is the SAME stat list resolveWordlist walks, in the
//     same order, so it can never disagree with what a real run would pick. It
//     answers "why is hashsmith using the built-in list on this box?" in about
//     ten os.Stat calls.
//
//   - `--scan` is the slow filesystem walk. It exists because the fixed list
//     cannot know about /home/op/ctf/lists/rockyou-full.txt — but it is opt-in
//     and never on the attack path, because a walk is slow (minutes on a large
//     disk), silently incomplete on macOS without Full Disk Access, and
//     non-deterministic in what it picks. Its output is a SUGGESTION the
//     operator pins with HASHSMITH_WORDLIST, not a default the tool adopts on
//     its own.

import (
	"context"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"time"
)

// wordlistScanMinSize is the size below which a scan hit is ignored. A
// dictionary attack worth switching to is megabytes; without a floor the walk
// reports every README.txt and license file on the disk and buries the one
// useful line.
const wordlistScanMinSize = 1 << 20 // 1 MiB

// wordlistScanMaxDepth bounds how deep the walk descends. Deep trees are
// almost always caches, build outputs or container layers rather than a
// wordlist an operator installed on purpose.
const wordlistScanMaxDepth = 14

// wordlistScanDefaultTimeout bounds the walk even when nobody is watching to
// press Ctrl-C — a scan wired into a script must terminate.
const wordlistScanDefaultTimeout = 90 * time.Second

// wordlistScanSkipDirs are absolute paths never descended into. /proc, /sys,
// /dev and /run are synthetic kernel filesystems (walking them is pointless
// and can block on device nodes); /Volumes, /net, /Network and /mnt are where
// removable and NETWORK mounts appear, and walking a network mount turns a
// local scan into an unbounded remote one; /System/Volumes/Data is macOS's
// firmlink back to the root filesystem, which would make the walk traverse
// everything twice.
var wordlistScanSkipDirs = map[string]bool{
	"/proc":                true,
	"/sys":                 true,
	"/dev":                 true,
	"/run":                 true,
	"/net":                 true,
	"/mnt":                 true,
	"/Network":             true,
	"/Volumes":             true,
	"/System/Volumes/Data": true,
	"/System/Volumes/VM":   true,
	"/private/var/vm":      true,
	// macOS OS and application payloads. These are full of multi-megabyte
	// .txt/.dic files — third-party licence notices, Xcode documentation
	// indexes, Office spell-check dictionaries — none of which is a wordlist
	// anyone installed, and all of which would otherwise dominate the listing.
	"/System":              true,
	"/Applications":        true,
	"/Library/Caches":      true,
	"/private/var/folders": true,
}

// wordlistScanNoiseNames are name fragments that mark a large text file as
// something other than a wordlist. Licence notices and changelogs are the two
// commonest megabyte-scale .txt files on a developer machine.
var wordlistScanNoiseNames = []string{
	"thirdparty", "third_party", "third-party",
	"licence", "license", "notices", "changelog", "copying", "credits",
}

// wordlistNameScore ranks a hit by how much its NAME says "wordlist": 2 for a
// rockyou, 1 for another wordlist-ish name, 0 for a file that merely happens
// to be a large .txt. The scan cannot open and inspect every candidate, so the
// name is all there is — which is exactly why this output is a suggestion the
// operator pins by hand, never a default the tool adopts.
func wordlistNameScore(name string) int {
	lower := strings.ToLower(name)
	if strings.Contains(lower, "rockyou") {
		return 2
	}
	for _, hint := range []string{"wordlist", "password", "passlist", "dict", "seclist"} {
		if strings.Contains(lower, hint) {
			return 1
		}
	}
	return 0
}

// wordlistScanSkipNames are directory base names skipped anywhere they occur:
// package caches and version-control stores hold enormous numbers of files and
// no installed wordlist.
var wordlistScanSkipNames = map[string]bool{
	".git":         true,
	".svn":         true,
	"node_modules": true,
	".Trash":       true,
	".cache":       true,
}

// scannedWordlist is one hit from --scan.
type scannedWordlist struct {
	path string
	size int64
}

// looksLikeWordlistFile decides whether a scanned file is worth reporting. A
// trailing ".gz" is stripped first, so rockyou.txt.gz is judged on ".txt" —
// the reader decompresses it transparently anyway (see openWordlist).
func looksLikeWordlistFile(name string, size, minSize int64) bool {
	if size < minSize {
		return false
	}
	lower := strings.ToLower(name)
	lower = strings.TrimSuffix(lower, ".gz")
	for _, noise := range wordlistScanNoiseNames {
		if strings.Contains(lower, noise) {
			return false
		}
	}
	switch filepath.Ext(lower) {
	case ".txt", ".lst", ".dic", ".dict", ".words", ".wordlist":
		return true
	}
	// Extensionless files still count when the name says what they are —
	// SecLists and hand-built lists frequently have no suffix at all.
	for _, hint := range []string{"rockyou", "wordlist", "passwords", "passlist"} {
		if strings.Contains(lower, hint) {
			return true
		}
	}
	return false
}

// wordlistScanRoots is where --scan starts. Unix walks from "/" (minus the
// skip list); Windows has no /usr/share and no single root, so it walks the
// current volume.
func wordlistScanRoots() []string {
	if runtime.GOOS == "windows" {
		if cwd, err := os.Getwd(); err == nil {
			if vol := filepath.VolumeName(cwd); vol != "" {
				return []string{vol + string(filepath.Separator)}
			}
		}
		if home, err := wordlistUserHomeDir(); err == nil && home != "" {
			return []string{home}
		}
		return []string{"."}
	}
	return []string{"/"}
}

// scanForWordlists walks roots and returns plausible wordlists, largest first.
// It stops early — returning what it has, not an error — when ctx is done, so
// Ctrl-C during a long scan still prints the hits found so far instead of
// throwing them away.
func scanForWordlists(ctx context.Context, roots []string, minSize int64) ([]scannedWordlist, bool) {
	var out []scannedWordlist
	seen := map[string]bool{}
	interrupted := false

	for _, root := range roots {
		rootDepth := strings.Count(filepath.Clean(root), string(filepath.Separator))
		_ = filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
			select {
			case <-ctx.Done():
				interrupted = true
				return filepath.SkipAll
			default:
			}
			if err != nil {
				// Unreadable directory (permissions, a vanished mount): skip
				// it rather than abort the whole scan. On macOS without Full
				// Disk Access this is most of ~/Library, which is precisely
				// why a scan can never be trusted as a default.
				if d != nil && d.IsDir() {
					return fs.SkipDir
				}
				return nil
			}
			if d.IsDir() {
				if wordlistScanSkipDirs[filepath.Clean(path)] || wordlistScanSkipNames[d.Name()] {
					return fs.SkipDir
				}
				if strings.Count(filepath.Clean(path), string(filepath.Separator))-rootDepth > wordlistScanMaxDepth {
					return fs.SkipDir
				}
				return nil
			}
			if !d.Type().IsRegular() {
				return nil
			}
			info, ierr := d.Info()
			if ierr != nil || !looksLikeWordlistFile(d.Name(), info.Size(), minSize) {
				return nil
			}
			if seen[path] {
				return nil
			}
			seen[path] = true
			out = append(out, scannedWordlist{path: path, size: info.Size()})
			return nil
		})
		if interrupted {
			break
		}
	}

	// Rank by how wordlist-ish the name is first, size second: a 3 MiB
	// rockyou.txt is a far better suggestion than a 10 MiB documentation dump
	// that happens to end in .txt.
	sort.Slice(out, func(i, j int) bool {
		si, sj := wordlistNameScore(filepath.Base(out[i].path)), wordlistNameScore(filepath.Base(out[j].path))
		if si != sj {
			return si > sj
		}
		if out[i].size != out[j].size {
			return out[i].size > out[j].size
		}
		return out[i].path < out[j].path
	})
	return out, interrupted
}

// suggestScannedWordlist picks the one to recommend. scanForWordlists already
// sorted best-first (name score, then size), so this is the head of the list.
func suggestScannedWordlist(hits []scannedWordlist) (scannedWordlist, bool) {
	if len(hits) == 0 {
		return scannedWordlist{}, false
	}
	return hits[0], true
}

// humanWordlistSize renders a byte count compactly for the listing.
func humanWordlistSize(n int64) string {
	const unit = 1024
	if n < unit {
		return fmt.Sprintf("%d B", n)
	}
	div, exp := int64(unit), 0
	for v := n / unit; v >= unit && exp < 3; v /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %ciB", float64(n)/float64(div), "KMGT"[exp])
}

func runWordlists(args []string) error {
	fs2 := flag.NewFlagSet("wordlists", flag.ContinueOnError)
	fs2.SetOutput(io.Discard)
	scan := fs2.Bool("scan", false, "walk the filesystem for wordlists (SLOW — minutes on a large disk; the fast listing above is what an actual run uses)")
	scanRoot := fs2.String("scan-root", "", "restrict --scan to this directory instead of the whole filesystem")
	timeout := fs2.Duration("scan-timeout", wordlistScanDefaultTimeout, "give up on --scan after this long and report what was found")
	minSize := fs2.Int64("scan-min-size", wordlistScanMinSize, "ignore --scan hits smaller than this many bytes")
	if err := parseArgsFlexible(fs2, args); err != nil {
		return err
	}

	printWordlistCandidateTable(os.Stdout)

	if !*scan {
		fmt.Fprintln(os.Stdout)
		fmt.Fprintln(os.Stdout, "Pin a specific list with -w <path> or "+wordlistEnvVar+"=<path>.")
		fmt.Fprintln(os.Stdout, "Search the filesystem for others with `hashsmith wordlists --scan` (slow).")
		return nil
	}

	roots := wordlistScanRoots()
	if strings.TrimSpace(*scanRoot) != "" {
		roots = []string{*scanRoot}
	}

	// Ctrl-C ends the walk and prints what it found; it does not kill the
	// process mid-listing. A scan the operator abandons is still allowed to be
	// useful.
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	if *timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, *timeout)
		defer cancel()
	}

	fmt.Fprintf(os.Stdout, "\nScanning %s for wordlists >= %s (Ctrl-C to stop)...\n",
		strings.Join(roots, ", "), humanWordlistSize(*minSize))
	start := time.Now()
	hits, interrupted := scanForWordlists(ctx, roots, *minSize)
	fmt.Fprintf(os.Stdout, "Scanned in %s%s.\n", time.Since(start).Round(time.Millisecond),
		map[bool]string{true: " (stopped early — results are partial)"}[interrupted])

	if len(hits) == 0 {
		fmt.Fprintln(os.Stdout, "No wordlists found.")
		return nil
	}
	const maxShown = 25
	fmt.Fprintf(os.Stdout, "\nFound %d:\n", len(hits))
	for i, h := range hits {
		if i >= maxShown {
			fmt.Fprintf(os.Stdout, "  ... and %d more\n", len(hits)-maxShown)
			break
		}
		fmt.Fprintf(os.Stdout, "  %10s  %s\n", humanWordlistSize(h.size), h.path)
	}
	best, ok := suggestScannedWordlist(hits)
	if !ok {
		return nil
	}
	if wordlistNameScore(filepath.Base(best.path)) == 0 {
		// Nothing found is NAMED like a wordlist, so every hit is just a large
		// text file. Printing a confident `export HASHSMITH_WORDLIST=...` for
		// one of those would be the tool guessing and sounding certain — the
		// scan has no way to tell a password list from a log dump, and pinning
		// the wrong file would make every later run attack nonsense while
		// reporting "not found" as though it meant something.
		fmt.Fprintln(os.Stdout, "\nNone of these is NAMED like a wordlist — they are simply the largest")
		fmt.Fprintln(os.Stdout, "text files found. Pin one only if you know it is a password list:")
		fmt.Fprintf(os.Stdout, "  export %s=<path>\n", wordlistEnvVar)
		return nil
	}
	fmt.Fprintf(os.Stdout, "\nTo use one of these by default:\n  export %s=%s\n",
		wordlistEnvVar, best.path)
	fmt.Fprintf(os.Stdout, "Or for a single run:\n  hashsmith crack -w %s <hash>\n", best.path)
	return nil
}

// printWordlistCandidateTable writes the fast listing: every location checked,
// in resolution order, and which one a run would actually take.
func printWordlistCandidateTable(w io.Writer) {
	fmt.Fprintln(w, "Wordlist resolution order (used when -w is not given; first match wins):")
	fmt.Fprintln(w)

	env := strings.TrimSpace(os.Getenv(wordlistEnvVar))
	switch {
	case env == "":
		fmt.Fprintf(w, "   0  $%-56s not set\n", wordlistEnvVar)
	case usableWordlistFile(env):
		fmt.Fprintf(w, "   0  $%-56s %s  %s\n", wordlistEnvVar, "FOUND", env)
	default:
		fmt.Fprintf(w, "   0  $%-56s SET BUT UNREADABLE  %s\n", wordlistEnvVar, env)
	}

	for i, c := range wordlistCandidateStatus() {
		label := c.template
		status := "-"
		if c.exists {
			status = "FOUND  " + humanWordlistSize(c.size)
		}
		fmt.Fprintf(w, "  %2d  %-57s %s\n", i+1, label, status)
	}
	fmt.Fprintf(w, "  %2d  %-57s always available\n", len(wordlistCandidatePaths)+1, defaultWordlistLabel)

	fmt.Fprintln(w)
	// Reported through the same resolver a run uses, so this line is the
	// answer, not a second guess at it.
	choice, err := resolveWordlist("", false)
	if err != nil {
		fmt.Fprintf(w, "Selected: ERROR — %v\n", err)
		return
	}
	fmt.Fprintf(w, "Selected: %s\n", choice.menuLabel())
}
