package main

// ── Automatic wordlist discovery ─────────────────────────────────────────────
//
// Omitting -w used to mean "attack with the 230,930-word built-in common.txt".
// Most operators already have rockyou.txt (~14.3M words) installed by their
// distribution or by SecLists, so the default was quietly two orders of
// magnitude weaker than the machine could do. This resolves the default
// against a FIXED list of known install locations instead.
//
// Three properties are deliberate:
//
//  1. It is a stat list, not a filesystem search. Ten os.Stat calls cost
//     microseconds and always give the same answer on the same machine. A
//     `find /` sweep was measured on the dev machine still running after 20
//     seconds having walked ~500k paths, fails silently on macOS behind Full
//     Disk Access, and is non-deterministic — it will happily pick a truncated
//     rockyou out of Downloads or a Docker layer. The slow search still
//     exists, but only behind `hashsmith wordlists --scan`, where it is
//     explicit and off the attack path.
//
//  2. It resolves ONCE, at the CLI entry point, and the resolved path is what
//     flows through the whole run: the pre-count that sizes the progress bar,
//     the feasibility ETA, --keyspace, and the attack itself all see the same
//     path. That is what keeps the ETA honest about the list actually being
//     attacked, and it is why nothing below this file stats candidates again.
//
//  3. It always says what it chose (announceWordlist). A security tool that
//     silently attacks a different keyspace depending on which machine it is
//     on produces "not found" results that mean nothing — the exact
//     silent-wrong-answer class this codebase keeps removing.
//
// -w always wins and skips discovery entirely: no existing invocation changes
// meaning.

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// wordlistEnvVar names the environment override, checked before any candidate
// path. Unlike a candidate, it is an explicit request: if it is set and the
// file cannot be read, that is an error rather than a silent fall-through to
// the next candidate — the operator asked for THAT file, and continuing with a
// different keyspace would be the silent wrong answer this whole feature
// exists to avoid.
const wordlistEnvVar = "HASHSMITH_WORDLIST"

// wordlistCandidatePaths is the ordered list of locations checked when neither
// -w nor $HASHSMITH_WORDLIST is given. First match wins; a leading "~/" is
// expanded to the user's home directory (see expandWordlistPath).
//
// This is a package-level var, not a const list, so tests can point it at a
// temp directory and assert the whole resolution order deterministically. A
// discovery test that only passes on a machine with rockyou.txt installed
// would be worthless — CI has no rockyou.txt.
//
// The Windows story is "finds nothing, uses the embedded list": there is no
// /usr/share there, os.Stat simply fails on each absolute candidate, and the
// two portable entries (~/wordlists, ./rockyou.txt) still work.
var wordlistCandidatePaths = []string{
	"/usr/share/wordlists/rockyou.txt",
	"/usr/share/wordlists/rockyou.txt.gz",
	"/usr/share/seclists/Passwords/Leaked-Databases/rockyou.txt",
	"/usr/share/wordlists/seclists/Passwords/Leaked-Databases/rockyou.txt",
	"/opt/homebrew/share/wordlists/rockyou.txt",
	"/usr/local/share/wordlists/rockyou.txt",
	"~/wordlists/rockyou.txt",
	"~/.local/share/wordlists/rockyou.txt",
	"./rockyou.txt",
}

// wordlistUserHomeDir resolves "~" in a candidate path. It is a var so tests
// can supply a temp home without touching the real one.
var wordlistUserHomeDir = os.UserHomeDir

// wordlistOrigin records WHY a wordlist was chosen. The distinction is not
// cosmetic: only an auto-detected list can differ from machine to machine,
// which is what makes a distributed --skip/--limit slice unsafe (see
// distributedWordlistWarning).
type wordlistOrigin int

const (
	// wordlistFromFlag: an explicit -w / --wordlist. Discovery is skipped.
	wordlistFromFlag wordlistOrigin = iota
	// wordlistFromEnv: $HASHSMITH_WORDLIST.
	wordlistFromEnv
	// wordlistAutoDetected: found by scanning wordlistCandidatePaths.
	wordlistAutoDetected
	// wordlistEmbeddedDefault: nothing found (or --no-auto-wordlist), so the
	// built-in common.txt is used. Always available; never fails.
	wordlistEmbeddedDefault
)

// wordlistChoice is the resolved default for one run. path is "" for the
// embedded list, matching openWordlist's existing "empty path = built-in"
// contract, so every downstream caller keeps working unchanged.
type wordlistChoice struct {
	path   string
	origin wordlistOrigin
	// gzip reports that the file begins with the gzip magic bytes, so the
	// reader will decompress it. Detected once here, from the content — a
	// mislabelled file still works, and a ".gz" that is actually plain text
	// is read as plain text (see openWordlist).
	gzip bool
	// forced records that --no-auto-wordlist selected the embedded list, so
	// the announcement says "you asked for this" rather than the misleading
	// "nothing installed was found" — discovery never ran at all.
	forced bool
	// envIgnored records that $HASHSMITH_WORDLIST was set but bypassed by
	// --no-auto-wordlist, so the announcement can say so instead of leaving
	// the operator wondering why their override did nothing.
	envIgnored bool
}

// autoDetected reports whether this choice came from the candidate scan — the
// only origin whose result can differ between machines.
func (c wordlistChoice) autoDetected() bool { return c.origin == wordlistAutoDetected }

// expandWordlistPath turns a candidate template into a real path: "~" and
// "~/..." become the user's home directory. Anything else is returned
// unchanged, including "./rockyou.txt", which os.Stat resolves against the
// working directory. An unavailable home directory yields "", which the
// caller treats as "this candidate does not exist".
func expandWordlistPath(p string) string {
	if p != "~" && !strings.HasPrefix(p, "~/") && !strings.HasPrefix(p, `~\`) {
		return p
	}
	home, err := wordlistUserHomeDir()
	if err != nil || home == "" {
		return ""
	}
	if p == "~" {
		return home
	}
	return filepath.Join(home, p[2:])
}

// usableWordlistFile reports whether path is a plausible wordlist: a regular,
// non-empty file. Directories, device nodes, FIFOs and zero-byte placeholders
// are skipped so discovery never selects something the attack cannot read
// (a zero-byte /usr/share/wordlists/rockyou.txt is a common leftover of an
// interrupted install, and picking it would mean attacking nothing at all).
func usableWordlistFile(path string) bool {
	if path == "" {
		return false
	}
	info, err := os.Stat(path)
	if err != nil {
		return false
	}
	return info.Mode().IsRegular() && info.Size() > 0
}

// wordlistCandidate is one row of the discovery table, for `hashsmith
// wordlists`.
type wordlistCandidate struct {
	template string // as listed, e.g. "~/wordlists/rockyou.txt"
	path     string // expanded; "" when the home directory is unavailable
	exists   bool
	size     int64
}

// wordlistCandidateStatus stats every candidate, in order, and reports what it
// found. This is the same list resolveWordlist walks, so `hashsmith wordlists`
// can never disagree with what an actual run would pick.
func wordlistCandidateStatus() []wordlistCandidate {
	out := make([]wordlistCandidate, 0, len(wordlistCandidatePaths))
	for _, tmpl := range wordlistCandidatePaths {
		c := wordlistCandidate{template: tmpl, path: expandWordlistPath(tmpl)}
		if c.path != "" {
			if info, err := os.Stat(c.path); err == nil && info.Mode().IsRegular() && info.Size() > 0 {
				c.exists = true
				c.size = info.Size()
			}
		}
		out = append(out, c)
	}
	return out
}

// resolveWordlist picks the wordlist for a run.
//
// Order:
//
//  1. flagPath (-w / --wordlist) — always wins, discovery is skipped entirely,
//     and the path is NOT validated here so a bad -w still fails at open time
//     with exactly the error it produced before this feature existed.
//  2. --no-auto-wordlist — forces the embedded list, for scripted runs that
//     need the same keyspace on every machine regardless of what is installed.
//  3. $HASHSMITH_WORDLIST — an explicit request; unreadable is an ERROR.
//  4. wordlistCandidatePaths, in order, first usable file wins.
//  5. the embedded common.txt, which always works.
func resolveWordlist(flagPath string, noAuto bool) (wordlistChoice, error) {
	if p := strings.TrimSpace(flagPath); p != "" {
		return wordlistChoice{path: p, origin: wordlistFromFlag, gzip: isGzipFile(p)}, nil
	}

	env := strings.TrimSpace(os.Getenv(wordlistEnvVar))

	// --no-auto-wordlist means "the built-in list, deterministically". It
	// bypasses the environment override too: a scripted run that pins the
	// keyspace must not change behaviour because of a variable inherited from
	// the shell. The bypass is announced rather than silent.
	if noAuto {
		return wordlistChoice{origin: wordlistEmbeddedDefault, forced: true, envIgnored: env != ""}, nil
	}

	if env != "" {
		f, err := os.Open(env)
		if err != nil {
			return wordlistChoice{}, fmt.Errorf("%s=%q cannot be read: %w "+
				"(refusing to silently fall back to a different wordlist — unset %s, "+
				"fix the path, or pass -w explicitly)", wordlistEnvVar, env, err, wordlistEnvVar)
		}
		gz := readerLooksGzipped(f)
		f.Close()
		if info, serr := os.Stat(env); serr == nil && info.IsDir() {
			return wordlistChoice{}, fmt.Errorf("%s=%q is a directory, not a wordlist", wordlistEnvVar, env)
		}
		return wordlistChoice{path: env, origin: wordlistFromEnv, gzip: gz}, nil
	}

	for _, tmpl := range wordlistCandidatePaths {
		p := expandWordlistPath(tmpl)
		if !usableWordlistFile(p) {
			continue
		}
		return wordlistChoice{path: p, origin: wordlistAutoDetected, gzip: isGzipFile(p)}, nil
	}
	return wordlistChoice{origin: wordlistEmbeddedDefault}, nil
}

// describe renders the one-line source announcement. One line is the point:
// it is printed on every run that reads a wordlist, so it has to be scannable,
// but it must never be absent — "which list did this actually attack?" is the
// question a bare "Not found" cannot answer on its own.
func (c wordlistChoice) describe() string {
	gz := ""
	if c.gzip {
		// Counting a gzip list decompresses one full pass (see
		// countWordlistLines); flagging it here is what tells the operator why
		// the progress total takes a moment to appear on a 14M-word list.
		gz = ", gzip"
	}
	switch c.origin {
	case wordlistFromFlag:
		if c.gzip {
			return "Wordlist: " + c.path + " (gzip)"
		}
		return "Wordlist: " + c.path
	case wordlistFromEnv:
		return "Wordlist: " + c.path + " (" + wordlistEnvVar + gz + ")"
	case wordlistAutoDetected:
		return "Wordlist: " + c.path + " (auto-detected" + gz + ")"
	default:
		switch {
		case c.forced && c.envIgnored:
			return "Wordlist: " + defaultWordlistLabel + " (--no-auto-wordlist; " +
				wordlistEnvVar + " ignored)"
		case c.forced:
			return "Wordlist: " + defaultWordlistLabel + " (--no-auto-wordlist)"
		case len(wordlistCandidatePaths) == 0:
			return "Wordlist: " + defaultWordlistLabel
		default:
			return "Wordlist: " + defaultWordlistLabel +
				" (no installed wordlist found — `hashsmith wordlists` shows where it looks)"
		}
	}
}

// menuLabel is describe() without the "Wordlist: " prefix, for the interactive
// menu — where the surrounding prompt already says "Wordlist".
func (c wordlistChoice) menuLabel() string {
	return strings.TrimPrefix(c.describe(), "Wordlist: ")
}

// announceWordlist prints the chosen source to stderr. stderr, not stdout, so
// it never contaminates `--stdout` candidate output or the single number
// `--keyspace` writes for a script to read.
func announceWordlist(c wordlistChoice) {
	fmt.Fprintln(os.Stderr, c.describe())
}

// distributedWordlistWarning returns the warning text for a distributed run
// built on an auto-detected wordlist, or "" when there is nothing to warn
// about.
//
// --skip/--limit slice a candidate stream by index, which only lines up if
// every machine enumerates the SAME stream. Auto-detection is per-machine by
// construction: machine A with rockyou.txt installed and machine B without it
// produce different streams, so their slices overlap and leave gaps, and the
// resulting "not found" covers less than the operator believes it covers —
// silently. --keyspace has the same exposure one step earlier: a script
// divides the printed number to build those slices.
//
// This warns rather than blocks: a single-machine --limit run (say, to time a
// slice) is perfectly legitimate, and refusing it would be the false-refusal
// error this codebase treats as worse than no guard at all.
func distributedWordlistWarning(c wordlistChoice, skip, limit int64, keyspaceOnly bool) string {
	if !c.autoDetected() || (skip == 0 && limit == 0 && !keyspaceOnly) {
		return ""
	}
	return fmt.Sprintf(
		"Warning: this wordlist was auto-detected, and --skip/--limit/--keyspace only "+
			"line up when every machine enumerates the SAME candidate stream.\n"+
			"  A machine without %s falls back to the built-in list, so its slice covers "+
			"different words — the slices overlap, leave gaps, and the run reports \"not found\" "+
			"for a keyspace it never fully searched.\n"+
			"  Pin every machine to the same list: -w %s (or %s=%s).",
		c.path, c.path, wordlistEnvVar, c.path)
}

// wordlistModeUsesList reports whether an attack mode actually reads a
// wordlist. brute and mask generate candidates from a charset or a mask and
// never open one, so announcing a wordlist for them would be noise at best and
// a lie at worst.
func wordlistModeUsesList(mode string) bool {
	switch strings.ToLower(strings.TrimSpace(mode)) {
	case "dict", "hybrid", "combinator", "prince", "markov", "":
		return true
	default:
		return false
	}
}

// resolveWordlistForMode is the single call every CLI entry point makes: it
// resolves the default only for modes that read a wordlist, announces the
// result, and hands back the path to thread through the rest of the run.
//
// Modes that do not read a wordlist skip resolution entirely, so `-M brute`
// neither stats candidates nor fails on a broken $HASHSMITH_WORDLIST it was
// never going to open.
func resolveWordlistForMode(mode, flagPath string, noAuto bool) (wordlistChoice, error) {
	if !wordlistModeUsesList(mode) {
		return wordlistChoice{path: flagPath, origin: wordlistFromFlag}, nil
	}
	c, err := resolveWordlist(flagPath, noAuto)
	if err != nil {
		return wordlistChoice{}, err
	}
	announceWordlist(c)
	return c, nil
}
