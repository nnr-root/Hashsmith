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
//  1. It is a stat list, not a filesystem search. A few dozen os.Stat calls
//     cost microseconds and always give the same answer on the same machine. A
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
//
// The operator can also PIN a default that outlives the shell, with `hashsmith
// wordlists --set-default` — see wordlist_config.go. It slots in below
// $HASHSMITH_WORDLIST and above the candidate scan; the reasoning for that
// position, and for why a stale saved default warns where a broken
// $HASHSMITH_WORDLIST errors, is in resolveWordlist.

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

// wordlistCandidateDirs and wordlistCandidateFilenames are crossed to build
// wordlistCandidatePaths. The list is expressed as a directory list times a
// filename list rather than as fifty-odd hand-written strings because that is
// what makes it reviewable: the interesting question is always "is this
// directory one where a real install puts a wordlist?", and a flat string list
// buries that question in repetition and invites a typo in one of the two
// filenames that nobody notices.
//
// ORDER IS THE CONTRACT (see wordlistCandidatePaths), and it goes:
//
//  1. system-wide install locations — the deliberate, curated copies a
//     package manager or a documented `git clone` put there;
//  2. the operator's own directories;
//  3. ~/Downloads, ~/Desktop and the working directory, LAST, because those
//     are where a truncated or unofficial copy lands: the half-finished
//     browser download, the 5 MiB "rockyou" from a random gist, the sample
//     list a tutorial told someone to curl. Attacking one of those while
//     believing the real 14M-word list was in play is exactly the
//     silent-wrong-answer failure this file exists to prevent, so a
//     system-wide copy always wins over them.
//
// SecLists appears twice per prefix because its capitalisation genuinely
// varies by installer: Debian/Kali's `apt install seclists` lays it down as
// lowercase `seclists`, while the project's own README says
// `git clone .../SecLists`, which yields the capitalised name. Case-insensitive
// filesystems (macOS, Windows) make one of each pair redundant; case-sensitive
// ones do not, and a stat that misses costs nothing.
var wordlistCandidateDirs = []string{
	// ── system-wide: package managers and documented install locations ──
	"/usr/share/wordlists",                                     // Kali, Parrot, BlackArch
	"/usr/share/seclists/Passwords/Leaked-Databases",           // apt install seclists
	"/usr/share/SecLists/Passwords/Leaked-Databases",           // git clone into /usr/share
	"/usr/share/wordlists/seclists/Passwords/Leaked-Databases", // Kali's symlink layout
	"/usr/share/wordlists/SecLists/Passwords/Leaked-Databases",
	"/usr/share/dict",    // words/cracklib territory; some distros drop lists here
	"/usr/share/john",    // John the Ripper ships password.lst and friends here
	"/usr/share/hashcat", // hashcat's data directory

	"/opt/homebrew/share/wordlists", // macOS Homebrew, Apple silicon prefix
	"/opt/homebrew/share/seclists/Passwords/Leaked-Databases",
	"/opt/homebrew/share/SecLists/Passwords/Leaked-Databases",
	"/usr/local/share/wordlists", // Homebrew on Intel macOS; `make install` on Unix
	"/usr/local/share/seclists/Passwords/Leaked-Databases",
	"/usr/local/share/SecLists/Passwords/Leaked-Databases",

	"/opt/wordlists", // the conventional "I installed it by hand" location
	"/opt/SecLists/Passwords/Leaked-Databases",
	"/opt/seclists/Passwords/Leaked-Databases",
	"/data/wordlists", // common mount point for a dedicated lists volume

	// Windows. os.Stat on these simply fails everywhere else, which costs a
	// failed syscall and nothing more. %USERPROFILE% needs no entry of its
	// own: os.UserHomeDir returns exactly that on Windows, so the "~/…"
	// entries below already cover %USERPROFILE%\wordlists and
	// %USERPROFILE%\Downloads — and they do it by asking the OS rather than
	// by trusting an environment variable a service account may not set.
	`C:\wordlists`,
	`C:\Tools\wordlists`,
	// WSL reaching the Windows side. Fixed paths only: no globbing, because a
	// glob over /mnt/c/Users/*/Downloads would be non-deterministic (which
	// user's copy wins depends on directory order) and would reach into other
	// accounts' download folders.
	"/mnt/c/wordlists",
	"/mnt/c/Tools/wordlists",

	// ── the operator's own directories ──
	"~/wordlists",
	"~/.local/share/wordlists",
	"~/SecLists/Passwords/Leaked-Databases", // the README's own clone target

	// ── last: most likely to hold a truncated or unofficial copy ──
	"~/Downloads",
	"~/Desktop",
	".", // the working directory
}

// wordlistCandidateFilenames are the names looked for in each directory. Plain
// text first, then gzip: when both are present the uncompressed one is cheaper
// to count and to stream, and they hold the same words.
var wordlistCandidateFilenames = []string{"rockyou.txt", "rockyou.txt.gz"}

// joinWordlistCandidate joins a candidate directory and filename WITHOUT
// filepath.Join, which would be wrong twice over here: on Unix it turns
// `C:\wordlists` into `C:\wordlists/rockyou.txt`, and it Cleans "." into a
// bare "rockyou.txt", losing the "./" that tells a reader of `hashsmith
// wordlists` that the entry means the working directory. The separator is
// chosen from the directory's own shape instead, so each entry is displayed
// and stat'ed in the form the operator would type on that platform.
func joinWordlistCandidate(dir, name string) string {
	if dir == "" {
		return name
	}
	if last := dir[len(dir)-1]; last == '/' || last == '\\' {
		return dir + name
	}
	if strings.Contains(dir, `\`) && !strings.Contains(dir, "/") {
		return dir + `\` + name
	}
	return dir + "/" + name
}

// buildWordlistCandidatePaths crosses the directory list with the filename
// list, directory-major: every name in one directory is tried before moving to
// the next. Directory-major is what keeps the ORDER meaningful — the ranking
// that matters is "which install is more trustworthy", not "is it gzipped".
func buildWordlistCandidatePaths(dirs, names []string) []string {
	out := make([]string, 0, len(dirs)*len(names))
	for _, dir := range dirs {
		for _, name := range names {
			out = append(out, joinWordlistCandidate(dir, name))
		}
	}
	return out
}

// wordlistCandidatePaths is the ordered list of locations checked when none of
// -w, $HASHSMITH_WORDLIST or the saved default applies. First match wins; a
// leading "~/" is expanded to the user's home directory (see
// expandWordlistPath).
//
// This is a package-level var, not a const list, so tests can point it at a
// temp directory and assert the whole resolution order deterministically. A
// discovery test that only passes on a machine with rockyou.txt installed
// would be worthless — CI has no rockyou.txt.
//
// Cost: one os.Stat per entry, resolved exactly once per run (see the file
// header). Even at ~56 entries that is a few hundred microseconds of failed
// syscalls on a cold cache, against an attack measured in minutes; it is not
// on any hot path and nothing below this file stats candidates again.
//
// The Windows story is "finds nothing installed, uses the embedded list"
// unless one of the C:\ entries or the portable ones (~/wordlists,
// ./rockyou.txt) hits: there is no /usr/share there, and os.Stat simply fails
// on each Unix candidate.
var wordlistCandidatePaths = buildWordlistCandidatePaths(wordlistCandidateDirs, wordlistCandidateFilenames)

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
	// wordlistFromConfig: the operator's saved default from
	// ~/.hashsmith/config.json (`hashsmith wordlists --set-default`). It
	// ranks below the environment variable deliberately — see resolveWordlist
	// — and, like auto-detection, it is machine-local.
	wordlistFromConfig
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
	// configIgnored records the same for a saved default bypassed by
	// --no-auto-wordlist. Same reasoning: a pinned setting that silently did
	// nothing is worse than one that says why it did nothing.
	configIgnored bool
	// staleDefault is a saved default that no longer resolves to a usable
	// file. Resolution WARNED and fell through to the next source rather than
	// failing; this carries the missing path so the warning can name it.
	staleDefault string
	// configProblem is the message from a settings file that could not be
	// read or parsed. Same treatment: warn, fall through, never panic and
	// never silently attack a different list.
	configProblem string
}

// autoDetected reports whether this choice came from the candidate scan.
func (c wordlistChoice) autoDetected() bool { return c.origin == wordlistAutoDetected }

// machineLocal reports whether this choice could resolve to a DIFFERENT file
// on another machine given the identical command line. Auto-detection is the
// obvious case (machine B may have no rockyou.txt at all), but a saved default
// is just as local: it lives in one operator's ~/.hashsmith/config.json, and
// the second machine either has a different setting or none. Both therefore
// make a distributed --skip/--limit slice unsafe; an explicit -w or
// $HASHSMITH_WORDLIST names the same path everywhere and does not.
func (c wordlistChoice) machineLocal() bool {
	return c.origin == wordlistAutoDetected || c.origin == wordlistFromConfig
}

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
//     It bypasses the environment override AND the saved default.
//  3. $HASHSMITH_WORDLIST — an explicit request; unreadable is an ERROR.
//  4. the saved default from ~/.hashsmith/config.json — a missing file WARNS
//     and falls through.
//  5. wordlistCandidatePaths, in order, first usable file wins.
//  6. the embedded common.txt, which always works.
//
// Steps 3 and 4 are in that order on purpose, and it is not arbitrary: the
// more recent and more deliberate the statement of intent, the higher it
// ranks. A flag is this command; an exported variable is this shell; a saved
// setting is whatever the operator wanted the last time they thought about it,
// possibly months ago. Ranking the setting above the variable would mean
// `HASHSMITH_WORDLIST=... hashsmith crack ...` silently did nothing.
//
// The env/config asymmetry on failure is deliberate for the same reason.
func resolveWordlist(flagPath string, noAuto bool) (wordlistChoice, error) {
	if p := strings.TrimSpace(flagPath); p != "" {
		return wordlistChoice{path: p, origin: wordlistFromFlag, gzip: isGzipFile(p)}, nil
	}

	env := strings.TrimSpace(os.Getenv(wordlistEnvVar))

	// The saved default is read here, before the --no-auto-wordlist branch, so
	// that branch can report that it bypassed one. A broken settings file is
	// carried as a warning, never as an error: see below.
	saved, cfgErr := savedWordlistDefault()
	base := wordlistChoice{}
	if cfgErr != nil {
		base.configProblem = cfgErr.Error()
	}

	// --no-auto-wordlist means "the built-in list, deterministically". It
	// bypasses the environment override and the saved default too: a scripted
	// run that pins the keyspace must not change behaviour because of a
	// variable inherited from the shell or a setting saved on this box. Both
	// bypasses are announced rather than silent.
	if noAuto {
		base.origin = wordlistEmbeddedDefault
		base.forced = true
		base.envIgnored = env != ""
		base.configIgnored = saved != ""
		return base, nil
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
		base.path, base.origin, base.gzip = env, wordlistFromEnv, gz
		return base, nil
	}

	// The saved default. A missing or unusable file here WARNS and falls
	// through; $HASHSMITH_WORDLIST in the same state is a hard error. The
	// difference is not inconsistency, it is the difference between the two
	// kinds of statement:
	//
	//   - $HASHSMITH_WORDLIST is an explicit request for THIS run. It was set
	//     seconds ago by the operator or the script launching the run, so a
	//     path that does not resolve means the operator's intent for this
	//     invocation cannot be honoured — attacking something else instead
	//     would be the silent wrong answer.
	//
	//   - a persisted setting is a preference recorded once and then applied
	//     forever. It goes stale in perfectly ordinary ways: the list was
	//     deleted, the external drive is unmounted, the config was synced from
	//     another machine with a different layout. If that were an error, one
	//     unmounted drive would make EVERY subsequent hashsmith run fail —
	//     locking the operator out of a tool that has a working built-in list
	//     sitting right there. So it warns, loudly and by name, and carries on
	//     down the order.
	if saved != "" {
		problem := wordlistFileProblem(saved)
		if problem == "" {
			base.path, base.origin, base.gzip = saved, wordlistFromConfig, isGzipFile(saved)
			return base, nil
		}
		base.staleDefault = saved
		base.configProblem = problem
	}

	for _, tmpl := range wordlistCandidatePaths {
		p := expandWordlistPath(tmpl)
		if !usableWordlistFile(p) {
			continue
		}
		base.path, base.origin, base.gzip = p, wordlistAutoDetected, isGzipFile(p)
		return base, nil
	}
	base.origin = wordlistEmbeddedDefault
	return base, nil
}

// warnings returns the prominent lines that must precede the one-line source
// announcement: a saved default that has gone stale, or a settings file that
// could not be read. Both change WHAT GETS ATTACKED relative to what the
// operator configured, which is why they are not folded into the one-liner —
// a run that quietly attacks 230k built-in words when the operator pinned a
// 14M-word list, and says so only in a parenthetical, produces a "not found"
// that means nothing.
func (c wordlistChoice) warnings() []string {
	var out []string
	if c.staleDefault != "" {
		out = append(out, fmt.Sprintf(
			"WARNING: the saved default wordlist %s is unusable (%s).\n"+
				"  This run will NOT attack it — falling back to the next source below, "+
				"which is a different keyspace than you configured.\n"+
				"  Fix the path, or run `hashsmith wordlists --clear-default` to forget it.",
			c.staleDefault, c.configProblem))
	} else if c.configProblem != "" {
		out = append(out, fmt.Sprintf(
			"WARNING: the hashsmith settings file could not be used: %s\n"+
				"  Any saved default wordlist is being IGNORED for this run.", c.configProblem))
	}
	return out
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
	case wordlistFromConfig:
		return "Wordlist: " + c.path + " (saved default" + gz + ")"
	case wordlistAutoDetected:
		return "Wordlist: " + c.path + " (auto-detected" + gz + ")"
	default:
		switch {
		case c.forced && c.envIgnored && c.configIgnored:
			return "Wordlist: " + defaultWordlistLabel + " (--no-auto-wordlist; " +
				wordlistEnvVar + " and the saved default ignored)"
		case c.forced && c.envIgnored:
			return "Wordlist: " + defaultWordlistLabel + " (--no-auto-wordlist; " +
				wordlistEnvVar + " ignored)"
		case c.forced && c.configIgnored:
			return "Wordlist: " + defaultWordlistLabel +
				" (--no-auto-wordlist; the saved default ignored)"
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
	// Warnings first, and on their own lines: they say the run is about to
	// attack something other than what was configured, which the operator has
	// to see before the one-liner that names the substitute.
	for _, w := range c.warnings() {
		clrYellow.Fprintln(os.Stderr, w)
	}
	fmt.Fprintln(os.Stderr, c.describe())
}

// distributedWordlistWarning returns the warning text for a distributed run
// built on a MACHINE-LOCAL wordlist — auto-detected, or the saved default —
// or "" when there is nothing to warn about.
//
// --skip/--limit slice a candidate stream by index, which only lines up if
// every machine enumerates the SAME stream. Auto-detection is per-machine by
// construction: machine A with rockyou.txt installed and machine B without it
// produce different streams, so their slices overlap and leave gaps, and the
// resulting "not found" covers less than the operator believes it covers —
// silently. A saved default has exactly the same exposure: it lives in one
// operator's ~/.hashsmith on one box, and the other machines in the fleet
// resolve to whatever THEY have. An explicit -w or $HASHSMITH_WORDLIST names
// the same path on every machine and so never warns. --keyspace has the same exposure one step earlier: a script
// divides the printed number to build those slices.
//
// This warns rather than blocks: a single-machine --limit run (say, to time a
// slice) is perfectly legitimate, and refusing it would be the false-refusal
// error this codebase treats as worse than no guard at all.
func distributedWordlistWarning(c wordlistChoice, skip, limit int64, keyspaceOnly bool) string {
	if !c.machineLocal() || (skip == 0 && limit == 0 && !keyspaceOnly) {
		return ""
	}
	how := "was auto-detected"
	why := fmt.Sprintf("A machine without %s falls back to the built-in list", c.path)
	if c.origin == wordlistFromConfig {
		how = "is this machine's saved default (`hashsmith wordlists --set-default`)"
		why = fmt.Sprintf("A machine with a different saved default — or none — reads a different file "+
			"than %s", c.path)
	}
	return fmt.Sprintf(
		"Warning: this wordlist %s, and --skip/--limit/--keyspace only "+
			"line up when every machine enumerates the SAME candidate stream.\n"+
			"  %s, so its slice covers "+
			"different words — the slices overlap, leave gaps, and the run reports \"not found\" "+
			"for a keyspace it never fully searched.\n"+
			"  Pin every machine to the same list: -w %s (or %s=%s).",
		how, why, c.path, wordlistEnvVar, c.path)
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
