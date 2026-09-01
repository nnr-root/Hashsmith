package main

import (
	"flag"
	"io"
	"os"
	"runtime"
	"strings"
)

// runAuto powers the bare-target shortcut. The target (a literal hash or a file
// with one hash per line) may appear anywhere among the flags — all of these are
// equivalent:
//
//	hashsmith <hash>
//	hashsmith hashes.txt
//	hashsmith <hash> -w list.txt
//	hashsmith -w list.txt <hash>
//	hashsmith --wordlist=list.txt hashes.txt
//
// When -t is omitted the hash type is auto-detected. The whole argument list is
// passed in; flags and the positional target are separated by the flexible
// parser.
func runAuto(args []string) error {
	fs := flag.NewFlagSet("auto", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	typ := fs.String("t", "", "hash type (omit or 'auto' to auto-detect)")
	mode := fs.String("M", "dict", "attack mode: dict|brute")
	wordlist := fs.String("w", "", "wordlist path (auto-detects an installed rockyou.txt, else the built-in common.txt — see `hashsmith wordlists`)")
	wordlistLong := fs.String("wordlist", "", "alias for -w")
	noAutoWordlist := fs.Bool("no-auto-wordlist", false, "skip wordlist auto-detection and use the built-in common.txt")
	charset := fs.String("C", "abcdefghijklmnopqrstuvwxyz0123456789", "charset (brute mode)")
	minLen := fs.Int("n", 1, "min length (brute)")
	maxLen := fs.Int("x", 4, "max length (brute)")
	salt := fs.String("s", "", "salt")
	saltMode := fs.String("S", "prefix", "salt mode: prefix|suffix")
	workers := fs.Int("p", 0, "parallel workers (0 = NumCPU)")
	outFile := fs.String("o", "", "write result to file")
	copyResult := fs.Bool("c", false, "copy result to clipboard")
	useRules := fs.Bool("r", false, "enable the built-in mangling rules in dict mode")
	var rulesFiles stringSliceFlag
	fs.Var(&rulesFiles, "rules", "path to a rule file (dict mode; overrides -r); repeatable to stack rule files left-to-right, e.g. --rules a.rule --rules b.rule")
	maskStr := fs.String("mask", "", "mask for -M mask (e.g. ?u?l?l?l?d?d)")
	cs1 := fs.String("1", "", "custom charset 1 (mask)")
	cs2 := fs.String("2", "", "custom charset 2 (mask)")
	cs3 := fs.String("3", "", "custom charset 3 (mask)")
	cs4 := fs.String("4", "", "custom charset 4 (mask)")
	increment := fs.Bool("increment", false, "mask increment mode")
	maskFirst := fs.Bool("mask-first", false, "hybrid mode: place the mask before the word (mask+word)")
	potPath := fs.String("pot", "", "potfile path (default ~/.hashsmith/hashsmith.pot)")
	noPot := fs.Bool("no-pot", false, "disable the potfile")
	showOnly := fs.Bool("show", false, "print already-cracked hashes from the potfile; do not attack")
	sessName := fs.String("session", "", "named resumable session (brute/mask/markov/hybrid/combinator/prince)")
	restore := fs.String("restore", "", "alias for --session")
	wordlist2 := fs.String("wordlist2", "", "right-hand wordlist for -M combinator")
	w2 := fs.String("w2", "", "alias for --wordlist2")
	princeElems := fs.Int("prince-elems", princeDefaultElems, "maximum elements concatenated into one chain (-M prince)")
	useGPU := fs.Bool("gpu", false, "use GPU brute/mask for md5, md4, ntlm, sha1, or sha256")
	force := fs.Bool("force", false, "start an attack even when the feasibility guard estimates it cannot finish (the ETA is still measured and printed)")
	if err := parseArgsFlexible(fs, args); err != nil {
		return err
	}

	targets, err := gatherInputs(fs.Args())
	if err != nil {
		return err
	}

	wl := *wordlist
	if wl == "" {
		wl = *wordlistLong
	}
	// Resolve once, exactly as runCrack does, so the bare-target shortcut and
	// the explicit `crack` subcommand attack the same keyspace and print the
	// same source line. runAuto has no --skip/--limit, so no distributed
	// warning applies here.
	wlChoice, err := resolveWordlistForMode(*mode, wl, *noAutoWordlist)
	if err != nil {
		return err
	}
	wl = wlChoice.path

	w := *workers
	if w < 1 {
		w = runtime.NumCPU()
	}
	mc := buildMaskConfig(*maskStr, *cs1, *cs2, *cs3, *cs4, *increment, *minLen, *maskFirst)
	sn := *sessName
	if sn == "" {
		sn = *restore
	}
	wl2 := *wordlist2
	if wl2 == "" {
		wl2 = *w2
	}
	cc, err := newCrackCtx(*potPath, *noPot, sn, *showOnly, wl2, *useGPU, 0, 0)
	if err != nil {
		return err
	}
	cc.princeElems = *princeElems
	cc.force = *force
	engine, err := buildRuleEngine(rulesFiles.values, *useRules)
	if err != nil {
		return err
	}
	return crackTargets(targets, *typ, *mode, wl, *charset,
		*minLen, *maxLen, w, *salt, *saltMode, *outFile, *copyResult, engine, mc, cc)
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
