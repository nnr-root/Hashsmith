package smith

// compat.go — a thin argv-rewriter letting a real hashcat or John the
// Ripper command line, pasted close to verbatim, run against this
// project's own crack engine. See
// docs/superpowers/specs/2026-08-31-hashsmith-throughput-and-reach-design.md
// §6/§8 for the original scope and its "alias flags, never fork
// semantics" constraint: this file only ever rewrites argv before the
// real flag parser sees it, never a second parser, never new runtime
// behavior.
//
// SAFETY IS THE WHOLE DESIGN HERE. hashcat reuses several single-letter
// flags this project already defines for something else entirely:
//
//	-M  hashcat: disable a GPU kernel optimization | here: attack mode
//	-t  hashcat: --markov-threshold (a number)      | here: hash type
//	-p  hashcat: hashlist/outfile separator char    | here: worker count
//	-n  hashcat: GPU kernel-accel tuning (a number) | here: brute min length
//	-s  hashcat: --skip (a number)                  | here: salt
//	-w  hashcat: workload profile 1-4 (a number)    | here: wordlist path
//	-r  hashcat: a rules FILE path                  | here: a boolean
//	-S  hashcat: --slow-candidates (a boolean)      | here: salt mode
//	-i  collides with this project's own top-level `-i <hash>` identify
//	    shortcut (main.go), not with a crack flag — same risk class
//
// Silently reinterpreting any of these under hashcat's meaning would not
// fail loudly — it would run with confidently wrong settings (e.g. a
// wordlist path of "4" from a pasted `-w 4` workload-profile flag). This
// layer therefore ONLY EVER recognizes -a/-m/--format and their
// genuinely unambiguous companions (this project has no native flag
// under those names at all), and REFUSES every other hashcat/JtR flag
// that collides with an existing native one — never guesses.
//
// Compat mode triggers only when -a, --attack-mode, -m, --hash-type,
// --format, or --format= appears in argv. A normal native invocation —
// no such flag — is returned completely unchanged, so this can never
// alter behavior for the CLI vocabulary this project already had.

import (
	"errors"
	"fmt"
	"strings"
)

// compatRefusedFlags names hashcat/JtR flags this layer deliberately does
// not translate, each with why — either because the flag collides with a
// DIFFERENT flag this project already defines under the same name (see
// this file's own top comment), or because it names a JtR/hashcat feature
// with no clean argv-level equivalent (--fork's real process-splitting,
// --incremental's config-file-driven character model). Refused
// unconditionally the moment compat mode has triggered.
var compatRefusedFlags = map[string]string{
	"-M":            "hashcat's -M disables a GPU kernel optimization; this project's own -M picks the attack mode",
	"-t":            "hashcat's -t sets --markov-threshold; this project's own -t picks the hash type — use --markov-threshold if that's what you meant",
	"-p":            "hashcat's -p sets a hashlist/outfile separator character; this project's own -p sets the worker count",
	"-n":            "hashcat's -n tunes GPU kernel acceleration; this project's own -n sets brute-force minimum length",
	"-s":            "hashcat's -s skips N candidates; this project's own -s is the salt — use --skip if that's what you meant",
	"-w":            "hashcat's -w picks a workload profile (1-4); this project's own -w is the wordlist path",
	"-r":            "hashcat's -r names a rules FILE; this project's own -r is a boolean (enable built-in rules) — use --rules <file> if that's what you meant",
	"-S":            "hashcat's -S enables slow-candidates mode; this project's own -S is the salt mode",
	"-i":            "hashcat's -i enables mask increment mode; this project reserves a bare -i for its own hash-identify shortcut — use --increment if that's what you meant",
	"-l":            "hashcat's -l limits N candidates from the start — use --limit directly",
	"-u":            "hashcat's -u tunes GPU kernel loops; this project has no equivalent",
	"-T":            "hashcat's -T tunes GPU thread count; this project has no equivalent",
	"-j":            "hashcat's -j applies one rule to the left wordlist; use --rules with a rule file instead",
	"-k":            "hashcat's -k applies one rule to the right wordlist; use --rules with a rule file instead",
	"-5":            "only custom charsets 1-4 are supported",
	"-6":            "only custom charsets 1-4 are supported",
	"-7":            "only custom charsets 1-4 are supported",
	"-8":            "only custom charsets 1-4 are supported",
	"--fork":        "hashcat/John's process-splitting has no argv-level equivalent — use --skip/--limit to divide the keyspace yourself",
	"--incremental": "John's --incremental pulls a named character-frequency model from john.conf, which this project does not read — use -M markov (optionally with --hcstat2) instead",
}

// nativeValueFlags lists this project's own flags that consume a following
// argument, beyond the ones compat mode already recognizes by name above.
// The positional scan below needs this to correctly skip a flag's value
// rather than mistaking it for a positional target/wordlist/mask — e.g.
// without this, `--session foo hash.txt` would see "foo" as an extra
// positional. Flags already handled specially elsewhere in this file
// (-a/-m/-1..-4/--format/--increment-min/--increment-max/--wordlist/--rules)
// are deliberately not repeated here.
var nativeValueFlags = map[string]bool{
	"-C": true, "-o": true,
	"--mask": true, "--pot": true, "--session": true, "--restore": true,
	"--wordlist2": true, "--w2": true, "--prince-elems": true,
	"--hcstat2": true, "--markov-threshold": true, "--outfile-format": true,
	"--passwd": true, "--split": true, "--assoc-wordlist": true,
}

// hashcatAttackModes maps hashcat's -a mode numbers to this project's own
// -M name plus how many trailing positional arguments that mode expects
// and what each one becomes. hashcat's own CLI convention places the
// target hash file first, then 1-N more positionals whose MEANING depends
// entirely on -a's value — unlike this project's own convention (a single
// trailing target, everything else named flags) — so translating -a
// correctly means reinterpreting those positionals, not just renaming a
// flag. Modes 2/4/5/8 do not exist in hashcat; omitted, so they fall
// through to compatUnknownAttackMode's refusal.
type hashcatAttackMode struct {
	nativeMode string
	// positionals names what each expected trailing positional becomes,
	// in the order hashcat itself expects them. "wordlist" may repeat
	// (association mode accepts one or more).
	positionals []string
	// minPositionals/maxPositionals bound how many trailing positionals
	// are valid; -1 for maxPositionals means unbounded (association mode).
	minPositionals, maxPositionals int
}

var hashcatAttackModes = map[string]hashcatAttackMode{
	"0": {nativeMode: "dict", positionals: []string{"wordlist"}, minPositionals: 1, maxPositionals: 1},
	"1": {nativeMode: "combinator", positionals: []string{"wordlist", "wordlist2"}, minPositionals: 2, maxPositionals: 2},
	"3": {nativeMode: "mask", positionals: []string{"mask"}, minPositionals: 1, maxPositionals: 1},
	"6": {nativeMode: "hybrid", positionals: []string{"wordlist", "mask"}, minPositionals: 2, maxPositionals: 2},
	"7": {nativeMode: "hybrid", positionals: []string{"mask", "wordlist"}, minPositionals: 2, maxPositionals: 2},
	"9": {nativeMode: "association", positionals: []string{"assocWordlist"}, minPositionals: 1, maxPositionals: -1},
}

// translateCompatArgs rewrites a hashcat- or John-the-Ripper-flavored argv
// into this project's own native flags, or returns args completely
// unchanged when no recognized hashcat/JtR trigger flag (-a/-m/--format)
// is present — see this file's own top comment for the full safety
// rationale. Called once, at the very top of runCrack/runAuto, before
// either builds its own flag.FlagSet.
func translateCompatArgs(args []string) ([]string, error) {
	if !compatModeTriggered(args) {
		return args, nil
	}

	var out []string
	var positionals []string
	var attackMode *hashcatAttackMode
	var attackModeSeen string

	next := func(i int, flagName string) (string, int, error) {
		if i+1 >= len(args) {
			return "", i, fmt.Errorf("%s requires a value", flagName)
		}
		return args[i+1], i + 1, nil
	}

	for i := 0; i < len(args); i++ {
		a := args[i]

		if reason, refused := compatRefusedFlags[a]; refused {
			return nil, fmt.Errorf("hashcat/John compat: %s is not supported — %s", a, reason)
		}
		if a == "--incremental" || strings.HasPrefix(a, "--incremental=") {
			return nil, fmt.Errorf("hashcat/John compat: %s", compatRefusedFlags["--incremental"])
		}

		switch {
		case a == "-a" || a == "--attack-mode":
			v, ni, err := next(i, a)
			if err != nil {
				return nil, err
			}
			i = ni
			m, ok := hashcatAttackModes[v]
			if !ok {
				return nil, fmt.Errorf("hashcat/John compat: -a %s is not a supported attack mode (supported: 0, 1, 3, 6, 7, 9)", v)
			}
			attackMode = &m
			attackModeSeen = v

		case a == "-m" || a == "--hash-type":
			v, ni, err := next(i, a)
			if err != nil {
				return nil, err
			}
			i = ni
			out = append(out, "-t", v)

		case a == "--format":
			v, ni, err := next(i, a)
			if err != nil {
				return nil, err
			}
			i = ni
			out = append(out, "-t", v)
		case strings.HasPrefix(a, "--format="):
			out = append(out, "-t", strings.TrimPrefix(a, "--format="))

		case a == "--increment-min":
			v, ni, err := next(i, a)
			if err != nil {
				return nil, err
			}
			i = ni
			out = append(out, "-n", v)
		case a == "--increment-max":
			v, ni, err := next(i, a)
			if err != nil {
				return nil, err
			}
			i = ni
			out = append(out, "-x", v)

		case a == "-1" || a == "-2" || a == "-3" || a == "-4":
			v, ni, err := next(i, a)
			if err != nil {
				return nil, err
			}
			i = ni
			out = append(out, a, v)

		case nativeValueFlags[a]:
			v, ni, err := next(i, a)
			if err != nil {
				return nil, err
			}
			i = ni
			out = append(out, a, v)

		case len(a) > 0 && a[0] == '-':
			// Everything else recognized as a flag (--show, --left,
			// --increment, --wordlist[=X], --rules[=X], and any other
			// already-native flag not listed above) already means the
			// same thing under both vocabularies, or is self-contained
			// via "=" — pass it through untouched.
			out = append(out, a)

		default:
			positionals = append(positionals, a)
		}
	}

	if attackMode == nil {
		// --format/-m alone (no -a) is a valid, narrower hashcat/JtR
		// invocation shape — e.g. `--format=raw-md5 hash.txt wordlist.txt`
		// defaults to straight/dict mode the same way hashcat's own -a
		// defaults to 0. Any positionals collected are then just this
		// project's own native positionals (target, and -w's value if a
		// wordlist positional was intended) — but this project has no
		// positional wordlist, only -w, so treat a bare extra positional
		// beyond the target as an error rather than silently dropping it.
		if len(positionals) > 1 {
			return nil, fmt.Errorf("hashcat/John compat: %d unexpected positional argument(s) %v without -a — pass a wordlist via -w explicitly", len(positionals)-1, positionals[1:])
		}
		out = append(out, positionals...)
		return out, nil
	}

	if len(positionals) < 1 {
		return nil, errors.New("hashcat/John compat: missing the target hash/hashlist positional argument")
	}
	target := positionals[0]
	rest := positionals[1:]
	if len(rest) < attackMode.minPositionals || (attackMode.maxPositionals >= 0 && len(rest) > attackMode.maxPositionals) {
		return nil, fmt.Errorf("hashcat/John compat: -a %s expects %s, got %d", attackModeSeen,
			compatPositionalCountDesc(attackMode), len(rest))
	}

	out = append(out, "-M", attackMode.nativeMode)
	if attackModeSeen == "7" {
		out = append(out, "--mask-first")
	}
	if attackMode.positionals[0] == "assocWordlist" {
		for _, w := range rest {
			out = append(out, "--assoc-wordlist", w)
		}
	} else {
		for idx, kind := range attackMode.positionals {
			switch kind {
			case "wordlist":
				out = append(out, "-w", rest[idx])
			case "wordlist2":
				out = append(out, "--wordlist2", rest[idx])
			case "mask":
				out = append(out, "--mask", rest[idx])
			}
		}
	}
	out = append(out, target)
	return out, nil
}

// compatPositionalCountDesc describes how many trailing positionals an
// attack mode expects, for an error message a user can act on.
func compatPositionalCountDesc(m *hashcatAttackMode) string {
	if m.maxPositionals < 0 {
		return fmt.Sprintf("at least %d wordlist(s) after the target", m.minPositionals)
	}
	if m.minPositionals == m.maxPositionals {
		return fmt.Sprintf("exactly %d argument(s) after the target", m.minPositionals)
	}
	return fmt.Sprintf("between %d and %d argument(s) after the target", m.minPositionals, m.maxPositionals)
}

// compatModeTriggered reports whether args contains any flag that only
// hashcat or John the Ripper would use to select the attack mode or hash
// type — the sole signal this layer uses to decide an invocation is
// hashcat/John-flavored rather than native. A native invocation (this
// project's own -M/-t and everything else) never contains any of these,
// so this can never fire by accident on existing usage.
func compatModeTriggered(args []string) bool {
	for _, a := range args {
		switch {
		case a == "-a" || a == "--attack-mode" || a == "-m" || a == "--hash-type" || a == "--format":
			return true
		case strings.HasPrefix(a, "--format="):
			return true
		}
	}
	return false
}
