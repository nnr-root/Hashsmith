package main

import (
	"fmt"
	"strings"
)

// ── John the Ripper's rule dialect ────────────────────────────────────────────
//
// John and Hashcat share most of their rule commands and disagree on a handful.
// Where they disagree the difference is not cosmetic — `p` duplicates the word
// in Hashcat and pluralises it in John — so the two dialects are compiled
// separately rather than merged. Merging would silently change what an existing
// Hashcat rule file does, and this project has verified candidate-for-candidate
// parity with Hashcat across all 28 of its stock rule files; that must not
// regress to gain John support.
//
// What John adds:
//
//   - Character classes.  `?d` is any digit, `?D` any non-digit, and the
//     reject and purge commands take them: `!?A` rejects a word containing a
//     non-letter, `/?v` rejects one without a vowel, `@?p` purges punctuation.
//   - Reject flags.  A rule may open with `-c`, `-8`, `-s`, `-p` or `-:` to
//     say which formats it applies to. Hashsmith has no format-capability
//     model to consult, so these are accepted and the rule is kept — dropping
//     the rule instead would silently shrink a ruleset.
//   - Length characters.  `*` is the maximum password length, `-` one less
//     and `+` one more.
//   - `M` and `Q`, memorise and reject-unless-changed, which Hashcat also has
//     and Hashsmith implemented for neither.

// johnClassMatch returns a predicate for a John character class, and whether
// the name was recognised. An uppercase name is the complement of its
// lowercase counterpart.
func johnClassMatch(name byte) (func(byte) bool, bool) {
	lower := name | 0x20
	var base func(byte) bool
	switch lower {
	case 'v':
		base = func(b byte) bool { return strings.IndexByte("aeiouAEIOU", b) >= 0 }
	case 'c':
		base = func(b byte) bool { return isASCIILetter(b) && strings.IndexByte("aeiouAEIOU", b) < 0 }
	case 'w':
		base = func(b byte) bool { return b == ' ' || b == '\t' }
	case 'p':
		base = func(b byte) bool { return strings.IndexByte(".,:;'?!`\"", b) >= 0 }
	case 's':
		base = func(b byte) bool {
			return b > 0x20 && b < 0x7f && !isASCIILetter(b) && !(b >= '0' && b <= '9')
		}
	case 'l':
		base = func(b byte) bool { return b >= 'a' && b <= 'z' }
	case 'u':
		base = func(b byte) bool { return b >= 'A' && b <= 'Z' }
	case 'd':
		base = func(b byte) bool { return b >= '0' && b <= '9' }
	case 'a':
		base = isASCIILetter
	case 'x':
		base = func(b byte) bool { return isASCIILetter(b) || (b >= '0' && b <= '9') }
	case 'z':
		base = func(byte) bool { return true }
	default:
		return nil, false
	}
	// An uppercase class name is the complement. 'z' has no complement: John
	// documents ?z as "all characters", and its uppercase form as none.
	if name >= 'A' && name <= 'Z' {
		inner := base
		return func(b byte) bool { return !inner(b) }, true
	}
	return base, true
}

func isASCIILetter(b byte) bool {
	return (b >= 'a' && b <= 'z') || (b >= 'A' && b <= 'Z')
}

// johnRejectFlags are the leading flags a John rule may carry to say which
// formats it applies to. Used when a file is ALREADY known to be John's.
const johnRejectFlags = "cC8spoP:<>v"

// johnOnlyRejectFlags is the subset safe to DETECT a John file from.
//
// The two dialects overlap here and the overlap is not theoretical: hashcat's
// `-N` decrements the character at position N, and its positions are 0-9 and
// A-Z — so `-8`, `-C` and `-P` are valid hashcat rules as well as valid John
// flags. hashcat's own specific.rule contains `-8`, and detecting on it read
// that whole file as John and silently dropped every candidate it produced.
//
// Only flags that cannot be a hashcat position are used to decide: the
// lowercase letters, ':' and the length flags.
const johnOnlyRejectFlags = "cspov:<>"

// stripJohnRejectFlags consumes any leading reject flags and returns the rest
// of the rule.
//
// Hashsmith has no format-capability model to consult, so a flagged rule is
// KEPT rather than dropped. That is the conservative direction: keeping a rule
// that John would have skipped costs some wasted candidates, while dropping
// one John would have run silently shrinks the ruleset and loses passwords.
// The one exception is a length flag (-<N, ->N), whose argument is consumed
// along with it so it cannot be mistaken for a command.
func stripJohnRejectFlags(line string) string {
	i := 0
	for i < len(line) {
		if line[i] == ' ' || line[i] == '\t' {
			i++
			continue
		}
		if line[i] != '-' || i+1 >= len(line) {
			break
		}
		f := line[i+1]
		if strings.IndexByte(johnRejectFlags, f) < 0 {
			break // -N is the decrement command, not a flag
		}
		i += 2
		// -<N and ->N carry a length argument.
		if (f == '<' || f == '>') && i < len(line) {
			i++
		}
	}
	return line[i:]
}

// johnLengthValue maps John's length characters. Hashsmith has no format
// maximum to consult, so John's documented default of 125 is used; the effect
// of `<*` is "no upper bound", which is what the rule means.
func johnLengthValue(c byte) (int, bool) {
	switch c {
	case '*':
		return 125, true
	case '-':
		return 124, true
	case '+':
		return 126, true
	}
	return 0, false
}

// johnPluralize appends an English plural suffix, John's `p` command.
func johnPluralize(r []byte) []byte {
	s := string(r)
	if s == "" {
		return r
	}
	last := s[len(s)-1]
	lower := strings.ToLower(s)
	switch {
	case strings.HasSuffix(lower, "s"), strings.HasSuffix(lower, "x"),
		strings.HasSuffix(lower, "z"), strings.HasSuffix(lower, "ch"),
		strings.HasSuffix(lower, "sh"):
		return append(r, 'e', 's')
	case last == 'f':
		return append(r[:len(r)-1], 'v', 'e', 's')
	case strings.HasSuffix(lower, "fe"):
		return append(r[:len(r)-2], 'v', 'e', 's')
	case strings.HasSuffix(lower, "y") && len(s) >= 2 && !isVowel(s[len(s)-2]):
		return append(r[:len(r)-1], 'i', 'e', 's')
	default:
		return append(r, 's')
	}
}

func isVowel(b byte) bool { return strings.IndexByte("aeiouAEIOU", b|0x20) >= 0 }

// looksLikeJohnRuleLine reports whether a line uses syntax only John has.
func looksLikeJohnRuleLine(line string) bool {
	t := strings.TrimSpace(line)
	if t == "" || strings.HasPrefix(t, "#") || strings.HasPrefix(t, "!") {
		return false
	}
	// A leading reject flag — but only one hashcat could not have written.
	if len(t) >= 2 && t[0] == '-' && strings.IndexByte(johnOnlyRejectFlags, t[1]) >= 0 {
		return true
	}
	// A backreference, or a class argument to a reject/purge command.
	if strings.Contains(t, `\p`) {
		return true
	}
	for i := 0; i+2 < len(t); i++ {
		switch t[i] {
		case '!', '/', '(', ')', '@':
			if t[i+1] == '?' {
				if _, ok := johnClassMatch(t[i+2]); ok {
					return true
				}
			}
		}
	}
	return false
}

// detectJohnDialect reports whether a rule file is written in John's dialect.
//
// Detection is per FILE, not per line: a file is one ruleset, and compiling
// half of it one way and half the other would produce candidates neither tool
// would. One unambiguous John line is enough, because Hashcat has no syntax
// that would produce a false positive here — every construct
// looksLikeJohnRuleLine tests for is one Hashcat does not have.
func detectJohnDialect(lines []string) bool {
	for _, l := range lines {
		if looksLikeJohnRuleLine(l) {
			return true
		}
	}
	return false
}

// errJohnOnly marks a construct this compiler only accepts in John's dialect,
// so a Hashcat file that happens to contain it still reports a real error.
func errJohnOnly(what string) error {
	return fmt.Errorf("%s is John-dialect syntax; this file was read as Hashcat rules", what)
}

// containsClass reports whether any byte of r matches the class predicate.
func containsClass(r []byte, match func(byte) bool) bool {
	for _, b := range r {
		if match(b) {
			return true
		}
	}
	return false
}

// johnMaxLength is John's maximum password length, used for its `*` length
// character and as the clamp for a position character it does not recognise.
const johnMaxLength = 125

// isRulePosChar reports whether c is a position/length character.
func isRulePosChar(c byte) bool {
	_, ok := rulePos(c)
	return ok
}

// johnPastTense is John's `P` command. Verified against john itself:
// password->passworded, try->tried, box->boxed, lady->ladied, wife->wifed.
func johnPastTense(r []byte) []byte {
	if len(r) == 0 {
		return r
	}
	last := r[len(r)-1] | 0x20
	switch {
	case last == 'e':
		return append(r, 'd')
	case last == 'y' && len(r) >= 2 && !isVowel(r[len(r)-2]):
		return append(r[:len(r)-1], 'i', 'e', 'd')
	default:
		return append(r, 'e', 'd')
	}
}

// johnProgressive is John's `I` command. Verified against john itself:
// password->passwording, try->trying, box->boxing, lady->ladying,
// wife->wifing (the trailing 'e' is dropped).
func johnProgressive(r []byte) []byte {
	if len(r) == 0 {
		return r
	}
	if r[len(r)-1]|0x20 == 'e' {
		return append(r[:len(r)-1], 'i', 'n', 'g')
	}
	return append(r, 'i', 'n', 'g')
}

// johnLengthRefOffset recognises John's runtime length characters: `l` is the
// original word's length and `m` is one less.
func johnLengthRefOffset(c byte) (int, bool) {
	switch c {
	case 'l':
		return 0, true
	case 'm':
		return -1, true
	}
	return 0, false
}

// countByte counts occurrences of x in r.
func countByte(r []byte, x byte) int {
	n := 0
	for _, b := range r {
		if b == x {
			n++
		}
	}
	return n
}

// countClass counts bytes of r matching the class predicate.
func countClass(r []byte, match func(byte) bool) int {
	n := 0
	for _, b := range r {
		if match(b) {
			n++
		}
	}
	return n
}
