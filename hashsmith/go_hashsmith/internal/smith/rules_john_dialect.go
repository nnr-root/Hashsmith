package smith

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
// johnSymbolClass is John's ?s, exactly as john matches it: 23 characters,
// with punctuation deliberately absent because that is ?p.
const johnSymbolClass = "$%^&*()-_+=|\\<>[]{}#@/~"

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
		// John's ?s is an explicit 23-character SET, not "everything that is
		// not a letter or a digit". The nine characters of ?p — . , : ; ' ? !
		// backtick and the double quote — are punctuation and are NOT symbols
		// here, so ?s and ?p do not overlap and neither covers all the
		// printable non-alphanumerics.
		//
		// Reading ?s as the broad complement made `s?s_` turn "P@ssw0rd!"
		// into "P_ssw0rd_" where john leaves the "!" alone. The set below was
		// read out of john itself, one character at a time, by substituting
		// over a word containing every printable byte.
		base = func(b byte) bool { return strings.IndexByte(johnSymbolClass, b) >= 0 }
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
	case 'o':
		// Control characters: everything below space, plus DEL.
		base = func(b byte) bool { return b < 0x20 || b == 0x7f }
	case 'y':
		// "Valid characters". John's own documentation says its rules engine
		// has very limited understanding of UTF-8 and that classes work on
		// ASCII even under --encoding=utf-8, so over bytes this is everything
		// but NUL — which john cannot carry in a word in any case.
		base = func(b byte) bool { return b != 0 }
	case 'b':
		// The 8th bit set. Verified against john with a UTF-8 "é", whose two
		// bytes both matched, which is the byte-oriented reading.
		base = func(b byte) bool { return b >= 0x80 }
	case '?':
		// ?? matches a literal '?', which is how a rule writes one where a
		// class name would otherwise be read.
		base = func(b byte) bool { return b == '?' }
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
// johnRuleRequiresWordPairs reports whether a line carries John's -p reject
// flag, which means "reject this rule unless word pair commands are currently
// allowed".
//
// Word pairs are a SINGLE-CRACK mode idea: the candidate source there is a
// user's GECOS field, so a rule can act on the first name, the second, or
// their concatenation. A wordlist run has no pairs, and john skips every such
// rule — `-p 1 l` through `john --wordlist --stdout` prints nothing at all,
// while the same rule without the flag is a hard error there ("Unallowed
// command").
//
// So these nine lines of john.conf are not a gap in what Hashsmith can read.
// They are rules that do not apply, and reporting them as broken told a user
// their ruleset was malformed when john was quietly skipping them too.
func johnRuleRequiresWordPairs(line string) bool {
	i := 0
	for i < len(line) {
		if line[i] == ' ' || line[i] == '\t' {
			i++
			continue
		}
		if line[i] != '-' || i+1 >= len(line) {
			return false
		}
		f := line[i+1]
		if strings.IndexByte(johnRejectFlags, f) < 0 {
			return false // -N is the decrement command, not a flag
		}
		if f == 'p' {
			return true
		}
		i += 2
		if (f == '<' || f == '>') && i < len(line) {
			i++
		}
	}
	return false
}

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
	// john's grammar commands are LOWERCASE ONLY, which its documentation
	// says in three words and which matters more than it sounds. Every suffix
	// test below is case-SENSITIVE, so "WIFE" pluralises to "WIFEs" and not
	// "WIVes", and "TRY" to "TRYs" and not "TRies". Hashsmith used to lower
	// the word before testing, which produced a different candidate for every
	// capitalised word ending in y, f, fe, s, x, z, ch or sh — and those are
	// exactly the words a ruleset reaches after a `c` or a `u`.
	//
	// Measured against john, not inferred: BED->BEDs, DAY->DAYs, TRY->TRYs,
	// WIFE->WIFEs, walks->walkses, leaf->leaves, knife->knives, boy->boys.
	if len(r) < 2 {
		return r // john leaves a one-character word alone
	}
	s := string(r)
	last := s[len(s)-1]
	switch {
	case last == 's' || last == 'x' || last == 'z' ||
		strings.HasSuffix(s, "ch") || strings.HasSuffix(s, "sh"):
		return append(r, 'e', 's')
	case strings.HasSuffix(s, "fe"):
		return append(r[:len(r)-2], 'v', 'e', 's')
	case last == 'f':
		return append(r[:len(r)-1], 'v', 'e', 's')
	case last == 'y' && !isVowel(s[len(s)-2]):
		return append(r[:len(r)-1], 'i', 'e', 's')
	default:
		return append(r, 's')
	}
}

// johnBGP reports whether b is one of the three consonants john doubles before
// "ed". The set is exactly "bgp" in john's own source, which is why "walking"
// becomes "walkingged" while "buzz" becomes "buzzed" and "sit" becomes
// "sited" — measured, and surprising enough that it would never be guessed.
func johnBGP(b byte) bool { return b == 'b' || b == 'g' || b == 'p' }

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
	// Measured against john across every branch: walked->walked (already
	// past, left alone), bed->bed, boy->boied (y becomes i with NO check on
	// what precedes it, unlike pluralisation), free->freed and wife->wifed (a
	// lowercase trailing e takes only a d), WIFE->WIFEed and BED->BEDed (an
	// uppercase one does not, because the test is case-sensitive),
	// walking->walkingged (a trailing b, g or p doubles unless the character
	// before it is also one), and sit->sited, buzz->buzzed, abcd->abcded.
	if len(r) < 3 {
		return r
	}
	last := r[len(r)-1]
	if last == 'd' && r[len(r)-2] == 'e' {
		return r // already ends in "ed"
	}
	switch {
	case last == 'y':
		return append(r[:len(r)-1], 'i', 'e', 'd')
	case last == 'e':
		return append(r, 'd')
	case johnBGP(last) && !johnBGP(r[len(r)-2]):
		return append(r, last, 'e', 'd')
	default:
		return append(r, 'e', 'd')
	}
}

// johnProgressive is John's `I` command. Measured against john:
// walking->walking (already progressive, left alone), walked->walkeding,
// free->freing and wife->wifing (a lowercase trailing e is dropped),
// WIFE->WIFEing (an uppercase one is not), boy->boying, try->trying,
// hi->hi and a->a (too short), and no consonant doubling, unlike `P`.
func johnProgressive(r []byte) []byte {
	if len(r) < 3 {
		return r
	}
	if r[len(r)-3] == 'i' && r[len(r)-2] == 'n' && r[len(r)-1] == 'g' {
		return r // already ends in "ing"
	}
	if r[len(r)-1] == 'e' {
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

// ── Keyboard-shift and case-conversion commands ───────────────────────────────
//
// John's `R`, `L` and `S` move a character by where it SITS ON A KEYBOARD, not
// by where it sits in the alphabet, so each needs the layout as data. The
// layout below is US QWERTY, which is john's own default and the one its
// documented examples are written against: "Crack96" -> "Vtsvl07" under `R`,
// "Xeaxj85" under `L`, and "cRACK(^" under `S`.
//
// Hashcat has `R` and `L` too and they mean something else entirely — a
// bitwise shift of the character at a given position, taking an operand John's
// forms do not. That is why these live behind the John dialect rather than
// beside their hashcat namesakes, and why `R` in a John rule must NOT be read
// as hashcat's `RN`: doing so consumed the following command as a position and
// silently changed the rule.
var (
	// qwertyRows pairs each unshifted row with its shifted row, in physical
	// order. A character's left and right neighbours come from its own row, so
	// the rows must not be concatenated.
	qwertyRows = [][2]string{
		{"`1234567890-=", "~!@#$%^&*()_+"},
		{"qwertyuiop[]\\", "QWERTYUIOP{}|"},
		{"asdfghjkl;'", "ASDFGHJKL:\""},
		{"zxcvbnm,./", "ZXCVBNM<>?"},
	}
	keyboardRight [256]byte
	keyboardLeft  [256]byte
	keyboardShift [256]byte
)

func init() {
	for i := 0; i < 256; i++ {
		keyboardRight[i] = byte(i)
		keyboardLeft[i] = byte(i)
		keyboardShift[i] = byte(i)
	}
	for _, row := range qwertyRows {
		for _, line := range row {
			for j := 0; j < len(line); j++ {
				if j+1 < len(line) {
					keyboardRight[line[j]] = line[j+1]
				}
				if j > 0 {
					keyboardLeft[line[j]] = line[j-1]
				}
			}
		}
		// Shift maps each position to the same position on the other row, in
		// both directions, so `S` is its own inverse.
		lower, upper := row[0], row[1]
		for j := 0; j < len(lower) && j < len(upper); j++ {
			keyboardShift[lower[j]] = upper[j]
			keyboardShift[upper[j]] = lower[j]
		}
	}
}

// johnShiftCase implements `S`: every character becomes what the same key
// produces with Shift held, so letters case-toggle and digits and punctuation
// become their shifted symbols. "Crack96" -> "cRACK(^".
func johnShiftCase(r []byte) []byte {
	out := make([]byte, len(r))
	for i, b := range r {
		out[i] = keyboardShift[b]
	}
	return out
}

// johnKeyboardShift implements `R` and `L`: each character moves one key
// right or left along its own keyboard row. A character at the end of its row,
// or not on the layout at all, is left alone — which is john's behaviour, not
// a simplification.
func johnKeyboardShift(r []byte, right bool) []byte {
	table := &keyboardLeft
	if right {
		table = &keyboardRight
	}
	out := make([]byte, len(r))
	for i, b := range r {
		out[i] = table[b]
	}
	return out
}

// johnVowelsConsonants implements `V`: lowercase the vowels, uppercase the
// consonants, leave everything else. "Crack96" -> "CRaCK96".
func johnVowelsConsonants(r []byte) []byte {
	out := make([]byte, len(r))
	for i, b := range r {
		switch {
		case !isASCIILetter(b):
			out[i] = b
		case isVowel(b):
			out[i] = toLowerByte(b)
		default:
			out[i] = toUpperByte(b)
		}
	}
	return out
}

// johnDefaultMinLength and johnDefaultMaxLength are the bounds `aN` and `bN`
// check against.
//
// Those two commands reject a word unless it would still fit the run's
// min/max length limits after N characters are added or removed. They are an
// EARLY-REJECTION optimisation: john uses them to throw a word away before
// spending work on the rest of the rule, and the candidate stream is the same
// either way when the limits are the defaults. Hashsmith has no per-run rule
// length limits to consult, so the defaults are what these compile against —
// which is exactly john's behaviour when a run sets neither -min-length nor
// -max-length, the ordinary case.
//
// This is not a no-op even so. With a minimum of zero, `b5` still rejects
// every word shorter than five characters, and john.conf's toggle-case
// rulesets lean on precisely that.
const (
	johnDefaultMinLength = 0
	johnDefaultMaxLength = johnMaxLength
)
