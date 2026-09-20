package main

import (
	"errors"
	"fmt"
	"strings"
)

// ── John the Ripper's rule preprocessor ───────────────────────────────────────
//
// John writes one rule LINE that stands for many rules. A bracket group is a
// list of alternatives, and a line with several groups expands to their
// product:
//
//	$[12]      ->  $1  $2
//	^[ab]$[12] ->  ^a$1  ^a$2  ^b$1  ^b$2
//
// A group may instead be LINKED to an earlier one with \pN, in which case it
// does not multiply: it takes the same index the N-th group took. That is what
// makes `-[:c] ... \p1[lc] ...` mean "when the first group picked ':' use 'l',
// when it picked 'c' use 'c'" — two rules, not four.
//
// This is not a corner of the syntax. Across the 614 rule lines John ships in
// its own configuration files, 84% use a bracket group and 48% use a
// backreference, so without the preprocessor essentially no John ruleset can
// be read at all — which is why Hashsmith previously compiled 1 of the 26
// lines in john.conf's own [List.Rules:Wordlist].

// johnPPGroup is one bracket group in a rule line.
type johnPPGroup struct {
	chars []byte
	link  int // 0 = independent and multiplies; N = same index as group N
}

// johnPPSegment is either literal rule text or a group reference.
type johnPPSegment struct {
	literal string
	group   int // 1-based index into the group list; 0 means this is literal
}

const maxJohnPreprocessorExpansion = 65536

// expandJohnRuleLine turns one John rule line into the rules it stands for.
// A line with no bracket group expands to itself, so this is safe to call on
// every line.
func expandJohnRuleLine(line string) ([]string, error) {
	segs, groups, err := parseJohnPreprocessor(line)
	if err != nil {
		return nil, err
	}
	if len(groups) == 0 {
		// A line with no bracket group still went through the preprocessor,
		// and the preprocessor is where a backslash escape is resolved — so
		// returning the RAW line here left `\[` as two characters and the
		// compiler answered `unknown rule command "\"`.
		//
		// The bug was not that escapes were unsupported. They worked: `[ab]\[`
		// expanded to `a[` and `b[` correctly. They worked only when some
		// UNRELATED group happened to appear on the same line, so whether a
		// rule compiled depended on a part of it that had nothing to do with
		// the escape. john.conf's own `>9 \[` hit exactly that.
		var b strings.Builder
		for _, s := range segs {
			b.WriteString(s.literal)
		}
		return []string{b.String()}, nil
	}

	// Only independent groups multiply; linked ones follow their target.
	var indep []int
	total := 1
	for i, g := range groups {
		if g.link == 0 {
			indep = append(indep, i)
			total *= len(g.chars)
		}
	}
	if total > maxJohnPreprocessorExpansion {
		// John generates its expansions lazily — its documentation says it
		// never keeps them all in memory — while Hashsmith materialises them
		// so that a program can be compiled once and reused. That is the
		// right trade for the rules people write and the wrong one for the
		// handful john.conf contains that stand for millions, so those are
		// refused with their actual size rather than capped silently.
		return nil, fmt.Errorf("rule %q expands to %d rules, past the %d Hashsmith will "+
			"materialise (John generates its expansions lazily and never holds them all)",
			line, total, maxJohnPreprocessorExpansion)
	}
	if total == 0 {
		return nil, fmt.Errorf("rule %q has an empty bracket group", line)
	}

	out := make([]string, 0, total)
	idx := make([]int, len(groups))
	counters := make([]int, len(indep))
	for {
		// Resolve linked groups from the independent ones they point at.
		for i := range indep {
			idx[indep[i]] = counters[i]
		}
		for i, g := range groups {
			if g.link == 0 {
				continue
			}
			src := g.link - 1
			if src < 0 || src >= len(groups) {
				return nil, fmt.Errorf("rule %q references group %d, which does not exist", line, g.link)
			}
			// John wraps when the linked group is shorter than its target.
			idx[i] = idx[src] % len(g.chars)
		}

		var b strings.Builder
		for _, s := range segs {
			if s.group == 0 {
				b.WriteString(s.literal)
				continue
			}
			g := groups[s.group-1]
			b.WriteByte(g.chars[idx[s.group-1]])
		}
		out = append(out, b.String())

		// Odometer, last independent group varying fastest — John's order.
		k := len(counters) - 1
		for k >= 0 {
			counters[k]++
			if counters[k] < len(groups[indep[k]].chars) {
				break
			}
			counters[k] = 0
			k--
		}
		if k < 0 {
			break
		}
	}
	return out, nil
}

// parseJohnPreprocessor splits a rule line into literal segments and groups.
func parseJohnPreprocessor(line string) ([]johnPPSegment, []johnPPGroup, error) {
	var segs []johnPPSegment
	var groups []johnPPGroup
	var lit strings.Builder

	flushLiteral := func() {
		if lit.Len() > 0 {
			segs = append(segs, johnPPSegment{literal: lit.String()})
			lit.Reset()
		}
	}

	for i := 0; i < len(line); {
		c := line[i]

		// \pN[...] — a group linked to the N-th group. \p[...] and \p0[...]
		// both link to the group immediately before it. An optional \r may
		// follow, marking the range as allowed to repeat characters; see
		// dedupeRangeChars.
		if c == '\\' && i+1 < len(line) && (line[i+1] == 'p' || line[i+1] == 'P') {
			j := i + 2
			link := len(groups) // default: the group just before this one
			if j < len(line) && line[j] >= '0' && line[j] <= '9' {
				// \p0 is documented as "parallel with the immediately
				// preceding range", which is the same as bare \p — so it
				// keeps the default rather than linking to a group zero that
				// does not exist.
				if line[j] != '0' {
					link = int(line[j] - '0')
				}
				j++
			}
			repeats := false
			if j+1 < len(line) && line[j] == '\\' && line[j+1] == 'r' {
				repeats = true
				j += 2
			}
			if j < len(line) && line[j] == '[' {
				chars, next, err := parseJohnBracket(line, j)
				if err != nil {
					return nil, nil, err
				}
				if link == 0 {
					return nil, nil, fmt.Errorf("rule %q: \\p has no preceding group", line)
				}
				flushLiteral()
				groups = append(groups, johnPPGroup{chars: dedupeRangeChars(chars, repeats), link: link})
				segs = append(segs, johnPPSegment{group: len(groups)})
				i = next
				continue
			}
			// Not a group reference: fall through and treat as literal.
		}

		// \N — a BACK-REFERENCE to an earlier range. Unlike \pN it has no
		// bracket of its own and adds no group: it emits whatever character
		// the referenced range is currently substituting. \0 refers to the
		// range immediately before it, \1 through \9 to ranges counted from
		// the left.
		//
		// Without this, `$[12]$\0` produced "$1$0" and "$2$0" — the escape
		// fell through to the "backslash escapes the next character" branch
		// below and a digit was appended literally. john produces "$1$1" and
		// "$2$2".
		if c == '\\' && i+1 < len(line) && line[i+1] >= '0' && line[i+1] <= '9' {
			ref := int(line[i+1] - '0')
			if ref == 0 {
				ref = len(groups)
			}
			if ref == 0 || ref > len(groups) {
				return nil, nil, fmt.Errorf("rule %q: \\%c refers to a range that does not exist",
					line, line[i+1])
			}
			flushLiteral()
			segs = append(segs, johnPPSegment{group: ref})
			i += 2
			continue
		}

		// \r[...] — a range allowed to repeat characters.
		if c == '\\' && i+2 < len(line) && line[i+1] == 'r' && line[i+2] == '[' {
			chars, next, err := parseJohnBracket(line, i+2)
			if err != nil {
				return nil, nil, err
			}
			flushLiteral()
			groups = append(groups, johnPPGroup{chars: dedupeRangeChars(chars, true)})
			segs = append(segs, johnPPSegment{group: len(groups)})
			i = next
			continue
		}

		// A backslash escapes the next character, so a literal '[' is writable.
		if c == '\\' && i+1 < len(line) {
			lit.WriteByte(line[i+1])
			i += 2
			continue
		}

		if c == '[' {
			chars, next, err := parseJohnBracket(line, i)
			if err != nil {
				return nil, nil, err
			}
			flushLiteral()
			groups = append(groups, johnPPGroup{chars: dedupeRangeChars(chars, false)})
			segs = append(segs, johnPPSegment{group: len(groups)})
			i = next
			continue
		}

		lit.WriteByte(c)
		i++
	}
	flushLiteral()
	return segs, groups, nil
}

// parseJohnBracket reads one [..] group starting at line[start] == '[' and
// returns its characters and the index just past the closing ']'.
//
// Ranges (a-z) expand, a leading or trailing '-' is a literal '-', and a
// backslash escapes the next character so ']' and '-' can be written.
func parseJohnBracket(line string, start int) ([]byte, int, error) {
	if start >= len(line) || line[start] != '[' {
		return nil, 0, errors.New("internal: not a bracket group")
	}
	var chars []byte
	i := start + 1
	for i < len(line) && line[i] != ']' {
		if line[i] == '\\' && i+1 < len(line) {
			chars = append(chars, line[i+1])
			i += 2
			continue
		}
		// A range needs a character on each side and a closing bracket after.
		if line[i] == '-' && len(chars) > 0 && i+1 < len(line) && line[i+1] != ']' {
			lo, hi := chars[len(chars)-1], line[i+1]
			if lo <= hi {
				for b := int(lo) + 1; b <= int(hi); b++ {
					chars = append(chars, byte(b))
				}
			} else {
				for b := int(lo) - 1; b >= int(hi); b-- {
					chars = append(chars, byte(b))
				}
			}
			i += 2
			continue
		}
		chars = append(chars, line[i])
		i++
	}
	if i >= len(line) {
		return nil, 0, fmt.Errorf("unterminated bracket group in %q", line)
	}
	if len(chars) == 0 {
		return nil, 0, fmt.Errorf("empty bracket group in %q", line)
	}
	return chars, i + 1, nil
}

// dedupeRangeChars applies John's duplicate rules to one range's characters.
//
// John does not expand a range literally. `[aeioua-z]` is documented as "vowels
// followed by all other letters", and the documentation says outright that the
// preprocessor "is smart enough not to produce duplicate rules in such cases".
// Hashsmith expanded it literally and so produced a duplicate candidate for
// every character a range repeated — `[aabbcc]` became six rules where john
// makes three.
//
// The \r escape turns that off, and the exact rule was measured against john
// rather than inferred, because the documentation's sentence about \r covers
// only the parallel-range case:
//
//	[abca]      -> abc      \r[abca]      -> abca
//	[a-ca-c]    -> abc      \r[a-ca-c]    -> abcabc
//	[aab]       -> ab       \r[aab]       -> ab
//	[1-9A-ZZ]   -> 35 chars \r[1-9A-ZZ]   -> 35 chars
//
// The last two are the tell: ADJACENT duplicates collapse whether or not \r
// is present, and \r suppresses only the global pass. john.conf's own
// `->\r[1-9A-ZZ]` is the fourth line, and reading \r as "keep everything"
// would have given it 36 branches against john's 35.
func dedupeRangeChars(chars []byte, repeats bool) []byte {
	if len(chars) < 2 {
		return chars
	}
	out := make([]byte, 0, len(chars))
	var seen [256]bool
	for i, c := range chars {
		if i > 0 && chars[i-1] == c {
			continue // adjacent duplicate: dropped either way
		}
		if !repeats {
			if seen[c] {
				continue
			}
			seen[c] = true
		}
		out = append(out, c)
	}
	return out
}
