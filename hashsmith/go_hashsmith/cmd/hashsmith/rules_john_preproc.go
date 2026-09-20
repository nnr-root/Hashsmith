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
		return []string{line}, nil
	}

	// Only independent groups multiply; linked ones follow their target.
	var indep []int
	total := 1
	for i, g := range groups {
		if g.link == 0 {
			indep = append(indep, i)
			total *= len(g.chars)
			if total > maxJohnPreprocessorExpansion {
				return nil, fmt.Errorf("rule %q expands to more than %d rules",
					line, maxJohnPreprocessorExpansion)
			}
		}
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

		// \pN[...] — a group linked to the N-th group. \p[...] links to the
		// group immediately before it.
		if c == '\\' && i+1 < len(line) && (line[i+1] == 'p' || line[i+1] == 'P') {
			j := i + 2
			link := len(groups) // default: the group just before this one
			if j < len(line) && line[j] >= '1' && line[j] <= '9' {
				link = int(line[j] - '0')
				j++
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
				groups = append(groups, johnPPGroup{chars: chars, link: link})
				segs = append(segs, johnPPSegment{group: len(groups)})
				i = next
				continue
			}
			// Not a group reference: fall through and treat as literal.
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
			groups = append(groups, johnPPGroup{chars: chars})
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
