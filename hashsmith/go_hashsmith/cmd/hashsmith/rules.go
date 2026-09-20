package main

// The rule language — a compact per-word transformation syntax compatible with
// the widely-used `.rule` file format. Each non-comment line is one rule: a
// sequence of single-character commands applied left-to-right to a dictionary
// word to produce one candidate. A command may reject the word (e.g. a length
// test fails), in which case the rule yields nothing.
//
// Supported commands:
//
//	:            no-op (pass the word through unchanged)
//	l u          lowercase / uppercase all
//	c C          capitalise (first up, rest low) / invert-capitalise
//	t TN         toggle case of all / of the character at position N
//	r            reverse
//	d  pN        duplicate the word / append N extra copies
//	f            reflect (append the word reversed)
//	q            duplicate every character
//	{ }          rotate left / right
//	[ ]          delete first / last character
//	DN           delete the character at position N
//	zN ZN        duplicate the first / last character N times
//	yN YN        duplicate the first / last N characters
//	'N           truncate to length N
//	$X ^X        append / prepend character X
//	@X           purge every occurrence of X
//	sXY          replace every X with Y
//	oNX iNX      overwrite / insert character X at position N
//	xNM          extract M characters starting at position N
//	*NM          swap the characters at positions N and M
//	k K          swap the first two / last two characters
//	ONM          omit M characters starting at position N
//	+N -N        increment / decrement the character at position N
//	LN RN        bitwise shift the character at position N left / right
//	.N ,N        replace the character at N with the one after / before it
//	E eX         title case, splitting on spaces / on X
//	3NX          toggle the character after the (N+1)th occurrence of X
//	<N >N _N     reject unless length < N / > N / == N
//	!X /X        reject if the word contains X / unless it contains X
//
// Positions and counts use the standard base-36 digit encoding: 0-9 then A-Z
// for 10-35.
//
// Two behaviours are inherited from hashcat deliberately, because diverging
// from them silently changes which passwords a rule file can find:
//
//   - A position operand past the end of the word leaves the word UNCHANGED.
//     Rejecting instead (which this engine used to do) drops candidates from
//     the search while still reporting "not found" — the one failure mode a
//     cracker must never have.
//   - A command whose result would reach maxRuleCandidate bytes is skipped and
//     the word carries on unchanged.
//
// Both are pinned by oracle vectors in rules_hashcat_compat_test.go, generated
// from the real hashcat binary by scripts/rules-oracle.sh.

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"strings"
)

// rulePos decodes a single base-36 position/count digit (0-9, A-Z → 0-35).
func rulePos(c byte) (int, bool) {
	switch {
	case c >= '0' && c <= '9':
		return int(c - '0'), true
	case c >= 'A' && c <= 'Z':
		return int(c-'A') + 10, true
	default:
		return 0, false
	}
}

// errRuleRejectedByHashcatToo marks a rule line that hashcat's own compiler
// also refuses. hashcat ships rule files containing such lines — bare "z"/"Z"
// with no position operand, and the InsidePro-era "SXY" — and answers them
// with "No valid rules left.", so skipping them costs no candidate relative to
// hashcat. They are therefore reported and skipped rather than aborting a run,
// while anything else unparsable (a real typo, which hashcat would have
// compiled) remains fatal. Without this split, strict mode would refuse whole
// stock rulesets that hashcat handles.
var errRuleRejectedByHashcatToo = errors.New("rule form hashcat also rejects")

type ruleOp func([]byte) ([]byte, bool)

type ruleProgram struct {
	src string
	ops []ruleOp
}

// maxRuleCandidate is the largest candidate a rule may build. hashcat carries
// a fixed password buffer (RP_PASSWORD_SIZE, 256) and skips any command whose
// result would reach it, leaving the word as it was rather than rejecting the
// rule outright — so "p9 p9" on an 8-byte word yields 80 bytes, not 800.
// Matching that exactly is what keeps candidate streams identical on rule
// files (dive.rule among the stock set) that chain growth commands.
const maxRuleCandidate = 256

// apply runs every op in order; a rejecting op aborts the rule (no candidate).
// An op whose result would reach maxRuleCandidate bytes is skipped, and the
// word carries on unchanged into the next op.
func (p ruleProgram) apply(word string) (string, bool) {
	r := []byte(word)
	for _, op := range p.ops {
		next, ok := op(r)
		if !ok {
			return "", false
		}
		if len(next) >= maxRuleCandidate && len(next) > len(r) {
			continue // over the buffer: hashcat skips the command, keeps the word
		}
		r = next
	}
	return string(r), true
}

// compileRuleLine parses one rule line into an executable program.
func compileRuleLine(line string) (ruleProgram, error) {
	var ops []ruleOp
	i, n := 0, len(line)

	// arg reads the immediate next byte (used for literal/position operands, so
	// that e.g. `$ ` correctly appends a space rather than skipping it).
	arg := func() (byte, bool) {
		if i < n {
			c := line[i]
			i++
			return c, true
		}
		return 0, false
	}
	posArg := func(cmd byte) (int, error) {
		c, ok := arg()
		if !ok {
			if cmd == 'z' || cmd == 'Z' {
				return 0, fmt.Errorf("command %q missing position: %w", string(cmd), errRuleRejectedByHashcatToo)
			}
			return 0, fmt.Errorf("command %q missing position", string(cmd))
		}
		p, ok := rulePos(c)
		if !ok {
			return 0, fmt.Errorf("command %q: bad position %q", string(cmd), string(c))
		}
		return p, nil
	}

	for i < n {
		c := line[i]
		i++
		if c == ' ' || c == '\t' {
			continue // whitespace separates commands
		}
		switch c {
		case ':':
			ops = append(ops, func(r []byte) ([]byte, bool) { return r, true })
		case 'l':
			ops = append(ops, opMap(toLowerByte))
		case 'u':
			ops = append(ops, opMap(toUpperByte))
		case 'c':
			ops = append(ops, opCapitalize)
		case 'C':
			ops = append(ops, opInvCapitalize)
		case 't':
			ops = append(ops, opMap(toggleByte))
		case 'r':
			ops = append(ops, opReverse)
		case 'd':
			ops = append(ops, func(r []byte) ([]byte, bool) { return append(append([]byte{}, r...), r...), true })
		case 'f':
			ops = append(ops, opReflect)
		case 'q':
			ops = append(ops, opDupEach)
		case '{':
			ops = append(ops, opRotLeft)
		case '}':
			ops = append(ops, opRotRight)
		case '[':
			ops = append(ops, func(r []byte) ([]byte, bool) {
				if len(r) == 0 {
					return r, true
				}
				return r[1:], true
			})
		case ']':
			ops = append(ops, func(r []byte) ([]byte, bool) {
				if len(r) == 0 {
					return r, true
				}
				return r[:len(r)-1], true
			})
		case 'k':
			ops = append(ops, opSwapFront)
		case 'K':
			ops = append(ops, opSwapBack)
		case '$':
			x, ok := arg()
			if !ok {
				return ruleProgram{}, errors.New("dangling '$' (append) with no character")
			}
			xr := x
			ops = append(ops, func(r []byte) ([]byte, bool) { return append(r, xr), true })
		case '^':
			x, ok := arg()
			if !ok {
				return ruleProgram{}, errors.New("dangling '^' (prepend) with no character")
			}
			xr := x
			ops = append(ops, func(r []byte) ([]byte, bool) {
				return append([]byte{xr}, r...), true
			})
		case '@':
			x, ok := arg()
			if !ok {
				return ruleProgram{}, errors.New("dangling '@' (purge) with no character")
			}
			xr := x
			ops = append(ops, func(r []byte) ([]byte, bool) {
				out := r[:0:0]
				for _, ch := range r {
					if ch != xr {
						out = append(out, ch)
					}
				}
				return out, true
			})
		case 's':
			x, ok1 := arg()
			y, ok2 := arg()
			if !ok1 || !ok2 {
				return ruleProgram{}, errors.New("command 's' needs two characters (sXY)")
			}
			xr, yr := x, y
			ops = append(ops, func(r []byte) ([]byte, bool) {
				out := make([]byte, len(r))
				for i, ch := range r {
					if ch == xr {
						out[i] = yr
					} else {
						out[i] = ch
					}
				}
				return out, true
			})
		case 'T':
			p, err := posArg(c)
			if err != nil {
				return ruleProgram{}, err
			}
			ops = append(ops, func(r []byte) ([]byte, bool) {
				if p >= len(r) {
					return r, true // out of range: hashcat leaves the word unchanged
				}
				out := append([]byte{}, r...)
				out[p] = toggleByte(out[p])
				return out, true
			})
		case 'D':
			p, err := posArg(c)
			if err != nil {
				return ruleProgram{}, err
			}
			ops = append(ops, func(r []byte) ([]byte, bool) {
				if p >= len(r) {
					return r, true // out of range: hashcat leaves the word unchanged
				}
				out := append([]byte{}, r[:p]...)
				return append(out, r[p+1:]...), true
			})
		case 'z':
			p, err := posArg(c)
			if err != nil {
				return ruleProgram{}, err
			}
			ops = append(ops, func(r []byte) ([]byte, bool) {
				if len(r) == 0 {
					return r, true
				}
				pre := make([]byte, p)
				for i := range pre {
					pre[i] = r[0]
				}
				return append(pre, r...), true
			})
		case 'Z':
			p, err := posArg(c)
			if err != nil {
				return ruleProgram{}, err
			}
			ops = append(ops, func(r []byte) ([]byte, bool) {
				if len(r) == 0 {
					return r, true
				}
				out := append([]byte{}, r...)
				for i := 0; i < p; i++ {
					out = append(out, r[len(r)-1])
				}
				return out, true
			})
		case 'y':
			p, err := posArg(c)
			if err != nil {
				return ruleProgram{}, err
			}
			ops = append(ops, func(r []byte) ([]byte, bool) {
				if p > len(r) {
					return r, true // hashcat no-ops rather than clamping to the word
				}
				return append(append([]byte{}, r[:p]...), r...), true
			})
		case 'Y':
			p, err := posArg(c)
			if err != nil {
				return ruleProgram{}, err
			}
			ops = append(ops, func(r []byte) ([]byte, bool) {
				if p > len(r) {
					return r, true // hashcat no-ops rather than clamping to the word
				}
				return append(append([]byte{}, r...), r[len(r)-p:]...), true
			})
		case 'p':
			p, err := posArg(c)
			if err != nil {
				return ruleProgram{}, err
			}
			ops = append(ops, func(r []byte) ([]byte, bool) {
				out := append([]byte{}, r...)
				for i := 0; i < p; i++ {
					out = append(out, r...)
				}
				return out, true
			})
		case '\'':
			p, err := posArg(c)
			if err != nil {
				return ruleProgram{}, err
			}
			ops = append(ops, func(r []byte) ([]byte, bool) {
				if p < len(r) {
					return r[:p], true
				}
				return r, true
			})
		case 'o':
			p, err := posArg(c)
			if err != nil {
				return ruleProgram{}, err
			}
			x, ok := arg()
			if !ok {
				return ruleProgram{}, errors.New("command 'o' needs a character (oNX)")
			}
			xr := x
			ops = append(ops, func(r []byte) ([]byte, bool) {
				if p >= len(r) {
					return r, true // out of range: hashcat leaves the word unchanged
				}
				out := append([]byte{}, r...)
				out[p] = xr
				return out, true
			})
		case 'i':
			p, err := posArg(c)
			if err != nil {
				return ruleProgram{}, err
			}
			x, ok := arg()
			if !ok {
				return ruleProgram{}, errors.New("command 'i' needs a character (iNX)")
			}
			xr := x
			ops = append(ops, func(r []byte) ([]byte, bool) {
				if p > len(r) {
					return r, true // out of range: hashcat leaves the word unchanged
				}
				out := append([]byte{}, r[:p]...)
				out = append(out, xr)
				return append(out, r[p:]...), true
			})
		case 'x':
			p, err := posArg(c)
			if err != nil {
				return ruleProgram{}, err
			}
			m, err := posArg(c)
			if err != nil {
				return ruleProgram{}, err
			}
			ops = append(ops, func(r []byte) ([]byte, bool) {
				// hashcat requires the whole extracted span to exist; a span
				// running past the end leaves the word unchanged (it does not
				// extract a short tail).
				if p+m > len(r) {
					return r, true
				}
				return append([]byte{}, r[p:p+m]...), true
			})
		case '*':
			a, err := posArg(c)
			if err != nil {
				return ruleProgram{}, err
			}
			b, err := posArg(c)
			if err != nil {
				return ruleProgram{}, err
			}
			ops = append(ops, func(r []byte) ([]byte, bool) {
				if a >= len(r) || b >= len(r) {
					return r, true // out of range: hashcat leaves the word unchanged
				}
				out := append([]byte{}, r...)
				out[a], out[b] = out[b], out[a]
				return out, true
			})
		case '<':
			p, err := posArg(c)
			if err != nil {
				return ruleProgram{}, err
			}
			ops = append(ops, func(r []byte) ([]byte, bool) { return r, len(r) < p })
		case '>':
			p, err := posArg(c)
			if err != nil {
				return ruleProgram{}, err
			}
			ops = append(ops, func(r []byte) ([]byte, bool) { return r, len(r) > p })
		case '_':
			p, err := posArg(c)
			if err != nil {
				return ruleProgram{}, err
			}
			ops = append(ops, func(r []byte) ([]byte, bool) { return r, len(r) == p })
		case '!':
			x, ok := arg()
			if !ok {
				return ruleProgram{}, errors.New("command '!' needs a character (!X)")
			}
			xr := x
			ops = append(ops, func(r []byte) ([]byte, bool) { return r, !containsByte(r, xr) })
		case '/':
			x, ok := arg()
			if !ok {
				return ruleProgram{}, errors.New("command '/' needs a character (/X)")
			}
			xr := x
			ops = append(ops, func(r []byte) ([]byte, bool) { return r, containsByte(r, xr) })
		case 'O':
			// ONM — omit M characters starting at position N.
			pn, err := posArg(c)
			if err != nil {
				return ruleProgram{}, err
			}
			m, err := posArg(c)
			if err != nil {
				return ruleProgram{}, err
			}
			ops = append(ops, func(r []byte) ([]byte, bool) {
				if pn+m > len(r) {
					return r, true
				}
				out := append([]byte{}, r[:pn]...)
				return append(out, r[pn+m:]...), true
			})
		case '+':
			// +N — increment the character at position N by one.
			pn, err := posArg(c)
			if err != nil {
				return ruleProgram{}, err
			}
			ops = append(ops, opAtPos(pn, func(b byte) byte { return b + 1 }))
		case '-':
			// -N — decrement the character at position N by one.
			pn, err := posArg(c)
			if err != nil {
				return ruleProgram{}, err
			}
			ops = append(ops, opAtPos(pn, func(b byte) byte { return b - 1 }))
		case 'L':
			// LN — bitwise shift the character at position N left.
			pn, err := posArg(c)
			if err != nil {
				return ruleProgram{}, err
			}
			ops = append(ops, opAtPos(pn, func(b byte) byte { return b << 1 }))
		case 'R':
			// RN — bitwise shift the character at position N right.
			pn, err := posArg(c)
			if err != nil {
				return ruleProgram{}, err
			}
			ops = append(ops, opAtPos(pn, func(b byte) byte { return b >> 1 }))
		case '.':
			// .N — replace the character at N with the one that follows it.
			pn, err := posArg(c)
			if err != nil {
				return ruleProgram{}, err
			}
			ops = append(ops, func(r []byte) ([]byte, bool) {
				if pn+1 >= len(r) {
					return r, true
				}
				out := append([]byte{}, r...)
				out[pn] = out[pn+1]
				return out, true
			})
		case ',':
			// ,N — replace the character at N with the one before it.
			pn, err := posArg(c)
			if err != nil {
				return ruleProgram{}, err
			}
			ops = append(ops, func(r []byte) ([]byte, bool) {
				if pn == 0 || pn >= len(r) {
					return r, true
				}
				out := append([]byte{}, r...)
				out[pn] = out[pn-1]
				return out, true
			})
		case 'E':
			// E — title case: lowercase everything, then capitalise the first
			// letter of every space-separated word.
			ops = append(ops, opTitle(' '))
		case 'e':
			// eX — title case using X as the word separator.
			x, ok := arg()
			if !ok {
				return ruleProgram{}, errors.New("command 'e' needs a separator (eX)")
			}
			ops = append(ops, opTitle(x))
		case '3':
			// 3NX — toggle the case of the character immediately after the
			// (N+1)th occurrence of X.
			pn, err := posArg(c)
			if err != nil {
				return ruleProgram{}, err
			}
			x, ok := arg()
			if !ok {
				return ruleProgram{}, errors.New("command '3' needs a separator (3NX)")
			}
			ops = append(ops, func(r []byte) ([]byte, bool) {
				seen := 0
				for i := 0; i < len(r); i++ {
					if r[i] != x {
						continue
					}
					if seen == pn {
						if i+1 >= len(r) {
							return r, true
						}
						out := append([]byte{}, r...)
						out[i+1] = toggleByte(out[i+1])
						return out, true
					}
					seen++
				}
				return r, true
			})
		case 'S':
			// InsidePro "SXY" case-sensitive replace. hashcat does not
			// implement it either, so a file using it is skipped here to the
			// same effect rather than refused outright.
			return ruleProgram{}, fmt.Errorf("command %q is not implemented: %w", string(c), errRuleRejectedByHashcatToo)
		default:
			return ruleProgram{}, fmt.Errorf("unknown rule command %q", string(c))
		}
	}
	if len(ops) == 0 {
		return ruleProgram{}, errors.New("empty rule")
	}
	return ruleProgram{src: line, ops: ops}, nil
}

// opAtPos builds an op that rewrites the single byte at position p with f,
// leaving the word untouched when p lies past its end (hashcat's behaviour for
// every position-indexed command).
func opAtPos(p int, f func(byte) byte) ruleOp {
	return func(r []byte) ([]byte, bool) {
		if p >= len(r) {
			return r, true
		}
		out := append([]byte{}, r...)
		out[p] = f(out[p])
		return out, true
	}
}

// opTitle lowercases the word, then uppercases the first byte and every byte
// that directly follows the separator sep.
func opTitle(sep byte) ruleOp {
	return func(r []byte) ([]byte, bool) {
		out := make([]byte, len(r))
		up := true
		for i, ch := range r {
			ch = toLowerByte(ch)
			if up {
				ch = toUpperByte(ch)
			}
			out[i] = ch
			up = r[i] == sep
		}
		return out, true
	}
}

// ── byte helpers ──────────────────────────────────────────────────────────────

func toLowerByte(r byte) byte {
	if r >= 'A' && r <= 'Z' {
		return r + 32
	}
	return r
}
func toUpperByte(r byte) byte {
	if r >= 'a' && r <= 'z' {
		return r - 32
	}
	return r
}
func toggleByte(r byte) byte {
	switch {
	case r >= 'a' && r <= 'z':
		return r - 32
	case r >= 'A' && r <= 'Z':
		return r + 32
	}
	return r
}
func containsByte(r []byte, x byte) bool {
	for _, ch := range r {
		if ch == x {
			return true
		}
	}
	return false
}

func opMap(f func(byte) byte) ruleOp {
	return func(r []byte) ([]byte, bool) {
		out := make([]byte, len(r))
		for i, ch := range r {
			out[i] = f(ch)
		}
		return out, true
	}
}
func opCapitalize(r []byte) ([]byte, bool) {
	out := make([]byte, len(r))
	for i, ch := range r {
		if i == 0 {
			out[i] = toUpperByte(ch)
		} else {
			out[i] = toLowerByte(ch)
		}
	}
	return out, true
}
func opInvCapitalize(r []byte) ([]byte, bool) {
	out := make([]byte, len(r))
	for i, ch := range r {
		if i == 0 {
			out[i] = toLowerByte(ch)
		} else {
			out[i] = toUpperByte(ch)
		}
	}
	return out, true
}
func opReverse(r []byte) ([]byte, bool) {
	out := make([]byte, len(r))
	for i, ch := range r {
		out[len(r)-1-i] = ch
	}
	return out, true
}
func opReflect(r []byte) ([]byte, bool) {
	out := append([]byte{}, r...)
	for i := len(r) - 1; i >= 0; i-- {
		out = append(out, r[i])
	}
	return out, true
}
func opDupEach(r []byte) ([]byte, bool) {
	out := make([]byte, 0, len(r)*2)
	for _, ch := range r {
		out = append(out, ch, ch)
	}
	return out, true
}
func opRotLeft(r []byte) ([]byte, bool) {
	if len(r) < 2 {
		return r, true
	}
	return append(append([]byte{}, r[1:]...), r[0]), true
}
func opRotRight(r []byte) ([]byte, bool) {
	if len(r) < 2 {
		return r, true
	}
	return append([]byte{r[len(r)-1]}, r[:len(r)-1]...), true
}
func opSwapFront(r []byte) ([]byte, bool) {
	if len(r) < 2 {
		return r, true
	}
	out := append([]byte{}, r...)
	out[0], out[1] = out[1], out[0]
	return out, true
}
func opSwapBack(r []byte) ([]byte, bool) {
	if len(r) < 2 {
		return r, true
	}
	out := append([]byte{}, r...)
	out[len(r)-1], out[len(r)-2] = out[len(r)-2], out[len(r)-1]
	return out, true
}

// ── engine ────────────────────────────────────────────────────────────────────

// ruleEngine expands a base word into mangled candidates. It is one of:
//
//   - the built-in curated rule set (builtin)
//   - a single compiled rule file (programs) — the original, unstacked shape;
//     expand/count for this shape are untouched from before rule stacking
//     existed, so a single `--rules FILE` run is byte-identical to before.
//   - a stack of 2+ rule files (layers), one slice of programs per file. See
//     expandStacked for the cross-product semantics.
type ruleEngine struct {
	programs     []ruleProgram   // set when built from exactly one rule file
	layers       [][]ruleProgram // set when built from 2+ stacked rule files
	stackedCount int             // precomputed, capped product of len(layers[i]); only meaningful when layers != nil
	builtin      bool
}

func builtinRuleEngine() *ruleEngine { return &ruleEngine{builtin: true} }

func (e *ruleEngine) count() int {
	if e == nil {
		return 0
	}
	if e.builtin {
		return NumManglingRules
	}
	if e.layers != nil {
		return e.stackedCount
	}
	return len(e.programs)
}

// expand returns the mangled candidates for word (identity excluded; the caller
// tests the base word itself).
func (e *ruleEngine) expand(word string) []mangledWord {
	if e == nil {
		return nil
	}
	if e.builtin {
		return expandRules(word)
	}
	if e.layers != nil {
		return e.expandStacked(word)
	}
	seen := make(map[string]struct{}, len(e.programs)+1)
	seen[word] = struct{}{}
	out := make([]mangledWord, 0, len(e.programs))
	for _, p := range e.programs {
		cand, ok := p.apply(word)
		if !ok {
			continue
		}
		if _, dup := seen[cand]; dup {
			continue
		}
		seen[cand] = struct{}{}
		out = append(out, mangledWord{password: cand, ruleLabel: p.src})
	}
	return out
}

// expandStacked applies a stack of rule files as their cross product: layer 0
// (the first --rules file) is the outer loop, the last layer varies fastest,
// matching hashcat-style "-r a.rule -r b.rule" stacking. Each candidate is
// produced by threading word through one program from each layer in order —
// p_last.apply(...p1.apply(p0.apply(word))...) — so a rejection at any layer
// short-circuits: no program from a later layer ever runs for that branch,
// and no candidate is produced for it. This is exactly what compiling the
// single line p0.src+p1.src+...+p_last.src and applying it once would do,
// EXCEPT that this path round-trips through a Go string between layers while
// a concatenated line stays in []byte throughout; the two differ only if an
// intermediate candidate is not valid UTF-8 (see rules_stacking_test.go).
//
// The ruleLabel of a stacked candidate is the concatenation of the source
// rules that produced it (p0.src+p1.src+...), which — per the oracle above —
// is itself a valid, single-line rule reproducing the same candidate from the
// original word.
//
// Dedup mirrors the single-file case: the base word itself and any duplicate
// candidate (by string equality) are skipped via a per-word `seen` set.
func (e *ruleEngine) expandStacked(word string) []mangledWord {
	seen := make(map[string]struct{}, e.stackedCount+1)
	seen[word] = struct{}{}
	out := make([]mangledWord, 0, e.stackedCount)
	var rec func(layer int, cur, label string)
	rec = func(layer int, cur, label string) {
		if layer == len(e.layers) {
			if _, dup := seen[cur]; dup {
				return
			}
			seen[cur] = struct{}{}
			out = append(out, mangledWord{password: cur, ruleLabel: label})
			return
		}
		for _, p := range e.layers[layer] {
			cand, ok := p.apply(cur)
			if !ok {
				continue // rejection short-circuits: later layers never run
			}
			rec(layer+1, cand, label+p.src)
		}
	}
	rec(0, word, "")
	return out
}

// maxStackedCandidates bounds the per-word candidate count of a stacked rule
// engine — the product of each layer's rule count, checked BEFORE any word is
// ever expanded. A stacked product can be enormous (three 1000-rule files is
// 10^9 per word): silently truncating that down to the cap would mean real
// candidates are never tried while the tool reports "not found", which is the
// worst possible failure mode for a cracking tool. So instead loadRuleFiles
// refuses to build the engine at all, naming the files and the product. The
// cap itself (1,000,000) comfortably covers realistic composable stacks —
// e.g. best64-sized (64) x a digit-suffix file (64) is 4,096, and even a
// 1,000-line file x a 1,000-line file lands exactly at the cap — while still
// catching the pathological multi-file products the design calls out.
const maxStackedCandidates = 1_000_000

// compileRuleFileLines reads and compiles every rule line in path, skipping
// blank lines and '#' comments. Invalid rules are counted (bad) and skipped,
// never causing a hard error by themselves — loadRuleFile and loadRuleFiles
// decide what an all-invalid file means for their caller.
func compileRuleFileLines(path string) ([]ruleProgram, int, error) {
	// A readable file first, then a bundled ruleset by bare name. A user's own
	// file always wins, because the bundled lookup is only reached when the
	// open failed.
	src, _, err := openRuleSource(path)
	if err != nil {
		return nil, 0, err
	}
	if c, ok := src.(io.Closer); ok {
		defer c.Close()
	}
	var programs []ruleProgram
	bad := 0 // rules only Hashsmith fails to parse — a real gap
	sc := bufio.NewScanner(src)
	sc.Buffer(make([]byte, 1<<20), 1<<20)
	for sc.Scan() {
		line := strings.TrimRight(sc.Text(), "\r\n")
		if strings.TrimSpace(line) == "" || strings.HasPrefix(strings.TrimSpace(line), "#") {
			continue
		}
		p, err := compileRuleLine(line)
		if err != nil {
			if !errors.Is(err, errRuleRejectedByHashcatToo) {
				bad++
			}
			continue
		}
		programs = append(programs, p)
	}
	if err := sc.Err(); err != nil {
		return nil, bad, err
	}
	return programs, bad, nil
}

// loadRuleFile compiles a single rule file, skipping blank lines and '#'
// comments. Invalid rules are counted and skipped; an error is returned only
// when no valid rule remains. The returned engine uses the unstacked
// `programs` shape, so behaviour (including expand's iteration order and
// dedup) is unchanged from before rule stacking existed.
func loadRuleFile(path string) (*ruleEngine, int, error) {
	programs, bad, err := compileRuleFileLines(path)
	if err != nil {
		return nil, bad, err
	}
	if len(programs) == 0 {
		return nil, bad, fmt.Errorf("no valid rules in %s", path)
	}
	return &ruleEngine{programs: programs}, bad, nil
}

// loadRuleFiles compiles one or more rule files into a ruleEngine. A single
// path is delegated straight to loadRuleFile (the unstacked shape, byte-
// identical to before stacking existed). Two or more paths become stacking
// layers: file i is layer i, applied left-to-right per expandStacked's
// cross-product semantics. Each file must contain at least one valid rule.
// The product of per-file rule counts is computed with satMul (so it cannot
// silently wrap) and checked against maxStackedCandidates before the engine
// is returned; a stack that would exceed the cap is refused with an error
// naming every file and the product, rather than built and truncated later.
func loadRuleFiles(paths []string) (*ruleEngine, int, error) {
	if len(paths) == 1 {
		return loadRuleFile(paths[0])
	}
	e := &ruleEngine{}
	totalBad := 0
	product := int64(1)
	for _, path := range paths {
		programs, bad, err := compileRuleFileLines(path)
		if err != nil {
			return nil, 0, err
		}
		if len(programs) == 0 {
			return nil, 0, fmt.Errorf("no valid rules in %s", path)
		}
		e.layers = append(e.layers, programs)
		totalBad += bad
		product = satMul(product, int64(len(programs)))
	}
	if product > maxStackedCandidates {
		return nil, 0, fmt.Errorf(
			"stacking %s would produce %d candidates per word, exceeding the %d-candidate cap; use fewer or smaller rule files",
			strings.Join(paths, " + "), product, maxStackedCandidates)
	}
	e.stackedCount = int(product)
	return e, totalBad, nil
}
