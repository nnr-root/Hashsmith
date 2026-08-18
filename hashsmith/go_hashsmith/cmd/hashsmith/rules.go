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
//	<N >N _N     reject unless length < N / > N / == N
//	!X /X        reject if the word contains X / unless it contains X
//
// Positions and counts use the standard base-36 digit encoding: 0-9 then A-Z
// for 10-35. Position-indexed commands reject the word when the index lies
// beyond its end.

import (
	"bufio"
	"errors"
	"fmt"
	"os"
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

type ruleOp func([]rune) ([]rune, bool)

type ruleProgram struct {
	src string
	ops []ruleOp
}

// apply runs every op in order; a rejecting op aborts the rule (no candidate).
func (p ruleProgram) apply(word string) (string, bool) {
	r := []rune(word)
	for _, op := range p.ops {
		var ok bool
		if r, ok = op(r); !ok {
			return "", false
		}
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
			ops = append(ops, func(r []rune) ([]rune, bool) { return r, true })
		case 'l':
			ops = append(ops, opMap(toLowerRune))
		case 'u':
			ops = append(ops, opMap(toUpperRune))
		case 'c':
			ops = append(ops, opCapitalize)
		case 'C':
			ops = append(ops, opInvCapitalize)
		case 't':
			ops = append(ops, opMap(toggleRune))
		case 'r':
			ops = append(ops, opReverse)
		case 'd':
			ops = append(ops, func(r []rune) ([]rune, bool) { return append(append([]rune{}, r...), r...), true })
		case 'f':
			ops = append(ops, opReflect)
		case 'q':
			ops = append(ops, opDupEach)
		case '{':
			ops = append(ops, opRotLeft)
		case '}':
			ops = append(ops, opRotRight)
		case '[':
			ops = append(ops, func(r []rune) ([]rune, bool) {
				if len(r) == 0 {
					return r, true
				}
				return r[1:], true
			})
		case ']':
			ops = append(ops, func(r []rune) ([]rune, bool) {
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
			xr := rune(x)
			ops = append(ops, func(r []rune) ([]rune, bool) { return append(r, xr), true })
		case '^':
			x, ok := arg()
			if !ok {
				return ruleProgram{}, errors.New("dangling '^' (prepend) with no character")
			}
			xr := rune(x)
			ops = append(ops, func(r []rune) ([]rune, bool) {
				return append([]rune{xr}, r...), true
			})
		case '@':
			x, ok := arg()
			if !ok {
				return ruleProgram{}, errors.New("dangling '@' (purge) with no character")
			}
			xr := rune(x)
			ops = append(ops, func(r []rune) ([]rune, bool) {
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
			xr, yr := rune(x), rune(y)
			ops = append(ops, func(r []rune) ([]rune, bool) {
				out := make([]rune, len(r))
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
			ops = append(ops, func(r []rune) ([]rune, bool) {
				if p >= len(r) {
					return nil, false
				}
				out := append([]rune{}, r...)
				out[p] = toggleRune(out[p])
				return out, true
			})
		case 'D':
			p, err := posArg(c)
			if err != nil {
				return ruleProgram{}, err
			}
			ops = append(ops, func(r []rune) ([]rune, bool) {
				if p >= len(r) {
					return nil, false
				}
				out := append([]rune{}, r[:p]...)
				return append(out, r[p+1:]...), true
			})
		case 'z':
			p, err := posArg(c)
			if err != nil {
				return ruleProgram{}, err
			}
			ops = append(ops, func(r []rune) ([]rune, bool) {
				if len(r) == 0 {
					return r, true
				}
				pre := make([]rune, p)
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
			ops = append(ops, func(r []rune) ([]rune, bool) {
				if len(r) == 0 {
					return r, true
				}
				out := append([]rune{}, r...)
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
			ops = append(ops, func(r []rune) ([]rune, bool) {
				k := p
				if k > len(r) {
					k = len(r)
				}
				return append(append([]rune{}, r[:k]...), r...), true
			})
		case 'Y':
			p, err := posArg(c)
			if err != nil {
				return ruleProgram{}, err
			}
			ops = append(ops, func(r []rune) ([]rune, bool) {
				k := p
				if k > len(r) {
					k = len(r)
				}
				return append(append([]rune{}, r...), r[len(r)-k:]...), true
			})
		case 'p':
			p, err := posArg(c)
			if err != nil {
				return ruleProgram{}, err
			}
			ops = append(ops, func(r []rune) ([]rune, bool) {
				out := append([]rune{}, r...)
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
			ops = append(ops, func(r []rune) ([]rune, bool) {
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
			xr := rune(x)
			ops = append(ops, func(r []rune) ([]rune, bool) {
				if p >= len(r) {
					return nil, false
				}
				out := append([]rune{}, r...)
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
			xr := rune(x)
			ops = append(ops, func(r []rune) ([]rune, bool) {
				if p > len(r) {
					return nil, false
				}
				out := append([]rune{}, r[:p]...)
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
			ops = append(ops, func(r []rune) ([]rune, bool) {
				if p >= len(r) {
					return nil, false
				}
				end := p + m
				if end > len(r) {
					end = len(r)
				}
				return append([]rune{}, r[p:end]...), true
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
			ops = append(ops, func(r []rune) ([]rune, bool) {
				if a >= len(r) || b >= len(r) {
					return nil, false
				}
				out := append([]rune{}, r...)
				out[a], out[b] = out[b], out[a]
				return out, true
			})
		case '<':
			p, err := posArg(c)
			if err != nil {
				return ruleProgram{}, err
			}
			ops = append(ops, func(r []rune) ([]rune, bool) { return r, len(r) < p })
		case '>':
			p, err := posArg(c)
			if err != nil {
				return ruleProgram{}, err
			}
			ops = append(ops, func(r []rune) ([]rune, bool) { return r, len(r) > p })
		case '_':
			p, err := posArg(c)
			if err != nil {
				return ruleProgram{}, err
			}
			ops = append(ops, func(r []rune) ([]rune, bool) { return r, len(r) == p })
		case '!':
			x, ok := arg()
			if !ok {
				return ruleProgram{}, errors.New("command '!' needs a character (!X)")
			}
			xr := rune(x)
			ops = append(ops, func(r []rune) ([]rune, bool) { return r, !containsRune(r, xr) })
		case '/':
			x, ok := arg()
			if !ok {
				return ruleProgram{}, errors.New("command '/' needs a character (/X)")
			}
			xr := rune(x)
			ops = append(ops, func(r []rune) ([]rune, bool) { return r, containsRune(r, xr) })
		default:
			return ruleProgram{}, fmt.Errorf("unknown rule command %q", string(c))
		}
	}
	if len(ops) == 0 {
		return ruleProgram{}, errors.New("empty rule")
	}
	return ruleProgram{src: line, ops: ops}, nil
}

// ── rune helpers ──────────────────────────────────────────────────────────────

func toLowerRune(r rune) rune {
	if r >= 'A' && r <= 'Z' {
		return r + 32
	}
	return r
}
func toUpperRune(r rune) rune {
	if r >= 'a' && r <= 'z' {
		return r - 32
	}
	return r
}
func toggleRune(r rune) rune {
	switch {
	case r >= 'a' && r <= 'z':
		return r - 32
	case r >= 'A' && r <= 'Z':
		return r + 32
	}
	return r
}
func containsRune(r []rune, x rune) bool {
	for _, ch := range r {
		if ch == x {
			return true
		}
	}
	return false
}

func opMap(f func(rune) rune) ruleOp {
	return func(r []rune) ([]rune, bool) {
		out := make([]rune, len(r))
		for i, ch := range r {
			out[i] = f(ch)
		}
		return out, true
	}
}
func opCapitalize(r []rune) ([]rune, bool) {
	out := make([]rune, len(r))
	for i, ch := range r {
		if i == 0 {
			out[i] = toUpperRune(ch)
		} else {
			out[i] = toLowerRune(ch)
		}
	}
	return out, true
}
func opInvCapitalize(r []rune) ([]rune, bool) {
	out := make([]rune, len(r))
	for i, ch := range r {
		if i == 0 {
			out[i] = toLowerRune(ch)
		} else {
			out[i] = toUpperRune(ch)
		}
	}
	return out, true
}
func opReverse(r []rune) ([]rune, bool) {
	out := make([]rune, len(r))
	for i, ch := range r {
		out[len(r)-1-i] = ch
	}
	return out, true
}
func opReflect(r []rune) ([]rune, bool) {
	out := append([]rune{}, r...)
	for i := len(r) - 1; i >= 0; i-- {
		out = append(out, r[i])
	}
	return out, true
}
func opDupEach(r []rune) ([]rune, bool) {
	out := make([]rune, 0, len(r)*2)
	for _, ch := range r {
		out = append(out, ch, ch)
	}
	return out, true
}
func opRotLeft(r []rune) ([]rune, bool) {
	if len(r) < 2 {
		return r, true
	}
	return append(append([]rune{}, r[1:]...), r[0]), true
}
func opRotRight(r []rune) ([]rune, bool) {
	if len(r) < 2 {
		return r, true
	}
	return append([]rune{r[len(r)-1]}, r[:len(r)-1]...), true
}
func opSwapFront(r []rune) ([]rune, bool) {
	if len(r) < 2 {
		return r, true
	}
	out := append([]rune{}, r...)
	out[0], out[1] = out[1], out[0]
	return out, true
}
func opSwapBack(r []rune) ([]rune, bool) {
	if len(r) < 2 {
		return r, true
	}
	out := append([]rune{}, r...)
	out[len(r)-1], out[len(r)-2] = out[len(r)-2], out[len(r)-1]
	return out, true
}

// ── engine ────────────────────────────────────────────────────────────────────

// ruleEngine expands a base word into mangled candidates. It is either the
// built-in curated rule set (builtin) or a compiled list of file rules.
type ruleEngine struct {
	programs []ruleProgram
	builtin  bool
}

func builtinRuleEngine() *ruleEngine { return &ruleEngine{builtin: true} }

func (e *ruleEngine) count() int {
	if e == nil {
		return 0
	}
	if e.builtin {
		return NumManglingRules
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

// loadRuleFile compiles a rule file, skipping blank lines and '#' comments.
// Invalid rules are counted and skipped; an error is returned only when no
// valid rule remains.
func loadRuleFile(path string) (*ruleEngine, int, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, 0, err
	}
	defer f.Close()
	e := &ruleEngine{}
	bad := 0
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 1<<20), 1<<20)
	for sc.Scan() {
		line := strings.TrimRight(sc.Text(), "\r\n")
		if strings.TrimSpace(line) == "" || strings.HasPrefix(strings.TrimSpace(line), "#") {
			continue
		}
		p, err := compileRuleLine(line)
		if err != nil {
			bad++
			continue
		}
		e.programs = append(e.programs, p)
	}
	if err := sc.Err(); err != nil {
		return nil, bad, err
	}
	if len(e.programs) == 0 {
		return nil, bad, fmt.Errorf("no valid rules in %s", path)
	}
	return e, bad, nil
}
