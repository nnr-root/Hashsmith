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

// errRuleLengthIsRuntime is not a failure. posArg returns it when a John
// length argument resolves from the original word (`l`, `m`) rather than from
// a constant: the command has been recorded in lengthRefAt and the caller only
// has to leave a placeholder op so the indices line up.
var errRuleLengthIsRuntime = errors.New("rule length resolves at run time")

// errRuleRejectedByHashcatToo marks a rule line that hashcat's own compiler
// also refuses. hashcat ships rule files containing such lines — bare "z"/"Z"
// with no position operand, and the InsidePro-era "SXY" — and answers them
// with "No valid rules left.", so skipping them costs no candidate relative to
// hashcat. They are therefore reported and skipped rather than aborting a run,
// while anything else unparsable (a real typo, which hashcat would have
// compiled) remains fatal. Without this split, strict mode would refuse whole
// stock rulesets that hashcat handles.
var errRuleRejectedByHashcatToo = errors.New("rule form hashcat also rejects")

// errRuleNotApplicable marks a rule that is well-formed but does not apply to
// the run at hand, so it is skipped without being counted against the file.
// John's -p flag is the case: it asks for word-pair commands, which exist only
// in single-crack mode, and john itself silently produces nothing for such a
// rule during a wordlist run.
var errRuleNotApplicable = errors.New("rule does not apply to this attack mode")

type ruleOp func([]byte) ([]byte, bool)

type ruleProgram struct {
	src string
	ops []ruleOp
	// lengthRefAt marks the ops whose length argument is not a constant but
	// the ORIGINAL word's length: John writes that as `l`, and `m` for one
	// less. `l d 'l` therefore duplicates the word and truncates it back to
	// what it was. Like memoryAt these cannot be ordinary closures, because
	// the value is only known once a word is being processed.
	lengthRefAt map[int]lengthRef
	// memoryAt marks the ops that are M (memorise) or Q (reject unless
	// changed). They cannot be ordinary closures: a program is compiled once
	// and then run concurrently by every worker, so a captured memory
	// variable would be shared across goroutines and race. The state belongs
	// to one execution, so apply owns it and handles these indices itself.
	memoryAt map[int]byte
	// extractAt marks the XNMI ops: take a substring of the MEMORISED word
	// and insert it into the current one. Like memoryAt these read state that
	// belongs to a single execution, so apply owns them rather than a
	// closure.
	extractAt map[int]xExtract
	// runtimeAt marks the ops whose operands are not constants but John's
	// numeric variables, its `p` (the position matched by the last / or %),
	// or the current length. Only a rule that actually uses one pays for
	// this: every constant-operand command stays an ordinary closure.
	runtimeAt map[int]runtimeOp
	// findsAt marks the / and % ops, which record into `p` the position they
	// matched, so a later command can act on it.
	findsAt map[int]findOp
}

// numSrc is where one numeric operand comes from.
type numSrc struct {
	kind byte // 'c' constant, 'v' variable, 'p' last-found position, 'l' length, 'm' length-1
	val  int  // the constant, or the variable index for 'v'
}

// runtimeOp is a command whose operands are only known while a word is being
// processed. The command letter selects what apply does with them.
type runtimeOp struct {
	cmd    byte   // 'v', 'T', 'D', 'o'
	target int    // for 'v': the variable being assigned
	a, b   numSrc // operands
	lit    byte   // for 'o': the replacement character
}

// findOp is a / or % command, which both rejects and records a position.
type findOp struct {
	match func(byte) bool // nil when matching a literal byte
	lit   byte
	count int // %N wants the Nth match; / wants the first
}

// johnNumVars is the number of John's user-defined numeric variables, a
// through k.
const johnNumVars = 11

// xExtract is one XNMI command: take up to length characters of the memorised
// word starting at start, and insert them into the current word at insert.
type xExtract struct {
	start  int
	length int
	insert int
}

// xMemLast is the start value for John's `m`, the last character position of
// the memorised word. It cannot be a constant because the memorised word's
// length is only known while a word is being processed.
const xMemLast = -1

// xToEnd stands for John's `z`, "infinite" position or length. Any value past
// the word's length behaves the same way, so one large sentinel covers it.
const xToEnd = 1 << 20

// xFoundPos is the start value for John's `p`, the position matched by the
// last / or % command.
const xFoundPos = -2

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
// lengthRef is a length argument resolved from the original word.
type lengthRef struct {
	cmd    byte // ' < > or _
	offset int  // 0 for `l`, -1 for `m`
}

func (p ruleProgram) apply(word string) (string, bool) {
	r := []byte(word)
	origLen := len(word)
	// Q with no preceding M compares against the original word, which is what
	// both John and Hashcat do.
	var memo []byte
	if len(p.memoryAt) > 0 || len(p.extractAt) > 0 {
		memo = []byte(word)
	}
	// John's numeric state. `p` starts at 0 and is set by / and %; the
	// variables start at 0 and are set by v.
	var vars [johnNumVars]int
	foundPos := 0
	resolve := func(src numSrc, cur []byte) int {
		switch src.kind {
		case 'v':
			return vars[src.val]
		case 'p':
			return foundPos
		case 'l':
			return len(cur)
		case 'm':
			return len(cur) - 1
		default:
			return src.val
		}
	}
	for idx, op := range p.ops {
		if ref, isLen := p.lengthRefAt[idx]; isLen {
			want := origLen + ref.offset
			if want < 0 {
				want = 0
			}
			switch ref.cmd {
			case '\'':
				if len(r) > want {
					r = r[:want]
				}
			case '<':
				if !(len(r) < want) {
					return "", false
				}
			case '>':
				if !(len(r) > want) {
					return "", false
				}
			case '_':
				if len(r) != want {
					return "", false
				}
			}
			continue
		}
		if f, isFind := p.findsAt[idx]; isFind {
			// / and % both reject AND record where they matched, which is
			// John's `p`. They are handled here rather than in a closure
			// because that recorded position belongs to one execution.
			seen, at := 0, -1
			for i, b := range r {
				hit := f.lit == b
				if f.match != nil {
					hit = f.match(b)
				}
				if hit {
					seen++
					if seen >= f.count {
						at = i
						break
					}
				}
			}
			if at < 0 {
				return "", false
			}
			foundPos = at
			continue
		}
		if op, isRuntime := p.runtimeAt[idx]; isRuntime {
			switch op.cmd {
			case 'v':
				// vVNM: update the length first — John documents that `l` is
				// refreshed by this command and is usable by it — then
				// assign N-M. Intermediate values may legitimately be
				// negative, so nothing is clamped here.
				vars[op.target] = resolve(op.a, r) - resolve(op.b, r)
			case 'T':
				at := resolve(op.a, r)
				if at >= 0 && at < len(r) {
					out := append([]byte{}, r...)
					out[at] = toggleByte(out[at])
					r = out
				}
			case 'D':
				at := resolve(op.a, r)
				if at >= 0 && at < len(r) {
					out := append([]byte{}, r[:at]...)
					r = append(out, r[at+1:]...)
				}
			case 'o':
				at := resolve(op.a, r)
				if at >= 0 && at < len(r) {
					out := append([]byte{}, r...)
					out[at] = op.lit
					r = out
				}
			}
			continue
		}
		if x, isExtract := p.extractAt[idx]; isExtract {
			start := x.start
			switch {
			case start == xMemLast:
				start = len(memo) - 1
				if start < 0 {
					start = 0
				}
			case start == xFoundPos:
				start = foundPos
			}
			if start < 0 {
				start = 0
			}
			if start > len(memo) {
				start = len(memo)
			}
			end := len(memo)
			if x.length < xToEnd && start+x.length < end {
				end = start + x.length
			}
			piece := memo[start:end]
			if len(piece) > 0 {
				at := x.insert
				if at > len(r) {
					at = len(r) // John appends rather than rejecting
				}
				out := make([]byte, 0, len(r)+len(piece))
				out = append(out, r[:at]...)
				out = append(out, piece...)
				out = append(out, r[at:]...)
				r = out
			}
			continue
		}
		if kind, isMem := p.memoryAt[idx]; isMem {
			if kind == 'M' {
				memo = append(memo[:0], r...)
			} else if bytesEqual(r, memo) {
				return "", false
			}
			continue
		}
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
// compileRuleLine compiles one rule in HASHCAT's dialect, which is the
// default and the one every existing caller means.
func compileRuleLine(line string) (ruleProgram, error) {
	return compileRuleLineDialect(line, false)
}

// compileRuleLineDialect compiles one rule. When john is true, John's
// additions are accepted: character classes, leading reject flags, its length
// characters, and its meaning for `p`. See rules_john_dialect.go for why the
// two are kept apart rather than merged.
func compileRuleLineDialect(line string, john bool) (ruleProgram, error) {
	var ops []ruleOp
	var memoryAt map[int]byte
	var lengthRefAt map[int]lengthRef
	var extractAt map[int]xExtract
	var runtimeAt map[int]runtimeOp
	var findsAt map[int]findOp
	if john {
		if johnRuleRequiresWordPairs(line) {
			return ruleProgram{}, fmt.Errorf("rule needs John's word-pair commands (-p), which "+
				"belong to single-crack mode: %w", errRuleNotApplicable)
		}
		line = stripJohnRejectFlags(line)
	}
	i, n := 0, len(line)

	// classArg reads a `?X` class argument when one is present, for the
	// commands that accept either a literal character or a class.
	classArg := func(cmd byte) (func(byte) bool, bool, error) {
		if i >= n || line[i] != '?' {
			return nil, false, nil
		}
		if !john {
			// In Hashcat's dialect '?' is just a character: `@?` purges a
			// literal '?', and its own d3ad0ne.rule contains exactly that.
			// Reporting a class here made a valid Hashcat rule unparseable.
			return nil, false, nil
		}
		if i+1 >= n {
			return nil, false, fmt.Errorf("command %q: '?' needs a class name", string(cmd))
		}
		name := line[i+1]
		match, ok := johnClassMatch(name)
		if !ok {
			return nil, false, fmt.Errorf("command %q: unknown character class %q", string(cmd), string(name))
		}
		i += 2
		return match, true, nil
	}

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
			// John writes a length as '*' (the maximum), '-' (one less) or
			// '+' (one more). Hashcat has no equivalent, so these are only
			// accepted in John's dialect.
			if john {
				if v, isLen := johnLengthValue(c); isLen {
					return v, nil
				}
				// `l` is the ORIGINAL word's length and `m` one less, so the
				// value is only known at run time. Measured against john
				// itself: `l d 'l` on "admin" returns "admin", not
				// "adminadmin". Only the length commands accept them.
				if off, isRef := johnLengthRefOffset(c); isRef {
					switch cmd {
					case '\'', '<', '>', '_':
						if lengthRefAt == nil {
							lengthRefAt = map[int]lengthRef{}
						}
						lengthRefAt[len(ops)] = lengthRef{cmd: cmd, offset: off}
						return 0, errRuleLengthIsRuntime
					}
				}
				// John clamps a position character it does not recognise to
				// the maximum length rather than rejecting the rule. Measured,
				// not assumed: `'l` applied to a 130-character word through
				// john itself returns 125 characters, John's maximum, where a
				// continued a=36..z=61 scheme would have returned 47.
				return johnMaxLength, nil
			}
			return 0, fmt.Errorf("command %q: bad position %q", string(cmd), string(c))
		}
		return p, nil
	}

	// runtimeOperandNext reports whether the operand about to be read needs
	// run-time state — a variable a-k, or John's `p`. It does not consume
	// anything, so a command can keep its fast constant-operand path and take
	// the slower one only when a rule actually uses a variable.
	//
	// `l` and `m` are deliberately NOT listed: posArg already resolves those
	// for the commands that accept them, and re-routing them here would
	// change behaviour that is measured and correct.
	runtimeOperandNext := func() bool {
		if !john || i >= n {
			return false
		}
		ch := line[i]
		return (ch >= 'a' && ch <= 'k') || ch == 'p'
	}

	// numArg reads one numeric operand in John's full vocabulary: a constant,
	// a variable a-k, `p` (the position matched by the last / or %), `l` (the
	// current length) or `m` (one less). It reports whether the operand needs
	// run-time state, so a command with only constant operands stays an
	// ordinary closure and pays nothing.
	numArg := func(cmd byte, what string) (numSrc, error) {
		ch, ok := arg()
		if !ok {
			return numSrc{}, fmt.Errorf("command %q is missing its %s", string(cmd), what)
		}
		if ch >= 'a' && ch <= 'k' {
			return numSrc{kind: 'v', val: int(ch - 'a')}, nil
		}
		switch ch {
		case 'p':
			return numSrc{kind: 'p'}, nil
		case 'l':
			return numSrc{kind: 'l'}, nil
		case 'm':
			return numSrc{kind: 'm'}, nil
		}
		if v, isPos := rulePos(ch); isPos {
			return numSrc{kind: 'c', val: v}, nil
		}
		if v, isLen := johnLengthValue(ch); isLen {
			return numSrc{kind: 'c', val: v}, nil
		}
		return numSrc{}, fmt.Errorf("command %q: %s %q is not a number, a variable a-k, or "+
			"one of John's p, l or m", string(cmd), what, string(ch))
	}

	// xArg reads one operand of the X command. It is deliberately stricter
	// than posArg: X refuses an operand it cannot resolve rather than
	// clamping it, because a clamped START silently extracts nothing.
	xArg := func(what string) (int, error) {
		ch, ok := arg()
		if !ok {
			return 0, fmt.Errorf("command 'X' is missing its %s", what)
		}
		if v, isPos := rulePos(ch); isPos {
			return v, nil
		}
		switch ch {
		case 'z':
			return xToEnd, nil
		case 'm':
			return xMemLast, nil
		case 'p':
			if what == "length" {
				return 0, errors.New("command 'X': a length cannot be 'p'")
			}
			return xFoundPos, nil
		}
		if v, isLen := johnLengthValue(ch); isLen {
			return v, nil
		}
		return 0, fmt.Errorf("command 'X': %s %q is not a number, 'z', 'm' or 'p'; the rule is "+
			"refused rather than read as a position past the end", what, string(ch))
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
			if match, isClass, err := classArg('@'); err != nil {
				return ruleProgram{}, err
			} else if isClass {
				ops = append(ops, func(r []byte) ([]byte, bool) {
					out := r[:0:0]
					for _, ch := range r {
						if !match(ch) {
							out = append(out, ch)
						}
					}
					return out, true
				})
				break
			}
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
			// sXY replaces every X with Y. John also spells s?CY, replacing
			// every character of CLASS C.
			//
			// The class form was not merely missing: without it `s?D*` read
			// '?' as the character to replace and 'D' as its replacement,
			// then met '*' as a command and failed. A rule whose next
			// character happened to be a valid command — `s?dl`, say — would
			// have compiled SILENTLY as "replace ? with d, then lowercase",
			// which is not what the rule says and produces a different
			// candidate stream with nothing to indicate it.
			//
			// It stays John-only for the reason @ and ( already are: in
			// hashcat's dialect '?' is an ordinary character, and its own
			// shipped rule files contain rules that mean it literally.
			if match, isClass, err := classArg('s'); err != nil {
				return ruleProgram{}, err
			} else if isClass {
				y, ok := arg()
				if !ok {
					return ruleProgram{}, errors.New("command 's?C' needs a replacement character")
				}
				yr := y
				ops = append(ops, func(r []byte) ([]byte, bool) {
					out := make([]byte, len(r))
					for i, ch := range r {
						if match(ch) {
							out[i] = yr
						} else {
							out[i] = ch
						}
					}
					return out, true
				})
				break
			}
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
			if runtimeOperandNext() {
				src, err := numArg('T', "position")
				if err != nil {
					return ruleProgram{}, err
				}
				if runtimeAt == nil {
					runtimeAt = map[int]runtimeOp{}
				}
				runtimeAt[len(ops)] = runtimeOp{cmd: 'T', a: src}
				ops = append(ops, func(r []byte) ([]byte, bool) { return r, true })
				break
			}
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
			if runtimeOperandNext() {
				src, err := numArg('D', "position")
				if err != nil {
					return ruleProgram{}, err
				}
				if runtimeAt == nil {
					runtimeAt = map[int]runtimeOp{}
				}
				runtimeAt[len(ops)] = runtimeOp{cmd: 'D', a: src}
				ops = append(ops, func(r []byte) ([]byte, bool) { return r, true })
				break
			}
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
		case '%':
			// %NX — reject unless the word contains at least N instances of
			// X. John only.
			//
			// hashcat DOCUMENTS %NX, (X and )X as rule operators, and an
			// earlier gap report counted them against Hashsmith on that
			// basis. Its v7.1.2 compiler rejects all three from a -r rule
			// file — "No valid rules left." — so implementing them in
			// hashcat's dialect would mean reading rules hashcat itself will
			// not. Checked against the binary rather than the documentation.
			//
			// Semantics verified against john: "%2s" keeps "password" and
			// drops "AdMiN"; the comparison is case-sensitive.
			if !john {
				return ruleProgram{}, fmt.Errorf("unknown rule command %q", string(c))
			}
			cnt, err := posArg(c)
			if err != nil {
				return ruleProgram{}, err
			}
			match, isClass, err := classArg('%')
			if err != nil {
				return ruleProgram{}, err
			}
			if isClass {
				// The Nth match is where `p` lands: john.conf's
				// `%4[ ] … vbpa Tb` capitalises the word after the FOURTH
				// space, which only works if % records that space's position
				// rather than the first one's.
				if findsAt == nil {
					findsAt = map[int]findOp{}
				}
				findsAt[len(ops)] = findOp{match: match, count: cnt}
				ops = append(ops, func(r []byte) ([]byte, bool) { return r, true })
				break
			}
			x, ok := arg()
			if !ok {
				return ruleProgram{}, errors.New("command '%' needs a character (%NX)")
			}
			xr := x
			if findsAt == nil {
				findsAt = map[int]findOp{}
			}
			findsAt[len(ops)] = findOp{lit: xr, count: cnt}
			ops = append(ops, func(r []byte) ([]byte, bool) { return r, true })
		case 'A':
			// AN"str" — insert a string at position N. John only; hashcat has
			// the single-character iNX instead. The character after the
			// position is the delimiter, so A2'-' works as well as A2"-".
			if !john {
				return ruleProgram{}, fmt.Errorf("unknown rule command %q", string(c))
			}
			at, err := posArg(c)
			if err != nil {
				return ruleProgram{}, err
			}
			delim, ok := arg()
			if !ok {
				return ruleProgram{}, errors.New(`command 'A' needs a delimited string (AN"str")`)
			}
			start := i
			for i < n && line[i] != delim {
				i++
			}
			if i >= n {
				return ruleProgram{}, fmt.Errorf("command 'A': unterminated string in %q", line)
			}
			ins := []byte(line[start:i])
			i++ // past the closing delimiter
			ops = append(ops, func(r []byte) ([]byte, bool) {
				if at > len(r) {
					return r, true // hashcat-style: skip rather than reject
				}
				out := make([]byte, 0, len(r)+len(ins))
				out = append(out, r[:at]...)
				out = append(out, ins...)
				return append(out, r[at:]...), true
			})
		case 'P':
			if !john {
				// Hashcat has no P; fall in with every other unknown command
				// so the file's error count means the same thing either way.
				return ruleProgram{}, fmt.Errorf("unknown rule command %q", string(c))
			}
			ops = append(ops, func(r []byte) ([]byte, bool) { return johnPastTense(r), true })
		case 'I':
			if !john {
				return ruleProgram{}, fmt.Errorf("unknown rule command %q", string(c))
			}
			ops = append(ops, func(r []byte) ([]byte, bool) { return johnProgressive(r), true })
		case 'p':
			// The dialects disagree: hashcat's pN duplicates the word N times,
			// John's bare p pluralises it. In John's dialect a following
			// position digit still means hashcat's form, because John has no
			// pN and the two cannot collide.
			if john && (i >= n || !isRulePosChar(line[i])) {
				ops = append(ops, func(r []byte) ([]byte, bool) { return johnPluralize(r), true })
				break
			}
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
				if errors.Is(err, errRuleLengthIsRuntime) {
					// Placeholder: apply resolves this against the original word.
					ops = append(ops, func(r []byte) ([]byte, bool) { return r, true })
					break
				}
				return ruleProgram{}, err
			}
			ops = append(ops, func(r []byte) ([]byte, bool) {
				if p < len(r) {
					return r[:p], true
				}
				return r, true
			})
		case 'o':
			if runtimeOperandNext() {
				src, err := numArg('o', "position")
				if err != nil {
					return ruleProgram{}, err
				}
				x, ok := arg()
				if !ok {
					return ruleProgram{}, errors.New("command 'o' needs a character (oNX)")
				}
				if runtimeAt == nil {
					runtimeAt = map[int]runtimeOp{}
				}
				runtimeAt[len(ops)] = runtimeOp{cmd: 'o', a: src, lit: x}
				ops = append(ops, func(r []byte) ([]byte, bool) { return r, true })
				break
			}
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
				if errors.Is(err, errRuleLengthIsRuntime) {
					// Placeholder: apply resolves this against the original word.
					ops = append(ops, func(r []byte) ([]byte, bool) { return r, true })
					break
				}
				return ruleProgram{}, err
			}
			ops = append(ops, func(r []byte) ([]byte, bool) { return r, len(r) < p })
		case '>':
			p, err := posArg(c)
			if err != nil {
				if errors.Is(err, errRuleLengthIsRuntime) {
					// Placeholder: apply resolves this against the original word.
					ops = append(ops, func(r []byte) ([]byte, bool) { return r, true })
					break
				}
				return ruleProgram{}, err
			}
			ops = append(ops, func(r []byte) ([]byte, bool) { return r, len(r) > p })
		case '_':
			p, err := posArg(c)
			if err != nil {
				if errors.Is(err, errRuleLengthIsRuntime) {
					// Placeholder: apply resolves this against the original word.
					ops = append(ops, func(r []byte) ([]byte, bool) { return r, true })
					break
				}
				return ruleProgram{}, err
			}
			ops = append(ops, func(r []byte) ([]byte, bool) { return r, len(r) == p })
		case 'M', 'Q':
			// Memorise / reject-unless-changed, John only.
			//
			// An earlier gap report listed these as "hashcat memory rules
			// Hashsmith is missing". They are not: hashcat v7.1.2 answers
			// "No valid rules left." for a file containing M, Q or both, so
			// accepting them in its dialect would have made Hashsmith read
			// rules hashcat refuses. Verified rather than assumed.
			//
			// They are marked by index rather than compiled into a closure —
			// see ruleProgram.memoryAt for why.
			if !john {
				return ruleProgram{}, fmt.Errorf("unknown rule command %q", string(c))
			}
			if memoryAt == nil {
				memoryAt = map[int]byte{}
			}
			memoryAt[len(ops)] = c
			ops = append(ops, func(r []byte) ([]byte, bool) { return r, true })
		case '(':
			// hashcat documents ( and ) but v7.1.2's compiler rejects them,
			// so they are John-dialect only here for the same reason M and Q
			// are: reading rules hashcat refuses would not be compatibility.
			if !john {
				return ruleProgram{}, fmt.Errorf("unknown rule command %q", string(c))
			}
			match, isClass, err := classArg('(')
			if err != nil {
				return ruleProgram{}, err
			}
			if isClass {
				ops = append(ops, func(r []byte) ([]byte, bool) {
					return r, len(r) > 0 && match(r[0])
				})
				break
			}
			x, ok := arg()
			if !ok {
				return ruleProgram{}, errors.New("command '(' needs a character")
			}
			xr := x
			ops = append(ops, func(r []byte) ([]byte, bool) { return r, len(r) > 0 && r[0] == xr })
		case ')':
			if !john {
				return ruleProgram{}, fmt.Errorf("unknown rule command %q", string(c))
			}
			match, isClass, err := classArg(')')
			if err != nil {
				return ruleProgram{}, err
			}
			if isClass {
				ops = append(ops, func(r []byte) ([]byte, bool) {
					return r, len(r) > 0 && match(r[len(r)-1])
				})
				break
			}
			x, ok := arg()
			if !ok {
				return ruleProgram{}, errors.New("command ')' needs a character")
			}
			xr := x
			ops = append(ops, func(r []byte) ([]byte, bool) {
				return r, len(r) > 0 && r[len(r)-1] == xr
			})
		case '!':
			match, isClass, err := classArg('!')
			if err != nil {
				return ruleProgram{}, err
			}
			if isClass {
				ops = append(ops, func(r []byte) ([]byte, bool) { return r, !containsClass(r, match) })
				break
			}
			x, ok := arg()
			if !ok {
				return ruleProgram{}, errors.New("command '!' needs a character (!X)")
			}
			xr := x
			ops = append(ops, func(r []byte) ([]byte, bool) { return r, !containsByte(r, xr) })
		case '/':
			// /X rejects unless the word contains X, and in John it ALSO
			// records where it matched — that position is John's `p`, which
			// `v` and the position commands read. In hashcat's dialect there
			// is no `p`, so the rejection stays an ordinary closure there and
			// only John's pays for the bookkeeping.
			match, isClass, err := classArg('/')
			if err != nil {
				return ruleProgram{}, err
			}
			if isClass {
				if john {
					if findsAt == nil {
						findsAt = map[int]findOp{}
					}
					findsAt[len(ops)] = findOp{match: match, count: 1}
					ops = append(ops, func(r []byte) ([]byte, bool) { return r, true })
					break
				}
				ops = append(ops, func(r []byte) ([]byte, bool) { return r, containsClass(r, match) })
				break
			}
			x, ok := arg()
			if !ok {
				return ruleProgram{}, errors.New("command '/' needs a character (/X)")
			}
			xr := x
			if john {
				if findsAt == nil {
					findsAt = map[int]findOp{}
				}
				findsAt[len(ops)] = findOp{lit: xr, count: 1}
				ops = append(ops, func(r []byte) ([]byte, bool) { return r, true })
				break
			}
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
		case 'L', 'R':
			// The two dialects disagree about this letter completely.
			//
			// hashcat's LN and RN take a position and shift THAT CHARACTER'S
			// BITS left or right. John's L and R take no operand at all and
			// move EVERY character one key left or right along the keyboard:
			// "Crack96" -> "Xeaxj85" and "Vtsvl07".
			//
			// Reading John's form as hashcat's is not a near miss. `l Q [RL]`
			// in john.conf became `l Q R` with `R` swallowing nothing, and the
			// rule failed to compile; where a command did follow, it would
			// have been eaten as a position and the rule would have run as
			// something the author never wrote.
			if john {
				right := c == 'R'
				ops = append(ops, func(r []byte) ([]byte, bool) {
					return johnKeyboardShift(r, right), true
				})
				break
			}
			pn, err := posArg(c)
			if err != nil {
				return ruleProgram{}, err
			}
			if c == 'L' {
				ops = append(ops, opAtPos(pn, func(b byte) byte { return b << 1 }))
			} else {
				ops = append(ops, opAtPos(pn, func(b byte) byte { return b >> 1 }))
			}
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
			// John's S shifts the whole word by keyboard: every character
			// becomes what its key produces with Shift held, so letters
			// case-toggle and digits become symbols. "Crack96" -> "cRACK(^".
			//
			// In hashcat's dialect the same letter is InsidePro's "SXY"
			// case-sensitive replace, which hashcat does not implement either,
			// so a file using it is still skipped to the same effect rather
			// than refused outright.
			if john {
				ops = append(ops, func(r []byte) ([]byte, bool) { return johnShiftCase(r), true })
				break
			}
			return ruleProgram{}, fmt.Errorf("command %q is not implemented: %w", string(c), errRuleRejectedByHashcatToo)
		case 'v':
			// vVNM — set variable V to N minus M, having first refreshed `l`
			// to the current length.
			//
			// The variables are a through k, and John documents that an
			// intermediate value may legitimately be negative, so nothing is
			// clamped at assignment; a command that later uses a negative
			// position simply finds it out of range, which is what John does.
			//
			// john.conf's own use is `va01 vbpa Tb`: set a to -1, set b to
			// p+1, toggle there — capitalise the character after the space
			// that `%N[ ]` just matched.
			if !john {
				return ruleProgram{}, fmt.Errorf("unknown rule command %q", string(c))
			}
			target, ok := arg()
			if !ok || target < 'a' || target > 'k' {
				return ruleProgram{}, errors.New("command 'v' needs a variable a-k (vVNM)")
			}
			aSrc, err := numArg('v', "first operand")
			if err != nil {
				return ruleProgram{}, err
			}
			bSrc, err := numArg('v', "second operand")
			if err != nil {
				return ruleProgram{}, err
			}
			if runtimeAt == nil {
				runtimeAt = map[int]runtimeOp{}
			}
			runtimeAt[len(ops)] = runtimeOp{cmd: 'v', target: int(target - 'a'), a: aSrc, b: bSrc}
			ops = append(ops, func(r []byte) ([]byte, bool) { return r, true })
		case 'X':
			// XNMI — take up to M characters of the MEMORISED word starting
			// at N, and insert them into the current word at position I.
			//
			// John's own examples, each verified here against john rather
			// than transcribed: X011 duplicates the first character, Xm1z the
			// last, dX0zz triplicates the word, and X0z0 — the form john.conf
			// actually uses, six times — prefixes the word with its
			// memorised self. The memory is the word as it was at the last M,
			// or the original word when there has been none, which is why
			// `dX0zz` gives three copies and not four.
			//
			// The operands do NOT go through posArg. posArg clamps a position
			// character it does not recognise to the maximum length, which is
			// right for a length and silently wrong for a start: `Xp…` would
			// become "start past the end", extract nothing, and leave the
			// word unchanged with no indication. X refuses what it cannot
			// resolve instead.
			if !john {
				return ruleProgram{}, fmt.Errorf("unknown rule command %q", string(c))
			}
			start, err := xArg("start")
			if err != nil {
				return ruleProgram{}, err
			}
			length, err := xArg("length")
			if err != nil {
				return ruleProgram{}, err
			}
			insert, err := xArg("insert position")
			if err != nil {
				return ruleProgram{}, err
			}
			if start == xMemLast && length == xMemLast {
				return ruleProgram{}, errors.New("command 'X': a length cannot be 'm'")
			}
			if extractAt == nil {
				extractAt = map[int]xExtract{}
			}
			extractAt[len(ops)] = xExtract{start: start, length: length, insert: insert}
			ops = append(ops, func(r []byte) ([]byte, bool) { return r, true })
		case 'V':
			// V — lowercase the vowels, uppercase the consonants.
			if !john {
				return ruleProgram{}, fmt.Errorf("unknown rule command %q", string(c))
			}
			ops = append(ops, func(r []byte) ([]byte, bool) { return johnVowelsConsonants(r), true })
		case 'W':
			// WN — SHIFT-toggle the character at position N, which is not the
			// same as case-toggling it. John documents W as a superset of T,
			// and the superset is the part that matters: T leaves a digit or a
			// symbol alone, while W gives what the same key produces with
			// Shift held. Measured against john, `W1` turns "P@ssw0rd!" into
			// "P2ssw0rd!", where a case-toggle returns the word unchanged.
			if !john {
				return ruleProgram{}, fmt.Errorf("unknown rule command %q", string(c))
			}
			pn, err := posArg(c)
			if err != nil {
				return ruleProgram{}, err
			}
			ops = append(ops, opAtPos(pn, func(b byte) byte { return keyboardShift[b] }))
		case '=':
			// =NX / =N?C — reject unless the character at position N is X, or
			// is in class C. The positional sibling of ( and ), which check
			// the first and last characters.
			if !john {
				return ruleProgram{}, fmt.Errorf("unknown rule command %q", string(c))
			}
			pn, err := posArg(c)
			if err != nil {
				return ruleProgram{}, err
			}
			match, isClass, err := classArg('=')
			if err != nil {
				return ruleProgram{}, err
			}
			if isClass {
				ops = append(ops, func(r []byte) ([]byte, bool) {
					return r, pn < len(r) && match(r[pn])
				})
				break
			}
			x, ok := arg()
			if !ok {
				return ruleProgram{}, errors.New("command '=' needs a character")
			}
			xr := x
			ops = append(ops, func(r []byte) ([]byte, bool) {
				return r, pn < len(r) && r[pn] == xr
			})
		case 'a', 'b':
			// aN / bN — reject unless the word would still fit the run's
			// length limits after N characters are added (a) or removed (b).
			//
			// These are john's early-rejection commands: they let a rule throw
			// a word away before the rest of it runs. See johnDefaultMinLength
			// for which limits they check against and why that is the right
			// answer rather than a placeholder.
			if !john {
				return ruleProgram{}, fmt.Errorf("unknown rule command %q", string(c))
			}
			pn, err := posArg(c)
			if err != nil {
				return ruleProgram{}, err
			}
			delta := pn
			if c == 'b' {
				delta = -pn
			}
			ops = append(ops, func(r []byte) ([]byte, bool) {
				got := len(r) + delta
				return r, got >= johnDefaultMinLength && got <= johnDefaultMaxLength
			})
		default:
			return ruleProgram{}, fmt.Errorf("unknown rule command %q", string(c))
		}
	}
	if len(ops) == 0 {
		return ruleProgram{}, errors.New("empty rule")
	}
	return ruleProgram{src: line, ops: ops, memoryAt: memoryAt, lengthRefAt: lengthRefAt,
		extractAt: extractAt, runtimeAt: runtimeAt, findsAt: findsAt}, nil
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

	var lines []string
	sc := bufio.NewScanner(src)
	sc.Buffer(make([]byte, 1<<20), 1<<20)
	for sc.Scan() {
		line := strings.TrimRight(sc.Text(), "\r\n")
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}
		lines = append(lines, line)
	}
	if err := sc.Err(); err != nil {
		return nil, 0, err
	}
	return compileRuleLines(lines)
}

// compileRuleLines compiles a whole ruleset, choosing its dialect first.
//
// The dialect is decided for the FILE, not per line: a file is one ruleset,
// and compiling half of it as Hashcat and half as John would produce
// candidates neither tool would.
//
// It is decided by COMPILING BOTH WAYS and keeping the better fit, rather than
// by looking for marker syntax. Marker syntax does not work, because the
// dialects genuinely overlap: hashcat's `-N` decrements the character at
// position N and its positions include 8, C and P, so `-8` is both a valid
// hashcat rule and a valid John reject flag; `@?d` is "purge '?', duplicate"
// in hashcat and "purge digits" in John. Two separate attempts at a marker
// heuristic each read a real hashcat file as John and silently dropped every
// candidate it produced — specific.rule on the first attempt, d3ad0ne.rule and
// dive.rule on the second.
//
// Compiling twice cannot make that mistake: a valid Hashcat file compiles
// cleanly as Hashcat, so it can never lose to the John attempt. Ties go to
// Hashcat, which is the dialect every existing caller means.
func compileRuleLines(lines []string) ([]ruleProgram, int, error) {
	hcPrograms, hcBad := compileRuleLinesAs(lines, false)

	// Only pay for the second attempt when the first one struggled. A file
	// that compiles cleanly as Hashcat is Hashcat.
	if hcBad == 0 {
		return hcPrograms, hcBad, nil
	}
	johnPrograms, johnBad := compileRuleLinesAs(lines, true)
	if johnBad < hcBad {
		return johnPrograms, johnBad, nil
	}
	return hcPrograms, hcBad, nil
}

// compileRuleLinesAs compiles every line in one dialect, expanding John's
// preprocessor when that is the dialect asked for.
func compileRuleLinesAs(lines []string, john bool) ([]ruleProgram, int) {
	var programs []ruleProgram
	bad := 0 // rules only Hashsmith fails to parse — a real gap

	for _, line := range lines {
		expanded := []string{line}
		if john {
			exp, err := expandJohnRuleLine(line)
			if err != nil {
				bad++
				continue
			}
			expanded = exp
		}
		lineBad := false
		for _, one := range expanded {
			if strings.TrimSpace(one) == "" {
				continue
			}
			p, err := compileRuleLineDialect(one, john)
			if err != nil {
				if !errors.Is(err, errRuleRejectedByHashcatToo) && !errors.Is(err, errRuleNotApplicable) {
					lineBad = true
				}
				continue
			}
			programs = append(programs, p)
		}
		// One bad LINE, however many rules it expanded to: the two dialects
		// expand differently, so counting expanded rules would compare
		// quantities that are not the same kind of thing.
		if lineBad {
			bad++
		}
	}
	return programs, bad
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
