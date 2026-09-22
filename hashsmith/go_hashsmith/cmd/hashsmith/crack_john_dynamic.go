package main

// John's dynamic formats: one engine, a few hundred schemes.
//
// Most password schemes in the wild are a short expression over a digest, a
// password and a salt — md5($s.$p), sha1(md5($p).$s), and so on endlessly.
// John does not write a format for each; it writes one evaluator and a table
// of expressions, and a record names its expression by number:
//
//	$dynamic_9$de2874e33da25313d808d2a8cbf31485$113-
//
// which is dynamic_9 — md5($s.md5($p)) — over the salt "113-". The table of
// expressions is john_dynamic_spec.go, transcribed from John itself. This file
// is the evaluator: a parser for the expression language, the mapping from its
// hash names to Hashsmith's implementations, and the record reader.
//
// The expression language, complete:
//
//	expression   concatenation of terms joined by "."
//	term         a call, a variable, or a literal
//	call         name(expression), where a name ending in _raw yields the
//	             digest's bytes and one ending in _64 its base64; a bare name
//	             yields lowercase hex, which is why md5(md5($p)) hashes the
//	             thirty-two characters of a hex digest and not sixteen bytes
//	variable     $p or $pass, $s or $salt, $s2, $u or $username
//	literal      anything else: "Y", "#", ":mongo:", 0xF7 for one byte, and
//	             \n \r \t for the obvious bytes
//
// alongside a handful of calls that are not digests at all — utf16, utf16le,
// utf16be, uc, lc, pad16, pad20, space_pad_10 — and one suffix, written
// "$p null_padded_to_len_100", that pads a term with NULs.
//
// A record whose expression names a digest Hashsmith does not implement, or
// whose stored field is not the hex the expression produces (Cisco's PIX and
// ASA records are dynamic_19 and dynamic_20, but store base64), is left for
// something else to claim rather than claimed and failed.

import (
	"bytes"
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha3"
	"crypto/sha512"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"hash"
	"strconv"
	"strings"
	"sync"

	"github.com/aead/skein"
	"golang.org/x/crypto/md4"
	xsha3 "golang.org/x/crypto/sha3"
)

const (
	johnDynamicPrefix = "$dynamic_"
	// John's spelling for an expression given on the spot rather than chosen
	// from its table.
	johnDynamicInlinePrefix = "@dynamic="
)

// johnDynamicMaxField bounds every field read out of a record, so a malformed
// line cannot ask for an unbounded allocation.
const johnDynamicMaxField = 1 << 16

type dynKind uint8

const (
	dynLiteral dynKind = iota
	dynVariable
	dynCall
)

// dynTerm is one node of a parsed expression. A call's operands are the terms
// its argument concatenates.
type dynTerm struct {
	kind dynKind
	lit  []byte    // dynLiteral
	v    byte      // dynVariable: 'p', 's', '2' or 'u'
	fn   string    // dynCall, with any encoding suffix already removed
	enc  byte      // dynCall: 'h' hex, 'r' raw, 'b' base64
	args []dynTerm // dynCall
	pad  int       // NUL-pad this term's value to this length, if non-zero
}

// dynEnv holds what a record supplies to the expression.
type dynEnv struct {
	pw, salt, salt2, user []byte
}

// ── the expression language ───────────────────────────────────────────────────

// dynNullPadSuffix is how John writes a padded operand inside an expression.
const dynNullPadSuffix = " null_padded_to_len_"

// parseDynExpr reads a concatenation. "." separates terms, but John does not
// always write it: md5(md5($s.$p):$s) runs a literal colon straight into the
// next variable, so the reading is a scan rather than a split.
func parseDynExpr(s string) ([]dynTerm, error) {
	var out []dynTerm
	for i := 0; i < len(s); {
		if s[i] == '.' {
			i++
			continue
		}
		var t dynTerm
		switch {
		case s[i] == '$':
			v, n := dynVariableAt(s[i:])
			if n == 0 {
				// $const and friends are defined in John's configuration file
				// rather than in the expression, so the expression alone does
				// not say what the record means.
				return nil, errors.New("dynamic expressions using " + dynTokenAt(s[i:]) +
					" are defined outside the format")
			}
			t.kind, t.v = dynVariable, v
			i += n
		default:
			if n := dynCallLen(s, i); n > 0 {
				call, err := parseDynCall(s[i : i+n])
				if err != nil {
					return nil, err
				}
				t = call
				i += n
				break
			}
			start := i
			for i < len(s) && s[i] != '.' && s[i] != '$' && dynCallLen(s, i) == 0 {
				i++
			}
			if i == start {
				return nil, errors.New("unreadable dynamic expression")
			}
			t.kind, t.lit = dynLiteral, dynLiteralBytes(s[start:i])
		}
		// A term may be padded, which John writes as a suffix on the operand:
		// md5($p null_padded_to_len_100).
		if strings.HasPrefix(s[i:], dynNullPadSuffix) {
			j := i + len(dynNullPadSuffix)
			k := j
			for k < len(s) && s[k] >= '0' && s[k] <= '9' {
				k++
			}
			n, err := strconv.Atoi(s[j:k])
			if err != nil || n <= 0 || n > johnDynamicMaxField {
				return nil, errors.New("invalid padding length in a dynamic expression")
			}
			t.pad = n
			i = k
		}
		out = append(out, t)
	}
	if len(out) == 0 {
		return nil, errors.New("empty dynamic expression")
	}
	return out, nil
}

// dynVariables, longest name first so that $s2 is not read as $s.
var dynVariables = []struct {
	name string
	v    byte
}{
	{"$username", 'u'}, {"$pass", 'p'}, {"$salt", 's'},
	{"$s2", '2'}, {"$p", 'p'}, {"$s", 's'}, {"$u", 'u'},
}

func dynVariableAt(s string) (byte, int) {
	for _, v := range dynVariables {
		if strings.HasPrefix(s, v.name) {
			return v.v, len(v.name)
		}
	}
	return 0, 0
}

// dynTokenAt names the unreadable token in an error message.
func dynTokenAt(s string) string {
	for i := 1; i < len(s); i++ {
		if s[i] == '.' || s[i] == '$' || s[i] == '(' || s[i] == ')' {
			return s[:i]
		}
	}
	return s
}

// dynCallLen returns the length of the call starting at i, or zero if what
// starts there is not one: an identifier followed by balanced parentheses.
func dynCallLen(s string, i int) int {
	j := i
	for j < len(s) && (s[j] == '_' || (s[j] >= 'a' && s[j] <= 'z') ||
		(s[j] >= 'A' && s[j] <= 'Z') || (s[j] >= '0' && s[j] <= '9')) {
		j++
	}
	if j == i || j >= len(s) || s[j] != '(' {
		return 0
	}
	depth := 0
	for k := j; k < len(s); k++ {
		switch s[k] {
		case '(':
			depth++
		case ')':
			depth--
			if depth == 0 {
				return k + 1 - i
			}
		}
	}
	return 0
}

// parseDynCall reads "name(expression)", taking the encoding from the name:
// a _raw suffix yields the digest's bytes and _64 its base64, while a bare
// name yields lowercase hex.
func parseDynCall(s string) (dynTerm, error) {
	var t dynTerm
	open := strings.IndexByte(s, '(')
	name, inner := s[:open], s[open+1:len(s)-1]
	args, err := parseDynExpr(inner)
	if err != nil {
		return t, err
	}
	t.kind, t.args = dynCall, args
	t.fn, t.enc = name, 'h'
	switch {
	case strings.HasSuffix(name, "_raw"):
		t.fn, t.enc = name[:len(name)-len("_raw")], 'r'
	case strings.HasSuffix(name, "_64"):
		t.fn, t.enc = name[:len(name)-len("_64")], 'b'
	}
	if _, ok := dynDigest(t.fn); !ok {
		if _, ok := dynModifier(t.fn); !ok {
			return t, errors.New("dynamic expressions using " + name + " are not supported")
		}
	}
	return t, nil
}

// dynLiteralBytes reads a literal: a hex byte written 0xNN, or plain text in
// which \n, \r and \t stand for the obvious bytes.
func dynLiteralBytes(s string) []byte {
	if len(s) == 4 && (strings.HasPrefix(s, "0x") || strings.HasPrefix(s, "0X")) {
		if b, err := hex.DecodeString(s[2:]); err == nil {
			return b
		}
	}
	out := make([]byte, 0, len(s))
	for i := 0; i < len(s); i++ {
		if s[i] == '\\' && i+1 < len(s) {
			switch s[i+1] {
			case 'n':
				out, i = append(out, '\n'), i+1
				continue
			case 'r':
				out, i = append(out, '\r'), i+1
				continue
			case 't':
				out, i = append(out, '\t'), i+1
				continue
			}
		}
		out = append(out, s[i])
	}
	return out
}

// dynDigest maps John's names for hashes onto Hashsmith's implementations.
// Names John knows and Hashsmith does not — tiger, panama, the haval family,
// the skein family — are simply absent, which is what makes a record naming
// one unreadable rather than wrong.
func dynDigest(name string) (func([]byte) []byte, bool) {
	simple := func(f func([]byte) []byte) (func([]byte) []byte, bool) { return f, true }
	switch name {
	case "md5":
		return simple(func(b []byte) []byte { s := md5.Sum(b); return s[:] })
	case "md4":
		return simple(func(b []byte) []byte { h := md4.New(); _, _ = h.Write(b); return h.Sum(nil) })
	case "md2":
		return simple(func(b []byte) []byte { d, _ := hex.DecodeString(md2Hex(b)); return d })
	case "sha1":
		return simple(func(b []byte) []byte { s := sha1.Sum(b); return s[:] })
	case "sha224":
		return simple(func(b []byte) []byte { s := sha256.Sum224(b); return s[:] })
	case "sha256":
		return simple(func(b []byte) []byte { s := sha256.Sum256(b); return s[:] })
	case "sha384":
		return simple(func(b []byte) []byte { s := sha512.Sum384(b); return s[:] })
	case "sha512":
		return simple(func(b []byte) []byte { s := sha512.Sum512(b); return s[:] })
	case "sha3_224":
		return simple(func(b []byte) []byte { s := sha3.Sum224(b); return s[:] })
	case "sha3_256":
		return simple(func(b []byte) []byte { s := sha3.Sum256(b); return s[:] })
	case "sha3_384":
		return simple(func(b []byte) []byte { s := sha3.Sum384(b); return s[:] })
	case "sha3_512":
		return simple(func(b []byte) []byte { s := sha3.Sum512(b); return s[:] })
	case "keccak_256":
		return simple(func(b []byte) []byte {
			h := xsha3.NewLegacyKeccak256()
			_, _ = h.Write(b)
			return h.Sum(nil)
		})
	case "keccak_512":
		return simple(func(b []byte) []byte {
			h := xsha3.NewLegacyKeccak512()
			_, _ = h.Write(b)
			return h.Sum(nil)
		})
	case "haval128_3", "haval128_4", "haval128_5",
		"haval160_3", "haval160_4", "haval160_5",
		"haval192_3", "haval192_4", "haval192_5",
		"haval224_3", "haval224_4", "haval224_5",
		"haval256_3", "haval256_4", "haval256_5":
		// Every combination of five output sizes and three pass counts is a
		// format of its own in John's table, and the name says which.
		size, passes, ok := havalParams(name)
		if !ok {
			return nil, false
		}
		return simple(func(b []byte) []byte { return havalSum(b, size, passes) })
	case "skein224", "skein256", "skein384", "skein512":
		// John's skein224 and friends are Skein-512 with a shorter output,
		// which is the usual reading of "Skein-N" and the one its own test
		// vectors use.
		size := map[string]int{"skein224": 28, "skein256": 32, "skein384": 48, "skein512": 64}[name]
		return simple(func(b []byte) []byte {
			h := skein.New(size, nil)
			_, _ = h.Write(b)
			return h.Sum(nil)
		})
	case "ripemd128", "ripemd160", "ripemd256", "ripemd320", "whirlpool", "gost", "tiger", "panama":
		ctor := map[string]func() hash.Hash{
			"ripemd128": func() hash.Hash { return newRIPEMD128() },
			"ripemd160": func() hash.Hash { return newRIPEMD160() },
			"ripemd256": func() hash.Hash { return newRIPEMD256() },
			"ripemd320": func() hash.Hash { return newRIPEMD320() },
			"whirlpool": func() hash.Hash { return newWhirlpool() },
			"gost":      func() hash.Hash { return newGOST94() },
			"tiger":     newTiger,
			"panama":    newPanama,
		}[name]
		return simple(func(b []byte) []byte {
			h := ctor()
			_, _ = h.Write(b)
			return h.Sum(nil)
		})
	}
	return nil, false
}

// dynModifier covers the calls that reshape bytes rather than hash them.
func dynModifier(name string) (func([]byte) []byte, bool) {
	switch name {
	case "utf16", "utf16le":
		return func(b []byte) []byte { return utf16le(string(b)) }, true
	case "utf16be":
		return func(b []byte) []byte { return utf16be(string(b)) }, true
	case "uc":
		return func(b []byte) []byte { return []byte(strings.ToUpper(string(b))) }, true
	case "lc":
		return func(b []byte) []byte { return []byte(strings.ToLower(string(b))) }, true
	case "pad16":
		return func(b []byte) []byte { return dynPad(b, 16, 0) }, true
	case "pad20":
		return func(b []byte) []byte { return dynPad(b, 20, 0) }, true
	case "space_pad_10":
		return func(b []byte) []byte { return dynPad(b, 10, ' ') }, true
	}
	return nil, false
}

// dynPad extends b to n bytes with fill. A value already that long is left
// alone rather than truncated, which is what John's padding does.
func dynPad(b []byte, n int, fill byte) []byte {
	if len(b) >= n {
		return b
	}
	out := make([]byte, n)
	copy(out, b)
	for i := len(b); i < n; i++ {
		out[i] = fill
	}
	return out
}

func evalDynExpr(terms []dynTerm, env *dynEnv) ([]byte, error) {
	var out []byte
	for i := range terms {
		b, err := evalDynTerm(&terms[i], env)
		if err != nil {
			return nil, err
		}
		out = append(out, b...)
	}
	return out, nil
}

func evalDynTerm(t *dynTerm, env *dynEnv) ([]byte, error) {
	var v []byte
	switch t.kind {
	case dynLiteral:
		v = t.lit
	case dynVariable:
		switch t.v {
		case 'p':
			v = env.pw
		case 's':
			v = env.salt
		case '2':
			v = env.salt2
		case 'u':
			v = env.user
		}
	case dynCall:
		inner, err := evalDynExpr(t.args, env)
		if err != nil {
			return nil, err
		}
		if mod, ok := dynModifier(t.fn); ok {
			v = mod(inner)
			break
		}
		digest, ok := dynDigest(t.fn)
		if !ok {
			return nil, errors.New("dynamic expressions using " + t.fn + " are not supported")
		}
		raw := digest(inner)
		switch t.enc {
		case 'r':
			v = raw
		case 'b':
			v = []byte(base64.StdEncoding.EncodeToString(raw))
		default:
			v = []byte(hex.EncodeToString(raw))
		}
	}
	if t.pad > 0 {
		v = dynPad(v, t.pad, 0)
	}
	return v, nil
}

// ── compiled expressions ──────────────────────────────────────────────────────

// dynCompiled caches one parsed expression. Parsing is cheap, but a crack runs
// the same expression once per candidate, so it is parsed once per number.
type dynCompiled struct {
	terms []dynTerm
	enc   byte   // the outermost call's encoding, which the stored field is in
	outer string // the outermost call's digest
	err   error
}

var dynCompiledCache sync.Map // expression string -> *dynCompiled

// compileDynamicExpr parses one expression, once. A crack runs the same
// expression for every candidate, so the parse is cached by its text — which
// also means a record carrying its own expression costs no more than a
// numbered one.
func compileDynamicExpr(spec string) *dynCompiled {
	if c, ok := dynCompiledCache.Load(spec); ok {
		return c.(*dynCompiled)
	}
	c := &dynCompiled{enc: 'h'}
	if terms, err := parseDynExpr(spec); err != nil {
		c.err = err
	} else if len(terms) != 1 || terms[0].kind != dynCall {
		c.err = errors.New("a dynamic expression must be one digest over its operands, not " + spec)
	} else {
		c.terms, c.enc, c.outer = terms, terms[0].enc, terms[0].fn
	}
	dynCompiledCache.Store(spec, c)
	return c
}

func compileDynamic(number int) *dynCompiled {
	spec, ok := johnDynamicSpecs[number]
	if !ok {
		return &dynCompiled{enc: 'h',
			err: errors.New("dynamic_" + strconv.Itoa(number) + " is not a format John defines")}
	}
	return compileDynamicExpr(spec)
}

// ── records ───────────────────────────────────────────────────────────────────

// dynRecord is one parsed $dynamic_N$ line.
type dynRecord struct {
	number int    // the format number, or -1 when the record carries its own
	expr   string // the expression itself, for a record that names one
	digest string
	env    dynEnv
}

// compiled returns the expression this record asks for.
func (r *dynRecord) compiled() *dynCompiled {
	if r.number < 0 {
		return compileDynamicExpr(r.expr)
	}
	return compileDynamic(r.number)
}

// parseJohnDynamic reads a record. Beyond the number and the stored digest, a
// record may carry a salt, and after it the two markers John appends for the
// values a salt cannot hold: "$$U" for a username and "$$2" for a second salt.
// Any of the three may be written "HEX$<hex>" when it holds bytes that would
// not survive a text line.
//
// John also accepts the whole thing behind a login, "postgres:$dynamic_1015$…",
// and that login is the username the expression means by $u.
func parseJohnDynamic(target string) (*dynRecord, error) {
	s := strings.TrimSpace(target)
	var login string
	for _, prefix := range []string{":" + johnDynamicPrefix, ":" + johnDynamicInlinePrefix} {
		if i := strings.Index(s, prefix); i >= 0 {
			login, s = s[:i], s[i+1:]
			break
		}
	}
	// A record may name its expression instead of a number, which is how
	// John lets one be given on the spot rather than chosen from its table:
	// "@dynamic=md5($p)@<digest>". The expression is read by the same parser
	// and compiled by the same cache, so nothing else changes.
	var number int
	var expr, rest string
	switch {
	case strings.HasPrefix(s, johnDynamicInlinePrefix):
		body := s[len(johnDynamicInlinePrefix):]
		end := strings.IndexByte(body, '@')
		if end <= 0 {
			return nil, errors.New("an inline dynamic expression must be closed with '@'")
		}
		number, expr, rest = -1, body[:end], body[end+1:]
	case strings.HasPrefix(s, johnDynamicPrefix):
		body := s[len(johnDynamicPrefix):]
		end := strings.IndexByte(body, '$')
		if end <= 0 {
			return nil, errors.New("a John dynamic record must name a format number")
		}
		n, err := strconv.Atoi(body[:end])
		if err != nil || n < 0 {
			return nil, errors.New("invalid John dynamic format number")
		}
		number, rest = n, body[end+1:]
	default:
		return nil, errors.New("not a John dynamic record")
	}
	if len(rest) > johnDynamicMaxField {
		return nil, errors.New("John dynamic record is too long")
	}

	rec := &dynRecord{number: number, expr: expr}
	rec.env.user = []byte(login)

	tail := ""
	if i := strings.IndexByte(rest, '$'); i >= 0 {
		rec.digest, tail = rest[:i], rest[i:]
	} else {
		rec.digest = rest
	}
	if rec.digest == "" {
		return nil, errors.New("a John dynamic record must carry a digest")
	}

	// What follows the digest is the salt and then John's markers. The markers
	// are looked for twice: once in the record as written, and again inside
	// the salt once it is decoded, because a record that hex-encodes its salt
	// encodes the markers along with it — PostgreSQL's dynamic_1015 stores
	// four random bytes followed by $$Upostgres, all as hex.
	if tail != "" {
		cut := dynReadMarkers([]byte(tail), &rec.env)
		var salt []byte
		if cut >= 1 {
			salt = dynFieldBytes(tail[1:cut])
		}
		rec.env.salt = salt[:dynReadMarkers(salt, &rec.env)]
	}
	return rec, nil
}

// dynReadMarkers assigns the values John appends after the salt and returns
// where they begin, which is where the salt ends.
func dynReadMarkers(b []byte, env *dynEnv) int {
	cut := len(b)
	for _, m := range dynMarkers {
		if i := bytes.Index(b, []byte(m)); i >= 0 && i < cut {
			cut = i
		}
	}
	for rest := b[cut:]; len(rest) >= len(dynMarkers[0]); {
		marker, body := string(rest[:3]), rest[3:]
		next := len(body)
		for _, m := range dynMarkers {
			if i := bytes.Index(body, []byte(m)); i >= 0 && i < next {
				next = i
			}
		}
		switch marker {
		case "$$U":
			env.user = dynFieldBytes(string(body[:next]))
		case "$$2":
			env.salt2 = dynFieldBytes(string(body[:next]))
		}
		rest = body[next:]
	}
	return cut
}

// dynMarkers are what John appends for the values a salt field cannot hold.
var dynMarkers = []string{"$$U", "$$2"}

// dynFieldBytes decodes John's "HEX$<hex>" spelling of a field that holds
// bytes rather than text; anything else is the text itself.
func dynFieldBytes(f string) []byte {
	if strings.HasPrefix(f, "HEX$") {
		if b, err := hex.DecodeString(f[len("HEX$"):]); err == nil {
			return b
		}
	}
	return []byte(f)
}

// ── the type ──────────────────────────────────────────────────────────────────

// isJohnDynamic reports whether a record is one this engine can answer for: a
// format number John defines, an expression built only from hashes Hashsmith
// implements, and a stored field in the encoding that expression produces.
// Everything else is left for another type to claim.
func isJohnDynamic(target string) bool {
	rec, err := parseJohnDynamic(target)
	if err != nil {
		return false
	}
	c := rec.compiled()
	if c.err != nil {
		return false
	}
	if c.enc == 'b' {
		_, err := base64.StdEncoding.DecodeString(rec.digest)
		return err == nil
	}
	return len(rec.digest) >= 16 && len(rec.digest)%2 == 0 && isHex(rec.digest)
}

// verifyJohnDynamic evaluates the record's expression over the candidate.
func verifyJohnDynamic(target, candidate string) (bool, error) {
	rec, err := parseJohnDynamic(target)
	if err != nil {
		return false, err
	}
	c := rec.compiled()
	if c.err != nil {
		return false, c.err
	}
	rec.env.pw = []byte(candidate)
	got, err := evalDynExpr(c.terms, &rec.env)
	if err != nil {
		return false, err
	}
	if c.enc == 'b' {
		return strings.TrimRight(rec.digest, "=") == strings.TrimRight(string(got), "="), nil
	}
	// The LinkedIn dump of 2012 is SHA-1 with the first five hex digits
	// overwritten with zeros, which is how those six million records are still
	// distributed. John reads them as dynamic_26 like any other SHA-1, and so
	// does this: twenty fewer bits still leaves a hundred and forty.
	if c.outer == "sha1" && len(rec.digest) == 2*sha1.Size && strings.HasPrefix(rec.digest, "00000") {
		return strings.EqualFold(rec.digest[5:], string(got)[5:]), nil
	}
	return dynHexMatches(rec.digest, string(got)), nil
}

// dynHexMatches compares a stored hex field against a full hex digest.
//
// The two are not always the same length. A format may store a truncated
// digest — dynamic_1029 is sha256($p) cut to sixteen bytes — and one may store
// a short digest in a longer field, as Skype's dynamic_1401 does by trailing
// an MD5 with zeros. Both are read as what they are: the stored field's own
// length decides how much of the digest it claims, and any excess must be the
// padding it looks like.
func dynHexMatches(stored, got string) bool {
	if len(stored) > len(got) {
		if strings.Trim(stored[len(got):], "0") != "" {
			return false
		}
		stored = stored[:len(got)]
	}
	if len(stored) < 16 || len(stored)%2 != 0 {
		return false
	}
	return strings.EqualFold(stored, got[:len(stored)])
}
