package main

import (
	"bufio"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// ── Fuzzing ───────────────────────────────────────────────────────────────────
//
// There are 231 verify* functions across 70 files, and every one of them
// parses data an attacker supplied: a hash file is something handed to you.
// None had any fuzz coverage.
//
// The contract each target asserts is the same and is deliberately weak: NEVER
// PANIC. Returning an error for malformed input is correct and expected; a
// slice bounds violation, a nil dereference or an unbounded allocation is not.
// A weak contract is the right one here because it is the one that holds for
// every parser at once, which is what makes a single target cover all of them.
//
// Run them with, for example:
//
//	go test ./cmd/hashsmith -run '^$' -fuzz FuzzVerifyCandidate -fuzztime 60s

// fuzzFastFormats are parser-heavy formats whose KDF is cheap, so a fuzz run
// spends its time in the parsing code where the crashes live rather than in
// PBKDF2. A record with a large iteration count is legal for many of the slow
// formats and would reduce the corpus to a handful of executions per second.
var fuzzFastFormats = []string{
	"md5", "sha1", "ntlm", "descrypt", "mysql41", "mssql2000", "mssql2005",
	"postgres", "skype", "juniper", "oracle11g", "episerver", "mongodb",
	"netntlmv2", "ansible", "blockchain", "rar5", "keepass", "luks",
	"axcrypt-sha1", "werkzeug", "azuresync", "nsec3", "skip32", "vnc",
	"sip", "ike", "chap", "krb5tgs", "pfx", "office", "itunes-backup",
	"bitwarden", "aescrypt", "electrum", "ethereum", "bitcoin",
}

// fuzzSeedsFromCorpus returns real records from the hashcat conformance corpus.
// Seeding with valid records is what gets the fuzzer past the "is this even a
// record" gate and into the field parsing underneath.
func fuzzSeedsFromCorpus(tb testing.TB, limit int) []string {
	tb.Helper()
	f, err := os.Open(filepath.Join("testdata", "hashcat_example_hashes.tsv"))
	if err != nil {
		return nil
	}
	defer f.Close()
	var out []string
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 64<<10), 8<<20)
	for sc.Scan() && len(out) < limit {
		line := sc.Text()
		if strings.HasPrefix(line, "#") {
			continue
		}
		p := strings.Split(line, "\t")
		// Skip the enormous ones: a 513 KB VeraCrypt header as a seed makes
		// every mutation enormous too, and the parser it exercises is reached
		// just as well by a short record.
		if len(p) == 4 && len(p[3]) < 512 {
			out = append(out, p[3])
		}
	}
	return out
}

// A malformed hash must produce an error, never a panic.
func FuzzVerifyCandidate(f *testing.F) {
	for _, s := range fuzzSeedsFromCorpus(f, 300) {
		f.Add(s, "hashcat")
	}
	f.Add("", "")
	f.Add("$", "x")
	f.Add("$luks$1$", "pw")
	f.Add("$keepass$*2*", "pw")
	f.Add("v1;PPH1_MD4,,,", "pw")

	f.Fuzz(func(t *testing.T, target, candidate string) {
		if len(target) > 4096 || len(candidate) > 256 {
			t.Skip()
		}
		for _, typ := range fuzzFastFormats {
			// The contract: any outcome except a panic.
			_, _ = verifyCandidate(candidate, target, typ, "", "prefix")
		}
	})
}

// Identification runs on every line of a dump before anything else does, so a
// panic here takes the whole run down before a single hash is tried.
func FuzzDetectHashTypes(f *testing.F) {
	for _, s := range fuzzSeedsFromCorpus(f, 300) {
		f.Add(s)
	}
	f.Add("")
	f.Add(":")
	f.Add("::::::::")
	f.Add("$")
	f.Add(strings.Repeat("a", 4096))

	f.Fuzz(func(t *testing.T, target string) {
		if len(target) > 8192 {
			t.Skip()
		}
		_ = detectHashTypes(target)
		_ = stripShadowUsername(target)
		_, _ = normalizeHashInput(target)
	})
}

// Every decoder takes arbitrary text by definition — that is what decoding is.
func FuzzDecodeText(f *testing.F) {
	for _, s := range []string{
		"aGVsbG8=", "48656c6c6f", "<~87cURD]~>", "MFRGG===", "%48%65",
		"-----BEGIN X-----\nAA==\n-----END X-----", "&#x48;", `H`,
		"....- ---..", "H4sIAAAAAAAA/w==", "", "=", "[", "++++.",
	} {
		f.Add(s)
	}

	f.Fuzz(func(t *testing.T, in string) {
		if len(in) > 8192 {
			t.Skip()
		}
		for _, codec := range codecCatalogueNames() {
			_, _ = decodeText(in, codec, 3, "key", 2)
		}
	})
}

// magic drives every decoder recursively over whatever it is given, which
// multiplies any single decoder's fragility by the depth of the search.
func FuzzMagicDecode(f *testing.F) {
	for _, s := range []string{
		"aGVsbG8=", "NzQ2ODY1", "H4sIAAAAAAAA/w==", "", "====", "%%%",
	} {
		f.Add(s)
	}

	f.Fuzz(func(t *testing.T, in string) {
		if len(in) > 1024 {
			t.Skip()
		}
		_ = magicDecode(in, 2)
	})
}

// Rule files come from wherever the operator found them, and both dialects are
// compiled for every file whose first attempt is imperfect.
func FuzzCompileRuleLine(f *testing.F) {
	for _, s := range []string{
		":", "l", "c $1", "sa@", "$[12]", `-[:c] \p1[lc] [PI]`,
		"<* >2 !?A l p", "M l Q", `A0"XY"`, "%2s", "'l", "x**", "",
		"[", "]", "\\", "?", "$", "^", "T", "p", "O", "i",
	} {
		f.Add(s)
	}

	f.Fuzz(func(t *testing.T, line string) {
		if len(line) > 512 {
			t.Skip()
		}
		_, _ = compileRuleLineDialect(line, false)
		_, _ = compileRuleLineDialect(line, true)
		if exp, err := expandJohnRuleLine(line); err == nil {
			// An expansion must be bounded: a line that stands for millions of
			// rules is refused, not materialised.
			if len(exp) > maxJohnPreprocessorExpansion {
				t.Fatalf("%q expanded to %d rules, past the cap", line, len(exp))
			}
		}
	})
}

// The input layer sees the rawest data of all — argv, straight from the shell.
func FuzzCollectInputs(f *testing.F) {
	for _, s := range []string{"", "-", "a,b", "  x  ", "-x", "\x00", strings.Repeat("a", 1000)} {
		f.Add(s)
	}

	f.Fuzz(func(t *testing.T, arg string) {
		if len(arg) > 4096 {
			t.Skip()
		}
		// noFile so the fuzzer cannot be steered into reading the filesystem.
		opts := inputOpts{split: true, sep: ",", trim: true, noFile: true}
		_, _ = collectInputsOpts(arg, opts)
	})
}

// The 7-Zip next-header is the most hostile input any extractor takes: a
// nested, self-describing structure of variable-length integers, where every
// count read from the file decides how many more reads follow. A length that
// says "two billion coders" must be refused, not allocated; a truncated block
// must end the parse, not index past the end.
//
// This target is why the parser reads counts through num(), which takes a cap,
// instead of through number(), which does not.
func FuzzSevenZipHeader(f *testing.F) {
	// Real headers as seeds, so the fuzzer starts from something that parses
	// and mutates outward rather than guessing the shape from nothing.
	f.Add([]byte{0x01, 0x04, 0x06, 0x00, 0x01, 0x09, 0x30, 0x00})
	f.Add([]byte{0x17, 0x06, 0x00, 0x01, 0x09, 0x50, 0x07, 0x0b, 0x01, 0x00})
	f.Add([]byte{0x01})
	f.Add([]byte{0x17})
	f.Add([]byte{})
	f.Add([]byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff})

	f.Fuzz(func(t *testing.T, hdr []byte) {
		if len(hdr) > 1<<16 {
			t.Skip()
		}
		info, err := parseSevenZipNextHeader(hdr)
		if err != nil {
			return
		}
		// A successful parse must not report more structure than the bytes
		// could possibly describe. Every folder, coder and size costs at least
		// one byte to encode, so a header claiming more of them than it has
		// bytes means a count was trusted instead of checked.
		if len(info.folders) > len(hdr) {
			t.Fatalf("%d folders from a %d-byte header", len(info.folders), len(hdr))
		}
		if len(info.packSizes) > len(hdr) {
			t.Fatalf("%d pack sizes from a %d-byte header", len(info.packSizes), len(hdr))
		}
		for _, fl := range info.folders {
			if len(fl.coders) > len(hdr) {
				t.Fatalf("%d coders from a %d-byte header", len(fl.coders), len(hdr))
			}
			for _, c := range fl.coders {
				if len(c.props) > len(hdr) {
					t.Fatalf("%d-byte props from a %d-byte header", len(c.props), len(hdr))
				}
				_, _ = parseSevenZipAESProps(c.props)
			}
		}
	})
}
