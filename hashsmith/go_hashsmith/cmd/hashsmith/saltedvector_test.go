package main

// Tests for the SALTED vector fast path — keyspace.go's fastAlgoPlanFor and
// transposed.go's resetSalted/fillFromSegment, i.e. the NEON/AVX2 cores
// hashing salt||candidate and candidate||salt instead of the bare candidate.
//
// The organising question is never "did it find something". A salt written one
// byte off, a bit length left at the candidate's own length, a padding lane
// that forgot the salt — each of those still finds SOMETHING for some inputs,
// and each is a wrong digest. So every test here compares against hashText,
// the same function the scalar verifier uses, rather than against a second
// generator of this path's own: if the two ever disagree the fast path is
// wrong by definition, whatever it managed to crack.

import (
	"context"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// ── 1. the digest: every lane equals hashText, at every accepted length ─────

// vecBackends are the two cores, named so a plan can be resolved for BOTH on
// one machine. On arm64 "neon" is the real assembly and "avx2" resolves to
// md5avx2_generic.go's word-decoding fallback; on amd64 it is the other way
// round. Either way both are held to hashText here, and the fallback is the
// oracle that makes a divergence in the assembly a test failure rather than a
// silent wrong answer (see md5neon_generic.go's comment).
var vecBackends = []string{"neon", "avx2"}

// saltedVecCase is one (type, salt, mode) combination the vector path claims
// to compute exactly, together with the longest candidate it should accept.
type saltedVecCase struct {
	name     string
	typ      string
	salt     string
	saltMode string
	// maxLen is the longest candidate that still fits one block WITH this
	// salt, derived below from the plan rather than hardcoded, so the case
	// list stays readable.
}

// The digest of every lane must equal hashText(candidate, typ, salt, mode) —
// at EVERY candidate length the path accepts, in both salt modes, for both
// cores. This is the test that catches a salt at the wrong offset: a prefix
// salt written where a suffix salt belongs still produces a well-formed block
// and a plausible digest, and only hashText says which one is right.
func TestVecSaltedDigestsMatchHashText(t *testing.T) {
	cases := []saltedVecCase{
		{"md5 prefix", "md5", "deadbeef", "prefix"},
		{"md5 suffix", "md5", "deadbeef", "suffix"},
		{"md5 default mode is prefix", "md5", "deadbeef", ""},
		{"md5 unrecognised mode is prefix", "md5", "deadbeef", "PREFIX"},
		{"md5 one-byte salt", "md5", "$", "prefix"},
		{"md5 one-byte suffix salt", "md5", "$", "suffix"},
		{"md5 word-aligned salt", "md5", "abcd", "suffix"},
		{"md5 salt with symbols", "md5", "s@lt!:_", "prefix"},
		{"md5 unsalted", "md5", "", "prefix"},
		{"md4 prefix", "md4", "deadbeef", "prefix"},
		{"md4 suffix", "md4", "deadbeef", "suffix"},
		{"ntlm prefix", "ntlm", "dead", "prefix"},
		{"ntlm suffix", "ntlm", "dead", "suffix"},
		{"ntlm unsalted", "ntlm", "", "prefix"},
		{"md5-salt-pass", "md5-salt-pass", "abc", "suffix"}, // the type fixes the order; -S is ignored
		{"md5-pass-salt", "md5-pass-salt", "abc", "prefix"}, // …in both directions
		{"hashcat 20", "20", "abc", ""},
		{"hashcat 10", "10", "abc", ""},
	}
	for _, backend := range vecBackends {
		for _, c := range cases {
			t.Run(backend+"/"+c.name, func(t *testing.T) {
				algo, ok := fastAlgoPlanForBackend(backend, c.typ, c.salt, c.saltMode)
				if !ok {
					t.Fatalf("no %s plan for %s", backend, c.typ)
				}
				checkSaltedLanesAgainstHashText(t, algo, c.typ, c.salt, c.saltMode)
			})
		}
	}
}

// checkSaltedLanesAgainstHashText fills a batch at every candidate length the
// plan accepts (including 0 and the boundary length, and including a partial
// final group whose padding lanes get cleaned) and compares every lane's
// digest to hashText.
func checkSaltedLanesAgainstHashText(t *testing.T, algo *fastAlgo, typ, salt, saltMode string) {
	t.Helper()
	group := algo.shape.group()
	out := make([][16]byte, group)
	// hashText of the EMPTY candidate under this salt: what a cleaned padding
	// lane must hash to, since fillFromSegment resets it to the empty
	// candidate wrapped in this batch's salt.
	emptyWant, err := hashText("", typ, salt, saltMode)
	if err != nil {
		t.Fatalf("hashText(%q): %v", "", err)
	}

	for length := 0; ; length++ {
		if !transposedSaltedLenOK(length, algo.enc, algo.salt.width()) {
			if length == 0 {
				t.Fatalf("no candidate length at all fits with this salt")
			}
			break
		}
		sets := make([][]byte, length)
		for i := range sets {
			sets[i] = []byte("ab")
		}
		total := maskKeyspace(sets)
		tb := newTransposedBatch(algo.shape)
		if err := tb.resetSalted(length, algo.enc, algo.salt); err != nil {
			t.Fatalf("len %d: resetSalted: %v", length, err)
		}
		// from=0 is the aligned case; from=total-3 makes the final group
		// partial for every length past 2, so the cleaned padding lanes are
		// exercised at every length too.
		froms := []int64{0}
		if total > 3 {
			froms = append(froms, total-3)
		}
		for _, from := range froms {
			n := tb.fillFromSegment(sets, from, total)
			if n == 0 {
				t.Fatalf("len %d from %d: filled nothing", length, from)
			}
			algo.group(tb, out)
			for i := 0; i < group; i++ {
				got := hex.EncodeToString(out[i][:])
				if i < n {
					cand := string(tb.candidateAt(i))
					if want := maskIdxToStr(from+int64(i), sets); cand != want {
						t.Fatalf("len %d from %d lane %d: candidateAt %q, maskIdxToStr says %q",
							length, from, i, cand, want)
					}
					want, err := hashText(cand, typ, salt, saltMode)
					if err != nil {
						t.Fatalf("hashText(%q): %v", cand, err)
					}
					if got != want {
						t.Fatalf("len %d from %d lane %d (%q): digest %s, hashText says %s",
							length, from, i, cand, got, want)
					}
					continue
				}
				// A padding lane: the empty candidate, salt included.
				if got != emptyWant {
					t.Fatalf("len %d from %d padding lane %d: digest %s, want the empty candidate's %s",
						length, from, i, got, emptyWant)
				}
			}
		}
	}
}

// ── 2. the block-fit ceiling ────────────────────────────────────────────────

// A salt that pushes a candidate past the one block the cores hash must
// DECLINE, at every gate: the length predicate, resetSalted, and the
// eligibility check the runners are behind. Producing a truncated message
// instead would be a silently wrong digest for every candidate in the run.
func TestVecSaltedBlockFitCeiling(t *testing.T) {
	for _, c := range []struct {
		enc       encodeMode
		saltWidth int
		lastOK    int
	}{
		{encRaw, 0, 55},
		{encRaw, 1, 54},
		{encRaw, 8, 47},
		{encRaw, 55, 0},
		{encUTF16LE, 0, 27}, // 2*27 = 54 <= 55
		{encUTF16LE, 2, 26}, // 2 + 52
		{encUTF16LE, 8, 23}, // 8 + 46
		{encUTF16LE, 54, 0}, // salt alone fills the block
	} {
		if !transposedSaltedLenOK(c.lastOK, c.enc, c.saltWidth) {
			t.Errorf("enc %v salt %d: length %d should fit", c.enc, c.saltWidth, c.lastOK)
		}
		if transposedSaltedLenOK(c.lastOK+1, c.enc, c.saltWidth) {
			t.Errorf("enc %v salt %d: length %d should NOT fit", c.enc, c.saltWidth, c.lastOK+1)
		}
	}
	// The zero-salt case must still answer exactly what transposedFixedLenOK
	// answered before salts existed.
	for n := -1; n <= 60; n++ {
		if got, want := transposedSaltedLenOK(n, encRaw, 0), n >= 0 && n <= transposedMaxLen; got != want {
			t.Errorf("raw len %d: %v, want %v", n, got, want)
		}
		if got, want := transposedSaltedLenOK(n, encUTF16LE, 0), n >= 0 && n <= transposedMaxLenUTF16LE; got != want {
			t.Errorf("utf16 len %d: %v, want %v", n, got, want)
		}
	}

	// resetSalted refuses rather than truncating.
	tb := newTransposedBatch(neonShape)
	salt := vecSalt{pre: []byte(strings.Repeat("s", 50))}
	if err := tb.resetSalted(5, encRaw, salt); err != nil {
		t.Errorf("50 + 5 = 55 must fit: %v", err)
	}
	if err := tb.resetSalted(6, encRaw, salt); err != errTransposedLen {
		t.Errorf("50 + 6 = 56 must be refused, got %v", err)
	}

	// And the gate the runners are actually behind declines the whole run,
	// leaving it to the scalar/contiguous path.
	if vectorBackendName() == "" {
		return
	}
	l := bruteLayout("abcdef", 6, 6)
	if _, ok := fastPathEligible("md5", strings.Repeat("s", 49), "prefix", l); !ok {
		t.Error("49 + 6 = 55 must still be eligible")
	}
	if _, ok := fastPathEligible("md5", strings.Repeat("s", 50), "prefix", l); ok {
		t.Error("50 + 6 = 56 must decline")
	}
	if _, ok := fastPathEligible("md5", strings.Repeat("s", 50), "suffix", l); ok {
		t.Error("50 + 6 = 56 must decline in suffix mode too")
	}
	// An increment-mode layout is only as eligible as its LONGEST segment.
	inc := bruteLayout("abcdef", 1, 6)
	if _, ok := fastPathEligible("md5", strings.Repeat("s", 50), "prefix", inc); ok {
		t.Error("a layout whose longest segment overflows must decline as a whole")
	}
}

// A non-ASCII salt under NTLM's UTF-16LE encoding must decline: utf16le is a
// UTF-8 decode followed by a UTF-16 encode, so a high byte does not survive as
// the naive b,0x00 expansion the message layout assumes. (The same rule
// fastPathEligible already applies to charsets — see
// TestUTF16LEDiffersFromNaiveExpansionOnHighBytes.)
func TestNTLMSaltMustBeASCII(t *testing.T) {
	if _, ok := vecSaltBytes("caf\xc3\xa9", encUTF16LE); ok {
		t.Error("a non-ASCII salt must be declined under encUTF16LE")
	}
	if b, ok := vecSaltBytes("abc", encUTF16LE); !ok || string(b) != "a\x00b\x00c\x00" {
		t.Errorf("utf16le salt = %q, %v", b, ok)
	}
	if b, ok := vecSaltBytes("caf\xc3\xa9", encRaw); !ok || string(b) != "caf\xc3\xa9" {
		t.Errorf("raw salt = %q, %v", b, ok)
	}
	if vectorBackendName() == "" {
		return
	}
	l := bruteLayout("abc", 3, 3)
	if _, ok := fastPathEligible("ntlm", "caf\xc3\xa9", "prefix", l); ok {
		t.Error("a non-ASCII salt must decline an ntlm run")
	}
	if _, ok := fastPathEligible("md5", "caf\xc3\xa9", "prefix", l); !ok {
		t.Error("a non-ASCII salt is fine for a raw-byte digest")
	}
}

// ── 3. the unsalted path is untouched ───────────────────────────────────────

// The empty salt must leave every word of every lane exactly as it was before
// salts existed: reset() and resetSalted(vecSalt{}) must be the same batch,
// and a cleaned lane must still be the zero-length message.
func TestUnsaltedBatchIsUnchanged(t *testing.T) {
	sets := [][]byte{[]byte("abc"), []byte("de")}
	for _, enc := range []encodeMode{encRaw, encUTF16LE} {
		a := newTransposedBatch(neonShape)
		b := newTransposedBatch(neonShape)
		if err := a.reset(len(sets), enc); err != nil {
			t.Fatal(err)
		}
		if err := b.resetSalted(len(sets), enc, vecSalt{}); err != nil {
			t.Fatal(err)
		}
		for i := range a.words {
			if a.words[i] != b.words[i] {
				t.Fatalf("enc %v: reset and resetSalted(empty) differ at word %d", enc, i)
			}
		}
		// The empty-candidate block is the zero-length message: 0x80, nothing
		// else, bit length 0.
		if a.empty[0] != 0x80 || a.empty[14] != 0 {
			t.Fatalf("enc %v: empty block = %v", enc, a.empty[:15])
		}
		for w := 1; w < 16; w++ {
			if a.empty[w] != 0 {
				t.Fatalf("enc %v: empty block word %d = %#x, want 0", enc, w, a.empty[w])
			}
		}
		a.fillFromSegment(sets, 0, maskKeyspace(sets))
		// A shrinking refill leaves the leftover lanes as the empty message.
		a.fillFromSegment(sets, maskKeyspace(sets)-1, maskKeyspace(sets))
		for i := 1; i < neonShape.group(); i++ {
			if got := a.words[a.wordIndex(i, 0)]; got != 0x80 {
				t.Fatalf("enc %v: cleaned lane %d word 0 = %#x, want 0x80", enc, i, got)
			}
			if got := a.words[a.wordIndex(i, 14)]; got != 0 {
				t.Fatalf("enc %v: cleaned lane %d bit length = %d, want 0", enc, i, got)
			}
		}
	}
}

// A shrinking refill of a SALTED batch must leave no lane holding a previous
// candidate — the stale-lane bug, which reports a candidate that was never
// tried as a hit. The salted shape must not weaken it: the leftover lanes
// carry the salt with an EMPTY candidate, never the last fill's bytes.
func TestSaltedReuseClearsStaleLanes(t *testing.T) {
	algo, ok := fastAlgoPlanForBackend("neon", "md5", "deadbeef", "prefix")
	if !ok {
		t.Fatal("no neon md5 plan")
	}
	sets := [][]byte{[]byte("abcdefghij"), []byte("abcdefghij")} // 100 > one group
	total := maskKeyspace(sets)
	tb := newTransposedBatch(algo.shape)
	if err := tb.resetSalted(len(sets), algo.enc, algo.salt); err != nil {
		t.Fatal(err)
	}
	group := algo.shape.group()
	out := make([][16]byte, group)
	if n := tb.fillFromSegment(sets, 0, total); n != group {
		t.Fatalf("first fill returned %d, want a full group of %d", n, group)
	}
	// Remember what a full group hashed to, then refill with ONE candidate.
	algo.group(tb, out)
	full := append([][16]byte{}, out...)
	n := tb.fillFromSegment(sets, total-1, total)
	if n != 1 {
		t.Fatalf("shrinking fill returned %d, want 1", n)
	}
	algo.group(tb, out)
	emptyHex, _ := hashText("", "md5", "deadbeef", "prefix")
	for i := 1; i < group; i++ {
		if out[i] == full[i] {
			t.Fatalf("lane %d still hashes the PREVIOUS fill's candidate", i)
		}
		if got := hex.EncodeToString(out[i][:]); got != emptyHex {
			t.Fatalf("lane %d hashes %s, want the salted empty candidate %s", i, got, emptyHex)
		}
	}
}

// ── 4. end to end: the same pairs, in the same order, as the scalar path ────

// saltedBruteRun cracks `lines` in BRUTE mode — the mode the vector path
// actually claims — and returns the -o file's lines.
func saltedBruteRun(t *testing.T, lines []string, charset string, n, x int, scalar bool, args ...string) []string {
	t.Helper()
	dir := t.TempDir()
	t.Setenv("HOME", dir)
	if scalar {
		t.Setenv("HASHSMITH_NO_FASTPATH", "1")
	} else {
		t.Setenv("HASHSMITH_NO_FASTPATH", "")
	}
	tf := filepath.Join(dir, "targets.txt")
	mustWrite(t, tf, strings.Join(lines, "\n")+"\n")
	out := filepath.Join(dir, "out.txt")
	full := append([]string{"-M", "brute", "-C", charset,
		"-n", fmt.Sprint(n), "-x", fmt.Sprint(x), "--no-pot", "-o", out}, args...)
	full = append(full, tf)
	exitCode = 0
	if err := runCrack(full); err != nil {
		t.Fatalf("runCrack: %v", err)
	}
	raw, err := os.ReadFile(out)
	if err != nil {
		return nil
	}
	var got []string
	for _, l := range strings.Split(strings.TrimRight(string(raw), "\n"), "\n") {
		if l != "" {
			got = append(got, l)
		}
	}
	return got
}

// The whole contract in one test: a salted brute run on the vector path must
// recover the same (target, plaintext) pairs, in the same order, as the same
// run with HASHSMITH_NO_FASTPATH=1 — and every plaintext, re-hashed with its
// own salt and mode, must match the target it is filed against.
func TestSaltedVectorEndToEndMatchesScalarPath(t *testing.T) {
	if vectorBackendName() == "" {
		t.Skip("no vector backend on this build")
	}
	plains := []string{"cab", "dig", "hej", "bid"}
	shapes := []struct {
		name  string
		typ   string
		mode  string
		build func() (lines []string, saltOf map[string]string, args []string)
	}{
		{
			name: "single target, prefix salt", typ: "md5", mode: "prefix",
			build: func() ([]string, map[string]string, []string) {
				h, _ := hashText("cab", "md5", "deadbeef", "prefix")
				return []string{h}, map[string]string{h: "deadbeef"},
					[]string{"-t", "md5", "-s", "deadbeef", "-S", "prefix"}
			},
		},
		{
			name: "single target, suffix salt", typ: "md5", mode: "suffix",
			build: func() ([]string, map[string]string, []string) {
				h, _ := hashText("cab", "md5", "deadbeef", "suffix")
				return []string{h}, map[string]string{h: "deadbeef"},
					[]string{"-t", "md5", "-s", "deadbeef", "-S", "suffix"}
			},
		},
		{
			name: "single target, one-byte salt", typ: "md5", mode: "suffix",
			build: func() ([]string, map[string]string, []string) {
				h, _ := hashText("cab", "md5", "$", "suffix")
				return []string{h}, map[string]string{h: "$"},
					[]string{"-t", "md5", "-s", "$", "-S", "suffix"}
			},
		},
		{
			name: "single target, salt at the block limit", typ: "md5", mode: "prefix",
			build: func() ([]string, map[string]string, []string) {
				salt := strings.Repeat("s", 52) // 52 + 3 = 55, the last that fits
				h, _ := hashText("cab", "md5", salt, "prefix")
				return []string{h}, map[string]string{h: salt},
					[]string{"-t", "md5", "-s", salt, "-S", "prefix"}
			},
		},
		{
			// One byte longer: the vector path must DECLINE and the run must
			// still crack it, on whichever path picks it up.
			name: "single target, salt past the block limit", typ: "md5", mode: "prefix",
			build: func() ([]string, map[string]string, []string) {
				salt := strings.Repeat("s", 53) // 53 + 3 = 56, one too many
				h, _ := hashText("cab", "md5", salt, "prefix")
				return []string{h}, map[string]string{h: salt},
					[]string{"-t", "md5", "-s", salt, "-S", "prefix"}
			},
		},
		{
			name: "single target, ntlm prefix salt", typ: "ntlm", mode: "prefix",
			build: func() ([]string, map[string]string, []string) {
				h, _ := hashText("cab", "ntlm", "de", "prefix")
				return []string{h}, map[string]string{h: "de"},
					[]string{"-t", "ntlm", "-s", "de", "-S", "prefix"}
			},
		},
		{
			name: "single target, md4 suffix salt", typ: "md4", mode: "suffix",
			build: func() ([]string, map[string]string, []string) {
				h, _ := hashText("cab", "md4", "de", "suffix")
				return []string{h}, map[string]string{h: "de"},
					[]string{"-t", "md4", "-s", "de", "-S", "suffix"}
			},
		},
		{
			name: "dump sharing one salt", typ: "md5", mode: "prefix",
			build: func() ([]string, map[string]string, []string) {
				var lines []string
				saltOf := map[string]string{}
				for _, p := range plains {
					h, _ := hashText(p, "md5", "shared", "prefix")
					lines = append(lines, h)
					saltOf[h] = "shared"
				}
				return lines, saltOf, []string{"-t", "md5", "-s", "shared", "-S", "prefix"}
			},
		},
		{
			// The one that matters for attribution: a salt per target,
			// carried in the target lines themselves (hashcat 20).
			name: "dump with per-target salts (hashcat 20)", typ: "md5-salt-pass", mode: "prefix",
			build: func() ([]string, map[string]string, []string) {
				var lines []string
				saltOf := map[string]string{}
				for i, p := range plains {
					salt := fmt.Sprintf("salt%d", i)
					d, _ := hashCompatSaltedDigest(p, "md5-salt-pass", salt)
					line := d + ":" + salt
					lines = append(lines, line)
					saltOf[line] = ""
				}
				return lines, saltOf, []string{"-t", "md5-salt-pass"}
			},
		},
		{
			name: "dump with per-target salts (hashcat 10)", typ: "md5-pass-salt", mode: "prefix",
			build: func() ([]string, map[string]string, []string) {
				var lines []string
				saltOf := map[string]string{}
				for i, p := range plains {
					salt := fmt.Sprintf("s%d", i)
					d, _ := hashCompatSaltedDigest(p, "md5-pass-salt", salt)
					line := d + ":" + salt
					lines = append(lines, line)
					saltOf[line] = ""
				}
				return lines, saltOf, []string{"-t", "md5-pass-salt"}
			},
		},
	}
	for _, sh := range shapes {
		t.Run(sh.name, func(t *testing.T) {
			lines, saltOf, args := sh.build()
			fast := saltedBruteRun(t, lines, "abcdefghij", 3, 3, false, args...)
			slow := saltedBruteRun(t, lines, "abcdefghij", 3, 3, true, args...)
			if len(fast) != len(lines) {
				t.Fatalf("fast path recovered %d of %d: %v", len(fast), len(lines), fast)
			}
			if strings.Join(fast, "\n") != strings.Join(slow, "\n") {
				t.Fatalf("fast and scalar paths disagree.\nfast:\n%s\nscalar:\n%s",
					strings.Join(fast, "\n"), strings.Join(slow, "\n"))
			}
			// Attribution: re-hash each reported plaintext with the target's
			// OWN salt and mode and compare it to the target it is filed
			// against. A mis-grouped dump still recovers every plaintext and
			// still reports the right count; only this catches it.
			pairs := map[string]string{}
			for _, l := range fast {
				matched := false
				for _, tgt := range lines {
					if strings.HasPrefix(l, tgt+":") {
						pairs[tgt] = l[len(tgt)+1:]
						matched = true
						break
					}
				}
				if !matched {
					if len(lines) != 1 {
						t.Fatalf("unparseable -o line %q", l)
					}
					pairs[lines[0]] = l
				}
			}
			mustAttribute(t, pairs, sh.typ, sh.mode, saltOf)
		})
	}
}

// A suffix-salted dump cracked as prefix must find NOTHING. If it finds
// everything, the salt is going in at one offset regardless of the mode.
func TestSaltedVectorRespectsSaltMode(t *testing.T) {
	if vectorBackendName() == "" {
		t.Skip("no vector backend on this build")
	}
	h, _ := hashText("cab", "md5", "deadbeef", "suffix")
	lines := []string{h}
	if got := saltedBruteRun(t, lines, "abcdefghij", 3, 3, false,
		"-t", "md5", "-s", "deadbeef", "-S", "prefix"); len(got) != 0 {
		t.Errorf("a suffix-salted target was cracked as prefix: %v", got)
	}
	if got := saltedBruteRun(t, lines, "abcdefghij", 3, 3, false,
		"-t", "md5", "-s", "deadbeef", "-S", "suffix"); len(got) != 1 {
		t.Errorf("suffix run recovered %d of 1: %v", len(got), got)
	}
}

// ── 5. --skip/--limit and --session over the salted vector path ─────────────

// The salted vector runner must slice the keyspace exactly as the scalar one
// does: a password in the low half is found by the low half's run and by
// nothing else.
func TestSaltedVectorHonoursSkipAndLimit(t *testing.T) {
	if vectorBackendName() == "" {
		t.Skip("no vector backend on this build")
	}
	for _, mode := range []string{"prefix", "suffix"} {
		t.Run(mode, func(t *testing.T) {
			const salt = "deadbeef"
			l := bruteLayout("abcdefghijklmnopqrstuvwxyz", 3, 3) // 17576
			half := l.total / 2
			for _, c := range []struct {
				name  string
				plain string
				lo    bool
			}{
				{"low half", "aab", true},
				{"high half", "zzy", false},
			} {
				target, err := hashText(c.plain, "md5", salt, mode)
				if err != nil {
					t.Fatal(err)
				}
				if _, ok := fastPathEligible("md5", salt, mode, l); !ok {
					t.Fatal("precondition: a salted md5 brute must be vector-eligible here")
				}
				run := func(from, limit int64) string {
					var attempts int64
					pw, _, err := runBruteOrMaskLayout(context.Background(), l, nil, from, limit, 4, &attempts,
						"md5", salt, mode, target, func(cand string) bool {
							ok, _ := verifyCandidate(cand, target, "md5", salt, mode)
							return ok
						})
					if err != nil {
						t.Fatal(err)
					}
					return pw
				}
				lo, hi := run(0, half), run(half, 0)
				if c.lo && (lo != c.plain || hi != "") {
					t.Errorf("%s: low=%q high=%q, want %q and \"\"", c.name, lo, hi, c.plain)
				}
				if !c.lo && (hi != c.plain || lo != "") {
					t.Errorf("%s: low=%q high=%q, want \"\" and %q", c.name, lo, hi, c.plain)
				}
			}
		})
	}
}

// A salted brute run with a session must still work end to end, on the vector
// runner it now takes: same checkpointing, same result.
func TestSaltedVectorSessionRuns(t *testing.T) {
	if vectorBackendName() == "" {
		t.Skip("no vector backend on this build")
	}
	for _, mode := range []string{"prefix", "suffix"} {
		t.Run(mode, func(t *testing.T) {
			t.Setenv("HOME", t.TempDir())
			cc, err := newCrackCtx("", true, "salted-vector-session-"+mode, false, "", false, 0, 0)
			if err != nil {
				t.Fatalf("newCrackCtx: %v", err)
			}
			target, _ := hashText("cab", "md5", "s4lt", mode)
			found, err := doCrack(target, "md5", "brute", "", "abc", 1, 3, 4, "s4lt", mode, "", false, nil, nil, cc)
			if err != nil {
				t.Fatalf("doCrack: %v", err)
			}
			if !found {
				t.Fatal("a salted brute run with a session must find its password")
			}
		})
	}
}

// ── 6. the multi-target runner, salted ──────────────────────────────────────

// Every hit inside ONE group must be reported, with a salt as without: a group
// is 20-24 candidates wide, so two targets whose plaintexts are adjacent land
// in the same group and stopping at the first would silently lose the second.
func TestSaltedFastMultiFindsEveryHitInsideOneGroup(t *testing.T) {
	if vectorBackendName() == "" {
		t.Skip("no vector backend on this build")
	}
	const salt = "pepper"
	// "aaa" and "aab" are indices 0 and 1 of this layout — the same group.
	plains := []string{"aaa", "aab"}
	var lines []string
	for _, p := range plains {
		h, _ := hashText(p, "md5", salt, "suffix")
		lines = append(lines, h)
	}
	batch := make([]*batchTarget, len(lines))
	for i, h := range lines {
		batch[i] = &batchTarget{norm: h, key: h, orig: h, salt: salt}
	}
	got := map[string]string{}
	var attempts int64
	ok := batchFastLayout(context.Background(), "md5", salt, "suffix",
		bruteLayout("abcdefghij", 3, 3), allIdx(len(batch)), batch, 0, 0, 2, &attempts, nil,
		func(pw string, idxs []int) bool {
			for _, i := range idxs {
				got[batch[i].key] = pw
			}
			return false
		})
	if !ok {
		t.Fatal("a salted multi-target md5 pass must be vector-eligible")
	}
	if len(got) != len(plains) {
		t.Fatalf("recovered %d of %d: %v", len(got), len(plains), got)
	}
	for i, h := range lines {
		if got[h] != plains[i] {
			t.Errorf("target %s: got %q, want %q", h, got[h], plains[i])
		}
	}
}
