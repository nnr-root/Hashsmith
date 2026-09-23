package smith

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// writeWords writes a wordlist and returns its path.
func writeWords(t *testing.T, words []string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "w.txt")
	if err := os.WriteFile(path, []byte(strings.Join(words, "\n")+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

// runDict runs a dictionary attack and reports what it found.
//
// The found flag is separate from the password because the empty string is a
// legitimate wordlist entry and a legitimate answer: returning "" for both
// "not found" and "found the empty password" made this helper's first version
// report a spurious failure for every type.
func runDict(t *testing.T, path, typ, target, salt, saltMode string, workers int) (string, bool, int64) {
	t.Helper()
	var attempts int64
	verify := func(pw string) bool {
		ok, _ := verifyCandidate(pw, target, typ, salt, saltMode)
		return ok
	}
	res, err := dictAttack(context.Background(), path, 0, 0, workers,
		&attempts, nil, verify, target, typ, salt, saltMode)
	if err != nil {
		t.Fatalf("dictAttack: %v", err)
	}
	return res.password, res.found, attempts
}

// TestDictVectorMatchesScalarOnEveryWord is the differential test that
// matters: for every word, the vector path and the scalar path must reach the
// same verdict. They are two implementations of one question, and the only
// way a faster one is worth having is if it answers identically.
func TestDictVectorMatchesScalarOnEveryWord(t *testing.T) {
	words := []string{
		"a", "ab", "abc", "password", "hunter2", "",
		"café", "naïve", "日本", "ünïcödé",
		strings.Repeat("x", 13), strings.Repeat("y", 27),
		strings.Repeat("z", 54), strings.Repeat("w", 55), strings.Repeat("v", 56),
		strings.Repeat("u", 200),
		"tab\there", "sp ace", `quo"te`, "emoji🙂",
	}
	path := writeWords(t, words)

	for _, tc := range []struct{ typ, salt, saltMode string }{
		{"md5", "", ""},
		{"md4", "", ""},
		{"ntlm", "", ""},
		{"md5", "deadbeef", "prefix"},
		{"md5", "deadbeef", "suffix"},
		{"sha1", "", ""},
		{"sha256", "", ""},
	} {
		tc := tc
		for _, want := range words {
			want := want
			t.Run(fmt.Sprintf("%s/%s/%q", tc.typ, tc.saltMode, want), func(t *testing.T) {
				target, err := hashText(want, tc.typ, tc.salt, tc.saltMode)
				if err != nil {
					t.Skipf("hashText: %v", err)
				}
				gotVec, okVec, _ := runDict(t, path, tc.typ, target, tc.salt, tc.saltMode, 4)

				t.Setenv("HASHSMITH_NO_FASTPATH", "1")
				gotScalar, okScalar, _ := runDict(t, path, tc.typ, target, tc.salt, tc.saltMode, 4)

				if okVec != okScalar || gotVec != gotScalar {
					t.Fatalf("vector found %q (%v), scalar found %q (%v) — the two paths disagree",
						gotVec, okVec, gotScalar, okScalar)
				}
				if !okScalar {
					t.Fatalf("neither path found %q, which is in the wordlist", want)
				}
			})
		}
	}
}

// TestDictVectorRefusesNonASCIIUnderUTF16 pins the specific defect this path
// shipped with for an hour.
//
// The transposed fill expands each candidate byte b to (b, 0x00), which is
// utf16le(s) only while s is ASCII. A mask run is protected because
// fastPathEligible refuses a charset containing any byte >= 0x80. A wordlist
// is a file of arbitrary UTF-8 nobody chose byte by byte, so the check has to
// be per word — and without it, `hash -t ntlm café` then cracking that digest
// from a one-word list reported "Not found" for a password sitting in the
// list.
func TestDictVectorRefusesNonASCIIUnderUTF16(t *testing.T) {
	d := newDictVectorLanes("ntlm", strings.Repeat("00", 16), "", "")
	if d == nil {
		t.Skip("no ntlm vector plan on this backend")
	}
	if d.algo.enc != encUTF16LE {
		t.Fatalf("ntlm plan is not UTF-16LE; this test guards the wrong thing")
	}
	for _, w := range []string{"café", "naïve", "日本", "\x80", "a\xffb"} {
		if d.accepts(w) {
			t.Errorf("accepts(%q) = true; a non-ASCII word cannot go through the "+
				"byte-to-(b,0x00) expansion and must fall back to the scalar verifier", w)
		}
	}
	for _, w := range []string{"", "a", "password", "hunter2", "~!@#$%^&*()"} {
		if !d.accepts(w) {
			t.Errorf("accepts(%q) = false; an ASCII word within the length limit must "+
				"take the vector path", w)
		}
	}
}

// TestDictVectorCountsEveryAttempt keeps the progress counter honest: a
// bucketed run hashes in groups, and a group that credited its padding lanes
// or dropped a partial bucket would report a keyspace it never searched.
func TestDictVectorCountsEveryAttempt(t *testing.T) {
	// Lengths chosen to leave several buckets partially full at end of
	// stream, which is where a missed flush shows up.
	var words []string
	for i := 0; i < 997; i++ {
		words = append(words, strings.Repeat(string(rune('a'+i%26)), 1+i%11))
	}
	path := writeWords(t, words)
	target, err := hashText("definitely-not-in-the-list", "md5", "", "")
	if err != nil {
		t.Fatal(err)
	}
	for _, workers := range []int{1, 2, 4, 8} {
		got, found, attempts := runDict(t, path, "md5", target, "", "", workers)
		if found {
			t.Fatalf("workers=%d: found %q in a list that does not contain it", workers, got)
		}
		if attempts != int64(len(words)) {
			t.Errorf("workers=%d: counted %d attempts, want %d — a bucket was dropped "+
				"or padding lanes were credited", workers, attempts, len(words))
		}
	}
}

// TestDictVectorFindsAtEveryPosition covers the partial-bucket flush from the
// other side: a password in the last few words of the stream sits in a bucket
// that never reaches a full group, and is only ever tested by the end-of-batch
// flush.
func TestDictVectorFindsAtEveryPosition(t *testing.T) {
	const n = 1500
	for _, pos := range []int{0, 1, 19, 20, 21, 511, 512, 513, n - 2, n - 1} {
		pos := pos
		t.Run(fmt.Sprint(pos), func(t *testing.T) {
			words := make([]string, n)
			for i := range words {
				words[i] = strings.Repeat(string(rune('a'+i%26)), 1+i%9)
			}
			words[pos] = "needle" + fmt.Sprint(pos)
			path := writeWords(t, words)
			target, err := hashText(words[pos], "md5", "", "")
			if err != nil {
				t.Fatal(err)
			}
			got, found, _ := runDict(t, path, "md5", target, "", "", 4)
			if !found || got != words[pos] {
				t.Fatalf("at position %d: found %q, want %q", pos, got, words[pos])
			}
		})
	}
}

// TestDictReaderArenaPreservesEveryWord guards the reader's arena: words are
// no longer individually allocated strings but substrings of one per-batch
// string, so an off-by-one in the offset bookkeeping would hand a worker a
// word with a neighbour's characters attached — and it would do it silently,
// since every such word is still a valid string.
//
// The list is built so that a boundary error cannot hide: lengths vary, empty
// lines appear (they are kept verbatim), and the words straddle the batch
// boundary at dictBatchSize.
func TestDictReaderArenaPreservesEveryWord(t *testing.T) {
	var words []string
	for i := 0; i < dictBatchSize*2+7; i++ {
		switch i % 5 {
		case 0:
			words = append(words, "")
		case 1:
			words = append(words, "w"+fmt.Sprint(i))
		default:
			words = append(words, strings.Repeat(string(rune('a'+i%26)), 1+i%12)+fmt.Sprint(i))
		}
	}
	path := writeWords(t, words)

	// Every distinct word must be findable, and nothing else must be. A
	// straddled boundary shows up as a word that cannot be found (its bytes
	// were split) or as a neighbour that can (its bytes were joined).
	for _, at := range []int{0, 1, 4, dictBatchSize - 1, dictBatchSize, dictBatchSize + 1, len(words) - 1} {
		want := words[at]
		target, err := hashText(want, "md5", "", "")
		if err != nil {
			t.Fatal(err)
		}
		got, found, _ := runDict(t, path, "md5", target, "", "", 4)
		if !found {
			t.Fatalf("index %d: %q was not found; the arena split or joined it", at, want)
		}
		if got != want {
			t.Fatalf("index %d: found %q, want %q", at, got, want)
		}
	}

	// And a word that is a CONCATENATION of two adjacent entries must NOT be
	// found, which is what an arena with lost boundaries would produce.
	glued := words[1] + words[2]
	target, err := hashText(glued, "md5", "", "")
	if err != nil {
		t.Fatal(err)
	}
	if _, found, _ := runDict(t, path, "md5", target, "", "", 4); found {
		t.Fatalf("found %q, which is two adjacent words run together — the arena lost a boundary", glued)
	}
}

// TestDictReaderArenaRespectsSkipAndLimit keeps the word-index bookkeeping
// honest across the rewrite: --skip/--limit count words of the whole file, and
// the arena changed how words are collected but must not change which ones.
func TestDictReaderArenaRespectsSkipAndLimit(t *testing.T) {
	var words []string
	for i := 0; i < 500; i++ {
		words = append(words, "word"+fmt.Sprint(i))
	}
	path := writeWords(t, words)

	target, err := hashText("word250", "md5", "", "")
	if err != nil {
		t.Fatal(err)
	}
	verify := func(pw string) bool {
		ok, _ := verifyCandidate(pw, target, "md5", "", "")
		return ok
	}

	for _, tc := range []struct {
		name        string
		skip, limit int64
		want        bool
	}{
		{"whole file", 0, 0, true},
		{"slice containing it", 200, 100, true},
		{"slice ending before it", 0, 250, false},
		{"slice starting after it", 251, 0, false},
		{"exactly it", 250, 1, true},
	} {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			var attempts int64
			res, err := dictAttack(context.Background(), path, tc.skip, tc.limit, 4,
				&attempts, nil, verify, target, "md5", "", "")
			if err != nil {
				t.Fatal(err)
			}
			if res.found != tc.want {
				t.Fatalf("skip=%d limit=%d: found=%v, want %v", tc.skip, tc.limit, res.found, tc.want)
			}
		})
	}
}
