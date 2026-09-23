package smith

import (
	"encoding/hex"
	"strings"
	"testing"
)

// The contiguous batch feeds sha1/sha256/md5 through the stdlib's own
// hardware-accelerated cores, so the only thing worth asserting about a new
// filler is that what it hashes is what hashText hashes. Every expected digest
// comes from hashText, never from the batch itself.
func TestContigFillFromWordsMatchesHashText(t *testing.T) {
	for _, tc := range []struct{ typ, salt, saltMode string }{
		{"sha1", "", ""},
		{"sha256", "", ""},
		{"md5", "", ""},
		{"sha1", "deadbeef", "prefix"},
		{"sha256", "deadbeef", "suffix"},
		{"md5", "s4lt", "prefix"},
		// The rest of the SHA-2 family, held back until there was something
		// to test them against. sha512's digest is exactly stdMaxDigestLen,
		// so it is the one that would overflow the slab if that constant
		// ever shrank.
		{"sha224", "", ""},
		{"sha384", "", ""},
		{"sha512", "", ""},
		{"sha224", "deadbeef", "prefix"},
		{"sha384", "deadbeef", "suffix"},
		{"sha512", "deadbeef", "prefix"},
	} {
		tc := tc
		t.Run(tc.typ+"/"+tc.saltMode, func(t *testing.T) {
			algo, sp, ok := stdSaltedPlanFor(tc.typ, tc.salt, tc.saltMode)
			if !ok {
				t.Skipf("no contiguous plan for %s", tc.typ)
			}
			const group = 16
			cb := newContigBatch(group, algo.digLen, sp)

			const width = 7
			words := make([]string, group)
			for i := range words {
				words[i] = string([]byte{
					byte('a' + i%26), byte('a' + (i/26)%26), 'q', 'r', 's',
					byte('0' + i%10), byte('0' + (i/10)%10),
				})
				if len(words[i]) != width {
					t.Fatalf("test word %q is not %d bytes", words[i], width)
				}
			}

			n := cb.fillFromWords(words)
			if n != group {
				t.Fatalf("filled %d slots, want %d", n, group)
			}
			algo.hashBatch(cb.messages(n), cb.stride, n, cb.out)

			for i, w := range words {
				want, err := hashText(w, tc.typ, tc.salt, tc.saltMode)
				if err != nil {
					t.Fatalf("hashText(%q): %v", w, err)
				}
				got := hex.EncodeToString(cb.digest(i))
				if !strings.EqualFold(got, want) {
					t.Fatalf("slot %d, word %q: contiguous core gave %s, hashText gives %s",
						i, w, got, want)
				}
				if back := string(cb.candidate(i)); back != w {
					t.Errorf("candidate(%d) = %q, want %q", i, back, w)
				}
			}
		})
	}
}

// A mixed-length bucket must stop rather than hash at the wrong stride, which
// would produce a wrong digest with no signal.
func TestContigFillFromWordsRefusesAMixedBucket(t *testing.T) {
	algo, sp, ok := stdSaltedPlanFor("sha1", "", "")
	if !ok {
		t.Skip("no sha1 contiguous plan")
	}
	cb := newContigBatch(8, algo.digLen, sp)
	if n := cb.fillFromWords([]string{"aaaa", "bbbb", "ccccc", "dddd"}); n != 2 {
		t.Fatalf("filled %d slots; want 2, stopping at the first wrong-length word", n)
	}
}

// ── the UTF-16LE constructions ───────────────────────────────────────────────

// TestContigUTF16MatchesCompatDigest drives the UTF-16LE salted constructions
// through the contiguous batch and compares against hashCompatSaltedDigest —
// which is what the scalar verifier uses, and the only authority here.
//
// These hash utf16le(password) || salt (or the reverse). The SALT is not
// encoded: hashCompatSaltedDigest writes its raw bytes and encodes only the
// password, so a fill that encoded both would agree with nothing.
func TestContigUTF16MatchesCompatDigest(t *testing.T) {
	for _, typ := range []string{
		"md5-utf16le-pass-salt", "md5-salt-utf16le-pass",
		"sha1-utf16le-pass-salt", "sha1-salt-utf16le-pass",
		"sha256-utf16le-pass-salt", "sha256-salt-utf16le-pass",
		"sha512-utf16le-pass-salt", "sha384-salt-utf16le-pass",
	} {
		typ := typ
		t.Run(typ, func(t *testing.T) {
			const salt = "s4ltyb1t"
			algo, sp, utf16, ok := stdSaltedPlanForEnc(typ, salt, "prefix")
			if !ok {
				t.Skipf("no contiguous plan for %s", typ)
			}
			if !utf16 {
				t.Fatalf("%s resolved without the UTF-16 flag; this test guards the wrong thing", typ)
			}
			const group = 12
			cb := newContigBatchEnc(group, algo.digLen, sp, true)

			const width = 5
			words := make([]string, group)
			for i := range words {
				words[i] = string([]byte{
					byte('a' + i%26), 'Z', '7', '_',
					byte('0' + i%10),
				})
				if len(words[i]) != width {
					t.Fatalf("test word %q is not %d bytes", words[i], width)
				}
			}

			n := cb.fillFromWords(words)
			if n != group {
				t.Fatalf("filled %d slots, want %d", n, group)
			}
			algo.hashBatch(cb.messages(n), cb.stride, n, cb.out)

			for i, w := range words {
				want, err := hashCompatSaltedDigest(w, typ, salt)
				if err != nil {
					t.Fatalf("hashCompatSaltedDigest(%q): %v", w, err)
				}
				got := hex.EncodeToString(cb.digest(i))
				if !strings.EqualFold(got, want) {
					t.Fatalf("slot %d, word %q: contiguous core gave %s, the scalar digest is %s",
						i, w, got, want)
				}
				// The recovered plaintext must be the password, not the
				// message: neither the salt nor the interleaved 0x00 bytes.
				if back := string(cb.candidate(i)); back != w {
					t.Errorf("candidate(%d) = %q, want %q", i, back, w)
				}
			}
		})
	}
}

// TestContigUTF16StrideAccountsForTheEncoding is the arithmetic a wrong stride
// hides: the candidate occupies two bytes per character, so the message the
// core is handed is longer than the raw form by exactly the candidate length.
func TestContigUTF16StrideAccountsForTheEncoding(t *testing.T) {
	const salt = "abc"
	algo, sp, _, ok := stdSaltedPlanForEnc("sha1-utf16le-pass-salt", salt, "prefix")
	if !ok {
		t.Skip("no plan")
	}
	raw := newContigBatchEnc(4, algo.digLen, sp, false)
	enc := newContigBatchEnc(4, algo.digLen, sp, true)
	words := []string{"abcd", "efgh"}
	raw.fillFromWords(words)
	enc.fillFromWords(words)
	if enc.stride != raw.stride+4 {
		t.Errorf("UTF-16 stride is %d and raw is %d; want raw+4 for a 4-character candidate",
			enc.stride, raw.stride)
	}
}

// TestMaskRunnersStillRefuseUTF16 pins the scope boundary. The mask and brute
// runners resolve through stdSaltedPlanFor, which must keep refusing these
// until contigBatch.fillFromSegment can encode them — its odometer writes one
// byte per character position. A silent widening here would hash the wrong
// message for every mask run of these types.
func TestMaskRunnersStillRefuseUTF16(t *testing.T) {
	for _, typ := range []string{
		"md5-utf16le-pass-salt", "sha1-utf16le-pass-salt",
		"sha256-salt-utf16le-pass", "sha512-utf16le-pass-salt",
	} {
		if _, _, ok := stdSaltedPlanFor(typ, "somesalt", "prefix"); ok {
			t.Errorf("%s is eligible for the mask path, whose fill cannot encode it", typ)
		}
		// But the dictionary resolver does take it.
		if _, _, utf16, ok := stdSaltedPlanForEnc(typ, "somesalt", "prefix"); !ok || !utf16 {
			t.Errorf("%s should resolve for the dictionary path with utf16=true, got ok=%v utf16=%v",
				typ, ok, utf16)
		}
	}
}
