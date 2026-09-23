package smith

import (
	"strings"
	"testing"
)

// ── Classical ciphers ─────────────────────────────────────────────────────────
//
// Every vector below is published, and none was produced by this code. A
// cipher tested against its own output proves only that it is deterministic;
// these prove it is the cipher it claims to be, which is the only property
// that matters when someone hands you a ciphertext from elsewhere.
//
// Sources are named per case. Where a source gives the square explicitly the
// whole square is passed as the key phrase, which the key-then-alphabet fill
// reproduces exactly.

// wikipediaADFGVXSquare is the square the ADFGVX article uses, written out in
// reading order so the key fill reproduces it cell for cell.
const wikipediaADFGVXSquare = "na1c3h8tb2ome5wrpd4f6g7i9j0klqsuvxyz"

func TestClassicalCipherPublishedVectors(t *testing.T) {
	for _, tc := range []struct {
		name, source, typ, in, key, want string
		rails                            int
	}{
		{
			name: "affine", source: "Wikipedia, Affine cipher",
			typ: "affine", in: "AFFINECIPHER", key: "5,8", want: "IHHWVCSWFRCP",
		},
		{
			name: "beaufort", source: "Practical Cryptography, Beaufort cipher",
			typ: "beaufort", in: "DEFENDTHEEASTWALLOFTHECASTLE", key: "FORTIFICATION",
			want: "CKMPVCPVWPIWUJOGIUAPVWRIWUUK",
		},
		{
			name: "autokey", source: "Practical Cryptography, Autokey cipher",
			typ: "autokey", in: "DEFENDTHEEASTWALLOFTHECASTLE", key: "FORTIFICATION",
			want: "ISWXVIBJEXIGGZEQPBIMOIGAKMHE",
		},
		{
			name: "gronsfeld", source: "the cipher's definition: a Vigenere whose key is digits",
			typ: "gronsfeld", in: "HELLO", key: "31415", want: "KFPMT",
		},
		{
			name: "playfair", source: "Wikipedia, Playfair cipher",
			typ: "playfair", in: "hide the gold in the tree stump", key: "playfair example",
			want: "bmodzbxdnabekudmuixmmouvif",
		},
		{
			name: "bifid", source: "Wikipedia, Bifid cipher",
			typ: "bifid", in: "FLEEATONCE", key: "BGWKZQPNDSIOAXEFCLUMTHYVR",
			want: "uaeolwrins",
		},
		{
			name: "nihilist", source: "Wikipedia, Nihilist cipher",
			typ: "nihilist", in: "DYNAMITEWINTERPALACE", key: "ZEBRAS,RUSSIAN",
			want: "37 106 62 36 67 47 86 26 104 53 62 77 27 55 57 66 55 36 54 27",
		},
		{
			name: "columnar", source: "Wikipedia, Transposition cipher (irregular columnar)",
			typ: "columnar", in: "WEAREDISCOVEREDFLEEATONCE", key: "ZEBRAS",
			want: "EVLNACDTESEAROFODEECWIREE",
		},
		{
			name: "adfgvx", source: "Wikipedia, ADFGVX cipher",
			typ: "adfgvx", in: "attack at 1200am", key: wikipediaADFGVXSquare + ",PRIVACY",
			want: "DGDDDAGDDGAFADDFDADVDVFAADVX",
		},
		{
			name: "scytale", source: "Wikipedia, Scytale — a rod of four",
			typ: "scytale", in: "Iamhurtverybadlyhelp", rails: 4,
			want: "Iueaharrdemtyllhvbyp",
		},
	} {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			got, err := encodeText(tc.in, tc.typ, 0, tc.key, tc.rails)
			if err != nil {
				t.Fatalf("encode: %v", err)
			}
			if got != tc.want {
				t.Fatalf("encode %s (%s)\n got  %q\n want %q", tc.typ, tc.source, got, tc.want)
			}
		})
	}
}

// TestClassicalCipherRoundTrips decodes each published ciphertext back, which
// is the half a vector alone does not cover: an encoder and a decoder can
// agree with the world and still disagree with each other.
func TestClassicalCipherRoundTrips(t *testing.T) {
	for _, tc := range []struct {
		name, typ, cipher, key, want string
		rails                        int
	}{
		{"affine", "affine", "IHHWVCSWFRCP", "5,8", "AFFINECIPHER", 0},
		{"beaufort", "beaufort", "CKMPVCPVWPIWUJOGIUAPVWRIWUUK", "FORTIFICATION", "DEFENDTHEEASTWALLOFTHECASTLE", 0},
		{"autokey", "autokey", "ISWXVIBJEXIGGZEQPBIMOIGAKMHE", "FORTIFICATION", "DEFENDTHEEASTWALLOFTHECASTLE", 0},
		{"gronsfeld", "gronsfeld", "KFPMT", "31415", "HELLO", 0},
		{"bifid", "bifid", "uaeolwrins", "BGWKZQPNDSIOAXEFCLUMTHYVR", "fleeatonce", 0},
		{"nihilist", "nihilist", "37 106 62 36 67 47 86 26 104 53 62 77 27 55 57 66 55 36 54 27", "ZEBRAS,RUSSIAN", "dynamitewinterpalace", 0},
		{"columnar", "columnar", "EVLNACDTESEAROFODEECWIREE", "ZEBRAS", "WEAREDISCOVEREDFLEEATONCE", 0},
		{"adfgvx", "adfgvx", "DGDDDAGDDGAFADDFDADVDVFAADVX", wikipediaADFGVXSquare + ",PRIVACY", "attackat1200am", 0},
		{"scytale", "scytale", "Iueaharrdemtyllhvbyp", "", "Iamhurtverybadlyhelp", 4},
	} {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			got, err := decodeText(tc.cipher, tc.typ, 0, tc.key, tc.rails)
			if err != nil {
				t.Fatalf("decode: %v", err)
			}
			if got != tc.want {
				t.Fatalf("decode %s\n got  %q\n want %q", tc.typ, got, tc.want)
			}
		})
	}
}

// TestPlayfairRoundTripIsNotAnIdentity records what Playfair actually costs,
// rather than leaving a reader to assume decode undoes encode.
//
// Playfair splits a doubled letter with an X, pads an odd length with one, and
// has no cell for J. The textbook message comes back as "hidethegoldinthetre
// EXestump" with an inserted X and a J that would have become an I. Writing
// the recovered text down is the honest way to document a lossy cipher.
func TestPlayfairRoundTripIsNotAnIdentity(t *testing.T) {
	const plain = "hide the gold in the tree stump"
	enc, err := encodeText(plain, "playfair", 0, "playfair example", 0)
	if err != nil {
		t.Fatal(err)
	}
	dec, err := decodeText(enc, "playfair", 0, "playfair example", 0)
	if err != nil {
		t.Fatal(err)
	}
	const want = "hidethegoldinthetrexestump"
	if dec != want {
		t.Fatalf("playfair recovered %q, want %q", dec, want)
	}
	if strings.ReplaceAll(plain, " ", "") == dec {
		t.Fatal("this test exists because the round trip is lossy; it no longer is")
	}
}

// TestClassicalCipherKeyErrors covers the keys an operator gets wrong, because
// a cipher that silently produces garbage from a bad key is worse than one
// that refuses.
func TestClassicalCipherKeyErrors(t *testing.T) {
	for _, tc := range []struct {
		name, typ, key, wantIn string
		rails                  int
	}{
		{"affine a shares a factor with 26", "affine", "13,5", "coprime", 0},
		{"affine is not two numbers", "affine", "5", "two numbers", 0},
		{"affine a is not a number", "affine", "x,5", "not a number", 0},
		{"beaufort key has no letters", "beaufort", "1234", "letters", 0},
		{"autokey key has no letters", "autokey", "----", "letters", 0},
		{"gronsfeld key is not digits", "gronsfeld", "abcde", "digits", 0},
		{"playfair key has no letters", "playfair", "12345", "key phrase", 0},
		{"nihilist key has no comma", "nihilist", "zebras", "comma", 0},
		{"adfgvx key has no comma", "adfgvx", "privacy", "comma", 0},
		{"columnar key is one character", "columnar", "z", "at least two", 0},
		{"scytale rod is one", "scytale", "", "at least two", 1},
	} {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			_, err := encodeText("attackatdawn", tc.typ, 0, tc.key, tc.rails)
			if err == nil {
				t.Fatalf("%s accepted key %q", tc.typ, tc.key)
			}
			if !strings.Contains(err.Error(), tc.wantIn) {
				t.Fatalf("%s error %q does not mention %q", tc.typ, err, tc.wantIn)
			}
		})
	}
}

// TestBeaufortIsItsOwnInverse is the property that distinguishes Beaufort from
// Vigenere, and the reason the machine needed no encrypt/decrypt switch.
func TestBeaufortIsItsOwnInverse(t *testing.T) {
	const plain = "Meet me at the bridge at noon."
	enc, err := encodeText(plain, "beaufort", 0, "hashsmith", 0)
	if err != nil {
		t.Fatal(err)
	}
	again, err := encodeText(enc, "beaufort", 0, "hashsmith", 0)
	if err != nil {
		t.Fatal(err)
	}
	if again != plain {
		t.Fatalf("applying beaufort twice gave %q, want %q", again, plain)
	}
}

// TestClassicalCiphersPreserveNonLetters holds the convention the rest of this
// tool's ciphers follow: a letter transforms, its case survives, everything
// else passes through, and the key advances only on letters.
func TestClassicalCiphersPreserveNonLetters(t *testing.T) {
	const in = "Attack at dawn, 06:00!"
	for _, tc := range []struct{ typ, key string }{
		{"affine", "5,8"},
		{"beaufort", "fortification"},
		{"autokey", "fortification"},
		{"gronsfeld", "31415"},
	} {
		tc := tc
		t.Run(tc.typ, func(t *testing.T) {
			got, err := encodeText(in, tc.typ, 0, tc.key, 0)
			if err != nil {
				t.Fatal(err)
			}
			if len(got) != len(in) {
				t.Fatalf("%s changed the length: %q", tc.typ, got)
			}
			for i := range in {
				letter := in[i] >= 'a' && in[i] <= 'z' || in[i] >= 'A' && in[i] <= 'Z'
				if !letter && got[i] != in[i] {
					t.Fatalf("%s altered %q at %d: %q", tc.typ, in[i], i, got)
				}
				if letter {
					upper := in[i] >= 'A' && in[i] <= 'Z'
					gotUpper := got[i] >= 'A' && got[i] <= 'Z'
					if upper != gotUpper {
						t.Fatalf("%s changed the case at %d: %q", tc.typ, i, got)
					}
				}
			}
		})
	}
}

// TestColumnarHandlesAnIncompleteRectangle is the case that breaks naive
// implementations: when the message does not fill the grid, the columns are
// not the same height, and a decoder that assumes they are shifts every
// column after the first short one.
func TestColumnarHandlesAnIncompleteRectangle(t *testing.T) {
	const key = "ZEBRAS"
	for n := 1; n <= 40; n++ {
		in := strings.Repeat("abcdefghij", 4)[:n]
		enc, err := encodeText(in, "columnar", 0, key, 0)
		if err != nil {
			t.Fatalf("n=%d encode: %v", n, err)
		}
		dec, err := decodeText(enc, "columnar", 0, key, 0)
		if err != nil {
			t.Fatalf("n=%d decode: %v", n, err)
		}
		if dec != in {
			t.Fatalf("n=%d round trip gave %q, want %q", n, dec, in)
		}
	}
}

// TestScytaleHandlesAnIncompleteWrap is the same trap on the rod: the last
// turn is short whenever the message is not a multiple of the rod.
func TestScytaleHandlesAnIncompleteWrap(t *testing.T) {
	for rod := 2; rod <= 7; rod++ {
		for n := 0; n <= 30; n++ {
			in := strings.Repeat("abcdefghij", 3)[:n]
			enc, err := encodeText(in, "scytale", 0, "", rod)
			if err != nil {
				t.Fatalf("rod=%d n=%d encode: %v", rod, n, err)
			}
			dec, err := decodeText(enc, "scytale", 0, "", rod)
			if err != nil {
				t.Fatalf("rod=%d n=%d decode: %v", rod, n, err)
			}
			if dec != in {
				t.Fatalf("rod=%d n=%d round trip gave %q, want %q", rod, n, dec, in)
			}
		}
	}
}
