//go:build slowtest

package smith

import "testing"

// Purely slow KDF verification at production iteration counts (200000 or
// 500000, fixed by the mode — there is no reduced-iteration form of a
// VeraCrypt SHA-256 record to test against cheaply). Moved out of the
// default suite for the same reason
// crack_hashcat_crypt_cascades_slow_test.go's own representatives are:
// see that file's comment. Fast structural coverage (malformed-record and
// wrong-KDF refusal) lives in pbkdf2_lane_veracrypt_test.go, untagged.
func TestPBKDF2VeraCryptSHA256LaneHasherMatchesPublishedVectors(t *testing.T) {
	for _, typ := range []string{
		"veracrypt-sha256-xts1024", "veracrypt-sha256-xts1536",
		"veracrypt-sha256-boot-xts512", "veracrypt-sha256-boot-xts1024", "veracrypt-sha256-boot-xts1536",
	} {
		t.Run(typ, func(t *testing.T) {
			v := publishedVectorForType(t, typ)
			mode := cryptCascadeModes[typ]
			h := newPBKDF2VeraCryptSHA256LaneHasher(v.target, mode)
			if h == nil {
				t.Fatalf("newPBKDF2VeraCryptSHA256LaneHasher refused %s's own published record", typ)
			}
			out := make([]bool, 1)
			h.Run([][]byte{[]byte(v.password)}, out)
			if !out[0] {
				t.Fatalf("lane hasher did not match %s's own published record with the correct password", typ)
			}
			h.Run([][]byte{[]byte("wrong")}, out)
			if out[0] {
				t.Fatalf("lane hasher false-matched a wrong password against %s's own published record", typ)
			}
		})
	}
}

// TestPBKDF2VeraCryptSHA256LaneHasherMatchesScalarInAFullGroup checks one
// mode's lane hasher against the scalar path for a full 8-candidate group
// (the width the real AVX2 core actually batches), rather than every batch
// size 1-9 the way faster formats' tests do — each additional candidate
// here costs another 200000-round scalar PBKDF2-SHA256 call, so this stays
// to one representative mode and one group.
func TestPBKDF2VeraCryptSHA256LaneHasherMatchesScalarInAFullGroup(t *testing.T) {
	const typ = "veracrypt-sha256-boot-xts512"
	v := publishedVectorForType(t, typ)
	mode := cryptCascadeModes[typ]
	h := newPBKDF2VeraCryptSHA256LaneHasher(v.target, mode)
	if h == nil {
		t.Fatalf("newPBKDF2VeraCryptSHA256LaneHasher refused %s's own published record", typ)
	}

	candidates := []string{
		"wrong1", "wrong2", "wrong3", "wrong4", "wrong5", "wrong6", "wrong7", v.password,
	}
	pw := make([][]byte, len(candidates))
	for i, c := range candidates {
		pw[i] = []byte(c)
	}
	out := make([]bool, len(candidates))
	h.Run(pw, out)
	for i, c := range candidates {
		want, err := verifyCandidate(c, v.target, typ, "", "prefix")
		if err != nil {
			t.Fatalf("verifyCandidate(%q): %v", c, err)
		}
		if out[i] != want {
			t.Errorf("candidate %q (position %d): lane hasher = %v, scalar = %v", c, i, out[i], want)
		}
	}
}
