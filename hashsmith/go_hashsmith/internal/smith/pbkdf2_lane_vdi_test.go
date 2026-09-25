package smith

import (
	"crypto/aes"
	"crypto/sha512"
	"encoding/hex"
	"fmt"
	"testing"

	"golang.org/x/crypto/pbkdf2"
	"golang.org/x/crypto/xts"
)

// mustBuildVDISHA512Vector builds a "$vdi$" record using the SHA-512
// digest variant, using the exact same production primitives verifyVDI
// itself uses (golang.org/x/crypto/pbkdf2 and golang.org/x/crypto/xts) —
// only in the forward (encrypt) direction, since no published SHA-512 VDI
// vector exists in this codebase (selftest_vectors.go's own "vdi" entry is
// SHA-256). The caller must still cross-check the result against verifyVDI
// directly, not merely trust this construction — see the test below.
func mustBuildVDISHA512Vector(t *testing.T, candidate string, keyLen int) string {
	t.Helper()
	keySalt := []byte("vdi-key-salt-16b")
	endSalt := []byte("vdi-final-salt16")
	const keyIter = 500
	const endIter = 500
	const digestLen = 64

	key := pbkdf2.Key([]byte(candidate), keySalt, keyIter, keyLen, sha512.New)
	dek := make([]byte, keyLen)
	for i := range dek {
		dek[i] = byte(i*13 + 1)
	}
	c, err := xts.NewCipher(aes.NewCipher, key)
	if err != nil {
		t.Fatalf("xts.NewCipher: %v", err)
	}
	encKey := make([]byte, keyLen)
	c.Encrypt(encKey, dek, 0)

	want := pbkdf2.Key(dek, endSalt, endIter, digestLen, sha512.New)

	cipherName := "aes-xts128"
	if keyLen == 64 {
		cipherName = "aes-xts256"
	}
	target := fmt.Sprintf("$vdi$%s$sha512$%d$%d$%d$%d$%s$%s$%s$%s",
		cipherName, keyIter, endIter, keyLen, digestLen,
		hex.EncodeToString(keySalt), hex.EncodeToString(endSalt),
		hex.EncodeToString(encKey), hex.EncodeToString(want))

	ok, err := verifyVDI(target, candidate)
	if err != nil || !ok {
		t.Fatalf("mustBuildVDISHA512Vector: constructed vector does not verify against its own candidate (ok=%v, err=%v) — construction is wrong", ok, err)
	}
	return target
}

func TestPBKDF2VDILaneHasherMatchesSelfGeneratedVector(t *testing.T) {
	for _, keyLen := range []int{32, 64} {
		t.Run(itoa(keyLen), func(t *testing.T) {
			target := mustBuildVDISHA512Vector(t, "hashsmith", keyLen)
			h := newPBKDF2VDILaneHasher(target)
			if h == nil {
				t.Fatal("newPBKDF2VDILaneHasher refused the self-generated record")
			}
			out := make([]bool, 1)
			h.Run([][]byte{[]byte("hashsmith")}, out)
			if !out[0] {
				t.Fatal("lane hasher did not match the self-generated record with the correct password")
			}
			h.Run([][]byte{[]byte("wrong")}, out)
			if out[0] {
				t.Fatal("lane hasher false-matched a wrong password against the self-generated record")
			}
		})
	}
}

func TestPBKDF2VDILaneHasherMatchesScalarAcrossBatchSizes(t *testing.T) {
	right := "hashsmith"
	candidates := []string{
		"wrong1", "wrong2", "", "a", "12345678",
		"wrong3", right,
	}
	target := mustBuildVDISHA512Vector(t, right, 64)
	h := newPBKDF2VDILaneHasher(target)
	if h == nil {
		t.Fatal("newPBKDF2VDILaneHasher refused the self-generated record")
	}

	for n := 1; n <= len(candidates); n++ {
		n := n
		t.Run(itoa(n), func(t *testing.T) {
			pw := make([][]byte, n)
			for i := 0; i < n; i++ {
				pw[i] = []byte(candidates[i])
			}
			out := make([]bool, n)
			h.Run(pw, out)
			for i := 0; i < n; i++ {
				want, err := verifyVDI(target, candidates[i])
				if err != nil {
					t.Fatalf("verifyVDI(%q): %v", candidates[i], err)
				}
				if out[i] != want {
					t.Errorf("batch of %d, candidate %q (position %d): lane hasher = %v, scalar = %v",
						n, candidates[i], i, out[i], want)
				}
			}
		})
	}
}

func TestPBKDF2VDILaneHasherIsStateless(t *testing.T) {
	right := "hashsmith"
	target := mustBuildVDISHA512Vector(t, right, 64)
	h := newPBKDF2VDILaneHasher(target)
	if h == nil {
		t.Fatal("newPBKDF2VDILaneHasher refused the self-generated record")
	}

	full := make([][]byte, pbkdf2Sha512Lanes)
	for i := range full {
		full[i] = []byte(right)
	}
	fullOut := make([]bool, pbkdf2Sha512Lanes)
	h.Run(full, fullOut)
	for i, ok := range fullOut {
		if !ok {
			t.Fatalf("full group lane %d: expected a match, got none", i)
		}
	}

	shortWrong := [][]byte{[]byte("nope")}
	shortOut := make([]bool, len(shortWrong))
	h.Run(shortWrong, shortOut)
	for i, ok := range shortOut {
		if ok {
			t.Fatalf("short batch lane %d: false match after a prior full-group hit — stale state leaked", i)
		}
	}
}

func TestNewPBKDF2VDILaneHasherRefusesSHA256AndMalformedRecords(t *testing.T) {
	const vdiSHA256Vector = "$vdi$aes-xts256$sha256$2000$2000$64$32$709f6df123f1ccb126ea1f3e565beb78d39cafdc98e0daa2e42cc43cef11f786$0340f137136ad54f59f4b24ef0bf35240e140dfd56bbc19ce70aee6575f0aabf$0a27e178f47a0b05a752d6e917b89ef4205c6ae76705c34858390f8afa6cf03a45d98fab53b76d8d1c68507e7810633db4b83501a2496b7e443eccb53dbc8473$7ac5f4ad6286406e84af31fd36881cf558d375ae29085b08e6f65ebfd15376ca"
	cases := []string{
		"",
		"not a record",
		vdiSHA256Vector,
	}
	for _, c := range cases {
		if h := newPBKDF2VDILaneHasher(c); h != nil {
			t.Errorf("newPBKDF2VDILaneHasher(%q) should have been refused", c)
		}
	}
}

func TestNewLaneHasherVDIGateIsInternallyConsistent(t *testing.T) {
	target := mustBuildVDISHA512Vector(t, "hashsmith", 64)
	factory, lanes, ok := newLaneHasher("vdi", target, "", "")
	wantOK := pbkdf2Sha512AVX2Eligible()
	if ok != wantOK {
		t.Fatalf("newLaneHasher(\"vdi\", ...) eligible=%v, want %v (pbkdf2Sha512AVX2Eligible)", ok, wantOK)
	}
	if !ok {
		t.Skip("not eligible on this hardware/build — nothing further to check")
	}
	if lanes != pbkdf2Sha512Lanes {
		t.Fatalf("newLaneHasher(\"vdi\", ...) lanes = %d, want %d", lanes, pbkdf2Sha512Lanes)
	}
	h := factory()
	if h == nil {
		t.Fatal("newLaneHasher(\"vdi\", ...) factory returned nil despite reporting eligible")
	}
	out := make([]bool, 1)
	h.Run([][]byte{[]byte("hashsmith")}, out)
	if !out[0] {
		t.Fatal("the wired-up hasher did not match the self-generated record")
	}
}
