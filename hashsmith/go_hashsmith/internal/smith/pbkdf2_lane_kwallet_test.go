package smith

import (
	cryptorand "crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"testing"

	"golang.org/x/crypto/blowfish"
)

// kwalletHashcatVector mirrors selftest_vectors.go's own cross-checked
// vector, passphrase "openwall" — the LEGACY (minor 0) shape, used only to
// confirm the lane hasher correctly refuses it: it is not PBKDF2 at all.
const kwalletHashcatVector = "$kwallet$112$25be8c9cdaa53f5404d7809ff48a37752b325c8ccd296fbd537440dfcef9d66f72940e97141d21702b325c8ccd296fbd537440dfcef9d66fcd953cf1e41904b0c494ad1e718760e74c4487cc1449233d85525e7974da221774010bb9582b1d68b55ea9288f53a2be6bd15b93a5e1b33d"

// mustBuildKWalletMinor1Vector self-generates a minor-1 (PBKDF2-HMAC-
// SHA512) $kwallet$ record — no minor-1 vector exists in this project's
// fixtures. It builds the ciphertext by running kwalletMatches' own
// decrypt pipeline in reverse (CBC-encrypt with golang.org/x/crypto/
// blowfish, the same standard cipher production code already uses — not a
// custom construction), for a chosen plaintext shape that satisfies the
// check: 8 bytes of "randomness", a length field, and an all-zero entry
// table. TestPBKDF2KWalletLaneHasherMatchesGeneratedVector cross-checks
// the result against verifyKWallet directly, not just internal
// consistency.
func mustBuildKWalletMinor1Vector(t *testing.T) string {
	t.Helper()
	const password = "hashsmith"
	const salt = "0123456789abcdef0123456789abcdef"
	const iterations = 3
	const entryTableLen = 40

	var lanes [pbkdf2Sha512Lanes][]byte
	for i := range lanes {
		lanes[i] = []byte(password)
	}
	derived := pbkdf2HMACSHA512DeriveBatch(&lanes, []byte(salt), iterations)
	key := derived[0][:56]

	c, err := blowfish.NewCipher(key)
	if err != nil {
		t.Fatal(err)
	}

	plain := make([]byte, 64)
	if _, err := cryptorand.Read(plain[:8]); err != nil {
		t.Fatal(err)
	}
	binary.BigEndian.PutUint32(plain[8:12], entryTableLen)
	// Pre-compensate for kwalletMatches' own post-decrypt swap of the
	// length field, so the value it recovers is the one just written.
	alterEndianity(plain[8:12])
	// plain[12:64] stays zero — comfortably clears the >=12-NUL check over
	// the first 52 bytes of the entry table.

	buf := make([]byte, 64)
	copy(buf, plain)
	prev := append([]byte(nil), buf[:8]...)
	for off := 8; off+8 <= 64; off += 8 {
		xored := make([]byte, 8)
		for i := 0; i < 8; i++ {
			xored[i] = buf[off+i] ^ prev[i]
		}
		ctBlock := make([]byte, 8)
		c.Encrypt(ctBlock, xored)
		copy(buf[off:off+8], ctBlock)
		prev = ctBlock
	}
	// Undo the whole-buffer swap kwalletMatches applies before decrypting.
	alterEndianity(buf)

	const fileLen = 1000
	return "$kwallet$" + itoa(fileLen) + "$" + hex.EncodeToString(buf) +
		"$1$" + itoa(len(salt)) + "$" + hex.EncodeToString([]byte(salt)) + "$" + itoa(iterations)
}

func TestPBKDF2KWalletLaneHasherMatchesGeneratedVector(t *testing.T) {
	target := mustBuildKWalletMinor1Vector(t)
	h := newPBKDF2KWalletLaneHasher(target)
	if h == nil {
		t.Fatal("newPBKDF2KWalletLaneHasher refused the generated minor-1 record")
	}
	out := make([]bool, 1)
	h.Run([][]byte{[]byte("hashsmith")}, out)
	if !out[0] {
		t.Fatal("lane hasher did not match the generated record with the correct password")
	}
	h.Run([][]byte{[]byte("wrong")}, out)
	if out[0] {
		t.Fatal("lane hasher false-matched a wrong password against the generated record")
	}
	// Cross-check against the scalar path too, not just internal consistency.
	want, err := verifyKWallet(target, "hashsmith")
	if err != nil || !want {
		t.Fatalf("verifyKWallet on the generated record: ok=%v err=%v", want, err)
	}
}

func TestPBKDF2KWalletLaneHasherMatchesScalarAcrossBatchSizes(t *testing.T) {
	right := "the-right-password"
	target := mustBuildKWalletMinor1Vector(t)
	candidates := []string{
		"wrong1", "wrong2", "", "a", "12345678",
		"wrong3", right,
	}
	h := newPBKDF2KWalletLaneHasher(target)
	if h == nil {
		t.Fatal("newPBKDF2KWalletLaneHasher refused the generated record")
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
				want, err := verifyKWallet(target, candidates[i])
				if err != nil {
					t.Fatalf("verifyKWallet(%q): %v", candidates[i], err)
				}
				if out[i] != want {
					t.Errorf("batch of %d, candidate %q (position %d): lane hasher = %v, scalar = %v",
						n, candidates[i], i, out[i], want)
				}
			}
		})
	}
}

func TestPBKDF2KWalletLaneHasherIsStateless(t *testing.T) {
	right := "hashsmith"
	target := mustBuildKWalletMinor1Vector(t)
	h := newPBKDF2KWalletLaneHasher(target)
	if h == nil {
		t.Fatal("newPBKDF2KWalletLaneHasher refused the generated record")
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

func TestNewPBKDF2KWalletLaneHasherRefusesLegacyAndMalformedRecords(t *testing.T) {
	cases := []string{
		"",
		"not a record",
		kwalletHashcatVector, // minor 0 (legacy), the published vector's own shape
	}
	for _, c := range cases {
		if h := newPBKDF2KWalletLaneHasher(c); h != nil {
			t.Errorf("newPBKDF2KWalletLaneHasher(%q) should have been refused (legacy minor-0 record)", c)
		}
	}
}

func TestNewLaneHasherKWalletGateIsInternallyConsistent(t *testing.T) {
	target := mustBuildKWalletMinor1Vector(t)
	factory, lanes, ok := newLaneHasher("kwallet", target, "", "")
	wantOK := pbkdf2Sha512AVX2Eligible()
	if ok != wantOK {
		t.Fatalf("newLaneHasher(\"kwallet\", ...) eligible=%v, want %v (pbkdf2Sha512AVX2Eligible)", ok, wantOK)
	}
	if !ok {
		t.Skip("not eligible on this hardware/build — nothing further to check")
	}
	if lanes != pbkdf2Sha512Lanes {
		t.Fatalf("newLaneHasher(\"kwallet\", ...) lanes = %d, want %d", lanes, pbkdf2Sha512Lanes)
	}
	h := factory()
	if h == nil {
		t.Fatal("newLaneHasher(\"kwallet\", ...) factory returned nil despite reporting eligible")
	}
	out := make([]bool, 1)
	h.Run([][]byte{[]byte("hashsmith")}, out)
	if !out[0] {
		t.Fatal("the wired-up hasher did not match the generated record")
	}

	// The legacy shape must fall back to the scalar path.
	if _, _, ok := newLaneHasher("kwallet", kwalletHashcatVector, "", ""); ok {
		t.Fatal("newLaneHasher(\"kwallet\", ...) accepted a legacy (minor 0) record")
	}
}
