package smith

import (
	"crypto/aes"
	"crypto/sha1"
	"crypto/sha512"
	"encoding/hex"
	"fmt"
	"testing"

	"golang.org/x/crypto/pbkdf2"
)

// aesIGEEncryptForTest is aesIGEDecrypt's forward twin, needed only to
// build a self-generated version-2 vector below: no published or
// crosschecked version-2 (SHA-512) Telegram Desktop vector exists in this
// codebase (selftest_vectors.go's own telegramDesktopPublishedRecord is
// version 1, SHA-1). Standard AES-IGE encryption is
// C_i = E(P_i xor C_{i-1}) xor P_{i-1}, the exact inverse of
// aesIGEDecrypt's P_i = D(C_i xor P_{i-1}) xor C_{i-1} — derived by reading
// that function's iv1/iv2 roles (iv1 tracks the previous ciphertext block,
// iv2 the previous plaintext block) and solving for encryption instead of
// decryption.
func aesIGEEncryptForTest(plain, key, iv []byte) []byte {
	block, err := aes.NewCipher(key)
	if err != nil {
		panic(err)
	}
	iv1 := append([]byte(nil), iv[:aes.BlockSize]...)
	iv2 := append([]byte(nil), iv[aes.BlockSize:]...)
	out := make([]byte, len(plain))
	tmp := make([]byte, aes.BlockSize)
	for at := 0; at < len(plain); at += aes.BlockSize {
		p := plain[at : at+aes.BlockSize]
		for i := 0; i < aes.BlockSize; i++ {
			tmp[i] = p[i] ^ iv1[i]
		}
		block.Encrypt(out[at:at+aes.BlockSize], tmp)
		for i := 0; i < aes.BlockSize; i++ {
			out[at+i] ^= iv2[i]
		}
		copy(iv1, out[at:at+aes.BlockSize])
		copy(iv2, p)
	}
	return out
}

// mustBuildTelegramDesktopV2Vector builds a version-2 "$telegram$2*..."
// record for the given salt/iterations/candidate, using the exact same
// production primitives verifyTelegramDesktop and telegramCheckPassword
// use (golang.org/x/crypto/pbkdf2 with sha512.New, and the same SHA-1
// key/iv derivation chain telegramCheckPassword itself computes) —
// inverted into an encrypt rather than a decrypt, since no published
// vector exists to check against. The caller must still cross-check the
// result against verifyTelegramDesktop directly, not merely trust this
// construction — see the test below.
func mustBuildTelegramDesktopV2Vector(t *testing.T, salt []byte, iterations int, candidate string) string {
	t.Helper()
	preimage := make([]byte, 0, len(salt)*2+len(candidate))
	preimage = append(preimage, salt...)
	preimage = append(preimage, candidate...)
	preimage = append(preimage, salt...)
	first := sha512.Sum512(preimage)
	authKey := pbkdf2.Key(first[:], salt, iterations, 136, sha512.New)

	plain := make([]byte, 32)
	for i := range plain {
		plain[i] = byte(i*7 + 3)
	}
	mk := sha1.Sum(plain)
	messageKey := mk[:16]

	hashA := sha1.Sum(append(append([]byte(nil), messageKey...), authKey[8:40]...))
	b := append(append([]byte(nil), authKey[40:56]...), messageKey...)
	b = append(b, authKey[56:72]...)
	hashB := sha1.Sum(b)
	c := append(append([]byte(nil), authKey[72:104]...), messageKey...)
	hashC := sha1.Sum(c)
	d := append(append([]byte(nil), messageKey...), authKey[104:136]...)
	hashD := sha1.Sum(d)

	key := append(append([]byte(nil), hashA[:8]...), hashB[8:20]...)
	key = append(key, hashC[4:16]...)
	iv := append(append([]byte(nil), hashA[8:20]...), hashB[:8]...)
	iv = append(iv, hashC[16:20]...)
	iv = append(iv, hashD[:8]...)

	ct := aesIGEEncryptForTest(plain, key, iv)
	blob := append(append([]byte(nil), messageKey...), ct...)

	target := fmt.Sprintf("$telegram$2*%d*%s*%s", iterations, hex.EncodeToString(salt), hex.EncodeToString(blob))
	ok, err := verifyTelegramDesktop(target, candidate)
	if err != nil || !ok {
		t.Fatalf("mustBuildTelegramDesktopV2Vector: constructed vector does not verify against its own candidate (ok=%v, err=%v) — construction is wrong", ok, err)
	}
	return target
}

const telegramDesktopV2Iterations = 2000

var telegramDesktopV2Salt = []byte("hashsmith-telegram-v2-salt")

func telegramDesktopV2Vector(t *testing.T) string {
	return mustBuildTelegramDesktopV2Vector(t, telegramDesktopV2Salt, telegramDesktopV2Iterations, "hashsmith")
}

func TestPBKDF2TelegramDesktopV2LaneHasherMatchesSelfGeneratedVector(t *testing.T) {
	target := telegramDesktopV2Vector(t)
	h := newPBKDF2TelegramDesktopV2LaneHasher(target)
	if h == nil {
		t.Fatal("newPBKDF2TelegramDesktopV2LaneHasher refused the self-generated record")
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
}

func TestPBKDF2TelegramDesktopV2LaneHasherMatchesScalarAcrossBatchSizes(t *testing.T) {
	target := telegramDesktopV2Vector(t)
	right := "hashsmith"
	candidates := []string{
		"wrong1", "wrong2", "", "a", "12345678",
		"wrong3", right,
	}
	h := newPBKDF2TelegramDesktopV2LaneHasher(target)
	if h == nil {
		t.Fatal("newPBKDF2TelegramDesktopV2LaneHasher refused the self-generated record")
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
				want, err := verifyTelegramDesktop(target, candidates[i])
				if err != nil {
					t.Fatalf("verifyTelegramDesktop(%q): %v", candidates[i], err)
				}
				if out[i] != want {
					t.Errorf("batch of %d, candidate %q (position %d): lane hasher = %v, scalar = %v",
						n, candidates[i], i, out[i], want)
				}
			}
		})
	}
}

func TestPBKDF2TelegramDesktopV2LaneHasherIsStateless(t *testing.T) {
	target := telegramDesktopV2Vector(t)
	right := "hashsmith"
	h := newPBKDF2TelegramDesktopV2LaneHasher(target)
	if h == nil {
		t.Fatal("newPBKDF2TelegramDesktopV2LaneHasher refused the self-generated record")
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

func TestNewPBKDF2TelegramDesktopV2LaneHasherRefusesVersion1AndMalformedRecords(t *testing.T) {
	cases := []string{
		"",
		"not a record",
		telegramDesktopPublishedRecord, // version 1
		"$telegram$2*AA*AA*AA",
	}
	for _, c := range cases {
		if h := newPBKDF2TelegramDesktopV2LaneHasher(c); h != nil {
			t.Errorf("newPBKDF2TelegramDesktopV2LaneHasher(%q) should have been refused", c)
		}
	}
}

func TestNewLaneHasherTelegramDesktopV2GateIsInternallyConsistent(t *testing.T) {
	target := telegramDesktopV2Vector(t)
	factory, lanes, ok := newLaneHasher("telegram-desktop", target, "", "")
	wantOK := pbkdf2Sha512AVX2Eligible()
	if ok != wantOK {
		t.Fatalf("newLaneHasher(\"telegram-desktop\", ...) eligible=%v, want %v (pbkdf2Sha512AVX2Eligible)", ok, wantOK)
	}
	if !ok {
		t.Skip("not eligible on this hardware/build — nothing further to check")
	}
	if lanes != pbkdf2Sha512Lanes {
		t.Fatalf("newLaneHasher(\"telegram-desktop\", ...) lanes = %d, want %d", lanes, pbkdf2Sha512Lanes)
	}
	h := factory()
	if h == nil {
		t.Fatal("newLaneHasher(\"telegram-desktop\", ...) factory returned nil despite reporting eligible")
	}
	out := make([]bool, 1)
	h.Run([][]byte{[]byte("hashsmith")}, out)
	if !out[0] {
		t.Fatal("the wired-up hasher did not match the self-generated record")
	}
}
