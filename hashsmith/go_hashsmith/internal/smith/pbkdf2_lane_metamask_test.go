package smith

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"testing"

	"golang.org/x/crypto/pbkdf2"
)

// mustBuildMetaMaskVector self-generates a $metamask$ (long, standard
// AES-GCM) record — no published vector exists in this project's fixtures.
// It uses the same stdlib GCM Seal that metaMaskOpens's Open call inverts,
// so this is a standard, independently-specified construction, not a
// custom cipher mode (unlike VirtualBox's AES-XTS, which this project has
// not yet built a test encoder for).
func mustBuildMetaMaskVector(t *testing.T, password string) string {
	t.Helper()
	salt := make([]byte, 32)
	if _, err := rand.Read(salt); err != nil {
		t.Fatalf("rand.Read(salt): %v", err)
	}
	nonce := make([]byte, 16)
	if _, err := rand.Read(nonce); err != nil {
		t.Fatalf("rand.Read(nonce): %v", err)
	}
	key := pbkdf2.Key([]byte(password), salt, metaMaskIterations, 32, sha256.New)
	block, err := aes.NewCipher(key)
	if err != nil {
		t.Fatalf("aes.NewCipher: %v", err)
	}
	gcm, err := cipher.NewGCMWithNonceSize(block, len(nonce))
	if err != nil {
		t.Fatalf("cipher.NewGCMWithNonceSize: %v", err)
	}
	ct := gcm.Seal(nil, nonce, []byte(`{"data":"a MetaMask vault plaintext long enough to pass the length check"}`), nil)
	return "$metamask$" + base64.StdEncoding.EncodeToString(salt) + "$" +
		base64.StdEncoding.EncodeToString(nonce) + "$" + base64.StdEncoding.EncodeToString(ct)
}

func TestPBKDF2MetaMaskLaneHasherMatchesGeneratedVector(t *testing.T) {
	target := mustBuildMetaMaskVector(t, "hashsmith")
	h := newPBKDF2MetaMaskLaneHasher(target)
	if h == nil {
		t.Fatal("newPBKDF2MetaMaskLaneHasher refused the generated record")
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
	want, err := verifyMetaMask(target, "hashsmith", false)
	if err != nil || !want {
		t.Fatalf("verifyMetaMask on the generated record: ok=%v err=%v", want, err)
	}
}

func TestPBKDF2MetaMaskLaneHasherMatchesScalarAcrossBatchSizes(t *testing.T) {
	right := "the-right-password"
	target := mustBuildMetaMaskVector(t, right)
	candidates := []string{
		"wrong1", "wrong2", "", "a", "12345678", "wrong3",
		"wrong4", "wrong5", right,
	}
	h := newPBKDF2MetaMaskLaneHasher(target)
	if h == nil {
		t.Fatal("newPBKDF2MetaMaskLaneHasher refused the generated record")
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
				want, err := verifyMetaMask(target, candidates[i], false)
				if err != nil {
					t.Fatalf("verifyMetaMask(%q): %v", candidates[i], err)
				}
				if out[i] != want {
					t.Errorf("batch of %d, candidate %q (position %d): lane hasher = %v, scalar = %v",
						n, candidates[i], i, out[i], want)
				}
			}
		})
	}
}

func TestPBKDF2MetaMaskLaneHasherIsStateless(t *testing.T) {
	right := "hashsmith"
	target := mustBuildMetaMaskVector(t, right)
	h := newPBKDF2MetaMaskLaneHasher(target)
	if h == nil {
		t.Fatal("newPBKDF2MetaMaskLaneHasher refused the generated record")
	}

	full := make([][]byte, pbkdf2Sha256Lanes)
	for i := range full {
		full[i] = []byte(right)
	}
	fullOut := make([]bool, pbkdf2Sha256Lanes)
	h.Run(full, fullOut)
	for i, ok := range fullOut {
		if !ok {
			t.Fatalf("full group lane %d: expected a match, got none", i)
		}
	}

	shortWrong := [][]byte{[]byte("nope"), []byte("still nope")}
	shortOut := make([]bool, len(shortWrong))
	h.Run(shortWrong, shortOut)
	for i, ok := range shortOut {
		if ok {
			t.Fatalf("short batch lane %d: false match after a prior full-group hit — stale state leaked", i)
		}
	}
}

func TestNewPBKDF2MetaMaskLaneHasherRefusesShortVariantAndMalformedRecords(t *testing.T) {
	cases := []string{
		"",
		"not a record",
		"$metamask-short$AA==$AA==$AA==",
		"$metamask$not-base64$x$y",
	}
	for _, c := range cases {
		if h := newPBKDF2MetaMaskLaneHasher(c); h != nil {
			t.Errorf("newPBKDF2MetaMaskLaneHasher(%q) should have been refused", c)
		}
	}
}

func TestNewLaneHasherMetaMaskGateIsInternallyConsistent(t *testing.T) {
	target := mustBuildMetaMaskVector(t, "hashsmith")
	factory, lanes, ok := newLaneHasher("metamask", target, "", "")
	wantOK := pbkdf2Sha256AVX2Eligible()
	if ok != wantOK {
		t.Fatalf("newLaneHasher(\"metamask\", ...) eligible=%v, want %v (pbkdf2Sha256AVX2Eligible)", ok, wantOK)
	}
	if !ok {
		t.Skip("not eligible on this hardware/build — nothing further to check")
	}
	if lanes != pbkdf2Sha256Lanes {
		t.Fatalf("newLaneHasher(\"metamask\", ...) lanes = %d, want %d", lanes, pbkdf2Sha256Lanes)
	}
	h := factory()
	if h == nil {
		t.Fatal("newLaneHasher(\"metamask\", ...) factory returned nil despite reporting eligible")
	}
	out := make([]bool, 1)
	h.Run([][]byte{[]byte("hashsmith")}, out)
	if !out[0] {
		t.Fatal("the wired-up hasher did not match the generated record")
	}
}
