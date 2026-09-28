package smith

import (
	"crypto/aes"
	"crypto/sha256"
	"encoding/base64"
	"testing"

	"golang.org/x/crypto/pbkdf2"
)

// lastPassColonHashcatVector mirrors crack_hashcat_more_records_test.go's
// own hashcat mode 6800 vector, passphrase "hashcat".
const lastPassColonHashcatVector = "02eb97e869e0ddc7dc760fc633b4b54d:100100:pmix@trash-mail.com:9b071db7b8e265d4cadd3eb65ac0864a"

// mustBuildLastPassJohnVector builds a $lastpass$ record in John's own
// spelling (no published vector exists in this project's fixtures): a real
// PBKDF2-HMAC-SHA256 derivation of lastPassJohnGeneratedPass salted by the
// email below, at a low iteration count for a fast test, with the AES-ECB
// verifier encoded exactly as lastPassJohnMatches expects — the same
// stdlib primitives production code uses, just run forward instead of
// checked. TestPBKDF2LastPassRecordsLaneHasherMatchesJohnGeneratedVector
// cross-checks the result against verifyLastPassJohn, not just internal
// consistency.
const (
	lastPassJohnGeneratedEmail = "generated@example.com"
	lastPassJohnGeneratedPass  = "hashsmith"
	lastPassJohnGeneratedIter  = 500
)

func mustBuildLastPassJohnVector(t *testing.T) string {
	t.Helper()
	key := pbkdf2.Key([]byte(lastPassJohnGeneratedPass), []byte(lastPassJohnGeneratedEmail), lastPassJohnGeneratedIter, 32, sha256.New)
	block, err := aes.NewCipher(key)
	if err != nil {
		t.Fatalf("aes.NewCipher: %v", err)
	}
	pad := 16 - len(lastPassJohnGeneratedEmail)%16
	plain := append([]byte(lastPassJohnGeneratedEmail), make([]byte, pad)...)
	for i := len(plain) - pad; i < len(plain); i++ {
		plain[i] = byte(pad)
	}
	want := make([]byte, len(plain))
	for i := 0; i < len(plain); i += 16 {
		block.Encrypt(want[i:i+16], plain[i:i+16])
	}
	return "$lastpass$" + lastPassJohnGeneratedEmail + "$" +
		itoa(lastPassJohnGeneratedIter) + "$" + base64.StdEncoding.EncodeToString(want)
}

func TestPBKDF2LastPassRecordsLaneHasherMatchesColonHashcatVector(t *testing.T) {
	h := newPBKDF2LastPassRecordsLaneHasher(lastPassColonHashcatVector)
	if h == nil {
		t.Fatal("newPBKDF2LastPassRecordsLaneHasher refused hashcat's own published record")
	}
	out := make([]bool, 1)
	h.Run([][]byte{[]byte("hashcat")}, out)
	if !out[0] {
		t.Fatal("lane hasher did not match hashcat's own published record with the correct password")
	}
	h.Run([][]byte{[]byte("wrong")}, out)
	if out[0] {
		t.Fatal("lane hasher false-matched a wrong password against hashcat's own record")
	}
}

func TestPBKDF2LastPassRecordsLaneHasherMatchesJohnGeneratedVector(t *testing.T) {
	target := mustBuildLastPassJohnVector(t)
	h := newPBKDF2LastPassRecordsLaneHasher(target)
	if h == nil {
		t.Fatal("newPBKDF2LastPassRecordsLaneHasher refused the generated John-spelling record")
	}
	out := make([]bool, 1)
	h.Run([][]byte{[]byte(lastPassJohnGeneratedPass)}, out)
	if !out[0] {
		t.Fatal("lane hasher did not match the generated record with the correct password")
	}
	h.Run([][]byte{[]byte("wrong")}, out)
	if out[0] {
		t.Fatal("lane hasher false-matched a wrong password against the generated record")
	}
	// Cross-check against the scalar path too, not just internal consistency.
	want, err := verifyLastPassJohn(target, lastPassJohnGeneratedPass)
	if err != nil || !want {
		t.Fatalf("verifyLastPassJohn on the generated record: ok=%v err=%v", want, err)
	}
}

func TestPBKDF2LastPassRecordsLaneHasherMatchesScalarAcrossBatchSizes(t *testing.T) {
	for _, tc := range []struct {
		name   string
		target string
		right  string
	}{
		{"colon", lastPassColonHashcatVector, "hashcat"},
		{"john", mustBuildLastPassJohnVector(t), lastPassJohnGeneratedPass},
	} {
		t.Run(tc.name, func(t *testing.T) {
			candidates := []string{
				"wrong1", "wrong2", "", "a", "12345678", "wrong3",
				"wrong4", "wrong5", tc.right,
			}
			h := newPBKDF2LastPassRecordsLaneHasher(tc.target)
			if h == nil {
				t.Fatal("newPBKDF2LastPassRecordsLaneHasher refused the record")
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
						want, err := verifyLastPass(tc.target, candidates[i])
						if err != nil {
							t.Fatalf("verifyLastPass(%q): %v", candidates[i], err)
						}
						if out[i] != want {
							t.Errorf("batch of %d, candidate %q (position %d): lane hasher = %v, scalar = %v",
								n, candidates[i], i, out[i], want)
						}
					}
				})
			}
		})
	}
}

func TestPBKDF2LastPassRecordsLaneHasherIsStateless(t *testing.T) {
	h := newPBKDF2LastPassRecordsLaneHasher(lastPassColonHashcatVector)
	if h == nil {
		t.Fatal("newPBKDF2LastPassRecordsLaneHasher refused hashcat's own published record")
	}

	full := make([][]byte, pbkdf2Sha256Lanes)
	for i := range full {
		full[i] = []byte("hashcat")
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

func TestNewPBKDF2LastPassRecordsLaneHasherRefusesMalformedRecords(t *testing.T) {
	cases := []string{
		"",
		"not a record",
		"$lastpass$",
		"toofew:100:salt",
	}
	for _, c := range cases {
		if h := newPBKDF2LastPassRecordsLaneHasher(c); h != nil {
			t.Errorf("newPBKDF2LastPassRecordsLaneHasher(%q) should have been refused", c)
		}
	}
}

func TestNewLaneHasherLastPassGateIsInternallyConsistent(t *testing.T) {
	factory, lanes, ok := newLaneHasher("lastpass", lastPassColonHashcatVector, "", "")
	wantOK := pbkdf2Sha256AVX2Eligible()
	if ok != wantOK {
		t.Fatalf("newLaneHasher(\"lastpass\", ...) eligible=%v, want %v (pbkdf2Sha256AVX2Eligible)", ok, wantOK)
	}
	if !ok {
		t.Skip("not eligible on this hardware/build — nothing further to check")
	}
	if lanes != pbkdf2Sha256Lanes {
		t.Fatalf("newLaneHasher(\"lastpass\", ...) lanes = %d, want %d", lanes, pbkdf2Sha256Lanes)
	}
	h := factory()
	if h == nil {
		t.Fatal("newLaneHasher(\"lastpass\", ...) factory returned nil despite reporting eligible")
	}
	out := make([]bool, 1)
	h.Run([][]byte{[]byte("hashcat")}, out)
	if !out[0] {
		t.Fatal("the wired-up hasher did not match hashcat's own published record")
	}
}
