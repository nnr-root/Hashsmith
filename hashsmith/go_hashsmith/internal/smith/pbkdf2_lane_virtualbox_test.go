package smith

import (
	"bytes"
	"crypto/aes"
	"crypto/rand"
	"testing"

	"golang.org/x/crypto/xts"
)

// TestDecryptXTSZeroTweakAgainstIndependentXTS cross-checks
// decryptXTSZeroTweak — VirtualBox's own hand-written AES-XTS reader —
// against golang.org/x/crypto/xts, an independent, already-vendored
// implementation, using data-unit-number 0 (an all-zero tweak plaintext,
// which is exactly what "ZeroTweak" in the name means). No test in this
// project validated decryptXTSZeroTweak against anything before this: the
// only pre-existing VirtualBox tests checked detection and malformed-record
// rejection, never a real decrypt. This is the reason wiring an AVX2 lane
// hasher for VirtualBox could be trusted at all.
func TestDecryptXTSZeroTweakAgainstIndependentXTS(t *testing.T) {
	for trial := 0; trial < 20; trial++ {
		key := make([]byte, 32)
		if _, err := rand.Read(key); err != nil {
			t.Fatal(err)
		}
		ct := make([]byte, 32)
		if _, err := rand.Read(ct); err != nil {
			t.Fatal(err)
		}
		got, err := decryptXTSZeroTweak(key, ct)
		if err != nil {
			t.Fatal(err)
		}
		c, err := xts.NewCipher(aes.NewCipher, key)
		if err != nil {
			t.Fatal(err)
		}
		want := make([]byte, len(ct))
		c.Decrypt(want, ct, 0)
		if !bytes.Equal(got, want) {
			t.Fatalf("trial %d: decryptXTSZeroTweak disagrees with x/crypto/xts.Decrypt(...,0)\n got=%x\nwant=%x", trial, got, want)
		}
	}
}

// virtualBoxAES128HashcatVector mirrors selftest_vectors_hashcat_batch.go's
// own published vector (Hashcat mode 27500), password "hashcat". keyWords=8
// (AES-128-XTS), the variant the lane hasher accelerates.
const virtualBoxAES128HashcatVector = "$vbox$0$260000$fcc37189521686699a43e49514b91f159306be108b98895666583cd15c3e206b$8$288c3957db47e7c3dff2f7932121eb3395d21ab76b9cf3de2dc660310a25e7ad$20000$8847cd90f8acef74bae41155392908780eebb1d16452aa09b2f7b6cd7d8a4096$9f4d615b484f95c73944a98f392a3ce04f93403e8bb6257e6b6c854273d3a08a"

// virtualBoxAES256HashcatVector mirrors the same file's mode 27600 vector,
// also password "hashcat". keyWords=16 (AES-256-XTS) — used only to confirm
// the lane hasher correctly refuses it (a 64-byte first-stage key needs
// multi-block PBKDF2).
const virtualBoxAES256HashcatVector = "$vbox$0$160000$54aff69fca91c20b3b15618c6732c4a2f953dd88690cd4cc731569b6b80b5572$16$cfb003087e0c618afa9ad7e44adcd97517f039e0424dedb46db8affbb73cd064019abae19ee5e4f5b05b626e6bc5d7da65c61a5f94d7bcac521c388276e5358b$20000$2e5729055136168eea79cb3f1765450a35ab7540125f2ca2a46924a99fd0524d$b28d1db1cabe99ca989a405c33a27beeb9c0683b8b4b54b0e0d85f712f64d89c"

func TestPBKDF2VirtualBoxLaneHasherMatchesHashcatVector(t *testing.T) {
	h := newPBKDF2VirtualBoxLaneHasher(virtualBoxAES128HashcatVector, "virtualbox-aes128")
	if h == nil {
		t.Fatal("newPBKDF2VirtualBoxLaneHasher refused hashcat's own published AES-128 record")
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

func TestPBKDF2VirtualBoxLaneHasherMatchesScalarAcrossBatchSizes(t *testing.T) {
	right := "the-right-password"
	candidates := []string{
		"wrong1", "wrong2", "", "a", "12345678", "wrong3",
		"wrong4", "wrong5", right,
	}
	h := newPBKDF2VirtualBoxLaneHasher(virtualBoxAES128HashcatVector, "virtualbox-aes128")
	if h == nil {
		t.Fatal("newPBKDF2VirtualBoxLaneHasher refused hashcat's own published AES-128 record")
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
				want, err := verifyVirtualBox(virtualBoxAES128HashcatVector, candidates[i], "virtualbox-aes128")
				if err != nil {
					t.Fatalf("verifyVirtualBox(%q): %v", candidates[i], err)
				}
				if out[i] != want {
					t.Errorf("batch of %d, candidate %q (position %d): lane hasher = %v, scalar = %v",
						n, candidates[i], i, out[i], want)
				}
			}
		})
	}
}

func TestPBKDF2VirtualBoxLaneHasherIsStateless(t *testing.T) {
	right := "hashcat"
	h := newPBKDF2VirtualBoxLaneHasher(virtualBoxAES128HashcatVector, "virtualbox-aes128")
	if h == nil {
		t.Fatal("newPBKDF2VirtualBoxLaneHasher refused hashcat's own published AES-128 record")
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

func TestNewPBKDF2VirtualBoxLaneHasherRefusesAES256AndMalformedRecords(t *testing.T) {
	cases := []string{
		"",
		"not a record",
		"$vbox$0$1$00$8$00",
	}
	for _, c := range cases {
		if h := newPBKDF2VirtualBoxLaneHasher(c, "virtualbox-aes128"); h != nil {
			t.Errorf("newPBKDF2VirtualBoxLaneHasher(%q) should have been refused", c)
		}
	}
	// AES-256's 64-byte first-stage key needs multi-block PBKDF2.
	if h := newPBKDF2VirtualBoxLaneHasher(virtualBoxAES256HashcatVector, "virtualbox-aes256"); h != nil {
		t.Fatal("newPBKDF2VirtualBoxLaneHasher accepted an AES-256-XTS record")
	}
}

func TestNewLaneHasherVirtualBoxGateIsInternallyConsistent(t *testing.T) {
	factory, lanes, ok := newLaneHasher("virtualbox-aes128", virtualBoxAES128HashcatVector, "", "")
	wantOK := pbkdf2Sha256AVX2Eligible()
	if ok != wantOK {
		t.Fatalf("newLaneHasher(\"virtualbox-aes128\", ...) eligible=%v, want %v (pbkdf2Sha256AVX2Eligible)", ok, wantOK)
	}
	if !ok {
		t.Skip("not eligible on this hardware/build — nothing further to check")
	}
	if lanes != pbkdf2Sha256Lanes {
		t.Fatalf("newLaneHasher(\"virtualbox-aes128\", ...) lanes = %d, want %d", lanes, pbkdf2Sha256Lanes)
	}
	h := factory()
	if h == nil {
		t.Fatal("newLaneHasher(\"virtualbox-aes128\", ...) factory returned nil despite reporting eligible")
	}
	out := make([]bool, 1)
	h.Run([][]byte{[]byte("hashcat")}, out)
	if !out[0] {
		t.Fatal("the wired-up hasher did not match hashcat's own published record")
	}

	// AES-256 must fall back to the scalar path, never be silently
	// accelerated by the AES-128 core.
	if _, _, ok := newLaneHasher("virtualbox-aes256", virtualBoxAES256HashcatVector, "", ""); ok {
		t.Fatal("newLaneHasher(\"virtualbox-aes256\", ...) was unexpectedly eligible")
	}
}
