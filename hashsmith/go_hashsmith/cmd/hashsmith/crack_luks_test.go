package main

import (
	"crypto/aes"
	"crypto/sha256"
	"encoding/hex"
	"hash"
	"strings"
	"testing"

	"golang.org/x/crypto/pbkdf2"
	"golang.org/x/crypto/xts"
)

// afSplit is the inverse of afMerge: it spreads a master key across `stripes`
// blocks so that all stripes are needed to recover it. Used here to build a
// self-contained round-trip vector.
func afSplit(masterKey []byte, blockSize, stripes int, newHash func() hash.Hash) []byte {
	out := make([]byte, blockSize*stripes)
	d := make([]byte, blockSize)
	// Deterministic "random" filler blocks for the first stripes-1 blocks.
	filler := sha256.Sum256([]byte("hashsmith-luks-test-filler"))
	for i := 0; i < stripes-1; i++ {
		blk := out[i*blockSize : (i+1)*blockSize]
		for j := 0; j < blockSize; j++ {
			blk[j] = filler[(i*blockSize+j)%len(filler)]
			d[j] ^= blk[j]
		}
		d = afDiffuse(d, newHash)
	}
	last := out[(stripes-1)*blockSize : stripes*blockSize]
	for j := 0; j < blockSize; j++ {
		last[j] = d[j] ^ masterKey[j]
	}
	return out
}

// TestLUKSRoundTrip builds a minimal LUKS keyslot (AES-XTS, SHA-256), then
// confirms verifyLUKS recovers the passphrase — exercising the full
// PBKDF2 → AES-XTS → AF-merge → master-key-digest pipeline. (The same pipeline
// was also validated against real hashcat LUKS test images: aes/twofish ×
// xts/cbc-essiv/cbc-plain64 × sha1/sha256/sha512/ripemd160.)
func TestLUKSRoundTrip(t *testing.T) {
	const keyBytes, stripes = 32, 4
	newHash := sha256.New
	pw := "hashsmith"
	slotSalt := []byte("0123456789abcdef0123456789abcdef")
	mkSalt := []byte("fedcba9876543210fedcba9876543210")
	masterKey := []byte("MASTERKEY_masterkey_0123456789AB") // 32 bytes

	// Encrypt AF-split material with the slot key.
	material := afSplit(masterKey, keyBytes, stripes, newHash)
	slotKey := pbkdf2.Key([]byte(pw), slotSalt, 1, keyBytes, newHash)
	c, err := xts.NewCipher(aes.NewCipher, slotKey)
	if err != nil {
		t.Fatalf("xts: %v", err)
	}
	enc := make([]byte, len(material))
	c.Encrypt(enc, material, 0)

	mkDigest := pbkdf2.Key(masterKey, mkSalt, 1, 20, newHash)

	line := strings.Join([]string{
		"$luks$1", "sha256", "aes", "xts-plain64", "32",
		hex.EncodeToString(mkDigest), hex.EncodeToString(mkSalt), "1",
		"1", hex.EncodeToString(slotSalt), "4", hex.EncodeToString(enc),
	}, "$")

	if ok, err := verifyLUKS(line, pw); err != nil || !ok {
		t.Fatalf("LUKS round-trip verify failed: ok=%v err=%v", ok, err)
	}
	if ok, _ := verifyLUKS(line, "wrong"); ok {
		t.Error("LUKS should reject the wrong passphrase")
	}
	if got := detectHashTypes(line); len(got) != 1 || got[0] != "luks" {
		t.Errorf("detectHashTypes = %v, want [luks]", got)
	}
}
