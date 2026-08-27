package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/des"
	"crypto/hmac"
	"crypto/sha1"
	"encoding/binary"
	"fmt"
	"testing"

	"golang.org/x/crypto/pbkdf2"
)

func TestDMGPublishedVector(t *testing.T) {
	ok, err := verifyCandidate("vilefault", dmgPublishedRecord, "john:dmg", "", "prefix")
	if err != nil || !ok {
		t.Fatalf("published DMG vector: ok=%v err=%v", ok, err)
	}
	if bad, err := verifyCandidate("wrong-password", dmgPublishedRecord, "dmg", "", "prefix"); err != nil || bad {
		t.Fatalf("DMG wrong-password rejection: ok=%v err=%v", bad, err)
	}
}

func TestDMGV2Verifier(t *testing.T) {
	const password = "v2-password"
	salt := []byte("0123456789abcdefghij")
	iv := []byte("01234567abcdefghijklmnopqrstuvwx")
	derived := pbkdf2.Key([]byte(password), salt, 1000, 32, sha1.New)
	plainKeys := make([]byte, 48)
	for i := range plainKeys {
		plainKeys[i] = byte(i + 1)
	}
	triple, _ := des.NewTripleDESCipher(derived[:24])
	encryptedKeys := append([]byte(nil), plainKeys...)
	cipher.NewCBCEncrypter(triple, iv[:8]).CryptBlocks(encryptedKeys, encryptedKeys)

	plainChunk := make([]byte, 4096)
	for i := range plainChunk {
		plainChunk[i] = byte(i%251 + 1)
	}
	clear(plainChunk[128:136])
	var chunkNo [4]byte
	binary.LittleEndian.PutUint32(chunkNo[:], 7)
	mac := hmac.New(sha1.New, plainKeys[:20])
	_, _ = mac.Write(chunkNo[:])
	block, _ := aes.NewCipher(plainKeys[:16])
	encryptedChunk := append([]byte(nil), plainChunk...)
	cipher.NewCBCEncrypter(block, mac.Sum(nil)[:16]).CryptBlocks(encryptedChunk, encryptedChunk)
	record := fmt.Sprintf("$dmg$2*%d*%x*%d*%x*%d*%x*7*%d*%x*0*1000",
		len(salt), salt, len(iv), iv, len(encryptedKeys), encryptedKeys, len(encryptedChunk), encryptedChunk)

	if ok, err := verifyDMG(record, password); err != nil || !ok {
		t.Fatalf("DMG v2 correct password: ok=%v err=%v", ok, err)
	}
	if ok, err := verifyDMG(record, "wrong-password"); err != nil || ok {
		t.Fatalf("DMG v2 wrong password: ok=%v err=%v", ok, err)
	}
}

func TestDMGRejectsMalformedRecords(t *testing.T) {
	for _, record := range []string{
		"$dmg$3*20*00",
		"$dmg$1*20*00*56*00*48*00",
		"$dmg$2*1*00*8*0000000000000000*48*00*0*4096*00*0*1000",
	} {
		if ok, err := verifyDMG(record, "password"); err == nil || ok {
			t.Errorf("accepted malformed record %q: ok=%v err=%v", record, ok, err)
		}
	}
}
