package main

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/des"
	"crypto/hmac"
	"crypto/sha1"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"strconv"
	"strings"

	"golang.org/x/crypto/pbkdf2"
)

var dmgKeyWrapIV = []byte{0x4a, 0xdd, 0xa2, 0x2c, 0x79, 0xe8, 0x21, 0x05}

// verifyDMG implements the two records emitted by dmg2smith and dmg2john.
// Version 1 validates both Apple 3DES-wrapped keys. Version 2 decrypts the
// sampled encrypted filesystem block and applies John's eight-zero verifier.
func verifyDMG(target, candidate string) (bool, error) {
	if !strings.HasPrefix(target, "$dmg$") {
		return false, errors.New("invalid DMG record")
	}
	fields := strings.Split(strings.TrimPrefix(target, "$dmg$"), "*")
	if len(fields) == 0 {
		return false, errors.New("invalid DMG record")
	}
	switch fields[0] {
	case "1":
		return verifyDMGV1(fields, candidate)
	case "2":
		return verifyDMGV2(fields, candidate)
	default:
		return false, errors.New("unsupported DMG record version")
	}
}

func verifyDMGV1(fields []string, candidate string) (bool, error) {
	if len(fields) != 7 && len(fields) != 8 {
		return false, errors.New("invalid DMG v1 record")
	}
	salt, err := dmgSizedHex(fields[1], fields[2], 1, 64)
	if err != nil {
		return false, err
	}
	wrappedAES, err := dmgSizedHex(fields[3], fields[4], 16, 256)
	if err != nil || len(wrappedAES)%des.BlockSize != 0 {
		return false, errors.New("invalid DMG wrapped AES key")
	}
	wrappedHMAC, err := dmgSizedHex(fields[5], fields[6], 16, 256)
	if err != nil || len(wrappedHMAC)%des.BlockSize != 0 {
		return false, errors.New("invalid DMG wrapped HMAC key")
	}
	iterations := 1000
	if len(fields) == 8 {
		iterations, err = strconv.Atoi(fields[7])
		if err != nil || iterations < 1 || iterations > maxKDFIterations {
			return false, errors.New("invalid DMG iteration count")
		}
	}
	key := pbkdf2.Key([]byte(candidate), salt, iterations, 32, sha1.New)
	if _, ok := dmgUnwrap3DES(wrappedAES, key[:24]); !ok {
		return false, nil
	}
	if _, ok := dmgUnwrap3DES(wrappedHMAC, key[:24]); !ok {
		return false, nil
	}
	return true, nil
}

func verifyDMGV2(fields []string, candidate string) (bool, error) {
	// scp=0 omits zchunk; scp=1 carries a second 4096-byte encrypted sample.
	if len(fields) != 12 && len(fields) != 13 {
		return false, errors.New("invalid DMG v2 record")
	}
	salt, err := dmgSizedHex(fields[1], fields[2], 1, 64)
	if err != nil {
		return false, err
	}
	iv, err := dmgSizedHex(fields[3], fields[4], des.BlockSize, 64)
	if err != nil || len(iv) < des.BlockSize {
		return false, errors.New("invalid DMG IV")
	}
	keyBlob, err := dmgSizedHex(fields[5], fields[6], 32, 4096)
	if err != nil || len(keyBlob)%des.BlockSize != 0 {
		return false, errors.New("invalid DMG encrypted key blob")
	}
	chunkNo64, err := strconv.ParseUint(fields[7], 10, 32)
	if err != nil {
		return false, errors.New("invalid DMG chunk number")
	}
	dataSize, err := strconv.Atoi(fields[8])
	if err != nil || dataSize < 1 || dataSize > 8192 {
		return false, errors.New("invalid DMG data size")
	}
	chunk, err := hex.DecodeString(fields[9])
	if err != nil || len(chunk) != dataSize || len(chunk)%aes.BlockSize != 0 {
		return false, errors.New("invalid DMG encrypted chunk")
	}
	scp, err := strconv.Atoi(fields[10])
	if err != nil || (scp != 0 && scp != 1) {
		return false, errors.New("invalid DMG sparse-image flag")
	}
	var zeroChunk []byte
	iterationField := 11
	if scp == 1 {
		if len(fields) != 13 {
			return false, errors.New("missing DMG sparse-image chunk")
		}
		zeroChunk, err = hex.DecodeString(fields[11])
		if err != nil || len(zeroChunk) != 4096 || len(zeroChunk)%aes.BlockSize != 0 {
			return false, errors.New("invalid DMG sparse-image chunk")
		}
		iterationField = 12
	} else if len(fields) != 12 {
		return false, errors.New("unexpected DMG sparse-image chunk")
	}
	iterations, err := strconv.Atoi(fields[iterationField])
	if err != nil || iterations < 1 || iterations > maxKDFIterations {
		return false, errors.New("invalid DMG iteration count")
	}

	derived := pbkdf2.Key([]byte(candidate), salt, iterations, 32, sha1.New)
	triple, err := des.NewTripleDESCipher(derived[:24])
	if err != nil {
		return false, err
	}
	plainKeyBlob := append([]byte(nil), keyBlob...)
	cipher.NewCBCDecrypter(triple, iv[:des.BlockSize]).CryptBlocks(plainKeyBlob, plainKeyBlob)
	if len(plainKeyBlob) < 32 {
		return false, errors.New("DMG key blob is too short")
	}
	aesKey := plainKeyBlob[:32]
	if len(keyBlob) == 48 {
		aesKey = plainKeyBlob[:16]
	}
	hmacKey := plainKeyBlob[:20]
	if dmgChunkHasZeros(chunk, aesKey, hmacKey, uint32(chunkNo64)) {
		return true, nil
	}
	if scp == 1 && dmgChunkHasZeros(zeroChunk, aesKey, hmacKey, 0) {
		return true, nil
	}
	return false, nil
}

func dmgSizedHex(lengthText, hexText string, minLen, maxLen int) ([]byte, error) {
	n, err := strconv.Atoi(lengthText)
	if err != nil || n < minLen || n > maxLen {
		return nil, errors.New("invalid DMG field length")
	}
	b, err := hex.DecodeString(hexText)
	if err != nil || len(b) != n {
		return nil, errors.New("invalid DMG hexadecimal field")
	}
	return b, nil
}

func dmgUnwrap3DES(wrapped, key []byte) ([]byte, bool) {
	block, err := des.NewTripleDESCipher(key)
	if err != nil || len(wrapped)%des.BlockSize != 0 {
		return nil, false
	}
	stage := append([]byte(nil), wrapped...)
	cipher.NewCBCDecrypter(block, dmgKeyWrapIV).CryptBlocks(stage, stage)
	stage, ok := strictPKCS7Unpad(stage, des.BlockSize)
	if !ok || len(stage) <= des.BlockSize {
		return nil, false
	}
	for left, right := 0, len(stage)-1; left < right; left, right = left+1, right-1 {
		stage[left], stage[right] = stage[right], stage[left]
	}
	iv := append([]byte(nil), stage[:des.BlockSize]...)
	stage = append([]byte(nil), stage[des.BlockSize:]...)
	if len(stage) == 0 || len(stage)%des.BlockSize != 0 {
		return nil, false
	}
	cipher.NewCBCDecrypter(block, iv).CryptBlocks(stage, stage)
	return strictPKCS7Unpad(stage, des.BlockSize)
}

func dmgChunkHasZeros(encrypted, aesKey, hmacKey []byte, chunkNo uint32) bool {
	var number [4]byte
	binary.LittleEndian.PutUint32(number[:], chunkNo)
	mac := hmac.New(sha1.New, hmacKey)
	_, _ = mac.Write(number[:])
	iv := mac.Sum(nil)[:aes.BlockSize]
	block, err := aes.NewCipher(aesKey)
	if err != nil || len(encrypted)%aes.BlockSize != 0 {
		return false
	}
	plain := append([]byte(nil), encrypted...)
	cipher.NewCBCDecrypter(block, iv).CryptBlocks(plain, plain)
	return bytes.Contains(plain, make([]byte, 8))
}
