package main

import (
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

func verifyAndroidBackup(target, candidate string) (bool, error) {
	if !strings.HasPrefix(target, "$ab$") {
		return false, errors.New("invalid Android Backup record")
	}
	p := strings.Split(strings.TrimPrefix(target, "$ab$"), "*")
	if len(p) != 7 || p[1] != "0" {
		return false, errors.New("invalid Android Backup record")
	}
	version, err := strconv.Atoi(p[0])
	if err != nil || version < 1 || version > 5 {
		return false, errors.New("invalid Android Backup version")
	}
	rounds, err := strconv.Atoi(p[2])
	if err != nil || rounds < 1 || rounds > maxKDFIterations {
		return false, errors.New("invalid Android Backup iteration count")
	}
	userSalt, err1 := hex.DecodeString(p[3])
	checkSalt, err2 := hex.DecodeString(p[4])
	iv, err3 := hex.DecodeString(p[5])
	blob, err4 := hex.DecodeString(p[6])
	if err1 != nil || err2 != nil || err3 != nil || err4 != nil || len(userSalt) == 0 ||
		len(checkSalt) == 0 || len(iv) != aes.BlockSize || len(blob) == 0 || len(blob)%aes.BlockSize != 0 {
		return false, errors.New("invalid Android Backup encryption fields")
	}
	key := pbkdf2.Key([]byte(candidate), userSalt, rounds, 32, sha1.New)
	block, err := aes.NewCipher(key)
	if err != nil {
		return false, err
	}
	plain := append([]byte(nil), blob...)
	cipher.NewCBCDecrypter(block, iv).CryptBlocks(plain, plain)
	plain, ok := strictPKCS7Unpad(plain, aes.BlockSize)
	if !ok || len(plain) != 83 || plain[0] != 16 || plain[17] != 32 || plain[50] != 32 {
		return false, nil
	}
	// The fixed length-tagged master-key envelope plus valid CBC padding gives
	// a strong verifier without weakening compatibility with Android's two
	// historical password-character encodings.
	return true, nil
}

func strictPKCS7Unpad(data []byte, blockSize int) ([]byte, bool) {
	if len(data) == 0 || len(data)%blockSize != 0 {
		return nil, false
	}
	n := int(data[len(data)-1])
	if n < 1 || n > blockSize || n > len(data) {
		return nil, false
	}
	for _, b := range data[len(data)-n:] {
		if int(b) != n {
			return nil, false
		}
	}
	return data[:len(data)-n], true
}

func verifyMozillaNSS(target, candidate string) (bool, error) {
	p := strings.Split(target, "*")
	if len(p) != 11 || p[0] != "$mozilla$" || p[1] != "3" {
		return false, errors.New("invalid Mozilla/NSS key3 record")
	}
	entrySalt, err1 := hex.DecodeString(p[4])
	verifier, err2 := hex.DecodeString(p[8])
	globalSalt, err3 := hex.DecodeString(p[10])
	if err1 != nil || err2 != nil || err3 != nil || len(entrySalt) != 20 || len(verifier) != 16 || len(globalSalt) != 20 {
		return false, errors.New("invalid Mozilla/NSS salts or verifier")
	}
	h := sha1.New()
	h.Write(globalSalt)
	h.Write([]byte(candidate))
	hp := h.Sum(nil)
	h.Reset()
	h.Write(hp)
	h.Write(entrySalt)
	chp := h.Sum(nil)
	pes := make([]byte, 20)
	copy(pes, entrySalt)
	k1 := hmacSHA1(chp, append(append([]byte(nil), pes...), entrySalt...))
	tk := hmacSHA1(chp, pes)
	k2 := hmacSHA1(chp, append(tk, entrySalt...))
	keyMaterial := append(k1, k2...)
	block, err := des.NewTripleDESCipher(keyMaterial[:24])
	if err != nil {
		return false, err
	}
	plain := []byte("password-check\x02\x02")
	crypted := make([]byte, len(plain))
	cipher.NewCBCEncrypter(block, keyMaterial[32:40]).CryptBlocks(crypted, plain)
	return bytesEqualCT(crypted, verifier), nil
}

func hmacSHA1(key, message []byte) []byte {
	h := hmac.New(sha1.New, key)
	h.Write(message)
	return h.Sum(nil)
}

func verifyEncFS(target, candidate string) (bool, error) {
	if !strings.HasPrefix(target, "$encfs$") {
		return false, errors.New("invalid EncFS record")
	}
	p := strings.Split(strings.TrimPrefix(target, "$encfs$"), "*")
	if len(p) != 7 || p[2] != "0" {
		return false, errors.New("invalid EncFS record")
	}
	keyBits, err1 := strconv.Atoi(p[0])
	iterations, err2 := strconv.Atoi(p[1])
	saltLen, err3 := strconv.Atoi(p[3])
	dataLen, err4 := strconv.Atoi(p[5])
	salt, err5 := hex.DecodeString(p[4])
	data, err6 := hex.DecodeString(p[6])
	keyBytes := keyBits / 8
	if err1 != nil || err2 != nil || err3 != nil || err4 != nil || err5 != nil || err6 != nil ||
		(keyBits != 128 && keyBits != 192 && keyBits != 256) || iterations < 1 || iterations > maxKDFIterations ||
		saltLen != len(salt) || dataLen != len(data) || len(data) != keyBytes+20 {
		return false, errors.New("invalid EncFS KDF or encoded-key fields")
	}
	master := pbkdf2.Key([]byte(candidate), salt, iterations, keyBytes+16, sha1.New)
	checksum := binary.BigEndian.Uint32(data[:4])
	decoded := append([]byte(nil), data[4:]...)
	if err := encFSStreamDecode(decoded, uint64(checksum), master, keyBytes); err != nil {
		return false, err
	}
	return encFSMAC32(decoded, master[:keyBytes]) == checksum, nil
}

func encFSStreamDecode(data []byte, seed uint64, master []byte, keyBytes int) error {
	block, err := aes.NewCipher(master[:keyBytes])
	if err != nil {
		return err
	}
	iv := encFSIV(master[:keyBytes], master[keyBytes:keyBytes+16], seed+1)
	cipher.NewCFBDecrypter(block, iv).XORKeyStream(data, data)
	encFSUnshuffle(data)
	encFSFlip(data)
	iv = encFSIV(master[:keyBytes], master[keyBytes:keyBytes+16], seed)
	cipher.NewCFBDecrypter(block, iv).XORKeyStream(data, data)
	encFSUnshuffle(data)
	return nil
}

func encFSIV(key, baseIV []byte, seed uint64) []byte {
	message := append([]byte(nil), baseIV...)
	var little [8]byte
	binary.LittleEndian.PutUint64(little[:], seed)
	message = append(message, little[:]...)
	return hmacSHA1(key, message)[:16]
}

func encFSUnshuffle(data []byte) {
	for i := len(data) - 1; i > 0; i-- {
		data[i] ^= data[i-1]
	}
}

func encFSFlip(data []byte) {
	for start := 0; start < len(data); start += 64 {
		end := start + 64
		if end > len(data) {
			end = len(data)
		}
		for i, j := start, end-1; i < j; i, j = i+1, j-1 {
			data[i], data[j] = data[j], data[i]
		}
	}
}

func encFSMAC32(data, key []byte) uint32 {
	digest := hmacSHA1(key, data)
	var folded [8]byte
	for i := 0; i < 19; i++ {
		folded[i%8] ^= digest[i]
	}
	v := binary.BigEndian.Uint64(folded[:])
	return uint32(v>>32) ^ uint32(v)
}
