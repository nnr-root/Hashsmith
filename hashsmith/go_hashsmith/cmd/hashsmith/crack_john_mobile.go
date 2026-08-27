package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/des"
	"crypto/hmac"
	"crypto/sha1"
	"crypto/sha512"
	"encoding/hex"
	"errors"
	"strconv"
	"strings"

	"golang.org/x/crypto/pbkdf2"
)

func verifySignal(target, candidate string) (bool, error) {
	if !strings.HasPrefix(target, "$signal$") {
		return false, errors.New("invalid Signal record")
	}
	f := strings.Split(strings.TrimPrefix(target, "$signal$"), "$")
	if len(f) != 6 || f[0] != "1" {
		return false, errors.New("invalid Signal record")
	}
	iterations, err := strconv.Atoi(f[1])
	if err != nil || iterations < 1 || iterations > maxKDFIterations {
		return false, errors.New("invalid Signal iteration count")
	}
	encryptionSalt, e1 := hex.DecodeString(f[2])
	macSalt, e2 := hex.DecodeString(f[3])
	masterSecret, e3 := hex.DecodeString(f[4])
	want, e4 := hex.DecodeString(f[5])
	if e1 != nil || e2 != nil || e3 != nil || e4 != nil || len(encryptionSalt) > 32 ||
		len(macSalt) == 0 || len(macSalt) > 32 || len(masterSecret) <= sha1.Size ||
		len(masterSecret) > 128 || len(want) != sha1.Size || !hmac.Equal(masterSecret[len(masterSecret)-sha1.Size:], want) {
		return false, errors.New("invalid Signal cryptographic fields")
	}
	key := pkcs12KDF(candidate, macSalt, iterations, pkcs12IDKey, 16, sha1.New)
	mac := hmac.New(sha1.New, key)
	_, _ = mac.Write(masterSecret[:len(masterSecret)-sha1.Size])
	return hmac.Equal(mac.Sum(nil), want), nil
}

func verifyKeychain(target, candidate string) (bool, error) {
	if !strings.HasPrefix(target, "$keychain$*") {
		return false, errors.New("invalid macOS Keychain record")
	}
	f := strings.Split(strings.TrimPrefix(target, "$keychain$*"), "*")
	if len(f) != 3 {
		return false, errors.New("invalid macOS Keychain record")
	}
	salt, e1 := hex.DecodeString(f[0])
	iv, e2 := hex.DecodeString(f[1])
	ct, e3 := hex.DecodeString(f[2])
	if e1 != nil || e2 != nil || e3 != nil || len(salt) != 20 || len(iv) != des.BlockSize || len(ct) != 48 {
		return false, errors.New("invalid macOS Keychain cryptographic fields")
	}
	key := pbkdf2.Key([]byte(candidate), salt, 1000, 24, sha1.New)
	block, err := des.NewTripleDESCipher(key)
	if err != nil {
		return false, err
	}
	plain := append([]byte(nil), ct...)
	cipher.NewCBCDecrypter(block, iv).CryptBlocks(plain, plain)
	_, ok := strictPKCS7Unpad(plain, des.BlockSize)
	return ok && plain[len(plain)-1] == 4, nil
}

func verifyTelegramDesktop(target, candidate string) (bool, error) {
	if !strings.HasPrefix(target, "$telegram$") {
		return false, errors.New("invalid Telegram Desktop record")
	}
	f := strings.Split(strings.TrimPrefix(target, "$telegram$"), "*")
	if len(f) != 4 || (f[0] != "1" && f[0] != "2") {
		return false, errors.New("invalid Telegram Desktop record")
	}
	iterations, err := strconv.Atoi(f[1])
	if err != nil || iterations < 1 || iterations > maxKDFIterations {
		return false, errors.New("invalid Telegram Desktop iteration count")
	}
	salt, e1 := hex.DecodeString(f[2])
	blob, e2 := hex.DecodeString(f[3])
	if e1 != nil || e2 != nil || len(salt) == 0 || len(salt) > 64 || len(blob) < 32 ||
		len(blob) > 4096 || (len(blob)-16)%aes.BlockSize != 0 {
		return false, errors.New("invalid Telegram Desktop cryptographic fields")
	}
	var authKey []byte
	if f[0] == "1" {
		authKey = pbkdf2.Key([]byte(candidate), salt, iterations, 136, sha1.New)
	} else {
		preimage := make([]byte, 0, len(salt)*2+len(candidate))
		preimage = append(preimage, salt...)
		preimage = append(preimage, candidate...)
		preimage = append(preimage, salt...)
		first := sha512.Sum512(preimage)
		authKey = pbkdf2.Key(first[:], salt, iterations, 136, sha512.New)
	}
	return telegramCheckPassword(authKey, blob), nil
}

func telegramCheckPassword(authKey, blob []byte) bool {
	if len(authKey) < 136 || len(blob) < 32 {
		return false
	}
	messageKey := blob[:16]
	hashA := sha1.Sum(append(append([]byte(nil), messageKey...), authKey[8:40]...))
	b := make([]byte, 0, 48)
	b = append(b, authKey[40:56]...)
	b = append(b, messageKey...)
	b = append(b, authKey[56:72]...)
	hashB := sha1.Sum(b)
	c := append(append([]byte(nil), authKey[72:104]...), messageKey...)
	hashC := sha1.Sum(c)
	d := append(append([]byte(nil), messageKey...), authKey[104:136]...)
	hashD := sha1.Sum(d)

	key := make([]byte, 0, 32)
	key = append(key, hashA[:8]...)
	key = append(key, hashB[8:20]...)
	key = append(key, hashC[4:16]...)
	iv := make([]byte, 0, 32)
	iv = append(iv, hashA[8:20]...)
	iv = append(iv, hashB[:8]...)
	iv = append(iv, hashC[16:20]...)
	iv = append(iv, hashD[:8]...)
	plain, ok := aesIGEDecrypt(blob[16:], key, iv)
	if !ok {
		return false
	}
	digest := sha1.Sum(plain)
	return hmac.Equal(digest[:16], messageKey)
}

func aesIGEDecrypt(data, key, iv []byte) ([]byte, bool) {
	if len(iv) != 2*aes.BlockSize || len(data) == 0 || len(data)%aes.BlockSize != 0 {
		return nil, false
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, false
	}
	iv1 := append([]byte(nil), iv[:aes.BlockSize]...)
	iv2 := append([]byte(nil), iv[aes.BlockSize:]...)
	out := make([]byte, len(data))
	tmp := make([]byte, aes.BlockSize)
	for at := 0; at < len(data); at += aes.BlockSize {
		cipherBlock := data[at : at+aes.BlockSize]
		for i := range tmp {
			tmp[i] = cipherBlock[i] ^ iv2[i]
		}
		block.Decrypt(out[at:at+aes.BlockSize], tmp)
		for i := 0; i < aes.BlockSize; i++ {
			out[at+i] ^= iv1[i]
		}
		copy(iv1, cipherBlock)
		copy(iv2, out[at:at+aes.BlockSize])
	}
	return out, true
}
