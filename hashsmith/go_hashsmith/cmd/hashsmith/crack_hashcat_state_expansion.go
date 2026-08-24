package main

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/md5"
	"crypto/rc4"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/hex"
	"errors"
	"strconv"
	"strings"

	"golang.org/x/crypto/pbkdf2"
)

func verifyMD5DualSalt(target, candidate string) (bool, error) {
	fields := strings.Split(target, ":")
	if len(fields) != 3 || len(fields[0]) != 32 || !isHex(fields[0]) ||
		len(fields[1]) > 256 || len(fields[2]) > 256 {
		return false, errors.New("invalid MD5 dual-salt record")
	}
	if len(candidate) > 256 {
		return false, nil
	}
	sum := md5.Sum([]byte(fields[1] + candidate + fields[2]))
	return strings.EqualFold(hex.EncodeToString(sum[:]), fields[0]), nil
}

func verifyRC4DropN(target, candidate string) (bool, error) {
	fields := strings.Split(target, "$")
	if len(fields) != 7 || fields[0] != "" || fields[1] != "rc4" {
		return false, errors.New("invalid RC4 DropN record")
	}
	bits, err := strconv.Atoi(fields[2])
	if err != nil || (bits != 40 && bits != 72 && bits != 104) {
		return false, errors.New("invalid RC4 key size")
	}
	dropN, err := strconv.Atoi(fields[3])
	if err != nil || dropN < 0 || dropN > 999 {
		return false, errors.New("invalid RC4 drop count")
	}
	ciphertext, err := hex.DecodeString(fields[4])
	if err != nil || len(ciphertext) < 1 || len(ciphertext) > 64 {
		return false, errors.New("invalid RC4 ciphertext")
	}
	offset, err := strconv.Atoi(fields[5])
	if err != nil || offset < 0 || offset > len(ciphertext) {
		return false, errors.New("invalid RC4 plaintext offset")
	}
	plaintext, err := hex.DecodeString(fields[6])
	if err != nil || len(plaintext) < 1 || len(plaintext) > 8 || offset+len(plaintext) > len(ciphertext) {
		return false, errors.New("invalid RC4 known plaintext")
	}
	if len(candidate) != bits/8 {
		return false, nil
	}
	stream, err := rc4.NewCipher([]byte(candidate))
	if err != nil {
		return false, err
	}
	if dropN > 0 {
		discard := make([]byte, dropN)
		stream.XORKeyStream(discard, discard)
	}
	decrypted := make([]byte, len(ciphertext))
	stream.XORKeyStream(decrypted, ciphertext)
	return bytesEqualCT(decrypted[offset:offset+len(plaintext)], plaintext), nil
}

func parseBlockchainLegacy(target string) (salt, ciphertext []byte, err error) {
	const prefix = "$blockchain$"
	if !strings.HasPrefix(target, prefix) {
		return nil, nil, errors.New("invalid legacy Blockchain record prefix")
	}
	fields := strings.Split(target[len(prefix):], "$")
	if len(fields) != 2 {
		return nil, nil, errors.New("invalid legacy Blockchain record fields")
	}
	dataLen, err := strconv.Atoi(fields[0])
	if err != nil || dataLen < 32 || dataLen > maxKDFFieldSize {
		return nil, nil, errors.New("invalid legacy Blockchain data length")
	}
	data, err := hex.DecodeString(fields[1])
	if err != nil || len(data) != dataLen || len(data) < 32 {
		return nil, nil, errors.New("invalid legacy Blockchain data")
	}
	return data[:16], data[16:], nil
}

func verifyBlockchainLegacy(target, candidate string) (bool, error) {
	salt, ciphertext, err := parseBlockchainLegacy(target)
	if err != nil {
		return false, err
	}
	if len(candidate) > 256 {
		return false, nil
	}
	key := pbkdf2.Key([]byte(candidate), salt, 1, 32, sha1.New)
	block, err := aes.NewCipher(key)
	if err != nil {
		return false, err
	}
	plain := make([]byte, len(ciphertext))
	cipher.NewOFB(block, salt).XORKeyStream(plain, ciphertext)
	return bytes.HasPrefix(plain, []byte("{\n\"guid\"")) && bytes.Contains(plain, []byte("\"sharedKey\"")), nil
}

func verifyKrb5NT(target, candidate string) (bool, error) {
	if !strings.HasPrefix(target, "$krb5tgs$23$") && !strings.HasPrefix(target, "$krb5asrep$23$") {
		return false, errors.New("invalid Kerberos etype-23 NT-hash record")
	}
	checksum, edata, usages, err := parseKrb5(target)
	if err != nil {
		return false, err
	}
	key, err := hex.DecodeString(candidate)
	if err != nil || len(key) != 16 {
		return false, nil
	}
	for _, usage := range usages {
		if krb5RC4Check(key, checksum, edata, usage) {
			return true, nil
		}
	}
	return false, nil
}

func verifyPhpassMD5(target, candidate string) (bool, error) {
	if len(candidate) > 256 {
		return false, nil
	}
	digest := md5.Sum([]byte(candidate))
	return verifyPhpass(target, hex.EncodeToString(digest[:]))
}

func verifySymfonyLegacy(target, candidate string) (bool, error) {
	fields := strings.SplitN(target, ":", 2)
	if len(fields) != 2 || len(fields[0]) != sha256.Size*2 || !isHex(fields[0]) || len(fields[1]) > 256 {
		return false, errors.New("invalid Symfony legacy SHA-256 record")
	}
	if len(candidate) > 256 {
		return false, nil
	}
	word := candidate
	for i := 0; i < 10_000; i++ {
		if i > 5000 {
			word += fields[1]
		}
		sum := sha512.Sum512([]byte(word))
		word = hex.EncodeToString(sum[:])
	}
	final := sha256.Sum256([]byte(word))
	return strings.EqualFold(hex.EncodeToString(final[:]), fields[0]), nil
}
