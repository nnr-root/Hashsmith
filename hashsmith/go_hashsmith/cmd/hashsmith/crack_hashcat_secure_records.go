package main

// Compact encrypted/authentication records implemented from Hashcat's official
// module self-tests.  Each verifier accepts the canonical Hashcat text record;
// no extractor-only or synthetic representation is introduced here.

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"strings"

	"golang.org/x/crypto/pbkdf2"
)

func verifyVeeamVBK(target, candidate string) (bool, error) {
	parts := strings.Split(target, "*")
	if len(parts) != 4 || parts[0] != "$vbk$" || len(parts[1]) != 128 || !isHex(parts[1]) ||
		len(parts[3]) != 32 || !isHex(parts[3]) || len([]byte(candidate)) > 256 {
		return false, errors.New("invalid Veeam VBK record")
	}
	iterations, err := parseBoundedDecimal(parts[2], 10)
	if err != nil {
		return false, errors.New("invalid Veeam VBK iteration count")
	}
	salt, _ := hex.DecodeString(parts[1])
	ciphertext, _ := hex.DecodeString(parts[3])
	derived := pbkdf2.Key(utf16le(candidate), salt, iterations, 48, sha1.New)
	block, err := aes.NewCipher(derived[:32])
	if err != nil {
		return false, err
	}
	plain := make([]byte, len(ciphertext))
	cipher.NewCBCDecrypter(block, derived[32:]).CryptBlocks(plain, ciphertext)
	for _, b := range plain[4:] {
		if b != 0x0c {
			return false, nil
		}
	}
	return true, nil
}

func verifyMSOnlineAccount(target, candidate string) (bool, error) {
	parts := strings.Split(target, "$")
	if len(parts) != 5 || parts[0] != "" || parts[1] != "MSONLINEACCOUNT" || parts[2] != "0" ||
		len(parts[4]) != 64 || !isHex(parts[4]) || len([]byte(candidate)) > 256 {
		return false, errors.New("invalid Microsoft Online Account record")
	}
	iterations, err := parseBoundedDecimal(parts[3], 5)
	if err != nil {
		return false, errors.New("invalid Microsoft Online Account iteration count")
	}
	ciphertext, _ := hex.DecodeString(parts[4])
	key := pbkdf2.Key(utf16le(candidate), nil, iterations, 32, sha256.New)
	block, err := aes.NewCipher(key)
	if err != nil {
		return false, err
	}
	plain := make([]byte, len(ciphertext))
	cipher.NewCBCDecrypter(block, make([]byte, aes.BlockSize)).CryptBlocks(plain, ciphertext)
	want := []byte{0, 0, 0, 0, 1, 0, 0, 0}
	return bytesEqualCT(plain[:len(want)], want), nil
}

func verifySecureCRTV2(target, candidate string) (bool, error) {
	const prefix = "S:\"Config Passphrase\"=02:"
	cipherHex := strings.TrimPrefix(target, prefix)
	if cipherHex == target || len(cipherHex) < 96 || len(cipherHex) > 224 || len(cipherHex)%32 != 0 || !isHex(cipherHex) ||
		len([]byte(candidate)) > 55 {
		return false, errors.New("invalid SecureCRT MasterPassphrase v2 record")
	}
	ciphertext, _ := hex.DecodeString(cipherHex)
	digest := sha256.Sum256([]byte(candidate))
	block, err := aes.NewCipher(digest[:])
	if err != nil {
		return false, err
	}
	plain := make([]byte, len(ciphertext))
	cipher.NewCBCDecrypter(block, make([]byte, aes.BlockSize)).CryptBlocks(plain, ciphertext)
	password := []byte(candidate)
	required := 4 + len(password) + sha256.Size
	if len(plain) < required || plain[0] != byte(len(password)) || plain[1] != 0 || plain[2] != 0 || plain[3] != 0 {
		return false, nil
	}
	if !bytesEqualCT(plain[4:4+len(password)], password) {
		return false, nil
	}
	return bytesEqualCT(plain[4+len(password):required], digest[:]), nil
}

func verifyKNXIPSecure(target, candidate string) (bool, error) {
	const signature = "$knx-ip-secure-device-authentication-code$"
	parts := strings.Split(target, "*")
	if len(parts) != 4 || parts[0] != signature || len(parts[1]) != 4 || !isHex(parts[1]) ||
		len(parts[2]) != 64 || !isHex(parts[2]) || len(parts[3]) != 32 || !isHex(parts[3]) ||
		len([]byte(candidate)) > 20 {
		return false, errors.New("invalid KNX IP Secure authentication record")
	}
	sessionID, _ := hex.DecodeString(parts[1])
	publicXOR, _ := hex.DecodeString(parts[2])
	want, _ := hex.DecodeString(parts[3])
	key := pbkdf2.Key([]byte(candidate), []byte("device-authentication-code.1.secure.ip.knx.org"), 65536, 16, sha256.New)

	associated := make([]byte, 0, 6+len(sessionID)+len(publicXOR))
	associated = append(associated, 0x06, 0x10, 0x09, 0x52, 0x00, 0x38)
	associated = append(associated, sessionID...)
	associated = append(associated, publicXOR...)
	formattedLen := aes.BlockSize + 2 + len(associated)
	formattedLen = (formattedLen + aes.BlockSize - 1) &^ (aes.BlockSize - 1)
	formatted := make([]byte, formattedLen)
	binary.BigEndian.PutUint16(formatted[aes.BlockSize:], uint16(len(associated)))
	copy(formatted[aes.BlockSize+2:], associated)

	block, err := aes.NewCipher(key)
	if err != nil {
		return false, err
	}
	encrypted := make([]byte, len(formatted))
	cipher.NewCBCEncrypter(block, make([]byte, aes.BlockSize)).CryptBlocks(encrypted, formatted)
	yN := encrypted[len(encrypted)-aes.BlockSize:]
	nonce := make([]byte, aes.BlockSize)
	nonce[14] = 0xff
	s0 := make([]byte, aes.BlockSize)
	block.Encrypt(s0, nonce)
	got := make([]byte, aes.BlockSize)
	for i := range got {
		got[i] = yN[i] ^ s0[i]
	}
	return bytesEqualCT(got, want), nil
}

func verifyNetNTLMv2NT(target, candidate string) (bool, error) {
	if len(candidate) != 32 || !isHex(candidate) {
		return false, errors.New("NetNTLMv2-NT candidate must be a 32-hex NT hash")
	}
	nthash, _ := hex.DecodeString(candidate)
	return verifyNetNTLMv2NTHash(target, nthash)
}

func verifyTeamSpeak3(target, candidate string) (bool, error) {
	parts := strings.Split(target, "$")
	if len(parts) != 5 || parts[0] != "" || parts[1] != "teamspeak" || parts[2] != "3" ||
		len(parts[3]) != 28 || len(parts[4]) != 152 || len([]byte(candidate)) > 256 {
		return false, errors.New("invalid TeamSpeak 3 channel record")
	}
	want, err := base64.StdEncoding.DecodeString(parts[3])
	if err != nil || len(want) != sha1.Size {
		return false, errors.New("invalid TeamSpeak 3 digest")
	}
	salt, err := base64.StdEncoding.DecodeString(parts[4])
	if err != nil || len(salt) != 112 {
		return false, errors.New("invalid TeamSpeak 3 salt")
	}
	first := sha1.Sum([]byte(candidate))
	material := base64.StdEncoding.EncodeToString(first[:]) + base64.StdEncoding.EncodeToString(salt)
	got := sha1.Sum([]byte(material))
	return bytesEqualCT(got[:], want), nil
}

func parseBoundedDecimal(value string, maxDigits int) (int, error) {
	if value == "" || len(value) > maxDigits {
		return 0, errors.New("decimal field out of range")
	}
	n := 0
	for _, c := range value {
		if c < '0' || c > '9' {
			return 0, errors.New("invalid decimal field")
		}
		n = n*10 + int(c-'0')
	}
	if n < 1 || n > maxKDFIterations {
		return 0, errors.New("decimal field out of range")
	}
	return n, nil
}
