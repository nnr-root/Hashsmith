package main

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"strings"

	"golang.org/x/crypto/pbkdf2"
)

func verifyWPAPMKID(target, candidate string, candidateIsPMK bool) (bool, error) {
	// Hashcat 22001 accepts the modern WPA*01/WPA*02 representation and uses a
	// raw 32-byte PMK as its candidate. Reuse the complete WPA verifier for both
	// PMKID and EAPOL records rather than limiting this type to legacy PMKID text.
	if candidateIsPMK && strings.HasPrefix(strings.TrimSpace(target), "WPA*") {
		w, err := parseWPAHash(target)
		if err != nil {
			return false, err
		}
		pmk, err := hex.DecodeString(candidate)
		if err != nil || len(pmk) != 32 {
			return false, nil
		}
		return verifyWPAWithPMK(w, pmk)
	}

	fields := strings.Split(target, ":")
	wantFields := 4
	if candidateIsPMK {
		wantFields = 3
	}
	if len(fields) != wantFields {
		return false, errors.New("invalid WPA PMKID record")
	}
	pmkid, err := hex.DecodeString(fields[0])
	if err != nil || len(pmkid) != 16 {
		return false, errors.New("invalid WPA PMKID digest")
	}
	ap, err := hex.DecodeString(fields[1])
	if err != nil || len(ap) != 6 {
		return false, errors.New("invalid WPA PMKID AP MAC")
	}
	sta, err := hex.DecodeString(fields[2])
	if err != nil || len(sta) != 6 {
		return false, errors.New("invalid WPA PMKID station MAC")
	}
	var pmk []byte
	if candidateIsPMK {
		pmk, err = hex.DecodeString(candidate)
		if err != nil || len(pmk) != 32 {
			return false, nil
		}
	} else {
		essid, err := hex.DecodeString(fields[3])
		if err != nil || len(essid) > 32 {
			return false, errors.New("invalid WPA PMKID ESSID")
		}
		if len(candidate) < 8 || len(candidate) > 63 {
			return false, nil
		}
		pmk = wpaPMK(candidate, essid)
	}
	mac := hmac.New(sha1.New, pmk)
	mac.Write([]byte("PMK Name"))
	mac.Write(ap)
	mac.Write(sta)
	return hmac.Equal(mac.Sum(nil)[:16], pmkid), nil
}

func detectWPAPMKIDRecord(target string) string {
	fields := strings.Split(target, ":")
	if len(fields) != 3 && len(fields) != 4 {
		return ""
	}
	if len(fields[0]) != 32 || len(fields[1]) != 12 || len(fields[2]) != 12 ||
		!isHex(fields[0]) || !isHex(fields[1]) || !isHex(fields[2]) {
		return ""
	}
	if len(fields) == 3 {
		return "wpa-pmk"
	}
	if len(fields[3])%2 != 0 || len(fields[3]) > 64 || !isHexOrEmpty(fields[3]) {
		return ""
	}
	return "wpa-pmkid"
}

func pkcs7Unpad(block []byte, blockSize int) ([]byte, bool) {
	if len(block) == 0 || len(block)%blockSize != 0 {
		return nil, false
	}
	padding := int(block[len(block)-1])
	if padding < 1 || padding > blockSize || padding > len(block) {
		return nil, false
	}
	for _, b := range block[len(block)-padding:] {
		if int(b) != padding {
			return nil, false
		}
	}
	return block[:len(block)-padding], true
}

func verifyEthereumPresale(target, candidate string) (bool, error) {
	const prefix = "$ethereum$w*"
	if !strings.HasPrefix(target, prefix) {
		return false, errors.New("invalid Ethereum pre-sale record prefix")
	}
	fields := strings.Split(target[len(prefix):], "*")
	if len(fields) != 3 || len(fields[1]) != 40 || !isHex(fields[1]) ||
		len(fields[2]) != 32 || !isHex(fields[2]) {
		return false, errors.New("invalid Ethereum pre-sale record fields")
	}
	encrypted, err := hex.DecodeString(fields[0])
	if err != nil || len(encrypted) < 32 || len(encrypted) > maxKDFFieldSize || len(encrypted[16:])%aes.BlockSize != 0 {
		return false, errors.New("invalid Ethereum pre-sale seed")
	}
	if len(candidate) > 256 {
		return false, nil
	}
	key := pbkdf2.Key([]byte(candidate), []byte(candidate), 2000, 16, sha256.New)
	block, err := aes.NewCipher(key)
	if err != nil {
		return false, err
	}
	seedPadded := make([]byte, len(encrypted)-16)
	cipher.NewCBCDecrypter(block, encrypted[:16]).CryptBlocks(seedPadded, encrypted[16:])
	seed, ok := pkcs7Unpad(seedPadded, aes.BlockSize)
	if !ok {
		return false, nil
	}
	digest := keccak256(seed, []byte{0x02})
	want, _ := hex.DecodeString(fields[2])
	return bytesEqualCT(digest[:16], want), nil
}

func verifyAESCrypt(target, candidate string) (bool, error) {
	const prefix = "$aescrypt$1*"
	if !strings.HasPrefix(target, prefix) {
		return false, errors.New("invalid AES Crypt record prefix")
	}
	fields := strings.Split(target[len(prefix):], "*")
	if len(fields) != 4 {
		return false, errors.New("invalid AES Crypt record fields")
	}
	salt, err := hex.DecodeString(fields[0])
	if err != nil || len(salt) != 16 {
		return false, errors.New("invalid AES Crypt salt")
	}
	iv, err := hex.DecodeString(fields[1])
	if err != nil || len(iv) != 16 {
		return false, errors.New("invalid AES Crypt IV")
	}
	wrappedKey, err := hex.DecodeString(fields[2])
	if err != nil || len(wrappedKey) != 32 {
		return false, errors.New("invalid AES Crypt wrapped key")
	}
	want, err := hex.DecodeString(fields[3])
	if err != nil || len(want) != sha256.Size {
		return false, errors.New("invalid AES Crypt HMAC")
	}
	if len(candidate) > 128 {
		return false, nil
	}
	key := make([]byte, 32)
	copy(key, salt)
	password := utf16le(candidate)
	for i := 0; i < 8192; i++ {
		h := sha256.New()
		h.Write(key)
		h.Write(password)
		key = h.Sum(nil)
	}
	mac := hmac.New(sha256.New, key)
	mac.Write(iv)
	mac.Write(wrappedKey)
	return hmac.Equal(mac.Sum(nil), want), nil
}

const multibitBase58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
const multibitBitcoinJ = ".abcdefghijklmnopqrstuvwxyz"

func verifyMultiBitKey(target, candidate string) (bool, error) {
	const prefix = "$multibit$1*"
	if !strings.HasPrefix(target, prefix) {
		return false, errors.New("invalid MultiBit key record prefix")
	}
	fields := strings.Split(target[len(prefix):], "*")
	if len(fields) != 2 {
		return false, errors.New("invalid MultiBit key record fields")
	}
	salt, err := hex.DecodeString(fields[0])
	if err != nil || len(salt) != 8 {
		return false, errors.New("invalid MultiBit salt")
	}
	ciphertext, err := hex.DecodeString(fields[1])
	if err != nil || len(ciphertext) != 32 {
		return false, errors.New("invalid MultiBit ciphertext")
	}
	if len(candidate) > 256 {
		return false, nil
	}
	wordSalt := append(append([]byte{}, []byte(candidate)...), salt...)
	key1 := md5.Sum(wordSalt)
	key2Input := append(append([]byte{}, key1[:]...), wordSalt...)
	key2 := md5.Sum(key2Input)
	ivInput := append(append([]byte{}, key2[:]...), wordSalt...)
	iv := md5.Sum(ivInput)
	key := append(append([]byte{}, key1[:]...), key2[:]...)
	block, err := aes.NewCipher(key)
	if err != nil {
		return false, err
	}
	plain := make([]byte, len(ciphertext))
	cipher.NewCBCDecrypter(block, iv[:]).CryptBlocks(plain, ciphertext)
	switch plain[0] {
	case 'K', 'L', 'Q', '5':
		return allInAlphabet(plain, multibitBase58), nil
	case '\n':
		return plain[1] < 128 && string(plain[2:6]) == "org." && allInAlphabet(plain[6:14], multibitBitcoinJ), nil
	case '#':
		return bytes.HasPrefix(plain, []byte("# KEEP YOUR PRIV")), nil
	default:
		return false, nil
	}
}

func allInAlphabet(value []byte, alphabet string) bool {
	for _, b := range value {
		if !strings.ContainsRune(alphabet, rune(b)) {
			return false
		}
	}
	return true
}

func verifyTerraWallet(target, candidate string) (bool, error) {
	if len(target) != 172 {
		return false, errors.New("invalid Terra Station wallet length")
	}
	salt, err := hex.DecodeString(target[:32])
	if err != nil {
		return false, errors.New("invalid Terra Station salt")
	}
	iv, err := hex.DecodeString(target[32:64])
	if err != nil {
		return false, errors.New("invalid Terra Station IV")
	}
	ciphertext, err := base64.StdEncoding.DecodeString(target[64:])
	if err != nil || len(ciphertext) != 80 {
		return false, errors.New("invalid Terra Station ciphertext")
	}
	if len(candidate) > 256 {
		return false, nil
	}
	key := pbkdf2.Key([]byte(candidate), salt, 100, 32, sha1.New)
	block, err := aes.NewCipher(key)
	if err != nil {
		return false, err
	}
	plain := make([]byte, len(ciphertext))
	cipher.NewCBCDecrypter(block, iv).CryptBlocks(plain, ciphertext)
	return bytes.Equal(plain[len(plain)-16:], bytes.Repeat([]byte{16}, 16)), nil
}

func isTerraWallet(target string) bool {
	if len(target) != 172 || !isHex(target[:64]) {
		return false
	}
	decoded, err := base64.StdEncoding.DecodeString(target[64:])
	return err == nil && len(decoded) == 80
}
