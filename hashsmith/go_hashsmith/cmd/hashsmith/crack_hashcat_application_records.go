package main

// Application-specific authentication records from Hashcat's official test
// modules. These formats need more structure than the generic digest engine.

import (
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"math/big"
	"strings"
)

const dahuaAlphabet = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"

func isDahuaAuthToken(text string) bool {
	if len(text) != 8 {
		return false
	}
	for _, ch := range text {
		if !strings.ContainsRune(dahuaAlphabet, ch) {
			return false
		}
	}
	return true
}

func verifyDahuaAuthMD5(target, candidate string, besder bool) (bool, error) {
	if !isDahuaAuthToken(target) || len([]byte(candidate)) > 55 {
		return false, errors.New("invalid Dahua/Besder authentication record")
	}
	sum := md5.Sum([]byte(candidate))
	got := make([]byte, 8)
	for i := range got {
		v := int(sum[i*2]) + int(sum[i*2+1])
		if besder {
			v &= 0xff
		}
		got[i] = dahuaAlphabet[v%len(dahuaAlphabet)]
	}
	return subtle.ConstantTimeCompare(got, []byte(target)) == 1, nil
}

func verifyNetWitnessSHA256(target, candidate string) (bool, error) {
	if !isNetWitnessSHA256Record(target) || len([]byte(candidate)) > 256 {
		return false, errors.New("invalid NetWitness SHA-256 record")
	}
	fields := strings.Split(target, ":")
	want, _ := hex.DecodeString(fields[0])
	salt, _ := decodeBase64Flexible(fields[1], false)
	inner := sha256.Sum256([]byte(candidate))
	innerHex := strings.ToUpper(hex.EncodeToString(inner[:]))
	h := sha256.New()
	_, _ = h.Write([]byte(innerHex))
	_, _ = h.Write(salt)
	return subtle.ConstantTimeCompare(h.Sum(nil), want) == 1, nil
}

func isNetWitnessSHA256Record(target string) bool {
	fields := strings.Split(target, ":")
	if len(fields) != 2 || len(fields[0]) != 64 || !isHex(fields[0]) {
		return false
	}
	salt, err := decodeBase64Flexible(fields[1], false)
	return err == nil && len(salt) <= 256
}

func verifySaltedUsernameSHA1(target, candidate string) (bool, error) {
	fields := strings.Split(target, ":")
	if len(fields) != 3 || len(fields[0]) != 40 || !isHex(fields[0]) ||
		len(fields[1]) > 256 || len(fields[1])%2 != 0 || !isHexOrEmpty(fields[1]) ||
		len(fields[2]) > 256 || len(fields[2])%2 != 0 || !isHexOrEmpty(fields[2]) ||
		len([]byte(candidate)) > 256 {
		return false, errors.New("invalid salted username SHA-1 record")
	}
	want, _ := hex.DecodeString(fields[0])
	salt, _ := hex.DecodeString(fields[1])
	username, _ := hex.DecodeString(fields[2])
	innerHash := sha1.New()
	_, _ = innerHash.Write(utf16le(string(username)))
	_, _ = innerHash.Write([]byte{':'})
	_, _ = innerHash.Write(utf16le(candidate))
	outerHash := sha1.New()
	_, _ = outerHash.Write(salt)
	_, _ = outerHash.Write(innerHash.Sum(nil))
	return subtle.ConstantTimeCompare(outerHash.Sum(nil), want) == 1, nil
}

func isHexOrEmpty(text string) bool {
	return text == "" || isHex(text)
}

var radmin3Modulus = func() *big.Int {
	const modulusHex = "9847fc7e0f891dfd5d02f19d587d8f77aec0b980d4304b0113b406f23e2cec58cafca04a53e36fb68e0c3bff92cf335786b0dbe60dfe4178ef2fcd2a4dd09947ffd8df96fd0f9e2981a32da95503342eca9f08062cbdd4ac2d7cdf810db4db96db70102266261cd3f8bdd56a102fc6ceedbba5eae99e6127bdd952f7a0d18a79021c881ae63ec4b3590387f548598f2cb8f90dea36fc4f80c5473fdb6b0c6bdb0fdbaf4601f560dd149167ea125db8ad34fd0fd45350dec72cfb3b528ba2332d6091acea89dfd06c9c4d18f697245bd2ac9278b92bfe7dbafaa0c43b40a71f1930ebc4fd24c9e5a2e5a4ccf5d7f51544d70b2bca4af5b8d37b379fd7740a682f"
	n, ok := new(big.Int).SetString(modulusHex, 16)
	if !ok {
		panic("invalid Radmin3 modulus")
	}
	return n
}()

func verifyRadmin3(target, candidate string) (bool, error) {
	if !strings.HasPrefix(target, "$radmin3$") || len([]byte(candidate)) > 256 {
		return false, errors.New("invalid Radmin3 record")
	}
	fields := strings.Split(strings.TrimPrefix(target, "$radmin3$"), "*")
	if len(fields) != 3 || len(fields[0]) > 512 || len(fields[0])%2 != 0 || !isHexOrEmpty(fields[0]) ||
		len(fields[1]) != 64 || !isHex(fields[1]) || len(fields[2]) != 512 || !isHex(fields[2]) {
		return false, errors.New("invalid Radmin3 record")
	}
	username, _ := hex.DecodeString(fields[0])
	salt, _ := hex.DecodeString(fields[1])
	want, _ := hex.DecodeString(fields[2])
	innerHash := sha1.New()
	_, _ = innerHash.Write(username)
	_, _ = innerHash.Write([]byte{':'})
	_, _ = innerHash.Write(utf16le(candidate))
	exponentHash := sha1.New()
	_, _ = exponentHash.Write(salt)
	_, _ = exponentHash.Write(innerHash.Sum(nil))
	exponent := new(big.Int).SetBytes(exponentHash.Sum(nil))
	verifier := new(big.Int).Exp(big.NewInt(5), exponent, radmin3Modulus).Bytes()
	if len(verifier) > len(want) {
		return false, errors.New("invalid Radmin3 verifier width")
	}
	got := make([]byte, len(want))
	copy(got[len(got)-len(verifier):], verifier)
	return subtle.ConstantTimeCompare(got, want) == 1, nil
}
