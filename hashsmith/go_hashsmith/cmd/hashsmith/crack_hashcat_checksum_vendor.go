package main

// Seeded checksums and compact vendor records from Hashcat's official modules.

import (
	"crypto/hmac"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"hash/crc64"
	"strconv"
	"strings"
)

var crc64JonesTable = crc64.MakeTable(0x95ac9329ac4bc9b5)

func verifyMurmur3Seeded(target, candidate string) (bool, error) {
	parts := strings.Split(target, ":")
	if len(parts) != 2 || len(parts[0]) != 8 || !isHex(parts[0]) || len(parts[1]) != 8 || !isHex(parts[1]) ||
		len([]byte(candidate)) > 31 {
		return false, errors.New("invalid seeded MurmurHash3 record")
	}
	seed, _ := strconv.ParseUint(parts[1], 16, 32)
	got := fmt.Sprintf("%08x", murmur3_32Seed([]byte(candidate), uint32(seed)))
	return strings.EqualFold(got, parts[0]), nil
}

func verifyCRC32CSeeded(target, candidate string) (bool, error) {
	parts := strings.Split(target, ":")
	if len(parts) != 2 || len(parts[0]) != 8 || !isHex(parts[0]) || len(parts[1]) != 8 || !isHex(parts[1]) ||
		len([]byte(candidate)) > 256 {
		return false, errors.New("invalid seeded CRC32C record")
	}
	initial, _ := strconv.ParseUint(parts[1], 16, 32)
	// Digest::CRC/Hashcat expose the finalized CRC as the initial value; the
	// reflected update loop operates on its complemented internal register.
	crc := ^uint32(initial)
	for _, b := range []byte(candidate) {
		crc = crc32cTable[byte(crc)^b] ^ crc>>8
	}
	got := fmt.Sprintf("%08x", crc^0xffffffff)
	return strings.EqualFold(got, parts[0]), nil
}

func verifyCRC64Jones(target, candidate string) (bool, error) {
	parts := strings.Split(target, ":")
	if len(parts) != 2 || len(parts[0]) != 16 || !isHex(parts[0]) || len(parts[1]) != 16 || !isHex(parts[1]) ||
		len([]byte(candidate)) > 256 {
		return false, errors.New("invalid CRC64-Jones record")
	}
	initial, _ := strconv.ParseUint(parts[1], 16, 64)
	crc := initial
	for _, b := range []byte(candidate) {
		crc = crc64JonesTable[byte(crc)^b] ^ crc>>8
	}
	got := fmt.Sprintf("%016x", crc)
	return strings.EqualFold(got, parts[0]), nil
}

func verifyCitrixSHA512(target, candidate string) (bool, error) {
	if len(target) != 137 || target[0] != '2' || !isHex(target[1:9]) || !isHex(target[9:]) ||
		len([]byte(candidate)) > 256 {
		return false, errors.New("invalid Citrix NetScaler SHA-512 record")
	}
	h := sha512.New()
	_, _ = h.Write([]byte(target[1:9]))
	_, _ = h.Write([]byte(candidate))
	_, _ = h.Write([]byte{0})
	return strings.EqualFold(hex.EncodeToString(h.Sum(nil)), target[9:]), nil
}

func verifyFortiGate256(target, candidate string) (bool, error) {
	if len(target) != 63 || !strings.HasPrefix(target, "SH2") || len([]byte(candidate)) > 256 {
		return false, errors.New("invalid FortiGate256 record")
	}
	decoded, err := base64.StdEncoding.DecodeString(target[3:])
	if err != nil || len(decoded) != 44 {
		return false, errors.New("invalid FortiGate256 payload")
	}
	salt, want := decoded[:12], decoded[12:]
	h := sha256.New()
	_, _ = h.Write(salt)
	_, _ = h.Write([]byte(candidate))
	_, _ = h.Write(fortiGateMagic)
	return bytesEqualCT(h.Sum(nil), want), nil
}

func verifyUmbracoHMACSHA1(target, candidate string) (bool, error) {
	if len(target) != 28 || len([]byte(candidate)) > 256 {
		return false, errors.New("invalid Umbraco HMAC-SHA1 record")
	}
	want, err := base64.StdEncoding.DecodeString(target)
	if err != nil || len(want) != sha1.Size {
		return false, errors.New("invalid Umbraco HMAC-SHA1 digest")
	}
	unicodePassword := utf16le(candidate)
	mac := hmac.New(sha1.New, unicodePassword)
	_, _ = mac.Write(unicodePassword)
	return hmac.Equal(mac.Sum(nil), want), nil
}

func isUmbracoHMACSHA1(target string) bool {
	if len(target) != 28 {
		return false
	}
	decoded, err := base64.StdEncoding.DecodeString(target)
	return err == nil && len(decoded) == sha1.Size
}
