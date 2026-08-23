package main

// Authentication and application records implemented from Hashcat's official
// module test suites. All parsers retain the canonical interchange spelling.

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"hash"
	"strconv"
	"strings"

	"golang.org/x/crypto/pbkdf2"
)

func verifyPostgresCRAM(target, candidate string) (bool, error) {
	parts := strings.Split(target, "$")
	if len(parts) != 3 || parts[0] != "" || parts[1] != "postgres" {
		return false, errors.New("invalid PostgreSQL CRAM-MD5 record")
	}
	fields := strings.Split(parts[2], "*")
	if len(fields) != 3 || fields[0] == "" || len(fields[0]) > 55 || len(fields[1]) != 8 || !isHex(fields[1]) ||
		len(fields[2]) != 32 || !isHex(fields[2]) {
		return false, errors.New("invalid PostgreSQL CRAM-MD5 fields")
	}
	salt, _ := hex.DecodeString(fields[1])
	inner := md5HexString(candidate + fields[0])
	h := md5.New()
	_, _ = h.Write([]byte(inner))
	_, _ = h.Write(salt)
	return strings.EqualFold(hex.EncodeToString(h.Sum(nil)), fields[2]), nil
}

func isTOTPRecord(target string) bool {
	parts := strings.Split(target, ":")
	if len(parts) < 2 || len(parts) > 8 || len(parts)%2 != 0 {
		return false
	}
	for i := 0; i < len(parts); i += 2 {
		if len(parts[i]) != 6 {
			return false
		}
		if _, err := strconv.Atoi(parts[i]); err != nil {
			return false
		}
		if _, err := strconv.ParseUint(parts[i+1], 10, 64); err != nil {
			return false
		}
	}
	return true
}

func verifyTOTP(target, candidate string) (bool, error) {
	if !isTOTPRecord(target) {
		return false, errors.New("invalid TOTP record")
	}
	parts := strings.Split(target, ":")
	for i := 0; i < len(parts); i += 2 {
		want, _ := strconv.Atoi(parts[i])
		timestamp, _ := strconv.ParseUint(parts[i+1], 10, 64)
		var counter [8]byte
		binary.BigEndian.PutUint64(counter[:], timestamp/30)
		mac := hmac.New(sha1.New, []byte(candidate))
		_, _ = mac.Write(counter[:])
		digest := mac.Sum(nil)
		offset := digest[len(digest)-1] & 0x0f
		got := int(binary.BigEndian.Uint32(digest[offset:offset+4])&0x7fffffff) % 1000000
		if got != want {
			return false, nil
		}
	}
	return true, nil
}

func snmpV3AuthDigest(candidate string, engineID, packet []byte, newHash func() hash.Hash, digestLen int) []byte {
	password := []byte(candidate)
	h := newHash()
	for written := 0; written < 1048576; {
		n := len(password)
		if n > 1048576-written {
			n = 1048576 - written
		}
		_, _ = h.Write(password[:n])
		written += n
	}
	passwordDigest := h.Sum(nil)
	h.Reset()
	_, _ = h.Write(passwordDigest)
	_, _ = h.Write(engineID)
	_, _ = h.Write(passwordDigest)
	localizedKey := h.Sum(nil)
	mac := hmac.New(newHash, localizedKey)
	_, _ = mac.Write(packet)
	return mac.Sum(nil)[:digestLen]
}

func verifySNMPv3(target, candidate string) (bool, error) {
	parts := strings.Split(target, "$")
	if len(parts) != 7 || parts[0] != "" || parts[1] != "SNMPv3" || len(candidate) < 8 || len(candidate) > 256 {
		return false, errors.New("invalid SNMPv3 record or password length")
	}
	type snmpVariant struct {
		newHash      func() hash.Hash
		digestLen    int
		minPacketHex int
		padEngineID  bool
	}
	variants := map[string]snmpVariant{
		"1": {md5.New, 12, 24, false},
		"2": {sha1.New, 12, 24, false},
		"3": {sha256.New224, 16, 32, false},
		"4": {sha256.New, 24, 48, false},
		"5": {sha512.New384, 32, 64, true},
		"6": {sha512.New, 48, 96, true},
	}
	variant, knownVariant := variants[parts[2]]
	if parts[2] != "0" && !knownVariant {
		return false, errors.New("unsupported SNMPv3 authentication type")
	}
	if parts[2] == "0" {
		variant = snmpVariant{md5.New, 12, 24, false}
	}
	if len(parts[3]) < 1 || len(parts[3]) > 8 {
		return false, errors.New("invalid SNMPv3 packet number")
	}
	if _, err := strconv.ParseUint(parts[3], 10, 32); err != nil {
		return false, errors.New("invalid SNMPv3 packet number")
	}
	if len(parts[4]) < variant.minPacketHex || len(parts[4]) > 3000 || len(parts[4])%2 != 0 || !isHex(parts[4]) ||
		len(parts[5]) < 10 || len(parts[5]) > 34 || len(parts[5])%2 != 0 || !isHex(parts[5]) ||
		len(parts[6]) != variant.digestLen*2 || !isHex(parts[6]) {
		return false, errors.New("invalid SNMPv3 fields")
	}
	packet, _ := hex.DecodeString(parts[4])
	engineID, _ := hex.DecodeString(parts[5])
	if variant.padEngineID && len(engineID) < 17 {
		engineID = append(engineID, make([]byte, 17-len(engineID))...)
	}
	want, _ := hex.DecodeString(parts[6])
	if got := snmpV3AuthDigest(candidate, engineID, packet, variant.newHash, variant.digestLen); bytesEqualCT(got, want) {
		return true, nil
	}
	if parts[2] == "0" {
		got := snmpV3AuthDigest(candidate, engineID, packet, sha1.New, 12)
		return bytesEqualCT(got, want), nil
	}
	return false, nil
}

func verifyQNX(target, candidate, variant string) (bool, error) {
	parts := strings.Split(target, "@")
	if len(parts) != 4 || parts[0] != "" || len(parts[3]) != 16 {
		return false, errors.New("invalid QNX shadow record")
	}
	tagParts := strings.Split(parts[1], ",")
	if len(tagParts) < 1 || len(tagParts) > 2 || tagParts[0] != variant {
		return false, errors.New("invalid QNX hash variant")
	}
	iterations := 1000
	if len(tagParts) == 2 {
		var err error
		iterations, err = strconv.Atoi(tagParts[1])
		if err != nil || iterations < 1 || iterations > maxKDFIterations {
			return false, errors.New("invalid QNX iteration count")
		}
	}
	var newHash func() hash.Hash
	var digestLen int
	switch variant {
	case "m":
		newHash, digestLen = md5.New, md5.Size
	case "s":
		newHash, digestLen = sha256.New, sha256.Size
	case "S":
		newHash, digestLen = sha512.New, sha512.Size
	default:
		return false, errors.New("unsupported QNX hash variant")
	}
	if len(parts[2]) != digestLen*2 || !isHex(parts[2]) {
		return false, errors.New("invalid QNX digest")
	}
	h := newHash()
	_, _ = h.Write([]byte(parts[3]))
	for i := 0; i <= iterations; i++ {
		_, _ = h.Write([]byte(candidate))
	}
	return strings.EqualFold(hex.EncodeToString(h.Sum(nil)), parts[2]), nil
}

func verifySAPIteratedSHA(target, candidate, variant string) (bool, error) {
	var prefix string
	var newHash func() hash.Hash
	var digestLen int
	switch variant {
	case "sha1":
		prefix, newHash, digestLen = "{x-issha, ", sha1.New, sha1.Size
	case "sha256":
		prefix, newHash, digestLen = "{x-isSHA256, ", sha256.New, sha256.Size
	case "sha384":
		prefix, newHash, digestLen = "{x-isSHA384, ", sha512.New384, sha512.Size384
	case "sha512":
		prefix, newHash, digestLen = "{x-isSHA512, ", sha512.New, sha512.Size
	default:
		return false, errors.New("unsupported SAP iSSHA variant")
	}
	if !strings.HasPrefix(target, prefix) {
		return false, errors.New("invalid SAP iSSHA record")
	}
	close := strings.IndexByte(target[len(prefix):], '}')
	if close < 1 {
		return false, errors.New("invalid SAP iSSHA iteration field")
	}
	close += len(prefix)
	iterations, err := strconv.Atoi(strings.TrimSpace(target[len(prefix):close]))
	if err != nil || iterations < 1 || iterations > maxKDFIterations {
		return false, errors.New("invalid SAP iSSHA iteration count")
	}
	decoded, err := base64.StdEncoding.DecodeString(target[close+1:])
	if err != nil || len(decoded) <= digestLen || len(decoded) > digestLen+maxKDFFieldSize {
		return false, errors.New("invalid SAP iSSHA payload")
	}
	want, salt := decoded[:digestLen], decoded[digestLen:]
	digest := salt
	for i := 0; i < iterations; i++ {
		h := newHash()
		_, _ = h.Write([]byte(candidate))
		_, _ = h.Write(digest)
		digest = h.Sum(nil)
	}
	return bytesEqualCT(digest, want), nil
}

func verifyStellarWallet(target, candidate string) (bool, error) {
	parts := strings.Split(target, "$")
	if len(parts) != 5 || parts[0] != "" || parts[1] != "stellar" {
		return false, errors.New("invalid Stellar wallet record")
	}
	salt, err := base64.StdEncoding.DecodeString(parts[2])
	if err != nil || len(salt) != 16 {
		return false, errors.New("invalid Stellar wallet salt")
	}
	iv, err := base64.StdEncoding.DecodeString(parts[3])
	if err != nil || len(iv) != 12 {
		return false, errors.New("invalid Stellar wallet IV")
	}
	ciphertext, err := base64.StdEncoding.DecodeString(parts[4])
	if err != nil || len(ciphertext) != 72 {
		return false, errors.New("invalid Stellar wallet ciphertext")
	}
	key := pbkdf2.Key([]byte(candidate), salt, 4096, 32, sha256.New)
	block, err := aes.NewCipher(key)
	if err != nil {
		return false, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return false, err
	}
	_, err = gcm.Open(nil, iv, ciphertext, nil)
	return err == nil, nil
}

func progressCRCTableValue(v byte) uint16 {
	crc := uint16(v)
	for i := 0; i < 8; i++ {
		if crc&1 != 0 {
			crc = crc>>1 ^ 0xa001
		} else {
			crc >>= 1
		}
	}
	return crc
}

func verifyOpenEdge(target, candidate string) (bool, error) {
	word := []byte(candidate)
	if len(target) != 16 || len(word) > 16 {
		return false, errors.New("invalid OpenEdge Progress record or password length")
	}
	for _, b := range []byte(target) {
		if !((b >= 'A' && b <= 'Z') || (b >= 'a' && b <= 'z')) {
			return false, errors.New("invalid OpenEdge Progress encoding")
		}
	}
	var scratch, encoded [16]byte
	hashValue := uint16(17)
	for round := 0; round < 5; round++ {
		for j, b := range word {
			scratch[15-j%16] ^= b
		}
		for j := 0; j < 16; j += 2 {
			for k := 15; k >= 0; k-- {
				hashValue = hashValue>>8 ^ progressCRCTableValue(byte(hashValue)) ^ progressCRCTableValue(scratch[k])
			}
			scratch[j] = byte(hashValue)
			scratch[j+1] = byte(hashValue >> 8)
		}
	}
	for i, b := range scratch {
		low := b & 0x7f
		if low >= 'A' && low <= 'Z' || low >= 'a' && low <= 'z' {
			encoded[i] = low
		} else {
			encoded[i] = (b >> 4) + 'a'
		}
	}
	return bytesEqualCT(encoded[:], []byte(target)), nil
}

func awsHMACSHA256(key []byte, message string) []byte {
	mac := hmac.New(sha256.New, key)
	_, _ = mac.Write([]byte(message))
	return mac.Sum(nil)
}

func verifyAWSSignatureV4(target, candidate string) (bool, error) {
	parts := strings.Split(target, "$")
	if len(parts) != 8 || parts[0] != "" || parts[1] != "AWS-Sig-v4" || parts[2] != "0" ||
		len(parts[3]) != 16 || parts[4] == "" || parts[5] == "" || len(parts[6]) != 64 || !isHex(parts[6]) ||
		len(parts[7]) != 64 || !isHex(parts[7]) {
		return false, errors.New("invalid AWS Signature v4 record")
	}
	longDate, region, service, canonical := parts[3], parts[4], parts[5], parts[6]
	if longDate[8] != 'T' || longDate[15] != 'Z' {
		return false, errors.New("invalid AWS Signature v4 date")
	}
	if _, err := strconv.ParseUint(longDate[:8]+longDate[9:15], 10, 64); err != nil {
		return false, errors.New("invalid AWS Signature v4 date")
	}
	date := longDate[:8]
	kDate := awsHMACSHA256([]byte("AWS4"+candidate), date)
	kRegion := awsHMACSHA256(kDate, region)
	kService := awsHMACSHA256(kRegion, service)
	kSigning := awsHMACSHA256(kService, "aws4_request")
	stringToSign := fmt.Sprintf("AWS4-HMAC-SHA256\n%s\n%s/%s/%s/aws4_request\n%s", longDate, date, region, service, canonical)
	got := awsHMACSHA256(kSigning, stringToSign)
	want, _ := hex.DecodeString(parts[7])
	return bytesEqualCT(got, want), nil
}
