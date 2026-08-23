package main

// Legacy database, DNS, and known-plaintext cipher verifiers. The record
// layouts and limits follow Hashcat's official modules; Oracle H and NSEC3 also
// accept John the Ripper's canonical text forms.

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/des"
	"crypto/sha1"
	"crypto/subtle"
	"encoding/base32"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"strconv"
	"strings"
	"unicode/utf16"
)

func verifyOracleH(target, candidate string) (bool, error) {
	want, username, ok := parseOracleH(target)
	if !ok || len([]byte(candidate)) > 30 {
		return false, errors.New("invalid Oracle H record")
	}
	upper := strings.ToUpper(username + candidate)
	units := utf16.Encode([]rune(upper))
	data := make([]byte, 0, ((len(units)*2+7)/8)*8)
	for _, unit := range units {
		data = append(data, byte(unit>>8), byte(unit))
	}
	if rem := len(data) % des.BlockSize; rem != 0 {
		data = append(data, make([]byte, des.BlockSize-rem)...)
	}
	first, err := oracleDESCBC(data, []byte{0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef})
	if err != nil {
		return false, err
	}
	second, err := oracleDESCBC(data, first)
	if err != nil {
		return false, err
	}
	return subtle.ConstantTimeCompare(second, want) == 1, nil
}

func parseOracleH(target string) (digest []byte, username string, ok bool) {
	var digestText string
	if strings.HasPrefix(target, "O$") {
		body := strings.TrimPrefix(target, "O$")
		fields := strings.Split(body, "#")
		if len(fields) != 2 {
			return nil, "", false
		}
		username, digestText = fields[0], fields[1]
	} else {
		fields := strings.Split(target, ":")
		if len(fields) != 2 {
			return nil, "", false
		}
		digestText, username = fields[0], fields[1]
	}
	if len(digestText) != 16 || !isHex(digestText) || len(username) < 1 || len([]byte(username)) > 30 {
		return nil, "", false
	}
	digest, _ = hex.DecodeString(digestText)
	return digest, username, true
}

func oracleDESCBC(data, key []byte) ([]byte, error) {
	block, err := des.NewCipher(key)
	if err != nil {
		return nil, err
	}
	out := make([]byte, len(data))
	cipher.NewCBCEncrypter(block, make([]byte, des.BlockSize)).CryptBlocks(out, data)
	return append([]byte(nil), out[len(out)-des.BlockSize:]...), nil
}

type nsec3Record struct {
	want       []byte
	domain     string
	salt       []byte
	iterations int
	john       bool
}

func parseNSEC3(target string) (nsec3Record, error) {
	var record nsec3Record
	if strings.HasPrefix(target, "$NSEC3$") {
		fields := strings.Split(target, "$")
		if len(fields) != 6 || fields[0] != "" || fields[1] != "NSEC3" ||
			len(fields[4]) != 40 || !isHex(fields[4]) || fields[5] == "" || !strings.HasSuffix(fields[5], ".") {
			return record, errors.New("invalid John NSEC3 record")
		}
		record.iterations, _ = strconv.Atoi(fields[2])
		if record.iterations < 0 || record.iterations > 65535 || len(fields[3])%2 != 0 || !isHexOrEmpty(fields[3]) {
			return record, errors.New("invalid John NSEC3 parameters")
		}
		record.salt, _ = hex.DecodeString(fields[3])
		record.want, _ = hex.DecodeString(fields[4])
		record.domain, record.john = fields[5], true
		return record, nil
	}
	fields := strings.Split(target, ":")
	if len(fields) != 4 || len(fields[0]) != 32 || len(fields[1]) > 256 ||
		(fields[1] != "" && !strings.HasPrefix(fields[1], ".")) || len(fields[2]) > 256 ||
		len(fields[2])%2 != 0 || !isHexOrEmpty(fields[2]) || len(fields[3]) < 1 || len(fields[3]) > 6 {
		return record, errors.New("invalid Hashcat NSEC3 record")
	}
	encoded := strings.ToUpper(fields[0])
	record.want, _ = base32.HexEncoding.WithPadding(base32.NoPadding).DecodeString(encoded)
	if len(record.want) != sha1.Size {
		return record, errors.New("invalid NSEC3 digest")
	}
	record.iterations, _ = strconv.Atoi(fields[3])
	if record.iterations < 0 || record.iterations > 999999 {
		return record, errors.New("invalid NSEC3 iteration count")
	}
	record.salt, _ = hex.DecodeString(fields[2])
	record.domain = fields[1]
	return record, nil
}

func verifyNSEC3(target, candidate string) (bool, error) {
	record, err := parseNSEC3(target)
	if err != nil || len([]byte(candidate)) > 63 {
		if err != nil {
			return false, err
		}
		return false, errors.New("NSEC3 candidate exceeds 63 bytes")
	}
	name := candidate + record.domain
	if record.john {
		name = candidate + "." + record.domain
	}
	wire, err := dnsNameWire(name)
	if err != nil {
		return false, err
	}
	initial := make([]byte, 0, len(wire)+len(record.salt))
	initial = append(initial, wire...)
	initial = append(initial, record.salt...)
	sum := sha1.Sum(initial)
	for i := 0; i < record.iterations; i++ {
		next := make([]byte, 0, sha1.Size+len(record.salt))
		next = append(next, sum[:]...)
		next = append(next, record.salt...)
		sum = sha1.Sum(next)
	}
	return subtle.ConstantTimeCompare(sum[:], record.want) == 1, nil
}

func dnsNameWire(name string) ([]byte, error) {
	name = strings.ToLower(strings.Trim(name, "."))
	if name == "" {
		return []byte{0}, nil
	}
	labels := strings.Split(name, ".")
	wire := make([]byte, 0, len(name)+2)
	for _, label := range labels {
		if len(label) == 0 || len(label) > 63 {
			return nil, errors.New("invalid DNS label in NSEC3 record")
		}
		wire = append(wire, byte(len(label)))
		wire = append(wire, label...)
	}
	wire = append(wire, 0)
	if len(wire) > 255 {
		return nil, errors.New("NSEC3 domain exceeds wire-format limit")
	}
	return wire, nil
}

func isNSEC3Record(target string) bool {
	_, err := parseNSEC3(target)
	return err == nil
}

var skip32FTable = [256]byte{
	0xa3, 0xd7, 0x09, 0x83, 0xf8, 0x48, 0xf6, 0xf4, 0xb3, 0x21, 0x15, 0x78, 0x99, 0xb1, 0xaf, 0xf9,
	0xe7, 0x2d, 0x4d, 0x8a, 0xce, 0x4c, 0xca, 0x2e, 0x52, 0x95, 0xd9, 0x1e, 0x4e, 0x38, 0x44, 0x28,
	0x0a, 0xdf, 0x02, 0xa0, 0x17, 0xf1, 0x60, 0x68, 0x12, 0xb7, 0x7a, 0xc3, 0xe9, 0xfa, 0x3d, 0x53,
	0x96, 0x84, 0x6b, 0xba, 0xf2, 0x63, 0x9a, 0x19, 0x7c, 0xae, 0xe5, 0xf5, 0xf7, 0x16, 0x6a, 0xa2,
	0x39, 0xb6, 0x7b, 0x0f, 0xc1, 0x93, 0x81, 0x1b, 0xee, 0xb4, 0x1a, 0xea, 0xd0, 0x91, 0x2f, 0xb8,
	0x55, 0xb9, 0xda, 0x85, 0x3f, 0x41, 0xbf, 0xe0, 0x5a, 0x58, 0x80, 0x5f, 0x66, 0x0b, 0xd8, 0x90,
	0x35, 0xd5, 0xc0, 0xa7, 0x33, 0x06, 0x65, 0x69, 0x45, 0x00, 0x94, 0x56, 0x6d, 0x98, 0x9b, 0x76,
	0x97, 0xfc, 0xb2, 0xc2, 0xb0, 0xfe, 0xdb, 0x20, 0xe1, 0xeb, 0xd6, 0xe4, 0xdd, 0x47, 0x4a, 0x1d,
	0x42, 0xed, 0x9e, 0x6e, 0x49, 0x3c, 0xcd, 0x43, 0x27, 0xd2, 0x07, 0xd4, 0xde, 0xc7, 0x67, 0x18,
	0x89, 0xcb, 0x30, 0x1f, 0x8d, 0xc6, 0x8f, 0xaa, 0xc8, 0x74, 0xdc, 0xc9, 0x5d, 0x5c, 0x31, 0xa4,
	0x70, 0x88, 0x61, 0x2c, 0x9f, 0x0d, 0x2b, 0x87, 0x50, 0x82, 0x54, 0x64, 0x26, 0x7d, 0x03, 0x40,
	0x34, 0x4b, 0x1c, 0x73, 0xd1, 0xc4, 0xfd, 0x3b, 0xcc, 0xfb, 0x7f, 0xab, 0xe6, 0x3e, 0x5b, 0xa5,
	0xad, 0x04, 0x23, 0x9c, 0x14, 0x51, 0x22, 0xf0, 0x29, 0x79, 0x71, 0x7e, 0xff, 0x8c, 0x0e, 0xe2,
	0x0c, 0xef, 0xbc, 0x72, 0x75, 0x6f, 0x37, 0xa1, 0xec, 0xd3, 0x8e, 0x62, 0x8b, 0x86, 0x10, 0xe8,
	0x08, 0x77, 0x11, 0xbe, 0x92, 0x4f, 0x24, 0xc5, 0x32, 0x36, 0x9d, 0xcf, 0xf3, 0xa6, 0xbb, 0xac,
	0x5e, 0x6c, 0xa9, 0x13, 0x57, 0x25, 0xb5, 0xe3, 0xbd, 0xa8, 0x3a, 0x01, 0x05, 0x59, 0x2a, 0x46,
}

func skip32G(key []byte, round int, w uint16) uint16 {
	g1, g2 := byte(w>>8), byte(w)
	g3 := skip32FTable[g2^key[(4*round)%10]] ^ g1
	g4 := skip32FTable[g3^key[(4*round+1)%10]] ^ g2
	g5 := skip32FTable[g4^key[(4*round+2)%10]] ^ g3
	g6 := skip32FTable[g5^key[(4*round+3)%10]] ^ g4
	return uint16(g5)<<8 | uint16(g6)
}

func skip32Encrypt(key, plaintext []byte) [4]byte {
	wl := binary.BigEndian.Uint16(plaintext[:2])
	wr := binary.BigEndian.Uint16(plaintext[2:])
	for round := 0; round < 24; round += 2 {
		wr ^= skip32G(key, round, wl) ^ uint16(round)
		wl ^= skip32G(key, round+1, wr) ^ uint16(round+1)
	}
	var out [4]byte
	binary.BigEndian.PutUint16(out[:2], wr)
	binary.BigEndian.PutUint16(out[2:], wl)
	return out
}

func verifySkip32(target, candidate string) (bool, error) {
	if !isHexPair(target, 8, 8) || len([]byte(candidate)) != 10 {
		return false, errors.New("invalid Skip32 record or key length")
	}
	fields := strings.Split(target, ":")
	want, _ := hex.DecodeString(fields[0])
	plaintext, _ := hex.DecodeString(fields[1])
	got := skip32Encrypt([]byte(candidate), plaintext)
	return subtle.ConstantTimeCompare(got[:], want) == 1, nil
}

func verifyAESNOKDF(target, candidate string, keySize int) (bool, error) {
	if !isHexPair(target, 32, 32) || len([]byte(candidate)) > keySize {
		return false, errors.New("invalid AES-ECB NOKDF record or key length")
	}
	fields := strings.Split(target, ":")
	want, _ := hex.DecodeString(fields[0])
	plaintext, _ := hex.DecodeString(fields[1])
	key := make([]byte, keySize)
	copy(key, []byte(candidate))
	block, err := aes.NewCipher(key)
	if err != nil {
		return false, err
	}
	got := make([]byte, aes.BlockSize)
	block.Encrypt(got, plaintext)
	return subtle.ConstantTimeCompare(got, want) == 1, nil
}
