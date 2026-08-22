package main

// Small compatibility formats whose records carry parameters alongside a
// checksum or KDF result. Keeping their parsing here prevents the raw digest
// path from silently treating those parameters as ordinary prefix/suffix salt.

import (
	"crypto/sha1"
	"encoding/binary"
	"errors"
	"fmt"
	"hash/crc32"
	"strconv"
	"strings"
)

func verifyPBKDF1SHA1(target, candidate string) (bool, error) {
	f := strings.Split(target, ":")
	if len(f) != 5 || !strings.EqualFold(f[0], "PBKDF1") || !strings.EqualFold(f[1], "sha1") {
		return false, errors.New("invalid PBKDF1 hash (need PBKDF1:sha1:iter:b64salt:b64digest)")
	}
	iterations, err := strconv.Atoi(f[2])
	if err != nil || iterations < 1 || iterations > maxKDFIterations {
		return false, errors.New("invalid PBKDF1 iteration count")
	}
	salt, err := decodeBase64Flexible(f[3], false)
	if err != nil || len(salt) > maxKDFFieldSize {
		return false, errors.New("invalid PBKDF1 salt (base64)")
	}
	want, err := decodeBase64Flexible(f[4], false)
	if err != nil || len(want) == 0 || len(want) > sha1.Size {
		return false, errors.New("invalid PBKDF1 digest (base64, at most 20 bytes)")
	}
	first := sha1.Sum(append(append([]byte{}, candidate...), salt...))
	digest := first[:]
	for i := 1; i < iterations; i++ {
		next := sha1.Sum(digest)
		digest = next[:]
	}
	return bytesEqualCT(digest[:len(want)], want), nil
}

func isPBKDF1SHA1(target string) bool {
	f := strings.Split(target, ":")
	if len(f) != 5 || !strings.EqualFold(f[0], "PBKDF1") || !strings.EqualFold(f[1], "sha1") {
		return false
	}
	iterations, err := strconv.Atoi(f[2])
	if err != nil || iterations < 1 || iterations > maxKDFIterations {
		return false
	}
	salt, err := decodeBase64Flexible(f[3], false)
	if err != nil || len(salt) > maxKDFFieldSize {
		return false
	}
	digest, err := decodeBase64Flexible(f[4], false)
	return err == nil && len(digest) > 0 && len(digest) <= sha1.Size
}

func crc32HashcatHex(text, initial string) (string, error) {
	if len(initial) != 8 || !isHex(initial) {
		return "", errors.New("Hashcat CRC32 requires an 8-hex initial value")
	}
	value, _ := strconv.ParseUint(initial, 16, 32)
	return fmt.Sprintf("%08x", crc32.Update(uint32(value), crc32.IEEETable, []byte(text))), nil
}

func verifyCRC32Hashcat(target, candidate, initial string) (bool, error) {
	want := target
	if initial == "" {
		f := strings.Split(target, ":")
		if len(f) != 2 {
			return false, errors.New("invalid Hashcat CRC32 record (need crc32:initial-value)")
		}
		want, initial = f[0], f[1]
	}
	if len(want) != 8 || !isHex(want) {
		return false, errors.New("invalid CRC32 checksum (need 8 hex chars)")
	}
	got, err := crc32HashcatHex(candidate, initial)
	return err == nil && strings.EqualFold(got, want), err
}

// Hashcat mode 25700 uses the original MurmurHash (not MurmurHash3), with a
// 32-bit seed stored after the checksum.
func murmurHash25700(data []byte, seed uint32) uint32 {
	const multiplier uint32 = 0x7fd652ad
	h := seed + 0xdeadbeef
	blocks := len(data) / 4
	for i := 0; i < blocks; i++ {
		tmp := (h + binary.LittleEndian.Uint32(data[i*4:])) * multiplier
		h = tmp ^ tmp>>16
	}
	if len(data)&3 != 0 {
		var tail [4]byte
		copy(tail[:], data[blocks*4:])
		tmp := (h + binary.LittleEndian.Uint32(tail[:])) * multiplier
		h = tmp ^ tmp>>16
	}
	h *= multiplier
	h ^= h >> 10
	h *= multiplier
	h ^= h >> 17
	return h
}

func murmurHash25700Hex(text, seedText string) (string, error) {
	if len(seedText) != 8 || !isHex(seedText) {
		return "", errors.New("MurmurHash requires an 8-hex seed")
	}
	seed, _ := strconv.ParseUint(seedText, 16, 32)
	return fmt.Sprintf("%08x", murmurHash25700([]byte(text), uint32(seed))), nil
}

func verifyMurmurHash25700(target, candidate, seedText string) (bool, error) {
	want := target
	if seedText == "" {
		f := strings.Split(target, ":")
		if len(f) != 2 {
			return false, errors.New("invalid MurmurHash record (need hash:seed)")
		}
		want, seedText = f[0], f[1]
	}
	if len(want) != 8 || !isHex(want) {
		return false, errors.New("invalid MurmurHash checksum")
	}
	got, err := murmurHash25700Hex(candidate, seedText)
	return err == nil && strings.EqualFold(got, want), err
}

func murmurHash64A(data []byte, seed uint64) uint64 {
	const multiplier uint64 = 0xc6a4a7935bd1e995
	h := seed ^ uint64(len(data))*multiplier
	for len(data) >= 8 {
		k := binary.LittleEndian.Uint64(data)
		k *= multiplier
		k ^= k >> 47
		k *= multiplier
		h ^= k
		h *= multiplier
		data = data[8:]
	}
	var tail uint64
	for i, b := range data {
		tail |= uint64(b) << (8 * i)
	}
	if len(data) != 0 {
		h ^= tail
		h *= multiplier
	}
	h ^= h >> 47
	h *= multiplier
	h ^= h >> 47
	return h
}

func murmurHash64AHex(text, seedText string) (string, error) {
	var seed uint64
	if seedText != "" {
		if len(seedText) != 16 || !isHex(seedText) {
			return "", errors.New("MurmurHash64A requires a 16-hex seed")
		}
		seed, _ = strconv.ParseUint(seedText, 16, 64)
	}
	return fmt.Sprintf("%016x", murmurHash64A([]byte(text), seed)), nil
}

func verifyMurmurHash64A(target, candidate, seedText string, truncated bool) (bool, error) {
	want := target
	if seedText == "" && strings.Contains(target, ":") {
		f := strings.Split(target, ":")
		if len(f) != 2 {
			return false, errors.New("invalid MurmurHash64A record (need hash:seed)")
		}
		want, seedText = f[0], f[1]
	}
	wantLen := 16
	if truncated {
		wantLen = 8
	}
	if len(want) != wantLen || !isHex(want) {
		return false, errors.New("invalid MurmurHash64A checksum")
	}
	got, err := murmurHash64AHex(candidate, seedText)
	if truncated {
		got = got[:8]
	}
	return err == nil && strings.EqualFold(got, want), err
}

func isHexPair(target string, left, right int) bool {
	f := strings.Split(target, ":")
	return len(f) == 2 && len(f[0]) == left && len(f[1]) == right && isHex(f[0]) && isHex(f[1])
}
