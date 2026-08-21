package main

import (
	"crypto/des"
	"crypto/sha3"
	"encoding/hex"
	"errors"
	"fmt"
	"hash"
	"hash/adler32"
	"hash/crc32"
	"hash/crc64"
	"strings"
)

func newSHA3_224() hash.Hash { return sha3.New224() }
func newSHA3_256() hash.Hash { return sha3.New256() }
func newSHA3_384() hash.Hash { return sha3.New384() }
func newSHA3_512() hash.Hash { return sha3.New512() }

var (
	crc32cTable      = crc32.MakeTable(crc32.Castagnoli)
	crc64Table       = crc64.MakeTable(crc64.ECMA)
	hashOutputCodecs = map[string]bool{
		"base32": true, "base32-nopad": true, "base32hex": true,
		"base32crockford": true, "zbase32": true, "base36": true, "base45": true,
		"base58": true, "base58flickr": true, "base58ripple": true,
		"base58check": true, "base62": true,
		"base64": true, "base64raw": true, "base64url": true,
		"base64url-padded": true, "base64-mime": true,
		"base85": true, "adobe85": true,
		"z85": true, "base91": true, "binary": true, "decimal": true,
		"octal": true, "pem": true, "gzip": true, "zlib": true,
		"hex-escape": true, "bubblebabble": true,
	}
)

// canonicalHashType accepts the punctuation variants people commonly use for
// standardized algorithm names while preserving Hashsmith's stable CLI tokens.
func canonicalHashType(typ string) string {
	t := strings.ToLower(strings.TrimSpace(typ))
	switch t {
	case "sha-1":
		return "sha1"
	case "sha-0":
		return "sha0"
	case "md-2":
		return "md2"
	case "sha-224", "sha2-224":
		return "sha224"
	case "sha-256", "sha2-256":
		return "sha256"
	case "sha-384", "sha2-384":
		return "sha384"
	case "sha-512", "sha2-512":
		return "sha512"
	case "sha512-224", "sha512/224", "sha-512/224":
		return "sha512_224"
	case "sha512-256", "sha512/256", "sha-512/256":
		return "sha512_256"
	case "sha3-224":
		return "sha3_224"
	case "sha3-256":
		return "sha3_256"
	case "sha3-384":
		return "sha3_384"
	case "sha3-512":
		return "sha3_512"
	case "sha3-256-sha3-256":
		return "sha3_256-sha3_256"
	case "hmac-sha3-224", "hmac-sha3/224":
		return "hmac-sha3_224"
	case "hmac-sha3-256", "hmac-sha3/256":
		return "hmac-sha3_256"
	case "hmac-sha3-384", "hmac-sha3/384":
		return "hmac-sha3_384"
	case "hmac-sha3-512", "hmac-sha3/512":
		return "hmac-sha3_512"
	case "hmac-sha3-224-saltkey", "hmac-sha3/224-saltkey":
		return "hmac-sha3_224-saltkey"
	case "hmac-sha3-256-saltkey", "hmac-sha3/256-saltkey":
		return "hmac-sha3_256-saltkey"
	case "hmac-sha3-384-saltkey", "hmac-sha3/384-saltkey":
		return "hmac-sha3_384-saltkey"
	case "hmac-sha3-512-saltkey", "hmac-sha3/512-saltkey":
		return "hmac-sha3_512-saltkey"
	case "hmac-ripemd-160":
		return "hmac-ripemd160"
	case "hmac-ripemd-160-saltkey":
		return "hmac-ripemd160-saltkey"
	case "keccak-256":
		return "keccak256"
	case "keccak-512":
		return "keccak512"
	case "shake128", "shake-128", "shake128/256":
		return "shake128-256"
	case "shake256", "shake-256", "shake256/512":
		return "shake256-512"
	case "blake2b-256":
		return "blake2b256"
	case "blake2b-384":
		return "blake2b384"
	case "blake2b-512":
		return "blake2b"
	case "blake2s-256":
		return "blake2s"
	case "ripemd-160":
		return "ripemd160"
	case "sm-3":
		return "sm3"
	case "lmhash", "lanman":
		return "lm"
	case "crc-32", "crc32-ieee":
		return "crc32"
	case "crc-32c", "castagnoli":
		return "crc32c"
	case "crc-64", "crc64-ecma":
		return "crc64"
	case "adler-32":
		return "adler32"
	case "fnv-1a-32":
		return "fnv1a32"
	case "fnv-1a-64":
		return "fnv1a64"
	case "xxh32", "xxhash-32":
		return "xxhash32"
	case "xxh64", "xxhash-64":
		return "xxhash64"
	case "murmur3", "murmurhash3", "murmurhash3-32":
		return "murmur3-32"
	case "mysql-a", "mysql-$a$", "caching-sha2-password", "mysql8-caching-sha2":
		return "mysql8"
	case "389-ds", "389ds", "redhat-389-ds", "pbkdf2-sha256-389ds":
		return "ldap-pbkdf2"
	default:
		return t
	}
}

func legacyLMHash(password string) (string, error) {
	for _, ch := range password {
		if ch > 0x7f {
			return "", errors.New("LM hashing accepts ASCII passwords only")
		}
	}
	upper := strings.ToUpper(password)
	plain := []byte(upper)
	if len(plain) > 14 {
		plain = plain[:14]
	}
	padded := make([]byte, 14)
	copy(padded, plain)
	magic := []byte("KGS!@#$%")
	out := make([]byte, 16)
	for half := 0; half < 2; half++ {
		key := expandLMKey(padded[half*7 : half*7+7])
		cipher, err := des.NewCipher(key[:])
		if err != nil {
			return "", err
		}
		cipher.Encrypt(out[half*8:half*8+8], magic)
	}
	return strings.ToUpper(hex.EncodeToString(out)), nil
}

// expandLMKey spreads 56 key bits across a DES key and sets odd parity.
func expandLMKey(in []byte) [8]byte {
	key := [8]byte{
		in[0] & 0xfe,
		((in[0] << 7) | (in[1] >> 1)) & 0xfe,
		((in[1] << 6) | (in[2] >> 2)) & 0xfe,
		((in[2] << 5) | (in[3] >> 3)) & 0xfe,
		((in[3] << 4) | (in[4] >> 4)) & 0xfe,
		((in[4] << 3) | (in[5] >> 5)) & 0xfe,
		((in[5] << 2) | (in[6] >> 6)) & 0xfe,
		(in[6] << 1) & 0xfe,
	}
	for i, b := range key {
		parity := byte(1)
		for bit := uint(1); bit < 8; bit++ {
			parity ^= (b >> bit) & 1
		}
		key[i] |= parity
	}
	return key
}

func checksumText(text, algorithm string) string {
	data := []byte(text)
	switch algorithm {
	case "crc32":
		return fmt.Sprintf("%08x", crc32.ChecksumIEEE(data))
	case "crc32c":
		return fmt.Sprintf("%08x", crc32.Checksum(data, crc32cTable))
	case "crc64":
		return fmt.Sprintf("%016x", crc64.Checksum(data, crc64Table))
	case "adler32":
		return fmt.Sprintf("%08x", adler32.Checksum(data))
	case "fnv1a32":
		h := uint32(2166136261)
		for _, b := range data {
			h = (h ^ uint32(b)) * 16777619
		}
		return fmt.Sprintf("%08x", h)
	case "fnv1a64":
		h := uint64(14695981039346656037)
		for _, b := range data {
			h = (h ^ uint64(b)) * 1099511628211
		}
		return fmt.Sprintf("%016x", h)
	case "xxhash32":
		return fmt.Sprintf("%08x", xxhash32(data))
	case "xxhash64":
		return fmt.Sprintf("%016x", xxhash64(data))
	case "murmur3-32":
		return fmt.Sprintf("%08x", murmur3_32(data))
	default:
		return ""
	}
}

func encodeHashOutput(hexDigest, encoding string) (string, error) {
	codec := canonicalCodecType(encoding)
	if codec == "" || codec == "hex" {
		return hexDigest, nil
	}
	if !hashOutputCodecs[codec] {
		return "", fmt.Errorf("unsupported hash output encoding: %s", encoding)
	}
	raw, err := hex.DecodeString(strings.TrimPrefix(strings.TrimPrefix(hexDigest, "0x"), "0X"))
	if err != nil {
		return "", fmt.Errorf("%s output is only supported for raw hexadecimal digests", encoding)
	}
	return encodeText(string(raw), codec, 0, "", 2)
}
