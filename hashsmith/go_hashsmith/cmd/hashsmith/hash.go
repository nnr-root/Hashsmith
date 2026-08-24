package main

import (
	"bytes"
	"crypto/hmac"
	"crypto/md5"
	"crypto/rand"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"hash"
	"io"
	"strconv"
	"strings"
	"unicode/utf16"

	"crypto/sha3"

	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/bcrypt"
	"golang.org/x/crypto/blake2b"
	"golang.org/x/crypto/blake2s"
	"golang.org/x/crypto/md4"
	"golang.org/x/crypto/ripemd160"
	"golang.org/x/crypto/scrypt"
	xsha3 "golang.org/x/crypto/sha3"
)

func runHash(args []string) error {
	fs := flag.NewFlagSet("hash", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	typ := fs.String("t", "", "type")
	outFile := fs.String("o", "", "output file")
	copyResult := fs.Bool("c", false, "copy to clipboard")
	salt := fs.String("s", "", "salt")
	saltMode := fs.String("S", "prefix", "salt mode")
	outEncoding := fs.String("e", "hex", "output encoding")
	if err := parseArgsFlexible(fs, args); err != nil {
		return err
	}
	inputs, err := gatherInputs(fs.Args())
	if err != nil {
		return err
	}
	results := make([]string, 0, len(inputs))
	for _, in := range inputs {
		result, err := hashText(in, *typ, *salt, *saltMode)
		if err != nil {
			return err
		}
		result, err = encodeHashOutput(result, *outEncoding)
		if err != nil {
			return err
		}
		results = append(results, result)
	}
	return outputResult(strings.Join(results, "\n"), *outFile, *copyResult)
}

func hashText(text string, algorithm string, salt string, saltMode string) (string, error) {
	algo := canonicalHashType(algorithm)
	saltInAlgorithms := map[string]bool{
		"bcrypt": true, "argon2": true, "scrypt": true, "postgres": true,
		"mysql8": true, "ldap-pbkdf2": true,
		"mssql2000": true, "mssql2005": true, "mssql2012": true,
		// Nested-digest types ignore the salt, so the generic prefix/suffix
		// concatenation must not touch them.
		"md5-md5": true, "sha1-sha1": true, "sha256-sha256": true,
		"sha512-sha512": true, "sha3_256-sha3_256": true,
		"sha1-md5-md5pass": true,
	}
	if _, ok := compatSaltedDigests[algo]; ok {
		saltInAlgorithms[algo] = true
	}
	if _, ok := compositeConstructions[algo]; ok {
		saltInAlgorithms[algo] = true
	}
	saltInAlgorithms["siphash"] = true
	for _, name := range []string{"crc32-hashcat", "murmurhash", "murmur64a"} {
		saltInAlgorithms[name] = true
	}
	if salt != "" && !saltInAlgorithms[algo] && !strings.HasPrefix(algo, "hmac-") {
		if saltMode == "suffix" {
			text = text + salt
		} else {
			text = salt + text
		}
	}

	if _, ok := compositeConstructions[algo]; ok {
		return hashComposite(text, algo, salt)
	}

	switch algo {
	case "md5":
		h := md5.Sum([]byte(text))
		return hex.EncodeToString(h[:]), nil
	case "md4":
		h := md4.New()
		_, _ = h.Write([]byte(text))
		return hex.EncodeToString(h.Sum(nil)), nil
	case "md2":
		return md2Hex([]byte(text)), nil
	case "sha0":
		return sha0Hex([]byte(text)), nil
	case "sha1":
		h := sha1.Sum([]byte(text))
		return hex.EncodeToString(h[:]), nil
	case "ripemd160":
		h := ripemd160.New()
		_, _ = h.Write([]byte(text))
		return hex.EncodeToString(h.Sum(nil)), nil
	case "ripemd128":
		h := newRIPEMD128()
		_, _ = h.Write([]byte(text))
		return hex.EncodeToString(h.Sum(nil)), nil
	case "ripemd256":
		h := newRIPEMD256()
		_, _ = h.Write([]byte(text))
		return hex.EncodeToString(h.Sum(nil)), nil
	case "ripemd320":
		h := newRIPEMD320()
		_, _ = h.Write([]byte(text))
		return hex.EncodeToString(h.Sum(nil)), nil
	case "siphash":
		if len(salt) == 32 && isHex(salt) {
			return sipHashHashcatHex(text, salt, 2, 4)
		}
		return sipHashHex(text, salt)
	case "sha224":
		h := sha256.Sum224([]byte(text))
		return hex.EncodeToString(h[:]), nil
	case "sha256":
		h := sha256.Sum256([]byte(text))
		return hex.EncodeToString(h[:]), nil
	case "sha384":
		h := sha512.Sum384([]byte(text))
		return hex.EncodeToString(h[:]), nil
	case "sha512":
		h := sha512.Sum512([]byte(text))
		return hex.EncodeToString(h[:]), nil
	case "md5-utf16le", "sha1-utf16le", "sha256-utf16le", "sha384-utf16le", "sha512-utf16le":
		return hashUTF16Digest(text, algo)
	case "md5-pass-salt", "md5-salt-pass", "md5-utf16le-pass-salt", "md5-salt-utf16le-pass",
		"sha1-pass-salt", "sha1-salt-pass", "sha1-utf16le-pass-salt", "sha1-salt-utf16le-pass",
		"sha224-pass-salt", "sha224-salt-pass",
		"sha256-pass-salt", "sha256-salt-pass", "sha256-utf16le-pass-salt", "sha256-salt-utf16le-pass",
		"sha384-pass-salt", "sha384-salt-pass", "sha384-utf16le-pass-salt", "sha384-salt-utf16le-pass",
		"sha512-pass-salt", "sha512-salt-pass", "sha512-utf16le-pass-salt", "sha512-salt-utf16le-pass",
		"blake2b-pass-salt", "blake2b-salt-pass", "blake2b256-pass-salt", "blake2b256-salt-pass":
		return hashCompatSaltedDigest(text, algo, salt)
	case "sha512_224":
		h := sha512.Sum512_224([]byte(text))
		return hex.EncodeToString(h[:]), nil
	case "sha512_256":
		h := sha512.Sum512_256([]byte(text))
		return hex.EncodeToString(h[:]), nil
	case "sha3_224":
		sum := sha3.Sum224([]byte(text))
		return hex.EncodeToString(sum[:]), nil
	case "sha3_256":

		sum := sha3.Sum256([]byte(text))
		return hex.EncodeToString(sum[:]), nil
	case "sha3_384":
		sum := sha3.Sum384([]byte(text))
		return hex.EncodeToString(sum[:]), nil
	case "whirlpool":
		h := newWhirlpool()
		_, _ = h.Write([]byte(text))
		return hex.EncodeToString(h.Sum(nil)), nil
	case "streebog256", "gost2012-256":
		h := newStreebog256()
		_, _ = h.Write([]byte(text))
		return hex.EncodeToString(h.Sum(nil)), nil
	case "streebog512", "gost2012-512":
		h := newStreebog512()
		_, _ = h.Write([]byte(text))
		return hex.EncodeToString(h.Sum(nil)), nil
	case "sha3_512":
		sum := sha3.Sum512([]byte(text))
		return hex.EncodeToString(sum[:]), nil
	case "sm3":
		return sm3Hex([]byte(text)), nil
	case "keccak224":
		return hex.EncodeToString(legacyKeccakSum([]byte(text), 28)), nil
	case "keccak256":
		h := xsha3.NewLegacyKeccak256()
		_, _ = h.Write([]byte(text))
		return hex.EncodeToString(h.Sum(nil)), nil
	case "keccak384":
		return hex.EncodeToString(legacyKeccakSum([]byte(text), 48)), nil
	case "keccak512":
		h := xsha3.NewLegacyKeccak512()
		_, _ = h.Write([]byte(text))
		return hex.EncodeToString(h.Sum(nil)), nil
	case "shake128-256":
		return hex.EncodeToString(sha3.SumSHAKE128([]byte(text), 32)), nil
	case "shake256-512":
		return hex.EncodeToString(sha3.SumSHAKE256([]byte(text), 64)), nil
	case "md5-md5":
		return nestedHex(md5.New, text), nil
	case "sha1-sha1":
		return nestedHex(sha1.New, text), nil
	case "sha256-sha256":
		return nestedHex(sha256.New, text), nil
	case "sha512-sha512":
		return nestedHex(sha512.New, text), nil
	case "sha3_256-sha3_256":
		return nestedHex(newSHA3_256, text), nil
	case "md5-md5-md5":
		return tripleMD5Hex(text), nil
	case "md5-upper-md5":
		return nestedCrossHex(md5.New, md5.New, text, true), nil
	case "md5-sha1":
		return nestedCrossHex(sha1.New, md5.New, text, false), nil
	case "sha1-md5":
		return nestedCrossHex(md5.New, sha1.New, text, false), nil
	case "sha1-md5-md5pass":
		first := md5.Sum([]byte(text))
		second := md5.Sum([]byte(hex.EncodeToString(first[:])))
		outer := sha1.Sum([]byte(hex.EncodeToString(second[:])))
		return hex.EncodeToString(outer[:]), nil
	case "hmac-md5":
		return hmacHex(md5.New, text, salt), nil
	case "hmac-sha1":
		return hmacHex(sha1.New, text, salt), nil
	case "hmac-sha256":
		return hmacHex(sha256.New, text, salt), nil
	case "hmac-sha512":
		return hmacHex(sha512.New, text, salt), nil
	case "hmac-sha224":
		return hmacHex(sha256.New224, text, salt), nil
	case "hmac-sha384":
		return hmacHex(sha512.New384, text, salt), nil
	case "hmac-sha3_224":
		return hmacHex(newSHA3_224, text, salt), nil
	case "hmac-sha3_256":
		return hmacHex(newSHA3_256, text, salt), nil
	case "hmac-sha3_384":
		return hmacHex(newSHA3_384, text, salt), nil
	case "hmac-sha3_512":
		return hmacHex(newSHA3_512, text, salt), nil
	case "hmac-ripemd160":
		return hmacHex(ripemd160.New, text, salt), nil
	case "hmac-ripemd320":
		return hmacHex(newRIPEMD320, text, salt), nil
	case "hmac-blake2s":
		return hmacHex(newBlake2s256Hash, text, salt), nil
	case "hmac-streebog256":
		return hmacStreebogHex(newStreebog256, text, salt), nil
	case "hmac-streebog512":
		return hmacStreebogHex(newStreebog512, text, salt), nil
	case "hmac-md5-saltkey":
		return hmacHex(md5.New, salt, text), nil
	case "hmac-sha1-saltkey":
		return hmacHex(sha1.New, salt, text), nil
	case "hmac-sha256-saltkey":
		return hmacHex(sha256.New, salt, text), nil
	case "hmac-sha512-saltkey":
		return hmacHex(sha512.New, salt, text), nil
	case "hmac-sha224-saltkey":
		return hmacHex(sha256.New224, salt, text), nil
	case "hmac-sha384-saltkey":
		return hmacHex(sha512.New384, salt, text), nil
	case "hmac-sha3_224-saltkey":
		return hmacHex(newSHA3_224, salt, text), nil
	case "hmac-sha3_256-saltkey":
		return hmacHex(newSHA3_256, salt, text), nil
	case "hmac-sha3_384-saltkey":
		return hmacHex(newSHA3_384, salt, text), nil
	case "hmac-sha3_512-saltkey":
		return hmacHex(newSHA3_512, salt, text), nil
	case "hmac-ripemd160-saltkey":
		return hmacHex(ripemd160.New, salt, text), nil
	case "hmac-ripemd320-saltkey":
		return hmacHex(newRIPEMD320, salt, text), nil
	case "hmac-streebog256-saltkey":
		return hmacStreebogHex(newStreebog256, salt, text), nil
	case "hmac-streebog512-saltkey":
		return hmacStreebogHex(newStreebog512, salt, text), nil
	case "blake2b":
		h := blake2b.Sum512([]byte(text))
		return hex.EncodeToString(h[:]), nil
	case "blake2b256":
		h := blake2b.Sum256([]byte(text))
		return hex.EncodeToString(h[:]), nil
	case "blake2b384":
		h, err := blake2b.New384(nil)
		if err != nil {
			return "", err
		}
		_, _ = h.Write([]byte(text))
		return hex.EncodeToString(h.Sum(nil)), nil
	case "blake2s":
		h := blake2s.Sum256([]byte(text))
		return hex.EncodeToString(h[:]), nil
	case "lm":
		return legacyLMHash(text)
	case "crc32-hashcat":
		return crc32HashcatHex(text, salt)
	case "murmurhash":
		return murmurHash25700Hex(text, salt)
	case "murmur64a":
		return murmurHash64AHex(text, salt)
	case "murmur64a-zero":
		return murmurHash64AHex(text, "")
	case "murmur64a-truncated":
		got, err := murmurHash64AHex(text, "")
		return got[:8], err
	case "crc32", "crc32c", "crc64", "adler32", "fnv1a32", "fnv1a64",
		"xxhash32", "xxhash64", "murmur3-32":
		return checksumText(text, algo), nil
	case "ntlm":
		h := md4.New()
		_, _ = h.Write(utf16le(text))
		return hex.EncodeToString(h.Sum(nil)), nil
	case "mysql323":
		return mysql323(text), nil
	case "mysql41":
		stage1 := sha1.Sum([]byte(text))
		stage2 := sha1.Sum(stage1[:])
		return "*" + strings.ToUpper(hex.EncodeToString(stage2[:])), nil
	case "mysql8":
		saltBytes, err := parseSaltBytes(salt, 20)
		if err != nil {
			return "", err
		}
		return encodeMySQL8(text, saltBytes, 5)
	case "ldap-pbkdf2":
		saltBytes, err := parseSaltBytes(salt, redHat389SaltLen)
		if err != nil {
			return "", err
		}
		return encodeRedHat389PBKDF2(text, saltBytes, 8192)
	case "mssql2000":
		h := sha1.Sum(utf16le(text))
		return strings.ToUpper(hex.EncodeToString(h[:])), nil
	case "mssql2005", "mssql2012":
		saltBytes, err := parseSaltBytes(salt, 4)
		if err != nil {
			return "", err
		}
		digest := sha1.Sum(append(saltBytes, utf16le(text)...))
		return fmt.Sprintf("0x0100%s%s", hex.EncodeToString(saltBytes), strings.ToUpper(hex.EncodeToString(digest[:]))), nil
	case "postgres":
		if salt == "" {
			return "", errors.New("postgres requires a username as salt")
		}
		h := md5.Sum([]byte(text + salt))
		return "md5" + hex.EncodeToString(h[:]), nil
	case "bcrypt":
		if salt == "" {
			return "", errors.New("bcrypt requires a salt (use --salt)")
		}
		value, err := strconv.Atoi(salt)
		if err != nil {
			return "", errors.New("bcrypt in Go backend accepts rounds as salt")
		}
		rounds := value
		hashed, err := bcrypt.GenerateFromPassword([]byte(text), rounds)
		if err != nil {
			return "", err
		}
		return string(hashed), nil
	case "argon2":
		saltBytes, err := parseSaltBytes(salt, 16)
		if err != nil {
			return "", err
		}
		mem := uint32(102400)
		iter := uint32(2)
		parallel := uint8(8)
		hashLen := uint32(32)
		key := argon2.IDKey([]byte(text), saltBytes, iter, mem, parallel, hashLen)
		b64 := base64.RawStdEncoding
		return fmt.Sprintf("$argon2id$v=19$m=%d,t=%d,p=%d$%s$%s", mem, iter, parallel, b64.EncodeToString(saltBytes), b64.EncodeToString(key)), nil
	case "scrypt":
		saltBytes, err := parseSaltBytes(salt, 16)
		if err != nil {
			return "", err
		}
		n := 1 << 14
		r := 8
		p := 1
		dklen := 64
		key, err := scrypt.Key([]byte(text), saltBytes, n, r, p, dklen)
		if err != nil {
			return "", err
		}
		return fmt.Sprintf("scrypt$%d$%d$%d$%s$%s", n, r, p, hex.EncodeToString(saltBytes), hex.EncodeToString(key)), nil
	default:
		return "", fmt.Errorf("unsupported hash algorithm: %s", algorithm)
	}
}

// nestedHex computes digest(hex(digest(text))) — a password hashed, hex-encoded,
// then hashed again (the common "double hash" storage pattern).
func nestedHex(newHash func() hash.Hash, text string) string {
	inner := newHash()
	inner.Write([]byte(text))
	innerHex := hex.EncodeToString(inner.Sum(nil))
	outer := newHash()
	outer.Write([]byte(innerHex))
	return hex.EncodeToString(outer.Sum(nil))
}

// hmacHex computes HMAC(key, message) and returns it as lowercase hex.
func hmacHex(newHash func() hash.Hash, key, message string) string {
	m := hmac.New(newHash, []byte(key))
	m.Write([]byte(message))
	return hex.EncodeToString(m.Sum(nil))
}

func newBlake2s256Hash() hash.Hash {
	h, _ := blake2s.New256(nil)
	return h
}

func parseSaltBytes(salt string, defaultLen int) ([]byte, error) {
	if strings.TrimSpace(salt) == "" {
		out := make([]byte, defaultLen)
		if _, err := rand.Read(out); err != nil {
			return nil, err
		}
		return out, nil
	}
	value := strings.TrimSpace(salt)
	if strings.HasPrefix(value, "0x") || strings.HasPrefix(value, "0X") {
		value = value[2:]
	}
	if value != "" && isHex(value) && len(value)%2 == 0 {
		return hex.DecodeString(value)
	}
	return []byte(value), nil
}

func isHex(s string) bool {
	for _, r := range s {
		if !strings.ContainsRune("0123456789abcdefABCDEF", r) {
			return false
		}
	}
	return s != ""
}

func mysql323(text string) string {
	nr := uint32(1345345333)
	add := uint32(7)
	nr2 := uint32(0x12345671)
	for _, ch := range text {
		if ch == ' ' || ch == '\t' {
			continue
		}
		tmp := uint32(ch)
		nr ^= (((nr & 63) + add) * tmp) + (nr << 8)
		nr2 += (nr2 << 8) ^ nr
		add += tmp
	}
	return fmt.Sprintf("%08x%08x", nr&0x7FFFFFFF, nr2&0x7FFFFFFF)
}

func utf16le(s string) []byte {
	runes := utf16.Encode([]rune(s))
	out := make([]byte, 0, len(runes)*2)
	for _, r := range runes {
		out = append(out, byte(r), byte(r>>8))
	}
	return out
}

func verifyArgon2(encoded string, password string) bool {
	parts := strings.Split(encoded, "$")
	if len(parts) != 6 || parts[0] != "" || parts[2] != "v=19" {
		return false
	}
	// Supported variants: argon2id and argon2i (argon2d isn't in the Go library).
	variant := parts[1]
	if variant != "argon2id" && variant != "argon2i" {
		return false
	}
	params := parts[3]
	saltB64 := parts[4]
	hashB64 := parts[5]

	var mem, iter uint32
	var parallel uint8
	seenM, seenT, seenP := false, false, false
	for _, token := range strings.Split(params, ",") {
		kv := strings.SplitN(token, "=", 2)
		if len(kv) != 2 {
			return false
		}
		switch kv[0] {
		case "m":
			v, err := strconv.ParseUint(kv[1], 10, 32)
			if err != nil || seenM {
				return false
			}
			mem, seenM = uint32(v), true
		case "t":
			v, err := strconv.ParseUint(kv[1], 10, 32)
			if err != nil || seenT {
				return false
			}
			iter, seenT = uint32(v), true
		case "p":
			v, err := strconv.ParseUint(kv[1], 10, 8)
			if err != nil || seenP || v == 0 {
				return false
			}
			parallel, seenP = uint8(v), true
		default:
			return false
		}
	}
	if !seenM || !seenT || !seenP || iter < 1 || iter > maxKDFIterations ||
		mem < 8*uint32(parallel) || uint64(mem)*1024 > maxScryptMemory {
		return false
	}

	salt, err := base64.RawStdEncoding.DecodeString(saltB64)
	if err != nil || len(salt) < 8 || len(salt) > maxKDFFieldSize {
		return false
	}
	expected, err := base64.RawStdEncoding.DecodeString(hashB64)
	if err != nil || len(expected) < 4 || len(expected) > maxKDFFieldSize {
		return false
	}
	var got []byte
	if variant == "argon2i" {
		got = argon2.Key([]byte(password), salt, iter, mem, parallel, uint32(len(expected)))
	} else {
		got = argon2.IDKey([]byte(password), salt, iter, mem, parallel, uint32(len(expected)))
	}
	return bytes.Equal(got, expected)
}
