package main

import (
	"bytes"
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
)

func runHash(args []string) error {
	fs := flag.NewFlagSet("hash", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	typ := fs.String("t", "", "type")
	text := fs.String("i", "", "text")
	filePath := fs.String("f", "", "input file")
	outFile := fs.String("o", "", "output file")
	copyResult := fs.Bool("c", false, "copy to clipboard")
	salt := fs.String("s", "", "salt")
	saltMode := fs.String("S", "prefix", "salt mode")
	outEncoding := fs.String("e", "hex", "output encoding")
	if err := fs.Parse(args); err != nil {
		return err
	}
	input, err := readInput(*text, *filePath)
	if err != nil {
		return err
	}
	result, err := hashText(input, *typ, *salt, *saltMode)
	if err != nil {
		return err
	}
	if strings.EqualFold(*outEncoding, "base58") {
		hexValue := result
		if strings.HasPrefix(strings.ToLower(hexValue), "0x") {
			hexValue = hexValue[2:]
		}
		if !isHex(hexValue) || len(hexValue)%2 != 0 {
			return errors.New("base58 output is only supported for hex hashes")
		}
		bytesValue, err := hex.DecodeString(hexValue)
		if err != nil {
			return errors.New("invalid hash for base58 output")
		}
		result = encodeBase58(bytesValue)
	}
	return outputResult(result, *outFile, *copyResult)
}

func hashText(text string, algorithm string, salt string, saltMode string) (string, error) {
	algo := strings.ToLower(algorithm)
	saltInAlgorithms := map[string]bool{
		"bcrypt": true, "argon2": true, "scrypt": true, "postgres": true,
		"mssql2000": true, "mssql2005": true, "mssql2012": true,
	}
	if salt != "" && !saltInAlgorithms[algo] {
		if saltMode == "suffix" {
			text = text + salt
		} else {
			text = salt + text
		}
	}

	switch algo {
	case "md5":
		h := md5.Sum([]byte(text))
		return hex.EncodeToString(h[:]), nil
	case "md4":
		h := md4.New()
		_, _ = h.Write([]byte(text))
		return hex.EncodeToString(h.Sum(nil)), nil
	case "sha1":
		h := sha1.Sum([]byte(text))
		return hex.EncodeToString(h[:]), nil
	case "ripemd160":
		h := ripemd160.New()
		_, _ = h.Write([]byte(text))
		return hex.EncodeToString(h.Sum(nil)), nil
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
	case "sha3_224":
		sum := sha3.Sum224([]byte(text))
		return hex.EncodeToString(sum[:]), nil
	case "sha3_256":

		sum := sha3.Sum256([]byte(text))
		return hex.EncodeToString(sum[:]), nil
	case "sha3_512":
		sum := sha3.Sum512([]byte(text))
		return hex.EncodeToString(sum[:]), nil
	case "blake2b":
		h := blake2b.Sum512([]byte(text))
		return hex.EncodeToString(h[:]), nil
	case "blake2s":
		h := blake2s.Sum256([]byte(text))
		return hex.EncodeToString(h[:]), nil
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
	if len(parts) < 6 || parts[1] != "argon2id" {
		return false
	}
	params := parts[3]
	saltB64 := parts[4]
	hashB64 := parts[5]

	mem, iter, parallel := uint32(102400), uint32(2), uint8(8)
	for _, token := range strings.Split(params, ",") {
		kv := strings.SplitN(token, "=", 2)
		if len(kv) != 2 {
			continue
		}
		switch kv[0] {
		case "m":
			if v, err := strconv.Atoi(kv[1]); err == nil {
				mem = uint32(v)
			}
		case "t":
			if v, err := strconv.Atoi(kv[1]); err == nil {
				iter = uint32(v)
			}
		case "p":
			if v, err := strconv.Atoi(kv[1]); err == nil {
				parallel = uint8(v)
			}
		}
	}

	salt, err := base64.RawStdEncoding.DecodeString(saltB64)
	if err != nil {
		return false
	}
	expected, err := base64.RawStdEncoding.DecodeString(hashB64)
	if err != nil {
		return false
	}
	got := argon2.IDKey([]byte(password), salt, iter, mem, parallel, uint32(len(expected)))
	return bytes.Equal(got, expected)
}
