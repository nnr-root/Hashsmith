package smith

// Windows Hello PIN/Password — Hashcat 28100.
//
//	$WINHELLO$*SHA512*<iterations>*<salt>*<digest>*<mk>*<hmac>*<blob>*<magic>
//
// Windows Hello protects a DPAPI-NG master key with the PIN, and the record is
// the master-key file's verification structure. Two stages:
//
//  1. PBKDF2-HMAC-SHA256 over the PIN, 32 bytes out, then SHA-512 of that.
//  2. HMAC-SHA512 over the file's own fields with SHA-1(master key) as the
//     key, with the stage-1 digest spliced into the message.
//
// The PIN does not enter either stage as itself. Windows first renders it as
// uppercase hexadecimal and then widens that to UTF-16LE, so the four-digit
// PIN 1234 is hashed as the sixteen bytes "3\0 1\0 3\0 2\0 3\0 3\0 3\0 4\0".
// The same expansion is applied again to the 32-byte PBKDF2 output before the
// SHA-512 in stage 1 — a detail that matters because it doubles the length of
// everything being hashed and is invisible in the record.
//
// The trailing magic field is the DPAPI constant "xT5rZW5qVVbrvpuA" with its
// NUL, hashed as part of the message exactly as it is stored.
//
// Note that hashcat compares only the first sixteen bytes of the final
// SHA-512. The record carries all sixty-four and this compares all of them:
// strictly stronger, and it cannot disagree with hashcat on a genuine record,
// because the stored value is that HMAC's real output.

import (
	"crypto/hmac"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"strconv"
	"strings"

	"golang.org/x/crypto/pbkdf2"
)

const (
	winHelloPrefix     = "$WINHELLO$*"
	winHelloFieldCount = 9
	winHelloMaxIter    = 10_000_000
	winHelloDerivedLen = 32
)

// winHelloHexUTF16 renders bytes as uppercase hex, each character widened to
// UTF-16LE. This is how Windows Hello presents both the PIN and the derived
// key to the hashes that consume them.
func winHelloHexUTF16(b []byte) []byte {
	const digits = "0123456789ABCDEF"
	out := make([]byte, 0, len(b)*4)
	for _, c := range b {
		out = append(out, digits[c>>4], 0, digits[c&0x0f], 0)
	}
	return out
}

func verifyWindowsHello(target, candidate string) (bool, error) {
	t := strings.TrimSpace(target)
	if !strings.HasPrefix(t, winHelloPrefix) {
		return false, errors.New("not a Windows Hello record")
	}
	f := strings.Split(t, "*")
	if len(f) != winHelloFieldCount {
		return false, errors.New("Windows Hello record must have 8 fields")
	}
	if f[1] != "SHA512" {
		return false, errors.New("Windows Hello record must name SHA512")
	}
	iter, err := strconv.Atoi(f[2])
	if err != nil || iter < 1 || iter > winHelloMaxIter {
		return false, errors.New("Windows Hello iteration count is out of range")
	}
	field := func(i int, what string) ([]byte, error) {
		b, err := hex.DecodeString(f[i])
		if err != nil || len(b) == 0 {
			return nil, errors.New("Windows Hello " + what + " must be hex")
		}
		return b, nil
	}
	salt, err := field(3, "salt")
	if err != nil {
		return false, err
	}
	want, err := field(4, "digest")
	if err != nil {
		return false, err
	}
	if len(want) != sha512.Size {
		return false, errors.New("Windows Hello digest must be 64 bytes")
	}
	masterKey, err := field(5, "master key")
	if err != nil {
		return false, err
	}
	hmacField, err := field(6, "hmac")
	if err != nil {
		return false, err
	}
	blob, err := field(7, "blob")
	if err != nil {
		return false, err
	}
	magic, err := field(8, "magic")
	if err != nil {
		return false, err
	}

	// Stage 1: the PIN as UTF-16LE hex, through PBKDF2, then hex-widened
	// again for the SHA-512.
	derived := pbkdf2.Key(winHelloHexUTF16([]byte(candidate)), salt, iter, winHelloDerivedLen, sha256.New)
	stage := sha512.Sum512(winHelloHexUTF16(derived))

	// Stage 2: HMAC-SHA512 keyed by SHA-1 of the master key.
	key := sha1.Sum(masterKey)
	mac := hmac.New(sha512.New, key[:])
	mac.Write(hmacField)
	mac.Write(magic)
	mac.Write(stage[:])
	mac.Write(blob)
	return subtle.ConstantTimeCompare(mac.Sum(nil), want) == 1, nil
}
