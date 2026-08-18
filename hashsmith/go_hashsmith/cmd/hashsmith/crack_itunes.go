package main

// iTunes backup (Manifest.plist keybag):
//
//	$itunes_backup$*<ver>*<wpky>*<iter>*<salt>*<dpsl>*<dpic>
//
// version 9  (iOS < 10.2): KEK = PBKDF2-HMAC-SHA1(password, salt, iter, 32)
// version 10 (iOS 10.2+) : an outer PBKDF2-HMAC-SHA256(password, dpsl, dpic) feeds
//                          the SHA-1 round above.
// A correct password unwraps the wrapped key (wpky) via RFC 3394 AES key-unwrap —
// the integrity check (A == 0xA6…A6) confirms it.

import (
	"crypto/aes"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"strconv"
	"strings"

	"golang.org/x/crypto/pbkdf2"
)

// aesUnwrap performs RFC 3394 AES key unwrap and reports whether the integrity
// check passes.
func aesUnwrap(kek, wrapped []byte) bool {
	if len(wrapped)%8 != 0 || len(wrapped) < 16 {
		return false
	}
	block, err := aes.NewCipher(kek)
	if err != nil {
		return false
	}
	n := len(wrapped)/8 - 1
	a := make([]byte, 8)
	copy(a, wrapped[:8])
	r := make([][]byte, n)
	for i := 0; i < n; i++ {
		r[i] = make([]byte, 8)
		copy(r[i], wrapped[8*(i+1):8*(i+2)])
	}
	var buf [16]byte
	for j := 5; j >= 0; j-- {
		for i := n; i >= 1; i-- {
			t := uint64(n*j + i)
			copy(buf[:8], a)
			// A ^= t (t is XORed into the low 8 bytes of A, big-endian)
			var tb [8]byte
			binary.BigEndian.PutUint64(tb[:], t)
			for k := 0; k < 8; k++ {
				buf[k] ^= tb[k]
			}
			copy(buf[8:], r[i-1])
			block.Decrypt(buf[:], buf[:])
			copy(a, buf[:8])
			copy(r[i-1], buf[8:])
		}
	}
	for _, b := range a {
		if b != 0xa6 {
			return false
		}
	}
	return true
}

func verifyITunesBackup(targetHash, candidate string) (bool, error) {
	if !strings.HasPrefix(targetHash, "$itunes_backup$*") {
		return false, errors.New("invalid iTunes backup hash (missing prefix)")
	}
	f := strings.Split(targetHash, "*")
	// f[0]="$itunes_backup$"; then ver, wpky, iter, salt, dpsl, dpic
	if len(f) < 7 {
		return false, errors.New("invalid iTunes backup hash (too few fields)")
	}
	wpky, err := hex.DecodeString(f[2])
	if err != nil || len(wpky) != 40 {
		return false, errors.New("invalid iTunes wrapped key")
	}
	iter, err := strconv.Atoi(f[3])
	if err != nil || iter < 1 {
		return false, errors.New("invalid iTunes iteration count")
	}
	salt, err := hex.DecodeString(f[4])
	if err != nil {
		return false, errors.New("invalid iTunes salt")
	}

	pw := []byte(candidate)
	// version 10 adds an outer PBKDF2-SHA256 pass.
	if f[5] != "" && f[6] != "" {
		dpsl, err := hex.DecodeString(f[5])
		if err != nil {
			return false, errors.New("invalid iTunes dpsl")
		}
		dpic, err := strconv.Atoi(f[6])
		if err != nil || dpic < 1 {
			return false, errors.New("invalid iTunes dpic")
		}
		pw = pbkdf2.Key(pw, dpsl, dpic, 32, sha256.New)
	}
	kek := pbkdf2.Key(pw, salt, iter, 32, sha1.New)
	return aesUnwrap(kek, wpky), nil
}
