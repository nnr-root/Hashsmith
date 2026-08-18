package main

// phpass portable hashes — WordPress ($P$) and phpBB3 ($H$).
//
//	setting  = "$P$" + count_char + 8-char salt
//	count    = 1 << itoa64_index(count_char)
//	hash     = md5(salt || password)
//	repeat count×: hash = md5(hash || password)
//	output   = setting || phpass_base64(hash)
//
// Drupal 7 ($S$) uses the same structure with SHA-512 and a longer output.

import (
	"crypto/md5"
	"crypto/sha512"
	"errors"
	"strings"
)

// verifyPhpass checks a candidate against a $P$/$H$ phpass hash.
func verifyPhpass(targetHash, candidate string) (bool, error) {
	if len(targetHash) != 34 || (!strings.HasPrefix(targetHash, "$P$") && !strings.HasPrefix(targetHash, "$H$")) {
		return false, errors.New("invalid phpass hash (need $P$/$H$ + 31 chars)")
	}
	countLog2 := strings.IndexByte(itoa64, targetHash[3])
	if countLog2 < 7 || countLog2 > 30 {
		return false, errors.New("invalid phpass cost")
	}
	count := 1 << uint(countLog2)
	salt := targetHash[4:12]

	h := md5.Sum(append([]byte(salt), candidate...))
	digest := h[:]
	pw := []byte(candidate)
	for i := 0; i < count; i++ {
		m := md5.New()
		m.Write(digest)
		m.Write(pw)
		digest = m.Sum(nil)
	}
	return targetHash[:12]+phpassBase64(digest) == targetHash, nil
}

// verifyDrupal7 checks a candidate against a Drupal 7 ($S$) hash.
func verifyDrupal7(targetHash, candidate string) (bool, error) {
	if len(targetHash) < 12 || !strings.HasPrefix(targetHash, "$S$") {
		return false, errors.New("invalid Drupal7 hash (need $S$ prefix)")
	}
	countLog2 := strings.IndexByte(itoa64, targetHash[3])
	if countLog2 < 7 || countLog2 > 30 {
		return false, errors.New("invalid Drupal7 cost")
	}
	count := 1 << uint(countLog2)
	salt := targetHash[4:12]

	h := sha512.Sum512(append([]byte(salt), candidate...))
	digest := h[:]
	pw := []byte(candidate)
	for i := 0; i < count; i++ {
		m := sha512.New()
		m.Write(digest)
		m.Write(pw)
		digest = m.Sum(nil)
	}
	// Drupal 7 keeps the 12-char setting plus the first 43 base64 digest chars.
	b64 := phpassBase64(digest)
	if len(b64) < 43 {
		return false, nil
	}
	return targetHash[:12]+b64[:43] == targetHash, nil
}

// phpassBase64 encodes bytes with the phpass/crypt bit ordering (LSB first).
func phpassBase64(input []byte) string {
	var out strings.Builder
	i := 0
	n := len(input)
	for i < n {
		value := int(input[i])
		i++
		out.WriteByte(itoa64[value&0x3f])
		if i < n {
			value |= int(input[i]) << 8
		}
		out.WriteByte(itoa64[(value>>6)&0x3f])
		if i >= n {
			break
		}
		i++
		if i < n {
			value |= int(input[i]) << 16
		}
		out.WriteByte(itoa64[(value>>12)&0x3f])
		if i >= n {
			break
		}
		i++
		out.WriteByte(itoa64[(value>>18)&0x3f])
	}
	return out.String()
}

// isPhpassHash / isDrupal7Hash recognise the respective formats.
func isPhpassHash(s string) bool {
	return len(s) == 34 && (strings.HasPrefix(s, "$P$") || strings.HasPrefix(s, "$H$"))
}

func isDrupal7Hash(s string) bool {
	return len(s) == 55 && strings.HasPrefix(s, "$S$")
}
