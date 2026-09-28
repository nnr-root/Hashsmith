package smith

// Nuked-Klan, a PHP portal from the early 2000s whose password check is the
// most elaborate way of achieving nothing in this catalogue.
//
//	$nk$*<40 hex site key>*#<offset><32 hex digest>
//
// The password is SHA-1'd and written as forty hex characters. Those forty
// characters are then INTERLEAVED, one at a time, with bytes taken from a
// twenty-byte site key read cyclically from a stored offset, giving eighty
// bytes, which are hashed with MD5.
//
// The interleaving is per-character, not per-byte: it alternates a hex DIGIT
// of the SHA-1 with a raw byte of the key. The key is the same for every
// account on a site, so it is a pepper rather than a salt — two users with the
// same password have the same record — and the offset is one hex digit, so it
// contributes at most sixteen variations. What the construction adds over
// md5(sha1(password)) is work for the defender.

import (
	"crypto/hmac"
	"crypto/md5"
	"crypto/sha1"
	"encoding/hex"
	"errors"
	"strings"
)

const nukedKlanPrefix = "$nk$*"

type nukedKlanRecord struct {
	key    []byte // twenty bytes, shared by every account on the site
	offset int    // where in the key the interleaving starts
	digest []byte
}

func nukedKlanFields(target string) (nukedKlanRecord, error) {
	var r nukedKlanRecord
	t := strings.TrimSpace(target)
	if !strings.HasPrefix(t, nukedKlanPrefix) {
		return r, errors.New("not a Nuked-Klan record")
	}
	keyHex, rest, ok := strings.Cut(t[len(nukedKlanPrefix):], "*")
	if !ok {
		return r, errors.New("a Nuked-Klan record is $nk$*<key>*#<offset><digest>")
	}
	key, err := decodeExactHex(keyHex, 20, "Nuked-Klan site key")
	if err != nil {
		return r, err
	}
	// The second field begins with a literal '#', then one hex digit of
	// offset, then the digest.
	if len(rest) != 1+1+2*md5.Size || rest[0] != '#' {
		return r, errors.New("a Nuked-Klan digest field is #<offset><32 hex>")
	}
	off := strings.IndexByte("0123456789abcdef", lowerByte(rest[1]))
	if off < 0 {
		return r, errors.New("a Nuked-Klan offset is one hex digit")
	}
	digest, err := decodeExactHex(rest[2:], md5.Size, "Nuked-Klan digest")
	if err != nil {
		return r, err
	}
	r.key, r.offset, r.digest = key, off, digest
	return r, nil
}

func lowerByte(b byte) byte {
	if b >= 'A' && b <= 'Z' {
		return b + 32
	}
	return b
}

func verifyNukedKlan(target, candidate string) (bool, error) {
	r, err := nukedKlanFields(target)
	if err != nil {
		return false, err
	}
	sum := sha1.Sum([]byte(candidate))
	digits := []byte(hex.EncodeToString(sum[:]))

	mixed := make([]byte, 0, 2*len(digits))
	k := r.offset
	for i := range digits {
		mixed = append(mixed, digits[i])
		// The wrap is checked before the byte is taken, not after, so an
		// offset of twenty reads key[0] on its first step rather than running
		// off the end.
		if k > 19 {
			k = 0
		}
		mixed = append(mixed, r.key[k])
		k++
	}
	got := md5.Sum(mixed)
	return hmac.Equal(got[:], r.digest), nil
}

func isNukedKlan(target string) bool {
	_, err := nukedKlanFields(target)
	return err == nil
}
