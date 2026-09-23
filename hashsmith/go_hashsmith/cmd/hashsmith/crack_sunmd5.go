package main

// SunMD5, the crypt(3) Solaris 9 introduced.
//
//	$md5[,rounds=N]$<salt>$<22 characters>
//
// It is MD5 iterated at least 4,096 times, and what makes it interesting is
// not the count but what is hashed. On each round a coin is flipped from the
// bits of the current digest, and when it comes up heads the round hashes a
// kilobyte and a half of Hamlet as well as the digest. Half the rounds are
// therefore cheap and half are expensive, and WHICH is decided by the digest
// — so the cost of checking a password depends on the password, and cannot be
// scheduled in advance.
//
// That was deliberate. A fast MD5 implementation gets its speed from fixed
// buffer sizes and unrolled loops; a hash whose block count depends on data it
// has not computed yet defeats both. Twenty years later it is also why SunMD5
// resists SIMD batching: the lanes fall out of step on the first coin flip.
//
// The coin itself is deliberately awkward — a bit of the digest indexed by a
// byte of the digest shifted by another byte of the digest — and its details
// are not worth paraphrasing beyond saying that they are a reproduction of
// Sun's, because there is no specification for this format other than the
// source.

import (
	"crypto/md5"
	"crypto/subtle"
	"errors"
	"strconv"
	"strings"
)

const (
	sunMD5Prefix     = "$md5$"
	sunMD5PrefixAlt  = "$md5,"
	sunMD5BasicRound = 4096
)

// sunMD5Bit returns bit n of the digest, counted from the low end of each byte
// and wrapped into the sixteen bytes available.
func sunMD5Bit(d []byte, n int) int {
	return int(d[(n>>3)&0xF]>>(uint(n)&7)) & 1
}

// sunMD5Indirect runs the seven coin steps, from one pair of starting offsets
// or the other depending on how its own coin landed. Every index wraps into
// the digest's sixteen bytes.
func sunMD5Indirect(d []byte, heads bool, hi, hj, li, lj int) int {
	i, j := li, lj
	if heads {
		i, j = hi, hj
	}
	var v int
	for k := 0; k < 7; k++ {
		v |= sunMD5Coin(d, (i+k)&0xF, (j+k)&0xF, k)
	}
	return v
}

// sunMD5Coin is one step of the coin flip.
func sunMD5Coin(d []byte, i, j, shift int) int {
	idx := int(d[int(d[i]>>(d[j]%5))&0x0F] >> ((d[j] >> (d[i] & 0x07)) & 0x01))
	return sunMD5Bit(d, idx) << uint(shift)
}

func sunMD5Fields(target string) (salt, digest string, rounds int, err error) {
	t := strings.TrimSpace(target)
	if !strings.HasPrefix(t, sunMD5Prefix) && !strings.HasPrefix(t, sunMD5PrefixAlt) {
		return "", "", 0, errors.New("not a SunMD5 record")
	}
	i := strings.LastIndexByte(t, '$')
	if i < 0 || i == len(t)-1 {
		return "", "", 0, errors.New("a SunMD5 record ends with its digest")
	}
	salt, digest = t[:i], t[i+1:]
	if len(digest) != 22 {
		return "", "", 0, errors.New("a SunMD5 digest is twenty-two characters")
	}
	for k := 0; k < len(digest); k++ {
		if strings.IndexByte(itoa64, digest[k]) < 0 {
			return "", "", 0, errors.New("a SunMD5 digest is crypt(3) characters")
		}
	}
	// The round count is written into the salt rather than beside it, and the
	// salt is hashed WHOLE — so "rounds=904" is both a parameter and part of
	// the input, and changing it changes the digest twice over.
	if r := strings.Index(salt, "rounds="); r >= 0 {
		v := salt[r+len("rounds="):]
		end := 0
		for end < len(v) && v[end] >= '0' && v[end] <= '9' {
			end++
		}
		if end == 0 {
			return "", "", 0, errors.New("a SunMD5 round count is a number")
		}
		n, convErr := strconv.Atoi(v[:end])
		if convErr != nil || n < 0 || n > 1<<24 {
			return "", "", 0, errors.New("invalid SunMD5 round count")
		}
		rounds = n
	}
	return salt, digest, rounds, nil
}

// sunMD5Decode reverses the encoding, which scatters the digest's bytes across
// the twenty-two characters rather than taking them in order.
func sunMD5Decode(s string) ([]byte, error) {
	from64 := func(at, n int) (uint32, error) {
		var v uint32
		for k := 0; k < n; k++ {
			i := strings.IndexByte(itoa64, s[at+k])
			if i < 0 {
				return 0, errors.New("a SunMD5 digest is crypt(3) characters")
			}
			v |= uint32(i) << uint(6*k)
		}
		return v, nil
	}
	out := make([]byte, 16)
	for g, pos := range [5][3]int{{0, 6, 12}, {1, 7, 13}, {2, 8, 14}, {3, 9, 15}, {4, 10, 5}} {
		v, err := from64(4*g, 4)
		if err != nil {
			return nil, err
		}
		out[pos[0]], out[pos[1]], out[pos[2]] = byte(v>>16), byte(v>>8), byte(v)
	}
	v, err := from64(20, 2)
	if err != nil {
		return nil, err
	}
	out[11] = byte(v)
	return out, nil
}

func verifySunMD5(target, candidate string) (bool, error) {
	salt, digest, extra, err := sunMD5Fields(target)
	if err != nil {
		return false, err
	}
	want, err := sunMD5Decode(digest)
	if err != nil {
		return false, err
	}

	sum := md5.Sum(append([]byte(candidate), salt...))
	d := sum[:]

	phrase := []byte(sunMD5ConstantPhrase)
	rounds := sunMD5BasicRound + extra
	for round := 0; round < rounds; round++ {
		// Two indices, each chosen by its own coin: the first from a bit of
		// the digest at the round number, the second from the bit 64 further
		// along. Whichever way each lands, seven coin steps walk a different
		// window of the digest.
		a := sunMD5Indirect(d, sunMD5Bit(d, round) != 0, 1, 4, 0, 3)
		b := sunMD5Indirect(d, sunMD5Bit(d, round+64) != 0, 9, 12, 8, 11)
		bit := sunMD5Bit(d, a) ^ sunMD5Bit(d, b)

		h := md5.New()
		_, _ = h.Write(d)
		if bit != 0 {
			_, _ = h.Write(phrase)
		}
		_, _ = h.Write([]byte(strconv.Itoa(round)))
		d = h.Sum(nil)
	}
	return subtle.ConstantTimeCompare(d, want) == 1, nil
}

func isSunMD5(target string) bool {
	_, _, _, err := sunMD5Fields(target)
	return err == nil
}
