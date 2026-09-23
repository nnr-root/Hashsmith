package main

// S/Key, the one-time-password scheme RFC 1760 and RFC 2289 describe.
//
//	[<hash>] <sequence> <seed>  <8-byte response>
//
// What is stored is not a password hash. It is the LAST one-time password the
// server accepted, and the scheme works by walking a hash chain backwards:
// the client computes the chain from the passphrase, hands over the value one
// step before the stored one, and the server hashes it once to check. The
// sequence number is how far down the chain the account has got, and it counts
// down — an account at 0096 has ninety-six logins left before it must be
// re-keyed.
//
// So cracking one is walking the chain FORWARDS from a candidate passphrase,
// sequence-number times. A low sequence number is therefore cheaper to attack
// than a high one, which inverts the usual relationship between a record's
// age and its cost: the more the account has been used, the faster its
// passphrase falls.
//
// The four hashes S/Key allows all fold their digest down to sixty-four bits,
// and the fold is an XOR of the digest's eight-byte groups — except SHA-1's,
// which is specified in terms of 32-bit words and comes out in a different
// order. MD4 is the default and what a record without a hash name means.

import (
	"crypto/hmac"
	"crypto/md5"
	"crypto/sha1"
	"encoding/binary"
	"errors"
	"hash"
	"strconv"
	"strings"

	"golang.org/x/crypto/md4"
	"golang.org/x/crypto/ripemd160"
)

type skeyRecord struct {
	newHash  func() hash.Hash
	isSHA1   bool
	sequence int
	seed     string
	response []byte
}

var skeyHashes = map[string]func() hash.Hash{
	"md4":    md4.New,
	"md5":    md5.New,
	"sha1":   sha1.New,
	"rmd160": ripemd160.New,
}

func skeyFields(target string) (skeyRecord, error) {
	var r skeyRecord
	f := strings.Fields(strings.TrimSpace(target))
	name := "md4"
	if len(f) == 4 {
		name, f = f[0], f[1:]
	}
	if len(f) != 3 {
		return r, errors.New("an S/Key record is [<hash>] <sequence> <seed>  <response>")
	}
	ctor, ok := skeyHashes[strings.ToLower(name)]
	if !ok {
		return r, errors.New("S/Key allows md4, md5, sha1 and rmd160")
	}
	r.newHash, r.isSHA1 = ctor, strings.EqualFold(name, "sha1")

	n, err := strconv.Atoi(f[0])
	if err != nil || n < 0 || n > 1<<20 {
		return r, errors.New("an S/Key sequence number is a count of logins remaining")
	}
	r.sequence = n

	// The seed is letters and digits, and is lower-cased before use — a rule
	// worth keeping because a record written with a capital in it still has to
	// answer.
	if f[1] == "" || len(f[1]) > 64 {
		return r, errors.New("an S/Key seed is one short word")
	}
	for i := 0; i < len(f[1]); i++ {
		c := f[1][i]
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z') {
			return r, errors.New("an S/Key seed is letters and digits")
		}
	}
	r.seed = strings.ToLower(f[1])

	if r.response, err = decodeExactHex(f[2], 8, "S/Key response"); err != nil {
		return r, err
	}
	return r, nil
}

// skeyFold reduces a digest to the eight bytes S/Key carries.
func skeyFold(d []byte, sha1Order bool) []byte {
	out := make([]byte, 8)
	if sha1Order {
		// SHA-1 is folded as five 32-bit words rather than byte-wise: the
		// third word into the first, the fourth into the second, the fifth
		// into the first again. The surviving two are written big-endian,
		// which is to say the digest's own byte order — the reference
		// implementation folds the state after SHA1Final has already put it
		// that way round, and a little-endian reading of the same words
		// produces a plausible-looking answer that never matches.
		w := make([]uint32, 5)
		for i := range w {
			w[i] = binary.BigEndian.Uint32(d[4*i:])
		}
		w[0] ^= w[2]
		w[1] ^= w[3]
		w[0] ^= w[4]
		binary.BigEndian.PutUint32(out[0:], w[0])
		binary.BigEndian.PutUint32(out[4:], w[1])
		return out
	}
	for i := range d {
		out[i%8] ^= d[i]
	}
	return out
}

func verifySKey(target, candidate string) (bool, error) {
	r, err := skeyFields(target)
	if err != nil {
		return false, err
	}
	h := r.newHash()
	_, _ = h.Write([]byte(r.seed + candidate))
	k := skeyFold(h.Sum(nil), r.isSHA1)
	for i := 0; i < r.sequence; i++ {
		h.Reset()
		_, _ = h.Write(k)
		k = skeyFold(h.Sum(nil), r.isSHA1)
	}
	return hmac.Equal(k, r.response), nil
}

func isSKey(target string) bool {
	_, err := skeyFields(target)
	return err == nil
}
