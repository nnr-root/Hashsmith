package main

// SipHash — a keyed pseudo-random function (Aumasson & Bernstein, 2012).
//
// SipHash is a MAC rather than a plain digest: it takes a 128-bit key and a
// message and produces a 64-bit tag. Hashcat mode 10100 stores the key in the
// hash line and treats each password candidate as the message.
//
// The round count is parameterised (c compression rounds per message word, d
// finalisation rounds) because mode 10100 carries them in the hash line;
// SipHash-2-4 is the standard choice.

import (
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"math/bits"
	"strconv"
	"strings"
)

// sipHash computes SipHash-c-d over msg with a 16-byte key.
func sipHash(c, d int, key [16]byte, msg []byte) uint64 {
	k0 := binary.LittleEndian.Uint64(key[0:8])
	k1 := binary.LittleEndian.Uint64(key[8:16])

	v0 := k0 ^ 0x736f6d6570736575
	v1 := k1 ^ 0x646f72616e646f6d
	v2 := k0 ^ 0x6c7967656e657261
	v3 := k1 ^ 0x7465646279746573

	round := func() {
		v0 += v1
		v1 = bits.RotateLeft64(v1, 13)
		v1 ^= v0
		v0 = bits.RotateLeft64(v0, 32)
		v2 += v3
		v3 = bits.RotateLeft64(v3, 16)
		v3 ^= v2
		v0 += v3
		v3 = bits.RotateLeft64(v3, 21)
		v3 ^= v0
		v2 += v1
		v1 = bits.RotateLeft64(v1, 17)
		v1 ^= v2
		v2 = bits.RotateLeft64(v2, 32)
	}

	full := len(msg) - len(msg)%8
	for i := 0; i < full; i += 8 {
		m := binary.LittleEndian.Uint64(msg[i : i+8])
		v3 ^= m
		for j := 0; j < c; j++ {
			round()
		}
		v0 ^= m
	}

	// The final word packs the trailing bytes with the message length in its
	// top byte, so messages differing only in length cannot collide.
	last := uint64(len(msg)&0xff) << 56
	for i, b := range msg[full:] {
		last |= uint64(b) << (8 * uint(i))
	}
	v3 ^= last
	for j := 0; j < c; j++ {
		round()
	}
	v0 ^= last

	v2 ^= 0xff
	for j := 0; j < d; j++ {
		round()
	}
	return v0 ^ v1 ^ v2 ^ v3
}

// sipHashKey turns a password into the 128-bit SipHash key, zero-padding or
// truncating as the cracking tools do.
func sipHashKey(password string) [16]byte {
	var k [16]byte
	copy(k[:], password)
	return k
}

// sipHashHex computes SipHash-2-4 with the password as the key and the salt as
// the message, and renders the 64-bit tag the way the reference vectors do.
func sipHashHex(password, message string) (string, error) {
	return fmt.Sprintf("%016x", sipHash(2, 4, sipHashKey(password), []byte(message))), nil
}

func sipHashHashcatHex(message, keyHex string, c, d int) (string, error) {
	keyBytes, err := hex.DecodeString(keyHex)
	if err != nil || len(keyBytes) != 16 {
		return "", errors.New("Hashcat SipHash requires a 32-hex key")
	}
	var key [16]byte
	copy(key[:], keyBytes)
	// Hashcat serializes the 64-bit tag in little-endian byte order.
	return fmt.Sprintf("%016x", bits.ReverseBytes64(sipHash(c, d, key, []byte(message)))), nil
}

// verifySipHash accepts a bare 16-hex tag (message supplied with -s) as well as
// the "<tag>:<c>:<d>:<message-hex>" line the cracking tools distribute.
func verifySipHash(target, candidate, salt string) (bool, error) {
	c, d := 2, 4
	message := []byte(salt)
	tag := target
	var storedKey string

	if f := strings.Split(target, ":"); len(f) == 4 {
		var err error
		tag = f[0]
		if c, err = strconv.Atoi(f[1]); err != nil || c < 1 || c > 64 {
			return false, errors.New("invalid SipHash compression-round count")
		}
		if d, err = strconv.Atoi(f[2]); err != nil || d < 1 || d > 64 {
			return false, errors.New("invalid SipHash finalisation-round count")
		}
		storedKey = f[3]
		if len(storedKey) != 32 || !isHex(storedKey) {
			return false, errors.New("invalid SipHash key (need 32 hex chars)")
		}
	} else if strings.Contains(target, ":") {
		return false, errors.New("invalid SipHash hash (need tag or tag:c:d:message)")
	}

	if len(tag) != 16 || !isHex(tag) {
		return false, errors.New("invalid SipHash tag (need 16 hex chars)")
	}
	var got string
	if storedKey != "" {
		got, _ = sipHashHashcatHex(candidate, storedKey, c, d)
	} else if len(salt) == 32 && isHex(salt) {
		got, _ = sipHashHashcatHex(candidate, salt, c, d)
	} else {
		got = fmt.Sprintf("%016x", sipHash(c, d, sipHashKey(candidate), message))
	}
	return strings.EqualFold(got, tag), nil
}

func isSipHash(s string) bool {
	f := strings.Split(s, ":")
	return len(f) == 4 && len(f[0]) == 16 && isHex(f[0]) && isHex(f[3])
}
