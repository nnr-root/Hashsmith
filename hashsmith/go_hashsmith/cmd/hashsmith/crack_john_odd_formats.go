package main

// Four formats with nothing in common but their obscurity, each of which is a
// few lines once its one surprise is known.
//
//	EPI        sha1(salt[:29] || password || 0x00)
//	leet       sha512(password.salt) XOR whirlpool(salt.password)
//	$sl3$      sha1(digits-as-values || 0x00 || IMEI || 0x00)
//	$adxcrypt$ a 32-bit fold of eight bytes, printed as eight digits
//
// The surprises are, in order: a NUL that is inside the digest because the C
// that wrote it measured the key with its terminator; a construction that
// XORs two different hash functions together, which is unusual enough that
// reading the record cannot suggest it; a password whose digits are hashed as
// the NUMBERS 0-9 rather than the characters '0'-'9'; and a "hash" that is
// not one.

import (
	"crypto/hmac"
	"crypto/sha1"
	"crypto/sha512"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"strings"
)

// ── EPI ───────────────────────────────────────────────────────────────────────

// An EPI record is two hex blobs separated by a space, each written with an
// "0x" in front:
//
//	0x<60 hex> 0x<40 hex>
//
// The first is a thirty-byte salt and the second the SHA-1. Only twenty-nine
// of the salt's thirty bytes are hashed, and the password is followed by a NUL
// — both because the original measured its buffers with sizeof and strlen+1
// rather than with the lengths it meant.
func epiFields(target string) (salt, digest []byte, err error) {
	t := strings.TrimSpace(target)
	a, b, ok := strings.Cut(t, " ")
	if !ok {
		return nil, nil, errors.New("an EPI record is two 0x-prefixed hex fields")
	}
	if !strings.HasPrefix(a, "0x") || !strings.HasPrefix(b, "0x") {
		return nil, nil, errors.New("an EPI record's fields each begin 0x")
	}
	if salt, err = decodeExactHex(a[2:], 30, "EPI salt"); err != nil {
		return nil, nil, err
	}
	if digest, err = decodeExactHex(b[2:], sha1.Size, "EPI digest"); err != nil {
		return nil, nil, err
	}
	return salt, digest, nil
}

func verifyEPI(target, candidate string) (bool, error) {
	salt, digest, err := epiFields(target)
	if err != nil {
		return false, err
	}
	h := sha1.New()
	_, _ = h.Write(salt[:29])
	_, _ = h.Write([]byte(candidate))
	_, _ = h.Write([]byte{0})
	return hmac.Equal(h.Sum(nil), digest), nil
}

func isEPI(target string) bool { _, _, err := epiFields(target); return err == nil }

// ── leet ──────────────────────────────────────────────────────────────────────

// "<salt>$<128 hex>", where the digest is
//
//	sha512(password || salt) XOR whirlpool(salt || password)
//
// Two hash functions over the same two strings in opposite orders, XORed
// together. Nothing about the record hints at it, and the shape — a salt, a
// dollar and a 512-bit digest — is what a plain salted SHA-512 looks like.
func leetFields(target string) (salt string, digest []byte, err error) {
	t := strings.TrimSpace(target)
	salt, d, ok := strings.Cut(t, "$")
	if !ok || salt == "" || len(salt) > maxKDFFieldSize || strings.Contains(d, "$") {
		return "", nil, errors.New("a leet record is <salt>$<digest>")
	}
	if digest, err = decodeExactHex(d, 64, "leet digest"); err != nil {
		return "", nil, err
	}
	return salt, digest, nil
}

func verifyLeet(target, candidate string) (bool, error) {
	salt, digest, err := leetFields(target)
	if err != nil {
		return false, err
	}
	a := sha512.Sum512([]byte(candidate + salt))
	w := newWhirlpool()
	_, _ = w.Write([]byte(salt + candidate))
	b := w.Sum(nil)
	got := make([]byte, len(a))
	for i := range got {
		got[i] = a[i] ^ b[i]
	}
	return hmac.Equal(got, digest), nil
}

func isLeet(target string) bool { _, _, err := leetFields(target); return err == nil }

// ── Nokia SL3 ─────────────────────────────────────────────────────────────────

// "$sl3$<14-digit IMEI>$<40 hex>" — the unlock code for a Nokia handset,
// which is fifteen digits and nothing else.
//
// Two things are worth stating. The IMEI is read as HEX, not as a number, so
// its fourteen digits become seven bytes; and the unlock code's digits are
// hashed as the values zero to nine rather than as the characters '0' to '9',
// which is the difference between a digest that verifies and one that does
// not.
//
// The keyspace is 10^15 and fixed — every SL3 code is exactly fifteen digits
// — so this is one of the few formats where an exhaustive attack is a
// statement about hardware rather than about the password.
const sl3Prefix = "$sl3$"

func sl3Fields(target string) (imei []byte, digest []byte, err error) {
	t := strings.TrimSpace(target)
	if !strings.HasPrefix(t, sl3Prefix) {
		return nil, nil, errors.New("not a Nokia SL3 record")
	}
	id, d, ok := strings.Cut(t[len(sl3Prefix):], "$")
	if !ok || len(id) != 14 {
		return nil, nil, errors.New("an SL3 record carries fourteen IMEI digits")
	}
	for i := 0; i < len(id); i++ {
		if id[i] < '0' || id[i] > '9' {
			return nil, nil, errors.New("an SL3 IMEI is digits")
		}
	}
	if imei, err = hex.DecodeString(id); err != nil {
		return nil, nil, errors.New("an SL3 IMEI is read as hex")
	}
	if digest, err = decodeExactHex(d, sha1.Size, "SL3 digest"); err != nil {
		return nil, nil, err
	}
	return imei, digest, nil
}

func verifySL3(target, candidate string) (bool, error) {
	imei, digest, err := sl3Fields(target)
	if err != nil {
		return false, err
	}
	if len(candidate) != 15 {
		return false, nil
	}
	code := make([]byte, 15)
	for i := 0; i < 15; i++ {
		if candidate[i] < '0' || candidate[i] > '9' {
			return false, nil
		}
		code[i] = candidate[i] - '0'
	}
	h := sha1.New()
	_, _ = h.Write(code)
	_, _ = h.Write([]byte{0})
	_, _ = h.Write(imei)
	_, _ = h.Write([]byte{0})
	return hmac.Equal(h.Sum(nil), digest), nil
}

func isSL3(target string) bool { _, _, err := sl3Fields(target); return err == nil }

// ── ADX ───────────────────────────────────────────────────────────────────────

// "$adxcrypt$<8 digits>", from ADX point-of-sale terminals.
//
// This is not a hash and the format's own test vectors say so: two of them
// give the same eight digits for "99999999" and for "786r", and the comment
// beside them notes that the collision "works fine on a real system". The
// whole check is one 32-bit value folded out of eight bytes, so collisions are
// not an accident of the construction, they are most of it.
//
// A password shorter than eight bytes is stretched by repeating it with each
// copied byte incremented by its position, which is the only part of this
// worth describing as design.
const adxPrefix = "$adxcrypt$"

func verifyADX(target, candidate string) (bool, error) {
	t := strings.TrimSpace(target)
	if !strings.HasPrefix(t, adxPrefix) {
		return false, errors.New("not an ADX record")
	}
	want := t[len(adxPrefix):]
	if len(want) != 8 {
		return false, errors.New("an ADX record is eight characters")
	}
	if candidate == "" {
		return false, nil
	}
	var buf [8]byte
	n := copy(buf[:], candidate)
	for n < 8 {
		for i := 0; i < len(candidate) && n < 8; i++ {
			buf[n] = candidate[i] + byte(n)
			n++
		}
	}
	a := (binary.LittleEndian.Uint32(buf[0:]) + binary.LittleEndian.Uint32(buf[4:])) ^ 0xBEEFFACE
	var got [8]byte
	for i := 0; i < 8; i++ {
		v := a & 0xF
		if v > 9 {
			v -= 7
		}
		got[i] = byte(v) + '0'
		a >>= 4
	}
	return string(got[:]) == want, nil
}

func isADX(target string) bool {
	t := strings.TrimSpace(target)
	if !strings.HasPrefix(t, adxPrefix) {
		return false
	}
	v := t[len(adxPrefix):]
	if len(v) != 8 {
		return false
	}
	for i := 0; i < len(v); i++ {
		if v[i] < '0' || v[i] > '9' {
			return false
		}
	}
	return true
}
