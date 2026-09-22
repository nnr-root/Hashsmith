package main

// Two Microsoft desktop formats whose protection was never meant to survive
// an attacker with the file.
//
//	$pst$<8 hex>                      Outlook personal-folders password
//	$money$<type>*<8-byte salt>*<4>   Microsoft Money file password
//
// Outlook's is the clearest example in the whole catalogue of a password
// check that is not a password hash. A .pst file stores a CRC-32 of the
// password — thirty-two bits, unsalted, and not one-way in any useful sense:
// the space of four-byte values is small enough to search directly, and
// millions of passwords share each value. Recovering "a" password takes
// seconds; recovering THE password is not something the file can tell you.
// Outlook itself never enforced it server-side, which is why the check is
// only a CRC in the first place.
//
// Money's is a real check, just a thin one: RC4 with a key built from the
// password and a stored salt, decrypting four known bytes.

import (
	"crypto/md5"
	"crypto/rc4"
	"crypto/sha1"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"hash/crc32"
	"strconv"
	"strings"
)

// ── Outlook .pst ──────────────────────────────────────────────────────────────

const pstPrefix = "$pst$"

// pstCRC is CRC-32 with the usual reflected polynomial but without either of
// the conventions that make the common "CRC-32" — it starts at zero and is
// not complemented at the end. Using Go's crc32.ChecksumIEEE here gives a
// different answer for every input.
func pstCRC(s string) uint32 {
	var crc uint32
	for i := 0; i < len(s); i++ {
		crc = crc32.IEEETable[byte(crc)^s[i]] ^ (crc >> 8)
	}
	return crc
}

func pstFields(target string) (uint32, error) {
	t := strings.TrimSpace(target)
	if !strings.HasPrefix(t, pstPrefix) {
		return 0, errors.New("not an Outlook .pst record")
	}
	v := t[len(pstPrefix):]
	if len(v) != 8 || !isHex(v) {
		return 0, errors.New("an Outlook .pst record is one 32-bit checksum")
	}
	n, err := strconv.ParseUint(v, 16, 32)
	if err != nil {
		return 0, errors.New("an Outlook .pst record is one 32-bit checksum")
	}
	return uint32(n), nil
}

// verifyPSTPassword checks a candidate against the stored checksum. A match
// is not proof: see the note above about what thirty-two bits can and cannot
// establish.
func verifyPSTPassword(target, candidate string) (bool, error) {
	want, err := pstFields(target)
	if err != nil {
		return false, err
	}
	// The stored value is a checksum of the password up to its first NUL,
	// which for a candidate from a wordlist is the whole of it.
	if i := strings.IndexByte(candidate, 0); i >= 0 {
		candidate = candidate[:i]
	}
	return pstCRC(candidate) == want, nil
}

func isPSTPassword(target string) bool { _, err := pstFields(target); return err == nil }

// ── Microsoft Money ───────────────────────────────────────────────────────────

const moneyPrefix = "$money$"

type moneyRecord struct {
	kind      int
	salt      [8]byte
	encrypted [4]byte
}

func moneyFields(target string) (moneyRecord, error) {
	var r moneyRecord
	t := strings.TrimSpace(target)
	if !strings.HasPrefix(t, moneyPrefix) {
		return r, errors.New("not a Microsoft Money record")
	}
	f := strings.Split(t[len(moneyPrefix):], "*")
	if len(f) != 3 {
		return r, errors.New("a Money record is <type>*<salt>*<encrypted bytes>")
	}
	kind, err := strconv.Atoi(f[0])
	if err != nil || (kind != 0 && kind != 1) {
		return r, errors.New("a Money record's type is 0 (MD5) or 1 (SHA-1)")
	}
	salt, err := decodeExactHex(f[1], 8, "Money salt")
	if err != nil {
		return r, err
	}
	enc, err := decodeExactHex(f[2], 4, "Money verifier")
	if err != nil {
		return r, err
	}
	r.kind = kind
	copy(r.salt[:], salt)
	copy(r.encrypted[:], enc)
	return r, nil
}

// moneyPasswordBlock is the buffer Money hashes: the password upper-cased with
// its eighth bit stripped, written as UTF-16LE into forty zero bytes, and
// hashed at that full length rather than at the length of the password.
//
// Both of those are load-bearing and neither is visible in the record. Money
// upper-cases, so its passwords are case-insensitive whatever the user typed;
// and the trailing zeros are inside the digest, so hashing the password alone
// gives a different key for every input.
func moneyPasswordBlock(candidate string) []byte {
	folded := make([]byte, 0, len(candidate))
	for i := 0; i < len(candidate); i++ {
		c := candidate[i]
		if c >= 'a' && c <= 'z' {
			c ^= 0x20
		} else {
			c &= 0x7f
		}
		folded = append(folded, c)
	}
	block := make([]byte, 40)
	u := utf16le(string(folded))
	copy(block, u)
	return block
}

func verifyMoney(target, candidate string) (bool, error) {
	r, err := moneyFields(target)
	if err != nil {
		return false, err
	}
	block := moneyPasswordBlock(candidate)
	var digest []byte
	if r.kind == 0 {
		sum := md5.Sum(block)
		digest = sum[:]
	} else {
		sum := sha1.Sum(block)
		digest = sum[:]
	}
	key := make([]byte, 0, 24)
	key = append(key, digest[:16]...)
	key = append(key, r.salt[:]...)
	c, err := rc4.NewCipher(key)
	if err != nil {
		return false, err
	}
	var out [4]byte
	c.XORKeyStream(out[:], r.encrypted[:])
	// The four bytes decrypt to the first four bytes of the salt, which is
	// the whole of the verifier: thirty-two bits, so a wrong password passes
	// about once in four billion.
	return binary.BigEndian.Uint32(out[:]) == binary.BigEndian.Uint32(r.salt[:4]), nil
}

func isMoney(target string) bool { _, err := moneyFields(target); return err == nil }

// ── RADIUS shared secret ──────────────────────────────────────────────────────

const radiusPrefix = "$radius$"

// John's record is
//
//	$radius$<type>*<id>*<known password>*<request authenticator>*<User-Password>
//
// and what is being recovered is not the user's password — that is written in
// the record — but the SHARED SECRET between the RADIUS client and the server.
//
// RFC 2865 hides the user's password by XORing it with MD5(secret ||
// authenticator). Anyone who captures an Access-Request and separately knows
// what the user typed can therefore recover that MD5 output exactly, and from
// there the only unknown is the secret. That is why a captured request plus
// one known password is enough, and why RADIUS secrets are worth changing
// after any capture.
func radiusFields(target string) (known string, auth, enc []byte, err error) {
	t := strings.TrimSpace(target)
	if !strings.HasPrefix(t, radiusPrefix) {
		return "", nil, nil, errors.New("not a RADIUS record")
	}
	f := strings.Split(t[len(radiusPrefix):], "*")
	if len(f) != 5 {
		return "", nil, nil, errors.New("a RADIUS record is <type>*<id>*<password>*<authenticator>*<User-Password>")
	}
	if f[2] == "" {
		return "", nil, nil, errors.New("a RADIUS record must carry the known password")
	}
	if auth, err = decodeExactHex(f[3], 16, "RADIUS request authenticator"); err != nil {
		return "", nil, nil, err
	}
	if enc, err = hex.DecodeString(f[4]); err != nil || len(enc) == 0 || len(enc)%16 != 0 {
		return "", nil, nil, errors.New("a RADIUS User-Password is a whole number of 16-byte blocks")
	}
	return f[2], auth, enc, nil
}

func verifyRadius(target, candidate string) (bool, error) {
	known, auth, enc, err := radiusFields(target)
	if err != nil {
		return false, err
	}
	// Only the first block is needed while the known password is shorter than
	// sixteen bytes, which it is in every record of this shape; the loop is
	// written out because RFC 2865 chains the blocks and a longer password
	// would otherwise be checked on its first sixteen bytes alone.
	want := make([]byte, len(enc))
	copy(want, known)
	prev := auth
	for off := 0; off < len(enc); off += 16 {
		h := md5.New()
		_, _ = h.Write([]byte(candidate))
		_, _ = h.Write(prev)
		mask := h.Sum(nil)
		for i := 0; i < 16; i++ {
			if enc[off+i]^mask[i] != want[off+i] {
				return false, nil
			}
		}
		prev = enc[off : off+16]
	}
	return true, nil
}

func isRadius(target string) bool {
	_, _, _, err := radiusFields(target)
	return err == nil
}
