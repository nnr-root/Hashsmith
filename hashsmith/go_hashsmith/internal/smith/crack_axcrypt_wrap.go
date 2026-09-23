package smith

// AxCrypt 1 and AxCrypt 2 — Hashcat 13200, 23500 and 23600.
//
//	$axcrypt$*1*<rounds>*<salt>*<wrapped>
//	$axcrypt$*2*<rounds>*<keywrap-salt>*<wrapped>*<wrap-rounds>*<kdf-salt>
//
// Both end at the same check: an AES key unwrap whose integrity value is the
// RFC 3394 constant, eight bytes of 0xa6. Everything before that is how the
// key-encrypting key is reached, and the two generations share nothing there —
// AxCrypt 1 takes a bare SHA-1 of the password, AxCrypt 2 runs PBKDF2-HMAC-
// SHA512 and folds the result.
//
// The unwrap itself is RFC 3394 with the round count opened up: the standard
// fixes six passes over the register file and AxCrypt makes it a parameter, so
// the work factor lives there rather than in a KDF. AxCrypt 1 alone departs
// from the standard in a second way, and it is the kind of detail that is only
// ever found by reading an implementation: RFC 3394 mixes the counter into the
// LOW-order end of A, and AxCrypt 1 mixes it into the HIGH-order end, in
// little-endian byte order. AxCrypt 2 does it the standard way.

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha1"
	"crypto/sha512"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"strconv"
	"strings"

	"golang.org/x/crypto/pbkdf2"
)

// aesKeyWrapIV is RFC 3394's default integrity check value.
var aesKeyWrapIV = []byte{0xa6, 0xa6, 0xa6, 0xa6, 0xa6, 0xa6, 0xa6, 0xa6}

// axcryptUnwrap runs the RFC 3394 unwrap over `rounds` passes instead of six
// and reports whether the integrity value came out right.
//
// counterHigh selects AxCrypt 1's placement of the counter (little-endian into
// A's first four bytes) over the standard's (big-endian into its last four).
func axcryptUnwrap(block cipher.Block, wrapped []byte, rounds int, counterHigh bool) bool {
	n := len(wrapped)/8 - 1
	if n < 1 {
		return false
	}
	a := make([]byte, 8)
	copy(a, wrapped[:8])
	r := make([]byte, len(wrapped)-8)
	copy(r, wrapped[8:])

	buf := make([]byte, 16)
	var ctr [4]byte
	for j := rounds - 1; j >= 0; j-- {
		for i := n; i >= 1; i-- {
			t := uint32(n*j + i)
			off := 4
			if counterHigh {
				binary.LittleEndian.PutUint32(ctr[:], t)
				off = 0
			} else {
				binary.BigEndian.PutUint32(ctr[:], t)
			}
			for k := 0; k < 4; k++ {
				a[off+k] ^= ctr[k]
			}
			copy(buf[:8], a)
			copy(buf[8:], r[(i-1)*8:i*8])
			block.Decrypt(buf, buf)
			copy(a, buf[:8])
			copy(r[(i-1)*8:i*8], buf[8:])
		}
	}
	return bytes.Equal(a, aesKeyWrapIV)
}

type axcryptRecord struct {
	version int
	// AxCrypt 1 has one round count. AxCrypt 2 has two, and they are NOT in
	// the order the field order suggests: the parser stores the third field to
	// salt_iter2, which drives the key unwrap, and the sixth to salt_iter,
	// which drives PBKDF2. The record's big number is the cheap loop.
	wrapRounds int
	kdfRounds  int
	salt       []byte // XORed into the KEK
	wrapped    []byte
	kdfSalt    []byte
}

func parseAxCrypt(target string) (*axcryptRecord, error) {
	t := strings.TrimSpace(target)
	if !strings.HasPrefix(t, "$axcrypt$*") {
		return nil, errors.New("not an AxCrypt record")
	}
	p := strings.Split(strings.TrimPrefix(t, "$axcrypt$*"), "*")
	if len(p) < 4 {
		return nil, errors.New("AxCrypt record is missing fields")
	}
	a := &axcryptRecord{}
	var err error
	if a.version, err = strconv.Atoi(p[0]); err != nil {
		return nil, errors.New("AxCrypt version must be a number")
	}
	if a.wrapRounds, err = strconv.Atoi(p[1]); err != nil || a.wrapRounds < 1 {
		return nil, errors.New("AxCrypt rounds must be a positive integer")
	}
	if a.salt, err = hex.DecodeString(p[2]); err != nil {
		return nil, errors.New("AxCrypt salt is not hex")
	}
	if a.wrapped, err = hex.DecodeString(p[3]); err != nil {
		return nil, errors.New("AxCrypt wrapped key is not hex")
	}
	switch a.version {
	case 1:
		if len(p) != 4 {
			return nil, errors.New("AxCrypt 1 record must have 4 fields")
		}
		if len(a.salt) != 16 || len(a.wrapped) != 24 {
			return nil, errors.New("AxCrypt 1 needs a 16-byte salt and a 24-byte wrapped key")
		}
	case 2:
		if len(p) != 6 {
			return nil, errors.New("AxCrypt 2 record must have 6 fields")
		}
		if a.kdfRounds, err = strconv.Atoi(p[4]); err != nil || a.kdfRounds < 1 {
			return nil, errors.New("AxCrypt 2 KDF rounds must be a positive integer")
		}
		if a.kdfSalt, err = hex.DecodeString(p[5]); err != nil {
			return nil, errors.New("AxCrypt 2 KDF salt is not hex")
		}
		// Only the leading bytes of each field are used: the key-wrap salt is
		// the first 16 bytes and the wrapped key the first 40. The rest of
		// what the extractor emits is the surrounding AxCrypt headers.
		if len(a.salt) < 32 || len(a.wrapped) < 40 || len(a.kdfSalt) == 0 {
			return nil, errors.New("AxCrypt 2 record fields are too short")
		}
	default:
		return nil, errors.New("unsupported AxCrypt version")
	}
	return a, nil
}

// verifyAxCrypt1 checks an AxCrypt 1 record, whose KEK is a bare SHA-1.
func verifyAxCrypt1(target, candidate string) (bool, error) {
	a, err := parseAxCrypt(target)
	if err != nil {
		return false, err
	}
	if a.version != 1 {
		return false, errors.New("not an AxCrypt 1 record")
	}
	sum := sha1.Sum([]byte(candidate))
	kek := make([]byte, 16)
	copy(kek, sum[:16])
	for i := range kek {
		kek[i] ^= a.salt[i]
	}
	block, err := aes.NewCipher(kek)
	if err != nil {
		return false, err
	}
	return axcryptUnwrap(block, a.wrapped, a.wrapRounds, true), nil
}

// verifyAxCrypt2 checks an AxCrypt 2 record. keyLen picks the file's cipher
// width, which the record does not carry — Hashcat splits it across two modes
// (23500 for AES-128, 23600 for AES-256) and so does this.
//
// Three things change with the width, not one. The 64 bytes of PBKDF2 output
// fold down to the KEK in four parts for AES-128 and two for AES-256; the
// cipher changes; and so does how much key is wrapped — 32 bytes under AES-128
// and 48 under AES-256, which is 40 and 56 bytes of wrapped data and therefore
// a different counter sequence through the unwrap.
func verifyAxCrypt2(target, candidate string, keyLen int) (bool, error) {
	a, err := parseAxCrypt(target)
	if err != nil {
		return false, err
	}
	if a.version != 2 {
		return false, errors.New("not an AxCrypt 2 record")
	}
	wrappedLen := 40
	if keyLen == 32 {
		wrappedLen = 56
	}
	if len(a.wrapped) < wrappedLen {
		return false, errors.New("AxCrypt 2 wrapped key is too short for this cipher width")
	}
	derived := pbkdf2.Key([]byte(candidate), a.kdfSalt, a.kdfRounds, 64, sha512.New)
	kek := make([]byte, keyLen)
	for i := 0; i < keyLen; i++ {
		kek[i] = derived[i] ^ derived[keyLen+i]
		if keyLen == 16 {
			kek[i] ^= derived[32+i] ^ derived[48+i]
		}
		kek[i] ^= a.salt[i]
	}
	block, err := aes.NewCipher(kek)
	if err != nil {
		return false, err
	}
	return axcryptUnwrap(block, a.wrapped[:wrappedLen], a.wrapRounds, false), nil
}
