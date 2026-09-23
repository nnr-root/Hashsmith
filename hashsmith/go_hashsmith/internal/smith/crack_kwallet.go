package smith

// KDE's KWallet.
//
//	$kwallet$<file length>$<64 bytes>[$<minor>$<salt len>$<salt>$<iterations>]
//
// Two key derivations, and the older one is the reason this format is worth
// reading rather than skimming. KWallet hashed the password in SIXTEEN-BYTE
// BLOCKS, each block SHA-1'd and then re-hashed two thousand times on its own,
// with the results concatenated — and then took as much of that as the key
// length wanted. The key length is chosen from the password's length: twenty
// bytes up to sixteen characters, forty up to thirty-two, fifty-six beyond.
//
// The effect is that a long password is not stronger in the way it looks.
// Its blocks are stretched independently, so the work is the same per block
// rather than per password, and a fifty-six-byte key made of four
// fourteen-byte slices is four independent 2,000-round chains rather than one.
// KWallet 4.13 replaced the whole thing with PBKDF2-HMAC-SHA512, which is the
// minor version 1 the record may carry.
//
// The check is the wallet's own header: eight bytes of randomness, then a
// four-byte length, then entries. A correct key decrypts a length that fits
// the file and, within the first fifty-two bytes of entries, at least twelve
// NULs — because a wallet's entries are length-prefixed UTF-16 strings and
// half of every ASCII character in one is a zero byte. Garbage from a wrong
// key has about two. That is weaker than a MAC and is all KWallet stores.
//
// Blowfish here is ordinary Blowfish with the bytes in the wrong order. KDE's
// implementation read the 32-bit words the other way round, so every buffer is
// byte-swapped in four-byte groups before the cipher touches it and the length
// field is swapped back afterwards.

import (
	"crypto/sha1"
	"crypto/sha512"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"strconv"
	"strings"

	"golang.org/x/crypto/blowfish"
	"golang.org/x/crypto/pbkdf2"
)

const kwalletPrefix = "$kwallet$"

type kwalletRecord struct {
	fileLen    int
	ct         []byte // the first 64 bytes of the wallet
	minor      int
	salt       []byte
	iterations int
}

func kwalletFields(target string) (kwalletRecord, error) {
	var r kwalletRecord
	t := strings.TrimSpace(target)
	if !strings.HasPrefix(t, kwalletPrefix) {
		return r, errors.New("not a KWallet record")
	}
	f := strings.Split(t[len(kwalletPrefix):], "$")
	if len(f) != 2 && len(f) != 6 {
		return r, errors.New("a KWallet record is <length>$<64 bytes>[$<minor>$<salt len>$<salt>$<iterations>]")
	}
	var err error
	if r.fileLen, err = boundedPositiveInt(f[0], "KWallet file length", 1<<28); err != nil {
		return r, err
	}
	// The record carries the whole first chunk of the wallet, and only its
	// first sixty-four bytes are used — the header and one round of entries.
	full, err := hex.DecodeString(f[1])
	if err != nil || len(full) < 64 {
		return r, errors.New("a KWallet record carries at least sixty-four bytes of the wallet")
	}
	r.ct = full[:64]
	// An old wallet carries nothing more and means minor version 0 with two
	// thousand iterations.
	r.iterations = 2000
	if len(f) == 6 {
		if r.minor, err = strconv.Atoi(f[2]); err != nil || r.minor < 0 || r.minor > 1 {
			return r, errors.New("a KWallet minor version is 0 or 1")
		}
		saltLen, err := boundedPositiveInt(f[3], "KWallet salt length", 256)
		if err != nil {
			return r, err
		}
		if r.salt, err = decodeExactHex(f[4], saltLen, "KWallet salt"); err != nil {
			return r, err
		}
		if r.iterations, err = boundedPositiveInt(f[5], "KWallet iteration count", 1<<24); err != nil {
			return r, err
		}
	}
	return r, nil
}

// kwalletLegacyKey is the pre-4.13 derivation: the password in sixteen-byte
// blocks, each hashed and then re-hashed two thousand times on its own.
func kwalletLegacyKey(password string) []byte {
	var out []byte
	for i := 0; i == 0 || i < len(password); i += 16 {
		end := i + 16
		if end > len(password) {
			end = len(password)
		}
		// A password of more than sixty characters stops contributing: the
		// buffer only has room for four blocks, and the last one takes
		// whatever is left rather than sixteen.
		if len(out) >= 60 {
			piece := password[i:]
			h := sha1.Sum([]byte(piece))
			d := h[:]
			for j := 1; j < 2000; j++ {
				s := sha1.Sum(d)
				d = s[:]
			}
			out = append(out, d...)
			break
		}
		h := sha1.Sum([]byte(password[i:end]))
		d := h[:]
		for j := 1; j < 2000; j++ {
			s := sha1.Sum(d)
			d = s[:]
		}
		out = append(out, d...)
		if len(out) >= 80 {
			break
		}
	}

	switch {
	case len(password) <= 16:
		return out[:20]
	case len(password) <= 32:
		return out[:40]
	case len(password) <= 48:
		return out[:56]
	default:
		// Beyond forty-eight characters the key is four fourteen-byte slices
		// taken from the starts of the four chains rather than their whole
		// outputs — which throws away six bytes of each and is why a very
		// long KWallet password buys less than it looks.
		key := make([]byte, 56)
		for i := 0; i < 4; i++ {
			copy(key[14*i:], out[20*i:20*i+14])
		}
		return key
	}
}

// alterEndianity byte-swaps each four-byte group, which is what KDE's
// Blowfish did to its buffers by accident and what every reader must do to
// follow it.
func alterEndianity(b []byte) {
	for i := 0; i+4 <= len(b); i += 4 {
		b[i], b[i+1], b[i+2], b[i+3] = b[i+3], b[i+2], b[i+1], b[i]
	}
}

func verifyKWallet(target, candidate string) (bool, error) {
	r, err := kwalletFields(target)
	if err != nil {
		return false, err
	}
	var key []byte
	if r.minor == 1 {
		key = pbkdf2.Key([]byte(candidate), r.salt, r.iterations, 56, sha512.New)
	} else {
		key = kwalletLegacyKey(candidate)
	}
	if len(key) == 0 {
		return false, nil
	}
	c, err := blowfish.NewCipher(key)
	if err != nil {
		return false, nil
	}

	buf := make([]byte, 64)
	copy(buf, r.ct)
	alterEndianity(buf)
	if r.minor == 1 {
		// CBC over everything after the first block, with that block as the
		// initialisation vector.
		prev := make([]byte, 8)
		copy(prev, buf[:8])
		for off := 8; off+8 <= 64; off += 8 {
			ct := make([]byte, 8)
			copy(ct, buf[off:off+8])
			c.Decrypt(buf[off:off+8], ct)
			for i := 0; i < 8; i++ {
				buf[off+i] ^= prev[i]
			}
			prev = ct
		}
	} else {
		for off := 8; off+8 <= 64; off += 8 {
			c.Decrypt(buf[off:off+8], buf[off:off+8])
		}
	}
	alterEndianity(buf[8:12])

	// Eight bytes of randomness, then the wallet's length, then its entries.
	size := int(binary.BigEndian.Uint32(buf[8:12]))
	if size < 0 || size > r.fileLen-12 {
		return false, nil
	}
	zeros := 0
	for i := 0; i < size && i < 52; i++ {
		if buf[12+i] == 0 {
			zeros++
		}
	}
	return zeros >= 12, nil
}

func isKWallet(target string) bool {
	_, err := kwalletFields(target)
	return err == nil
}
