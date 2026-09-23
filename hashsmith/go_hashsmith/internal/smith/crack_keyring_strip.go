package smith

// Two password managers whose files are on disk and whose verifier is the
// decryption itself.
//
//	$keyring$<salt>*<iterations>*<size>*<0>*<ciphertext>   GNOME keyring
//	$strip$*<1024 bytes of the first SQLite page>          STRIP
//
// Neither stores a digest. Both decrypt and then ask whether what came out
// makes sense, which is the honest way to check a container password and the
// reason a correct answer here is a correct answer rather than a collision.

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"strings"

	"golang.org/x/crypto/pbkdf2"
)

// ── GNOME keyring ─────────────────────────────────────────────────────────────

// The key derivation is iterated SHA-256 with the salt folded in once:
// sha256(password || salt), then the digest re-hashed on its own for the
// remaining rounds. That is weaker than PBKDF2 at the same count — the salt
// stops mattering after the first block, so an attacker can precompute nothing
// but also needs no per-iteration salt handling — and the iteration count is
// stored in the record and is usually a few thousand.
//
// Key and IV are the two halves of the final digest, AES-128-CBC, and the
// plaintext carries its own MD5 in its first sixteen bytes. That MD5 is the
// check: sixteen bytes have to agree, so a wrong password does not pass.
const keyringPrefix = "$keyring$"

type keyringRecord struct {
	salt       []byte
	iterations int
	size       int
	ct         []byte
}

func keyringFields(target string) (keyringRecord, error) {
	var r keyringRecord
	t := strings.TrimSpace(target)
	if !strings.HasPrefix(t, keyringPrefix) {
		return r, errors.New("not a GNOME keyring record")
	}
	f := strings.Split(t[len(keyringPrefix):], "*")
	if len(f) != 5 {
		return r, errors.New("a keyring record is <salt>*<iterations>*<size>*<0>*<ciphertext>")
	}
	var err error
	if r.salt, err = decodeExactHex(f[0], 8, "keyring salt"); err != nil {
		return r, err
	}
	if r.iterations, err = boundedPositiveInt(f[1], "keyring iteration count", 1<<22); err != nil {
		return r, err
	}
	if r.size, err = boundedPositiveInt(f[2], "keyring ciphertext size", 1<<20); err != nil {
		return r, err
	}
	if r.ct, err = hex.DecodeString(f[4]); err != nil || len(r.ct) < 16 || len(r.ct)%16 != 0 {
		return r, errors.New("a keyring ciphertext is whole AES blocks")
	}
	if r.size > len(r.ct) {
		return r, errors.New("a keyring record claims more ciphertext than it carries")
	}
	return r, nil
}

func verifyKeyring(target, candidate string) (bool, error) {
	r, err := keyringFields(target)
	if err != nil {
		return false, err
	}
	h := sha256.New()
	_, _ = h.Write([]byte(candidate))
	_, _ = h.Write(r.salt)
	digest := h.Sum(nil)
	for i := 1; i < r.iterations; i++ {
		sum := sha256.Sum256(digest)
		digest = sum[:]
	}

	block, err := aes.NewCipher(digest[:16])
	if err != nil {
		return false, err
	}
	out := make([]byte, r.size)
	cipher.NewCBCDecrypter(block, digest[16:32]).CryptBlocks(out, r.ct[:r.size])
	if len(out) < 16 {
		return false, nil
	}
	want := md5.Sum(out[16:])
	return hmac.Equal(out[:16], want[:]), nil
}

func isKeyring(target string) bool {
	_, err := keyringFields(target)
	return err == nil
}

// ── STRIP ─────────────────────────────────────────────────────────────────────

// STRIP is an iPhone password manager whose store is a SQLCipher database.
// The record is the first page of that file, 1,024 bytes of it, which carries
// both the salt and everything needed to check an answer.
//
// The check is the SQLite header. SQLCipher encrypts the page but leaves its
// structure intact underneath, so a correct key decrypts eight bytes at offset
// 16 into fields that a real SQLite page would have: a page size that is a
// power of two between 512 and 65536, a write-format byte of at most 2, and
// three bytes that SQLite has written as 0x40 0x20 0x20 since version 3. Those
// constraints are worth roughly thirty bits together, so a wrong password gets
// through about once in a billion and the format is honest about that: John
// checks the same eight bytes.
const stripPrefix = "$strip$*"

const (
	stripIterations = 4000
	stripPageSize   = 1024
)

func stripPage(target string) ([]byte, error) {
	t := strings.TrimSpace(target)
	if !strings.HasPrefix(t, stripPrefix) {
		return nil, errors.New("not a STRIP record")
	}
	page, err := hex.DecodeString(t[len(stripPrefix):])
	if err != nil || len(page) != stripPageSize {
		return nil, errors.New("a STRIP record is the first 1,024 bytes of the database")
	}
	return page, nil
}

func verifyStrip(target, candidate string) (bool, error) {
	page, err := stripPage(target)
	if err != nil {
		return false, err
	}
	key := pbkdf2.Key([]byte(candidate), page[:16], stripIterations, 32, sha1.New)
	block, err := aes.NewCipher(key)
	if err != nil {
		return false, err
	}
	// The IV sits at the end of the page's usable area, sixteen bytes before
	// its end, which is where SQLCipher puts it.
	var out [16]byte
	cipher.NewCBCDecrypter(block, page[1008:1024]).CryptBlocks(out[:], page[16:32])
	return stripHeaderLooksReal(out[:8]), nil
}

// stripHeaderLooksReal reads the eight bytes at offset 16 of a SQLite page as
// the header fields they would be.
func stripHeaderLooksReal(b []byte) bool {
	// b[0..7] are page bytes 16..23.
	pageSize := uint32(b[0])<<8 | uint32(b[1])<<16
	if b[3] > 2 {
		return false
	}
	if b[5] != 0x40 || b[6] != 0x20 || b[7] != 0x20 {
		return false
	}
	if pageSize <= 256 || pageSize > 65536 || pageSize&(pageSize-1) != 0 || pageSize&7 != 0 {
		return false
	}
	return uint32(pageSize)-uint32(b[4]) >= 480
}

func isStrip(target string) bool { _, err := stripPage(target); return err == nil }
