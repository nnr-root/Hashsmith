package smith

// Files written by `openssl enc`.
//
//	$openssl$<cipher>$<digest>$<salt length>$<salt>$<last chunks>$1$<hint>
//	$openssl$<cipher>$<digest>$<salt length>$<salt>$<last chunks>$0$<n>$<head>$<hint>
//
// The first field is a CIPHER INDEX, not a key length, and it counts DOWN:
// 0 is AES-256 and 1 is AES-128. That is John's numbering and there is no
// third value — openssl2john's default run writes 0, so a record straight out
// of that converter is an AES-256 one. Reading the field as a key length gets
// the two ciphers exactly backwards on a record that names either.
//
// The field after the sample says whether the file was INLINED: whether it is
// short enough that its only ciphertext block is the last one. That changes
// what the sample means and how it is decrypted:
//
//	1  the sample is sixteen bytes, the file's one and only block, and the
//	   IV is the one the password derived
//	0  the sample is thirty-two bytes — the block BEFORE the last one
//	   followed by the last one — and CBC makes the first of those the IV
//	   for the second, so the derived IV is not used here at all
//
// A reader that decrypts the whole sample under the derived IV gets the final
// block right by accident (CBC recovers from a wrong IV after one block) and
// the block before it as noise, which then fails any test applied to the
// plaintext as a whole. That is the failure with no symptom: the padding
// checks out, so the record looks readable, and the right password is
// rejected.
//
// `openssl enc` derives the key and IV from the password and an eight-byte
// salt one of two ways — EVP_BytesToKey (one pass of a digest, no iteration
// count, the historical default) or PBKDF2 at 10000 iterations (what
// -pbkdf2 selects, and what OpenSSL 1.1.0+ has nudged users toward ever
// since with a "deprecated key derivation used" warning when it's
// omitted) — and produces a byte-identical "Salted__" container either
// way, with nothing in the file saying which KDF made it. verifyOpenSSLEnc
// tries both rather than guessing (found missing, then fixed, by running
// real `openssl enc -pbkdf2` output through this package, 2026-09) — and
// then encrypts with no authentication of any kind, so there is nothing in
// the file that says whether a password was right either.
//
// So the check is circumstantial, and this is the one format here where that
// is worth stating plainly. The last block of a CBC file ends in PKCS#7
// padding, and a wrong key produces valid-looking padding about once in every
// 256 tries. That is not a check: a ten-million-candidate run would stop on a
// wrong answer with near certainty.
//
// Hashsmith therefore requires the padding AND that what precedes it is
// printable text, which takes the false-positive rate to roughly one in a
// hundred million. The cost is real and is the honest trade: an encrypted
// file whose first bytes are binary will not be recovered from a record this
// short. Reporting a wrong password instead would be worse.
//
// Trying two KDFs per candidate doubles the cost of every attempt, which
// matters more here than for most formats given how weak the per-attempt
// check already is — but the record format itself (John's own openssl2john
// spelling) is unchanged: this is a verify-side change, not a new field, so
// a record already extracted or shared before this fix still works.

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"hash"
	"strconv"
	"strings"

	"golang.org/x/crypto/pbkdf2"
)

const opensslEncPrefix = "$openssl$"

// evpBytesToKey is OpenSSL's own derivation: the digest of the previous
// block, the password and the salt, repeated until there are enough bytes for
// a key and an IV.
func evpBytesToKey(newHash func() hash.Hash, password, salt []byte, count, keyLen, ivLen int) (key, iv []byte) {
	var out, prev []byte
	for len(out) < keyLen+ivLen {
		h := newHash()
		_, _ = h.Write(prev)
		_, _ = h.Write(password)
		_, _ = h.Write(salt)
		prev = h.Sum(nil)
		for i := 1; i < count; i++ {
			h2 := newHash()
			_, _ = h2.Write(prev)
			prev = h2.Sum(nil)
		}
		out = append(out, prev...)
	}
	return out[:keyLen], out[keyLen : keyLen+ivLen]
}

type opensslEnc struct {
	newHash func() hash.Hash
	keyLen  int
	salt    []byte
	sample  []byte
	// inlined says the sample is the file's only block. When it is false
	// the sample carries the preceding block in front of the last one.
	inlined bool
	// head is up to 256 bytes from the START of the ciphertext, which some
	// records carry and which is worth far more than the tail: decrypted,
	// it is real plaintext rather than plaintext plus padding.
	head []byte
}

func parseOpenSSLEnc(target string) (*opensslEnc, error) {
	t := strings.TrimSpace(target)
	if !strings.HasPrefix(t, opensslEncPrefix) {
		return nil, errors.New("not an openssl enc record")
	}
	f := strings.Split(t[len(opensslEncPrefix):], "$")
	if len(f) < 5 {
		return nil, errors.New("an openssl enc record needs a key size, a digest, a salt and a sample")
	}
	r := &opensslEnc{}
	switch f[0] {
	case "0":
		r.keyLen = 32 // AES-256
	case "1":
		r.keyLen = 16 // AES-128
	default:
		return nil, errors.New("unsupported openssl enc cipher " + f[0] +
			" (0 is AES-256 and 1 is AES-128; there is no third)")
	}
	switch f[1] {
	case "0":
		r.newHash = md5.New
	case "1":
		r.newHash = sha1.New
	case "2":
		r.newHash = sha256.New
	default:
		return nil, errors.New("unsupported openssl enc digest " + f[1])
	}
	saltLen, err := strconv.Atoi(f[2])
	if err != nil || saltLen < 1 || saltLen > 64 {
		return nil, errors.New("invalid openssl enc salt length")
	}
	if r.salt, err = hex.DecodeString(f[3]); err != nil || len(r.salt) != saltLen {
		return nil, errors.New("invalid openssl enc salt")
	}
	if r.sample, err = hex.DecodeString(f[4]); err != nil ||
		len(r.sample) == 0 || len(r.sample)%aes.BlockSize != 0 {
		return nil, errors.New("invalid openssl enc sample")
	}

	// A record with no inlined flag is read as inlined, which is what a
	// sixteen-byte sample can only be.
	r.inlined = len(f) < 6 || f[5] != "0"
	if r.inlined {
		if len(r.sample) != aes.BlockSize {
			return nil, errors.New("an inlined openssl enc sample is one sixteen-byte block")
		}
	} else {
		if len(r.sample) < 2*aes.BlockSize {
			return nil, errors.New("a non-inlined openssl enc sample carries the block before the last one as well")
		}
		// The last two blocks are the ones that matter; older writers
		// put exactly two here and nothing depends on more.
		r.sample = r.sample[len(r.sample)-2*aes.BlockSize:]
		if len(f) >= 9 {
			head, err := hex.DecodeString(f[8])
			if err == nil && len(head) >= aes.BlockSize && len(head)%aes.BlockSize == 0 {
				r.head = head
			}
		}
	}
	return r, nil
}

// printableForOpenSSL reports whether every byte could be part of a text file.
func printableForOpenSSL(b []byte) bool {
	for _, c := range b {
		if c == '\n' || c == '\r' || c == '\t' {
			continue
		}
		if c < 0x20 || c > 0x7e {
			return false
		}
	}
	return true
}

// opensslPBKDF2Iterations is OpenSSL's own `-pbkdf2` default iteration
// count, confirmed directly against a real `openssl enc -help` (OpenSSL
// 3.6.3, 2026-09) rather than assumed — `-iter` overrides it, but that
// override is not recoverable from the "Salted__" container either, so only
// the default is tried.
const opensslPBKDF2Iterations = 10000

// verifyOpenSSLEnc checks a password against an `openssl enc` sample, trying
// both key-derivation schemes OpenSSL itself can produce for the same
// "Salted__" container: EVP_BytesToKey (the historical default) and PBKDF2
// (what `-pbkdf2` selects, and what OpenSSL 1.1.0+ nudges every user toward
// with a "deprecated key derivation used" warning when it is omitted).
// Nothing in the container says which one made it, so both have to be tried
// rather than guessed at — this was a real, found-by-testing-real-openssl-
// output gap (2026-09) before this function tried more than the legacy one.
//
// r.newHash already gives the extractor's own guess at the EVP_BytesToKey
// digest (the record's digest field enumerates md5/sha1/sha256, see
// parseOpenSSLEnc); reusing it for the PBKDF2 attempt too means the record
// that happens to carry sha256 also covers PBKDF2's own confirmed default
// digest, without a second digest dimension to guess across.
func verifyOpenSSLEnc(target, candidate string) (bool, error) {
	r, err := parseOpenSSLEnc(target)
	if err != nil {
		return false, err
	}
	legacyKey, legacyIV := evpBytesToKey(r.newHash, []byte(candidate), r.salt, 1, r.keyLen, aes.BlockSize)
	pbkdf2Out := pbkdf2.Key([]byte(candidate), r.salt, opensslPBKDF2Iterations, r.keyLen+aes.BlockSize, r.newHash)
	pbkdf2Key, pbkdf2IV := pbkdf2Out[:r.keyLen], pbkdf2Out[r.keyLen:]

	for _, kdf := range [][2][]byte{{legacyKey, legacyIV}, {pbkdf2Key, pbkdf2IV}} {
		key, iv := kdf[0], kdf[1]
		block, err := aes.NewCipher(key)
		if err != nil {
			return false, err
		}

		// Decrypt the FINAL block only, under whichever IV chains into it:
		// the derived one for a one-block file, the preceding ciphertext
		// block otherwise.
		last := r.sample
		chain := iv
		if !r.inlined {
			chain, last = r.sample[:aes.BlockSize], r.sample[aes.BlockSize:]
		}
		plain := make([]byte, aes.BlockSize)
		cipher.NewCBCDecrypter(block, chain).CryptBlocks(plain, last)

		n := int(plain[len(plain)-1])
		if n < 1 || n > aes.BlockSize || n > len(plain) {
			continue
		}
		bad := false
		for _, c := range plain[len(plain)-n:] {
			if int(c) != n {
				bad = true
				break
			}
		}
		if bad {
			continue
		}
		// Padding alone is one chance in 256. See the note at the top of
		// this file for why that is not enough on its own.
		if !printableForOpenSSL(plain[:len(plain)-n]) {
			continue
		}

		// When the record carries the head of the file, decrypt that too.
		// It is plaintext with no padding in it, so many more bytes have to
		// come out printable, and the one-in-256 padding coincidence stops
		// mattering.
		if len(r.head) > 0 {
			headPlain := make([]byte, len(r.head))
			cipher.NewCBCDecrypter(block, iv).CryptBlocks(headPlain, r.head)
			if !printableForOpenSSL(headPlain) {
				continue
			}
		}
		return true, nil
	}
	return false, nil
}

func isOpenSSLEnc(target string) bool {
	_, err := parseOpenSSLEnc(target)
	return err == nil
}
