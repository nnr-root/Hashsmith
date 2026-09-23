package smith

// LastPass, in the two shapes John records it that are not the sniffed
// exchange crack_hashcat_more_records.go already reads.
//
//	$lp$<email>[$<iterations>]$<16 bytes>        the browser extension
//	$lpcli$<type>$<email>$<iterations>$<iv>$<16> the lpass command line tool
//
// Both derive a key with PBKDF2-HMAC-SHA256 over the password, salted with the
// account's EMAIL ADDRESS — so the salt is public, shared across every device,
// and never rotated. Both then encrypt a fixed string with that key and store
// the result. Nothing is hashed: the verifier is a known plaintext.
//
// This is another entry that an earlier bounded search failed to reproduce,
// and the reason is the known plaintext. The extension encrypts the literal
// bytes "lastpass rocks" followed by two 0x02 bytes — PKCS#7 padding for a
// fourteen-byte message, written into the constant rather than computed — in
// ECB mode. The command-line tool encrypts the first sixteen bytes of
// "`lpass` was written by LastPass.\n" in CBC mode under a stored IV. No sweep
// over hashes of the password and the email reaches a string neither of them
// contains.
//
// The old default of 500 iterations is what a record without an iteration
// count means. LastPass raised its default several times over the years — to
// 5,000, then 100,100 — and a record carries whichever was in force, so the
// count in the record is a rough date stamp as well as a work factor.

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/sha256"
	"errors"
	"strings"

	"golang.org/x/crypto/pbkdf2"
)

const (
	lastpassPrefix    = "$lp$"
	lastpassCLIPrefix = "$lpcli$"

	// The iteration count a record without one was written under.
	lastpassDefaultIterations = 500

	// The two known plaintexts.
	lastpassVerifier    = "lastpass rocks\x02\x02"
	lastpassCLIVerifier = "`lpass` was written by LastPass.\n"
)

type lastpassRecord struct {
	email      string
	iterations int
	digest     []byte
	iv         []byte // CLI records only
}

// lastpassFields reads the extension's record, where the iteration count is
// optional and its absence means 500.
func lastpassLPFields(target string) (lastpassRecord, error) {
	var r lastpassRecord
	t := strings.TrimSpace(target)
	if !strings.HasPrefix(t, lastpassPrefix) {
		return r, errors.New("not a LastPass record")
	}
	f := strings.Split(t[len(lastpassPrefix):], "$")
	var digest string
	switch len(f) {
	case 2:
		r.email, r.iterations, digest = f[0], lastpassDefaultIterations, f[1]
	case 3:
		var err error
		if r.iterations, err = boundedPositiveInt(f[1], "LastPass iteration count", 1<<22); err != nil {
			return r, err
		}
		r.email, digest = f[0], f[2]
	default:
		return r, errors.New("a LastPass record is $lp$<email>[$<iterations>]$<verifier>")
	}
	if r.email == "" {
		return r, errors.New("a LastPass record's salt is the account's email address")
	}
	var err error
	if r.digest, err = decodeExactHex(digest, 16, "LastPass verifier"); err != nil {
		return r, err
	}
	return r, nil
}

func verifyLastPassLP(target, candidate string) (bool, error) {
	r, err := lastpassLPFields(target)
	if err != nil {
		return false, err
	}
	key := pbkdf2.Key([]byte(candidate), []byte(r.email), r.iterations, 32, sha256.New)
	block, err := aes.NewCipher(key)
	if err != nil {
		return false, err
	}
	var out [16]byte
	block.Encrypt(out[:], []byte(lastpassVerifier))
	return hmac.Equal(out[:], r.digest), nil
}

func isLastPassLP(target string) bool {
	_, err := lastpassLPFields(target)
	return err == nil
}

// lastpassCLIFields reads the command-line tool's record.
func lastpassCLIFields(target string) (lastpassRecord, error) {
	var r lastpassRecord
	t := strings.TrimSpace(target)
	if !strings.HasPrefix(t, lastpassCLIPrefix) {
		return r, errors.New("not a LastPass CLI record")
	}
	f := strings.Split(t[len(lastpassCLIPrefix):], "$")
	if len(f) != 5 {
		return r, errors.New("a LastPass CLI record is $lpcli$<type>$<email>$<iterations>$<iv>$<verifier>")
	}
	if f[0] != "0" {
		return r, errors.New("unsupported LastPass CLI record type")
	}
	var err error
	if r.iterations, err = boundedPositiveInt(f[2], "LastPass iteration count", 1<<22); err != nil {
		return r, err
	}
	if r.iv, err = decodeExactHex(f[3], 16, "LastPass CLI IV"); err != nil {
		return r, err
	}
	if r.digest, err = decodeExactHex(f[4], 16, "LastPass CLI verifier"); err != nil {
		return r, err
	}
	if r.email = f[1]; r.email == "" {
		return r, errors.New("a LastPass CLI record's salt is the account's email address")
	}
	return r, nil
}

func verifyLastPassCLI(target, candidate string) (bool, error) {
	r, err := lastpassCLIFields(target)
	if err != nil {
		return false, err
	}
	var key []byte
	if r.iterations == 1 {
		// One iteration is not PBKDF2 with a count of one: it is a plain
		// SHA-256 of the email followed by the password, which is what older
		// lpass builds wrote and is a different function entirely.
		h := sha256.New()
		_, _ = h.Write([]byte(r.email))
		_, _ = h.Write([]byte(candidate))
		key = h.Sum(nil)
	} else {
		key = pbkdf2.Key([]byte(candidate), []byte(r.email), r.iterations, 32, sha256.New)
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return false, err
	}
	var out [16]byte
	cipher.NewCBCEncrypter(block, r.iv).CryptBlocks(out[:], []byte(lastpassCLIVerifier)[:16])
	return hmac.Equal(out[:], r.digest), nil
}

func isLastPassCLI(target string) bool {
	_, err := lastpassCLIFields(target)
	return err == nil
}
