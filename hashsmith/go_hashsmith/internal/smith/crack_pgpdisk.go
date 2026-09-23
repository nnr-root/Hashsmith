package smith

// PGP Disk / Symantec Encryption Desktop volumes.
//
//	$pgpdisk$<version>*<algorithm>*<iterations>*<16-byte salt>*<verifier>
//
// The derivation is the same shape as the SDA's — a SHA-1 context fed the salt
// and then the password with a wrapping counter byte — with one addition: it
// produces as many 20-byte blocks as the cipher's key needs, and every block
// after the first is seeded with the one before it. Sixteen thousand rounds of
// SHA-1 updates is the whole work factor.
//
// The verifier is again the key encrypting its own first block, under whichever
// cipher the volume uses. The algorithm number says which, and the number is
// worth reading: 3 is CAST5 with a 64-bit block, 4 is Twofish, and 5 through 7
// are AES-256. A volume reporting 3 was made by a version of PGP old enough
// that the disk it protects is probably older still.

import (
	"crypto/aes"
	"crypto/hmac"
	"crypto/sha1"
	"errors"
	"strings"

	"golang.org/x/crypto/cast5"
	"golang.org/x/crypto/twofish"
)

const pgpDiskPrefix = "$pgpdisk$"

type pgpDiskRecord struct {
	algorithm  int
	iterations int
	salt       []byte
	verifier   []byte
}

func pgpDiskFields(target string) (pgpDiskRecord, error) {
	var r pgpDiskRecord
	t := strings.TrimSpace(target)
	if !strings.HasPrefix(t, pgpDiskPrefix) {
		return r, errors.New("not a PGP Disk record")
	}
	f := strings.Split(t[len(pgpDiskPrefix):], "*")
	if len(f) != 5 || f[0] != "0" {
		return r, errors.New("a PGP Disk record is $pgpdisk$0*<algorithm>*<iterations>*<salt>*<verifier>")
	}
	var err error
	if r.algorithm, err = boundedPositiveInt(f[1], "PGP Disk algorithm", 16); err != nil {
		return r, err
	}
	switch r.algorithm {
	case 3, 4, 5, 6, 7:
	default:
		return r, errors.New("this PGP Disk record names a cipher Hashsmith does not run")
	}
	if r.iterations, err = boundedPositiveInt(f[2], "PGP Disk iteration count", 1<<24); err != nil {
		return r, err
	}
	if r.salt, err = decodeExactHex(f[3], 16, "PGP Disk salt"); err != nil {
		return r, err
	}
	if r.verifier, err = decodeExactHex(f[4], 16, "PGP Disk verifier"); err != nil {
		return r, err
	}
	return r, nil
}

// pgpDiskKDF produces keyLen bytes. The output buffer is a whole number of
// SHA-1 blocks because the last block is written in full even when fewer bytes
// are wanted — a detail that matters only in that the buffer must be large
// enough for it.
func pgpDiskKDF(password string, salt []byte, saltLen, iterations, keyLen int) []byte {
	key := make([]byte, ((keyLen+sha1.Size-1)/sha1.Size)*sha1.Size)
	pw := []byte(password)
	needed, offset := keyLen, 0
	for needed > 0 {
		thisTime := sha1.Size
		if needed < thisTime {
			thisTime = needed
		}
		seed := sha1.New()
		if offset > 0 {
			// Each block after the first is chained to the first, not to its
			// immediate predecessor.
			_, _ = seed.Write(key[:sha1.Size])
		}
		_, _ = seed.Write(pw)
		hash := seed.Sum(nil)

		h := sha1.New()
		_, _ = h.Write(salt[:saltLen])
		for j := 0; j < iterations; j++ {
			_, _ = h.Write(hash[:thisTime])
			_, _ = h.Write([]byte{byte(j)})
		}
		copy(key[offset:], h.Sum(nil))

		needed -= thisTime
		offset += thisTime
	}
	return key[:keyLen]
}

func verifyPGPDisk(target, candidate string) (bool, error) {
	r, err := pgpDiskFields(target)
	if err != nil {
		return false, err
	}
	var got [16]byte
	switch r.algorithm {
	case 3:
		key := pgpDiskKDF(candidate, r.salt, 8, r.iterations, 16)
		c, err := cast5.NewCipher(key)
		if err != nil {
			return false, err
		}
		// CAST5's block is eight bytes, so only half the verifier is written
		// and the rest stays zero — which is what John compares against too.
		c.Encrypt(got[:8], key[:8])
	case 4:
		key := pgpDiskKDF(candidate, r.salt, 16, r.iterations, 32)
		c, err := twofish.NewCipher(key)
		if err != nil {
			return false, err
		}
		c.Encrypt(got[:], key[:16])
	default:
		key := pgpDiskKDF(candidate, r.salt, 16, r.iterations, 32)
		c, err := aes.NewCipher(key)
		if err != nil {
			return false, err
		}
		c.Encrypt(got[:], key[:16])
	}
	return hmac.Equal(got[:], r.verifier), nil
}

func isPGPDisk(target string) bool {
	_, err := pgpDiskFields(target)
	return err == nil
}
