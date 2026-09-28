package smith

import (
	"crypto/sha512"
	"hash"
	"reflect"
)

// isSHA512HashFunc reports whether f is crypto/sha512.New. vdiRecord
// stores its hash constructor as a func() hash.Hash (parseVDI dispatches
// on the record's own "sha256"/"sha512" field), and function values are
// only comparable to nil in Go, so identity is checked through reflect —
// the same technique any code distinguishing two possible hash.Hash
// constructors from one another needs.
func isSHA512HashFunc(f func() hash.Hash) bool {
	return reflect.ValueOf(f).Pointer() == reflect.ValueOf(sha512.New).Pointer()
}

// pbkdf2VDILaneHasher implements laneHasher for VirtualBox disk images'
// "$vdi$" records (crack_vdi.go) — a different format from the $vbox$
// records pbkdf2VirtualBoxLaneHasher already handles, sharing only the
// two-stage PBKDF2-then-XTS-then-PBKDF2 shape. Only the SHA-512 digest
// variant is wired here (r.newHash gates it); SHA-256 falls back to the
// scalar path via pbkdf2Sha256AVX2Eligible's own separate PBKDF2-SHA256
// dispatch, which this format does not currently use since VDI's SHA-256
// records were not part of this survey.
//
// Both stages fit a single SHA-512 block: keyLen is 32 or 64 bytes, and
// digestLen is at most 64, so this needs no multi-block primitive, unlike
// DiskCryptor and Telegram Desktop v2. decryptXTSZeroTweak already
// supports both AES-XTS key widths VDI uses and already decrypts at data
// unit number 0, matching verifyVDI's own c.Decrypt(dek, r.encKey, 0) —
// it needed no changes to be reused here.
type pbkdf2VDILaneHasher struct {
	rec *vdiRecord
}

// newPBKDF2VDILaneHasher parses targetHash via the same parseVDI verifyVDI
// uses, returning nil when the record does not parse or names a digest
// other than SHA-512.
func newPBKDF2VDILaneHasher(targetHash string) *pbkdf2VDILaneHasher {
	rec, err := parseVDI(targetHash)
	if err != nil || !isSHA512HashFunc(rec.newHash) {
		return nil
	}
	return &pbkdf2VDILaneHasher{rec: rec}
}

// Run derives the first-stage key for a batch of candidates, XTS-decrypts
// the stored encrypted data-encryption key per lane with it, then derives
// the second-stage key for that batch of (per-lane-different) results and
// compares each against the stored final hash — the same three-step shape
// pbkdf2VirtualBoxLaneHasher.Run uses for $vbox$ records.
func (h *pbkdf2VDILaneHasher) Run(pw [][]byte, out []bool) {
	i := 0
	for i < len(pw) {
		n := len(pw) - i
		if n > pbkdf2Sha512Lanes {
			n = pbkdf2Sha512Lanes
		}
		var lanes [pbkdf2Sha512Lanes][]byte
		for k := 0; k < n; k++ {
			lanes[k] = pw[i+k]
		}
		for k := n; k < pbkdf2Sha512Lanes; k++ {
			lanes[k] = lanes[n-1]
		}
		stage1 := pbkdf2HMACSHA512DeriveBatch(&lanes, h.rec.keySalt, h.rec.keyIter)

		var stage2Lanes [pbkdf2Sha512Lanes][]byte
		for k := 0; k < pbkdf2Sha512Lanes; k++ {
			plain, err := decryptXTSZeroTweak(stage1[k][:h.rec.keyLen], h.rec.encKey)
			if err != nil {
				plain = make([]byte, h.rec.keyLen)
			}
			stage2Lanes[k] = plain
		}
		stage2 := pbkdf2HMACSHA512DeriveBatch(&stage2Lanes, h.rec.endSalt, h.rec.endIter)
		for k := 0; k < n; k++ {
			out[i+k] = bytesEqualCT(stage2[k][:len(h.rec.want)], h.rec.want)
		}
		i += n
	}
}
