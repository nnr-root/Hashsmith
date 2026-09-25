package smith

import (
	"crypto/sha512"
	"encoding/hex"
	"strconv"
	"strings"
)

// pbkdf2TelegramDesktopV2LaneHasher implements laneHasher for Telegram
// Desktop's version-2 "$telegram$2*..." records (crack_john_mobile.go).
// Version 1 uses SHA-1 and is not wired here.
//
// The PBKDF2 password is not the candidate itself but
// SHA-512(salt||candidate||salt) — a per-candidate transform applied once
// per lane before the batch call, the same shape AzureSync and Mozilla's
// transforms already use. The derived key is 136 bytes, needing three
// SHA-512 blocks, so this is the second wired user of
// pbkdf2HMACSHA512DeriveBatchN after DiskCryptor. telegramCheckPassword
// itself (the post-PBKDF2 check) is untouched and already stood alone, so
// no extraction was needed there.
type pbkdf2TelegramDesktopV2LaneHasher struct {
	salt []byte
	iter int
	blob []byte
}

// newPBKDF2TelegramDesktopV2LaneHasher parses targetHash with a second,
// independent, narrower parser from verifyTelegramDesktop's own — it
// accepts only version "2" and applies the identical field validation,
// relying on the lane-vs-scalar parity test to catch any drift instead of
// sharing code with a function that also has to handle version "1"'s
// different hash.
func newPBKDF2TelegramDesktopV2LaneHasher(targetHash string) *pbkdf2TelegramDesktopV2LaneHasher {
	if !strings.HasPrefix(targetHash, "$telegram$") {
		return nil
	}
	f := strings.Split(strings.TrimPrefix(targetHash, "$telegram$"), "*")
	if len(f) != 4 || f[0] != "2" {
		return nil
	}
	iterations, err := strconv.Atoi(f[1])
	if err != nil || iterations < 1 || iterations > maxKDFIterations {
		return nil
	}
	salt, e1 := hex.DecodeString(f[2])
	blob, e2 := hex.DecodeString(f[3])
	if e1 != nil || e2 != nil || len(salt) == 0 || len(salt) > 64 || len(blob) < 32 ||
		len(blob) > 4096 || (len(blob)-16)%16 != 0 {
		return nil
	}
	return &pbkdf2TelegramDesktopV2LaneHasher{salt: salt, iter: iterations, blob: blob}
}

// Run mirrors pbkdf2DiskCryptorLaneHasher.Run's shape: a per-lane password
// transform, a multi-block batch call, then a per-lane scalar check
// (telegramCheckPassword) against the shared blob.
func (h *pbkdf2TelegramDesktopV2LaneHasher) Run(pw [][]byte, out []bool) {
	i := 0
	for i < len(pw) {
		n := len(pw) - i
		if n > pbkdf2Sha512Lanes {
			n = pbkdf2Sha512Lanes
		}
		var lanes [pbkdf2Sha512Lanes][]byte
		for k := 0; k < n; k++ {
			lanes[k] = telegramDesktopV2Password(h.salt, pw[i+k])
		}
		for k := n; k < pbkdf2Sha512Lanes; k++ {
			lanes[k] = lanes[n-1]
		}
		authKeys := pbkdf2HMACSHA512DeriveBatchN(&lanes, h.salt, h.iter, 136)
		for k := 0; k < n; k++ {
			out[i+k] = telegramCheckPassword(authKeys[k], h.blob)
		}
		i += n
	}
}

// telegramDesktopV2Password computes SHA-512(salt||candidate||salt) —
// version 2's PBKDF2 password — matching verifyTelegramDesktop's inline
// computation exactly.
func telegramDesktopV2Password(salt, candidate []byte) []byte {
	preimage := make([]byte, 0, len(salt)*2+len(candidate))
	preimage = append(preimage, salt...)
	preimage = append(preimage, candidate...)
	preimage = append(preimage, salt...)
	first := sha512.Sum512(preimage)
	return first[:]
}
