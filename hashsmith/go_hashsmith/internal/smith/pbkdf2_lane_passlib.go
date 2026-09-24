package smith

// pbkdf2PasslibLaneHasher implements laneHasher for Passlib's
// $pbkdf2-sha256$ records (crack_frameworks.go), batching pbkdf2Sha256Lanes
// candidate passwords through the shared pbkdf2HMACSHA256DeriveBatch
// primitive. The sha1/sha512 variants are not accelerated here —
// parsePasslibPBKDF2SHA256 refuses them, so they fall back to the scalar
// path, which already handles all three.
type pbkdf2PasslibLaneHasher struct {
	rec passlibPBKDF2SHA256Record
}

// newPBKDF2PasslibLaneHasher parses targetHash via the same
// parsePasslibPBKDF2SHA256 verifyPasslibPBKDF2's sha256 case reaches,
// returning nil (caller falls back to the scalar path) for anything that is
// not a $pbkdf2-sha256$ record.
func newPBKDF2PasslibLaneHasher(targetHash string) *pbkdf2PasslibLaneHasher {
	rec, err := parsePasslibPBKDF2SHA256(targetHash)
	if err != nil {
		return nil
	}
	return &pbkdf2PasslibLaneHasher{rec: rec}
}

// Run mirrors pbkdf2Onepassword8LaneHasher.Run's shape exactly.
func (h *pbkdf2PasslibLaneHasher) Run(pw [][]byte, out []bool) {
	i := 0
	for i < len(pw) {
		n := len(pw) - i
		if n > pbkdf2Sha256Lanes {
			n = pbkdf2Sha256Lanes
		}
		var lanes [pbkdf2Sha256Lanes][]byte
		for k := 0; k < n; k++ {
			lanes[k] = pw[i+k]
		}
		for k := n; k < pbkdf2Sha256Lanes; k++ {
			lanes[k] = lanes[n-1]
		}
		derived := pbkdf2HMACSHA256DeriveBatch(&lanes, h.rec.salt, h.rec.rounds)
		for k := 0; k < n; k++ {
			out[i+k] = bytesEqualCT(derived[k][:], h.rec.digest)
		}
		i += n
	}
}
