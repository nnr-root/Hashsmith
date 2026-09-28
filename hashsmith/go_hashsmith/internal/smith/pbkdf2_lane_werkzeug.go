package smith

// pbkdf2WerkzeugLaneHasher implements laneHasher for Werkzeug's
// "pbkdf2:sha256:..." records (crack_frameworks.go), batching
// pbkdf2Sha256Lanes candidate passwords through the shared
// pbkdf2HMACSHA256DeriveBatch primitive. Every other Werkzeug method
// (other PBKDF2 digests, scrypt, the legacy bare-HMAC methods) is not
// accelerated here — parseWerkzeugPBKDF2SHA256 refuses them, so they fall
// back to the scalar path, which already handles all of them.
type pbkdf2WerkzeugLaneHasher struct {
	rec werkzeugPBKDF2SHA256Record
}

// newPBKDF2WerkzeugLaneHasher parses targetHash via the same
// parseWerkzeugPBKDF2SHA256 verifyWerkzeug's pbkdf2-sha256 case reaches,
// returning nil (caller falls back to the scalar path) for anything else.
func newPBKDF2WerkzeugLaneHasher(targetHash string) *pbkdf2WerkzeugLaneHasher {
	rec, err := parseWerkzeugPBKDF2SHA256(targetHash)
	if err != nil {
		return nil
	}
	return &pbkdf2WerkzeugLaneHasher{rec: rec}
}

// Run mirrors pbkdf2Onepassword8LaneHasher.Run's shape exactly.
func (h *pbkdf2WerkzeugLaneHasher) Run(pw [][]byte, out []bool) {
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
