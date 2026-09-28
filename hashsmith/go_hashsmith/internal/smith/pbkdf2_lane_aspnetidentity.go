package smith

// pbkdf2ASPNetIdentityLaneHasher implements laneHasher for ASP.NET
// Identity v3 records whose PRF is SHA-256 and whose subkey fits in one
// PBKDF2 block (crack_frameworks.go), batching pbkdf2Sha256Lanes candidate
// passwords through the shared pbkdf2HMACSHA256DeriveBatch primitive. v2
// records (fixed SHA-1), v3's SHA-1/SHA-512 PRFs, and any v3 subkey longer
// than 32 bytes are not accelerated here — parseASPNetIdentitySHA256
// refuses them, so they fall back to the scalar path.
type pbkdf2ASPNetIdentityLaneHasher struct {
	rec aspNetIdentitySHA256Record
}

// newPBKDF2ASPNetIdentityLaneHasher parses targetHash via the same
// parseASPNetIdentitySHA256 verifyASPNetIdentity's v3/SHA-256 case reaches,
// returning nil (caller falls back to the scalar path) for anything else.
func newPBKDF2ASPNetIdentityLaneHasher(targetHash string) *pbkdf2ASPNetIdentityLaneHasher {
	rec, err := parseASPNetIdentitySHA256(targetHash)
	if err != nil {
		return nil
	}
	return &pbkdf2ASPNetIdentityLaneHasher{rec: rec}
}

// Run mirrors pbkdf2Onepassword8LaneHasher.Run's shape, except the compare
// is against a subkey that may be shorter than the batch primitive's full
// 32-byte output — PBKDF2 truncates rather than recomputing for a shorter
// dkLen, so the first len(digest) bytes of the full-length output are the
// same bytes a shorter request would have produced.
func (h *pbkdf2ASPNetIdentityLaneHasher) Run(pw [][]byte, out []bool) {
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
		derived := pbkdf2HMACSHA256DeriveBatch(&lanes, h.rec.salt, h.rec.iterations)
		for k := 0; k < n; k++ {
			out[i+k] = bytesEqualCT(derived[k][:len(h.rec.digest)], h.rec.digest)
		}
		i += n
	}
}
