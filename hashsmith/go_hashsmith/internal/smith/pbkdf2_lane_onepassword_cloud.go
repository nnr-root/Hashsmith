package smith

// pbkdf2OnePasswordCloudLaneHasher implements laneHasher for 1Password's
// cloud keychain format (crack_onepassword_cloud.go), batching
// pbkdf2Sha512Lanes candidate passwords through the shared
// pbkdf2HMACSHA512DeriveBatch primitive — the derived key here is exactly
// 64 bytes, one SHA-512 block.
type pbkdf2OnePasswordCloudLaneHasher struct {
	rec *onePasswordCloudRecord
}

// newPBKDF2OnePasswordCloudLaneHasher parses targetHash via the same
// parseOnePasswordCloud verifyOnePasswordCloud uses, returning nil (caller
// falls back to the scalar path) for anything that does not parse.
func newPBKDF2OnePasswordCloudLaneHasher(targetHash string) *pbkdf2OnePasswordCloudLaneHasher {
	rec, err := parseOnePasswordCloud(targetHash)
	if err != nil {
		return nil
	}
	return &pbkdf2OnePasswordCloudLaneHasher{rec: rec}
}

// Run mirrors pbkdf2Onepassword8LaneHasher.Run's shape exactly.
func (h *pbkdf2OnePasswordCloudLaneHasher) Run(pw [][]byte, out []bool) {
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
		derived := pbkdf2HMACSHA512DeriveBatch(&lanes, h.rec.salt, h.rec.iterations)
		for k := 0; k < n; k++ {
			out[i+k] = onePasswordCloudMatches(h.rec, derived[k][:])
		}
		i += n
	}
}
