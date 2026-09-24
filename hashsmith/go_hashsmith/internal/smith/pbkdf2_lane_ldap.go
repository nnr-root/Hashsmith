package smith

// pbkdf2RedHat389LaneHasher implements laneHasher for Red Hat / 389
// Directory Server's PBKDF2_SHA256 password scheme (crack_ldap_pbkdf2.go),
// batching pbkdf2Sha256Lanes candidate passwords through
// pbkdf2HMACSHA256DeriveBatchN — the multi-block primitive, since the
// stored digest here is 256 bytes, eight SHA-256 blocks.
type pbkdf2RedHat389LaneHasher struct {
	rec *redHat389Hash
}

// newPBKDF2RedHat389LaneHasher parses targetHash via the same
// parseRedHat389PBKDF2 verifyRedHat389PBKDF2 uses, returning nil (caller
// falls back to the scalar path) for anything that does not parse.
func newPBKDF2RedHat389LaneHasher(targetHash string) *pbkdf2RedHat389LaneHasher {
	rec, err := parseRedHat389PBKDF2(targetHash)
	if err != nil {
		return nil
	}
	return &pbkdf2RedHat389LaneHasher{rec: rec}
}

// Run mirrors pbkdf2AnsibleLaneHasher.Run's shape exactly, another
// multi-block-primitive user.
func (h *pbkdf2RedHat389LaneHasher) Run(pw [][]byte, out []bool) {
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
		derived := pbkdf2HMACSHA256DeriveBatchN(&lanes, h.rec.salt, h.rec.iterations, len(h.rec.digest))
		for k := 0; k < n; k++ {
			out[i+k] = redHat389Matches(h.rec, derived[k])
		}
		i += n
	}
}
