package smith

// pbkdf2ScramLaneHasher implements laneHasher for PostgreSQL
// SCRAM-SHA-256 records (crack_misc.go), batching pbkdf2Sha256Lanes
// candidate passwords through the shared pbkdf2HMACSHA256DeriveBatch
// primitive.
type pbkdf2ScramLaneHasher struct {
	rec scramRecord
}

// newPBKDF2ScramLaneHasher parses targetHash via the same parseSCRAM
// verifySCRAM uses, returning nil (caller falls back to the scalar path)
// for anything that does not parse as a valid record.
func newPBKDF2ScramLaneHasher(targetHash string) *pbkdf2ScramLaneHasher {
	rec, err := parseSCRAM(targetHash)
	if err != nil {
		return nil
	}
	return &pbkdf2ScramLaneHasher{rec: rec}
}

// Run mirrors pbkdf2Onepassword8LaneHasher.Run's shape exactly.
func (h *pbkdf2ScramLaneHasher) Run(pw [][]byte, out []bool) {
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
		derived := pbkdf2HMACSHA256DeriveBatch(&lanes, h.rec.salt, h.rec.iter)
		for k := 0; k < n; k++ {
			out[i+k] = scramMatches(derived[k][:], h.rec.storedKey)
		}
		i += n
	}
}
