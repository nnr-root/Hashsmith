package smith

// pbkdf2Oracle12cLaneHasher implements laneHasher for Oracle 12c "T:"
// verifiers (crack_oracle.go), batching pbkdf2Sha512Lanes candidate
// passwords through the shared pbkdf2HMACSHA512DeriveBatch primitive. The
// PBKDF2 salt is the record's own 16-byte salt with a fixed suffix
// appended — computed once at parse time, same shared value for every
// lane in the batch, exactly like any other fixed-salt format here.
type pbkdf2Oracle12cLaneHasher struct {
	rec oracle12cRecord
}

// newPBKDF2Oracle12cLaneHasher parses targetHash via the same
// parseOracle12c verifyOracle12c uses, returning nil (caller falls back to
// the scalar path) for anything that does not parse.
func newPBKDF2Oracle12cLaneHasher(targetHash string) *pbkdf2Oracle12cLaneHasher {
	rec, err := parseOracle12c(targetHash)
	if err != nil {
		return nil
	}
	return &pbkdf2Oracle12cLaneHasher{rec: rec}
}

// Run mirrors pbkdf2Cisco8LaneHasher.Run's shape exactly.
func (h *pbkdf2Oracle12cLaneHasher) Run(pw [][]byte, out []bool) {
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
		derived := pbkdf2HMACSHA512DeriveBatch(&lanes, h.rec.pbkdf2Salt, oracle12cIterations)
		for k := 0; k < n; k++ {
			out[i+k] = oracle12cMatches(&h.rec, derived[k][:])
		}
		i += n
	}
}
