package smith

// pbkdf2PadlockLaneHasher implements laneHasher for Padlock vault records
// (crack_padlock.go), batching pbkdf2Sha256Lanes candidate passwords
// through the shared pbkdf2HMACSHA256DeriveBatch primitive.
type pbkdf2PadlockLaneHasher struct {
	rec padlockRecord
}

// newPBKDF2PadlockLaneHasher parses targetHash via the same padlockFields
// verifyPadlock uses, returning nil (caller falls back to the scalar path)
// for anything that does not parse as a valid record.
func newPBKDF2PadlockLaneHasher(targetHash string) *pbkdf2PadlockLaneHasher {
	rec, err := padlockFields(targetHash)
	if err != nil {
		return nil
	}
	return &pbkdf2PadlockLaneHasher{rec: rec}
}

// Run mirrors pbkdf2Onepassword8LaneHasher.Run's shape exactly.
func (h *pbkdf2PadlockLaneHasher) Run(pw [][]byte, out []bool) {
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
			ok, err := padlockDecrypts(&h.rec, derived[k][:])
			out[i+k] = err == nil && ok
		}
		i += n
	}
}
