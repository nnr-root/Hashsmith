package smith

// pbkdf2CitrixPBKDF2LaneHasher implements laneHasher for Citrix NetScaler's
// PBKDF2 record shape (crack_hashcat_vendor_records.go), batching
// pbkdf2Sha256Lanes candidate passwords through the shared
// pbkdf2HMACSHA256DeriveBatch primitive.
type pbkdf2CitrixPBKDF2LaneHasher struct {
	salt []byte
	want []byte
}

// newPBKDF2CitrixPBKDF2LaneHasher parses targetHash via the same
// parseCitrixPBKDF2 verifyCitrixPBKDF2 uses, returning nil (caller falls
// back to the scalar path) for anything that does not parse.
func newPBKDF2CitrixPBKDF2LaneHasher(targetHash string) *pbkdf2CitrixPBKDF2LaneHasher {
	salt, want, err := parseCitrixPBKDF2(targetHash)
	if err != nil {
		return nil
	}
	return &pbkdf2CitrixPBKDF2LaneHasher{salt: salt, want: want}
}

// Run mirrors pbkdf2Cisco8LaneHasher.Run's shape exactly.
func (h *pbkdf2CitrixPBKDF2LaneHasher) Run(pw [][]byte, out []bool) {
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
		derived := pbkdf2HMACSHA256DeriveBatch(&lanes, h.salt, citrixPBKDF2Iterations)
		for k := 0; k < n; k++ {
			out[i+k] = bytesEqualCT(derived[k][:], h.want)
		}
		i += n
	}
}
