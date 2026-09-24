package smith

// pbkdf2Cisco8LaneHasher implements laneHasher for Cisco IOS type 8 hashes
// (crack_cisco.go), batching pbkdf2Sha256Lanes candidate passwords through
// the shared pbkdf2HMACSHA256DeriveBatch primitive — the same core
// pbkdf2Sha256LaneHasher, pbkdf2Onepassword8LaneHasher and
// pbkdf2DogechainLaneHasher use.
//
// Cisco type 8 is the simplest format wired so far: PBKDF2-HMAC-SHA256 at a
// fixed 20000 iterations, one shared salt (the literal 14-character string
// stored in the record), a 32-byte derived key, and no post-processing
// beyond re-encoding it with the crypt-64 alphabet and comparing 43
// characters — cheap next to the iterations that dominate a real record.
type pbkdf2Cisco8LaneHasher struct {
	salt string
	want string
}

// newPBKDF2Cisco8LaneHasher parses targetHash via the same parseCisco
// verifyCiscoType8 uses, returning nil (caller falls back to the scalar
// path) for anything that does not parse as a $8$ record.
func newPBKDF2Cisco8LaneHasher(targetHash string) *pbkdf2Cisco8LaneHasher {
	salt, want, err := parseCisco(targetHash, "$8$")
	if err != nil {
		return nil
	}
	return &pbkdf2Cisco8LaneHasher{salt: salt, want: want}
}

// Run mirrors pbkdf2Onepassword8LaneHasher.Run's shape exactly.
func (h *pbkdf2Cisco8LaneHasher) Run(pw [][]byte, out []bool) {
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
		derived := pbkdf2HMACSHA256DeriveBatch(&lanes, []byte(h.salt), ciscoType8Iterations)
		for k := 0; k < n; k++ {
			out[i+k] = ciscoType8Matches(derived[k][:], h.want)
		}
		i += n
	}
}
