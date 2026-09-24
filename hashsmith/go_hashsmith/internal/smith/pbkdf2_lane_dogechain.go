package smith

// pbkdf2DogechainLaneHasher implements laneHasher for Dogechain.info wallet
// records (crack_dogechain.go), batching pbkdf2Sha256Lanes candidate
// passwords through the shared pbkdf2HMACSHA256DeriveBatch primitive —
// the same core pbkdf2Sha256LaneHasher and pbkdf2Onepassword8LaneHasher
// use.
//
// The one wrinkle relative to 1Password 8: Dogechain's PBKDF2 password is
// not the candidate itself but dogechainPasswordText(candidate) — a
// per-candidate transform (SHA-256, then base64) that depends only on the
// candidate, never on the target record. That transform runs once per
// lane before the batch call, exactly where the scalar verifyDogechain
// already ran it inline; nothing about it needs to be — or can be —
// batched itself, since it is one hash operation per candidate, not
// thousands of PBKDF2 iterations.
type pbkdf2DogechainLaneHasher struct {
	rec dogechainRecord
}

// newPBKDF2DogechainLaneHasher parses targetHash via the same
// parseDogechainRecord verifyDogechain uses, returning nil (caller falls
// back to the scalar path) for anything that does not parse.
func newPBKDF2DogechainLaneHasher(targetHash string) *pbkdf2DogechainLaneHasher {
	rec, err := parseDogechainRecord(targetHash)
	if err != nil {
		return nil
	}
	return &pbkdf2DogechainLaneHasher{rec: rec}
}

// Run mirrors pbkdf2Onepassword8LaneHasher.Run's shape exactly, with the
// one addition of the per-lane password transform before batching.
func (h *pbkdf2DogechainLaneHasher) Run(pw [][]byte, out []bool) {
	i := 0
	for i < len(pw) {
		n := len(pw) - i
		if n > pbkdf2Sha256Lanes {
			n = pbkdf2Sha256Lanes
		}
		var lanes [pbkdf2Sha256Lanes][]byte
		for k := 0; k < n; k++ {
			lanes[k] = []byte(dogechainPasswordText(string(pw[i+k])))
		}
		for k := n; k < pbkdf2Sha256Lanes; k++ {
			lanes[k] = lanes[n-1]
		}
		derived := pbkdf2HMACSHA256DeriveBatch(&lanes, h.rec.salt, h.rec.iter)
		for k := 0; k < n; k++ {
			ok, err := dogechainDecrypts(&h.rec, derived[k][:])
			out[i+k] = err == nil && ok
		}
		i += n
	}
}
