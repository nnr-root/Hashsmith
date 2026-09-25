package smith

// pbkdf2KWalletLaneHasher implements laneHasher for KWallet's PBKDF2-HMAC-
// SHA512 shape (minor version 1, crack_kwallet.go), batching
// pbkdf2Sha512Lanes candidate passwords through the shared
// pbkdf2HMACSHA512DeriveBatch primitive. The legacy (minor 0) SHA-1 chain
// is not PBKDF2 at all and is not accelerated here.
type pbkdf2KWalletLaneHasher struct {
	rec kwalletRecord
}

// newPBKDF2KWalletLaneHasher parses targetHash via the same kwalletFields
// verifyKWallet uses, returning nil (caller falls back to the scalar path)
// for a legacy record or anything else that does not parse.
func newPBKDF2KWalletLaneHasher(targetHash string) *pbkdf2KWalletLaneHasher {
	rec, err := kwalletFields(targetHash)
	if err != nil || rec.minor != 1 {
		return nil
	}
	return &pbkdf2KWalletLaneHasher{rec: rec}
}

// Run mirrors pbkdf2Onepassword8LaneHasher.Run's shape exactly.
func (h *pbkdf2KWalletLaneHasher) Run(pw [][]byte, out []bool) {
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
			ok, err := kwalletMatches(&h.rec, derived[k][:56])
			out[i+k] = err == nil && ok
		}
		i += n
	}
}
