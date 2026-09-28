package smith

// pbkdf2StellarWalletLaneHasher implements laneHasher for Stellar wallet
// records (crack_hashcat_auth_records.go), batching pbkdf2Sha256Lanes
// candidate passwords through the shared pbkdf2HMACSHA256DeriveBatch
// primitive.
type pbkdf2StellarWalletLaneHasher struct {
	rec stellarWalletRecord
}

// newPBKDF2StellarWalletLaneHasher parses targetHash via the same
// parseStellarWallet verifyStellarWallet uses, returning nil (caller falls
// back to the scalar path) for anything that does not parse.
func newPBKDF2StellarWalletLaneHasher(targetHash string) *pbkdf2StellarWalletLaneHasher {
	rec, err := parseStellarWallet(targetHash)
	if err != nil {
		return nil
	}
	return &pbkdf2StellarWalletLaneHasher{rec: rec}
}

// Run mirrors pbkdf2Onepassword8LaneHasher.Run's shape exactly.
func (h *pbkdf2StellarWalletLaneHasher) Run(pw [][]byte, out []bool) {
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
		derived := pbkdf2HMACSHA256DeriveBatch(&lanes, h.rec.salt, stellarWalletIterations)
		for k := 0; k < n; k++ {
			ok, err := stellarWalletDecrypts(&h.rec, derived[k][:])
			out[i+k] = err == nil && ok
		}
		i += n
	}
}
