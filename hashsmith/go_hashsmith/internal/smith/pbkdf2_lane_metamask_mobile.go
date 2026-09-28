package smith

// pbkdf2MetaMaskMobileLaneHasher implements laneHasher for MetaMask
// Mobile wallet records (crack_metamask_mobile.go), batching
// pbkdf2Sha512Lanes candidate passwords through the shared
// pbkdf2HMACSHA512DeriveBatch primitive.
type pbkdf2MetaMaskMobileLaneHasher struct {
	rec *metamaskMobileRecord
}

// newPBKDF2MetaMaskMobileLaneHasher parses targetHash via the same
// parseMetaMaskMobile verifyMetaMaskMobile uses, returning nil (caller
// falls back to the scalar path) for anything that does not parse.
func newPBKDF2MetaMaskMobileLaneHasher(targetHash string) *pbkdf2MetaMaskMobileLaneHasher {
	rec, err := parseMetaMaskMobile(targetHash)
	if err != nil {
		return nil
	}
	return &pbkdf2MetaMaskMobileLaneHasher{rec: rec}
}

// Run mirrors pbkdf2Onepassword8LaneHasher.Run's shape exactly.
func (h *pbkdf2MetaMaskMobileLaneHasher) Run(pw [][]byte, out []bool) {
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
		derived := pbkdf2HMACSHA512DeriveBatch(&lanes, h.rec.salt, metamaskMobileIterations)
		for k := 0; k < n; k++ {
			ok, err := metamaskMobileMatches(h.rec, derived[k][:32])
			out[i+k] = err == nil && ok
		}
		i += n
	}
}
