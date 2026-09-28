package smith

// pbkdf2MetaMaskLaneHasher implements laneHasher for MetaMask's long
// ($metamask$, standard AES-GCM) vault records
// (crack_hashcat_containers.go), batching pbkdf2Sha256Lanes candidate
// passwords through the shared pbkdf2HMACSHA256DeriveBatch primitive. The
// short ($metamask-short$) variant uses a non-standard CTR construction
// and is not accelerated — parseMetaMaskLong refuses it, so it falls back
// to the scalar path.
type pbkdf2MetaMaskLaneHasher struct {
	rec metaMaskLongRecord
}

// newPBKDF2MetaMaskLaneHasher parses targetHash via the same
// parseMetaMaskLong verifyMetaMask's long branch uses, returning nil
// (caller falls back to the scalar path) for a short-variant record or
// anything else that does not parse.
func newPBKDF2MetaMaskLaneHasher(targetHash string) *pbkdf2MetaMaskLaneHasher {
	rec, err := parseMetaMaskLong(targetHash)
	if err != nil {
		return nil
	}
	return &pbkdf2MetaMaskLaneHasher{rec: rec}
}

// Run mirrors pbkdf2Onepassword8LaneHasher.Run's shape exactly.
func (h *pbkdf2MetaMaskLaneHasher) Run(pw [][]byte, out []bool) {
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
		derived := pbkdf2HMACSHA256DeriveBatch(&lanes, h.rec.salt, metaMaskIterations)
		for k := 0; k < n; k++ {
			ok, err := metaMaskOpens(&h.rec, derived[k][:])
			out[i+k] = err == nil && ok
		}
		i += n
	}
}
