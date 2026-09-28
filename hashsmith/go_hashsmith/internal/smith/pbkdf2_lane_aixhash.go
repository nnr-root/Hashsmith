package smith

// pbkdf2AIXLaneHasher implements laneHasher for AIX's {ssha256} password
// records (crack_aixhash.go), batching pbkdf2Sha256Lanes candidate
// passwords through the shared pbkdf2HMACSHA256DeriveBatch primitive. The
// {smd5}/{ssha1}/{ssha512} variants are not accelerated here —
// parseAIXSHA256Record refuses them, so they fall back to the scalar path,
// which already handles all four.
type pbkdf2AIXLaneHasher struct {
	rec aixSHA256Record
}

// newPBKDF2AIXLaneHasher parses targetHash via the same parseAIXSHA256Record
// verifyAIX's own {ssha256} case uses, returning nil (caller falls back to
// the scalar path) for anything that is not an {ssha256} record.
func newPBKDF2AIXLaneHasher(targetHash string) *pbkdf2AIXLaneHasher {
	rec, err := parseAIXSHA256Record(targetHash)
	if err != nil {
		return nil
	}
	return &pbkdf2AIXLaneHasher{rec: rec}
}

// Run mirrors pbkdf2Onepassword8LaneHasher.Run's shape exactly.
func (h *pbkdf2AIXLaneHasher) Run(pw [][]byte, out []bool) {
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
		derived := pbkdf2HMACSHA256DeriveBatch(&lanes, []byte(h.rec.salt), h.rec.iterations)
		for k := 0; k < n; k++ {
			out[i+k] = aixMatches(derived[k][:], h.rec.want)
		}
		i += n
	}
}
