package smith

// pbkdf2AndroidSamsungFDELaneHasher implements laneHasher for Samsung's
// Android full-disk-encryption records, Hashcat mode 12900
// (crack_android_fde.go), batching pbkdf2Sha256Lanes candidate passwords
// through the shared pbkdf2HMACSHA256DeriveBatch primitive.
type pbkdf2AndroidSamsungFDELaneHasher struct {
	rec androidSamsungFDERecord
}

// newPBKDF2AndroidSamsungFDELaneHasher parses targetHash via the same
// parseAndroidSamsungFDERecord verifyAndroidSamsungFDE uses, returning nil
// (caller falls back to the scalar path) for anything that does not parse
// as a valid 160-character hex record.
func newPBKDF2AndroidSamsungFDELaneHasher(targetHash string) *pbkdf2AndroidSamsungFDELaneHasher {
	rec, err := parseAndroidSamsungFDERecord(targetHash)
	if err != nil {
		return nil
	}
	return &pbkdf2AndroidSamsungFDELaneHasher{rec: rec}
}

// Run mirrors pbkdf2Onepassword8LaneHasher.Run's shape exactly.
func (h *pbkdf2AndroidSamsungFDELaneHasher) Run(pw [][]byte, out []bool) {
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
		derived := pbkdf2HMACSHA256DeriveBatch(&lanes, h.rec.salt, androidSamsungIterations)
		for k := 0; k < n; k++ {
			out[i+k] = androidSamsungFDEMatches(derived[k][:], &h.rec)
		}
		i += n
	}
}
