package smith

// pbkdf2LastPassRecordsLaneHasher implements laneHasher for the "lastpass"
// type registered in crack.go (crack_hashcat_more_records.go), which itself
// covers two record spellings of the same PBKDF2-HMAC-SHA256 construction:
// John's ("$lastpass$<email>$<iterations>$<base64>") and Hashcat's own
// (mode 6800, colon-separated). Named "..._records" (not "..._lastpass") to
// avoid colliding with pbkdf2_lane_lastpass.go, which covers the unrelated
// $lp$/$lpcli$ browser-extension and CLI formats from crack_lastpass.go.
//
// Both spellings share a salt (the account email), a PBKDF2-HMAC-SHA256
// call, and a 32-byte derived key — only the final "does this key match"
// check differs, mirroring verifyLastPass's own dispatch.
type pbkdf2LastPassRecordsLaneHasher struct {
	salt []byte
	iter int
	john bool

	johnEmail string
	johnWant  []byte

	colonRec lastPassColonRecord
}

// newPBKDF2LastPassRecordsLaneHasher parses targetHash exactly as
// verifyLastPass does — John's spelling first via johnLastPassFields, else
// the colon spelling via parseLastPassColon — returning nil (caller falls
// back to the scalar path) for anything that matches neither.
func newPBKDF2LastPassRecordsLaneHasher(targetHash string) *pbkdf2LastPassRecordsLaneHasher {
	if email, iterations, want, ok := johnLastPassFields(targetHash); ok {
		return &pbkdf2LastPassRecordsLaneHasher{
			salt: []byte(email), iter: iterations, john: true,
			johnEmail: email, johnWant: want,
		}
	}
	rec, err := parseLastPassColon(targetHash)
	if err != nil {
		return nil
	}
	return &pbkdf2LastPassRecordsLaneHasher{salt: rec.salt, iter: rec.iter, colonRec: rec}
}

// Run mirrors pbkdf2Onepassword8LaneHasher.Run's shape, dispatching to
// whichever spelling's match check this record needs.
func (h *pbkdf2LastPassRecordsLaneHasher) Run(pw [][]byte, out []bool) {
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
		derived := pbkdf2HMACSHA256DeriveBatch(&lanes, h.salt, h.iter)
		for k := 0; k < n; k++ {
			var ok bool
			var err error
			if h.john {
				ok, err = lastPassJohnMatches(h.johnEmail, derived[k][:], h.johnWant)
			} else {
				ok, err = lastPassColonMatches(&h.colonRec, derived[k][:])
			}
			out[i+k] = err == nil && ok
		}
		i += n
	}
}
