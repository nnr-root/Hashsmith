package smith

// pbkdf2LastpassLPLaneHasher and pbkdf2LastpassCLILaneHasher implement
// laneHasher for LastPass's two client formats (crack_lastpass.go), both
// batching pbkdf2Sha256Lanes candidate passwords through the shared
// pbkdf2HMACSHA256DeriveBatch primitive, salted by the account's email
// address rather than a random per-record salt.

type pbkdf2LastpassLPLaneHasher struct {
	rec lastpassRecord
}

// newPBKDF2LastpassLPLaneHasher parses targetHash via the same
// lastpassLPFields verifyLastPassLP uses, returning nil (caller falls back
// to the scalar path) for anything that does not parse as a valid record.
// Unlike the CLI variant below, the extension format has no
// non-PBKDF2 iteration-count special case to refuse.
func newPBKDF2LastpassLPLaneHasher(targetHash string) *pbkdf2LastpassLPLaneHasher {
	rec, err := lastpassLPFields(targetHash)
	if err != nil {
		return nil
	}
	return &pbkdf2LastpassLPLaneHasher{rec: rec}
}

// Run mirrors pbkdf2Onepassword8LaneHasher.Run's shape exactly.
func (h *pbkdf2LastpassLPLaneHasher) Run(pw [][]byte, out []bool) {
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
		derived := pbkdf2HMACSHA256DeriveBatch(&lanes, []byte(h.rec.email), h.rec.iterations)
		for k := 0; k < n; k++ {
			ok, err := lastpassLPMatches(&h.rec, derived[k][:])
			out[i+k] = err == nil && ok
		}
		i += n
	}
}

type pbkdf2LastpassCLILaneHasher struct {
	rec lastpassRecord
}

// newPBKDF2LastpassCLILaneHasher parses targetHash via the same
// lastpassCLIFields verifyLastPassCLI uses, then refuses (returns nil,
// falling back to the scalar path) a record whose iterations field is 1 —
// that is not PBKDF2 with a count of one, it is a plain SHA-256 of the
// email and password (see verifyLastPassCLI's own comment), a different
// function the batched PBKDF2 primitive cannot compute.
func newPBKDF2LastpassCLILaneHasher(targetHash string) *pbkdf2LastpassCLILaneHasher {
	rec, err := lastpassCLIFields(targetHash)
	if err != nil || rec.iterations == 1 {
		return nil
	}
	return &pbkdf2LastpassCLILaneHasher{rec: rec}
}

// Run mirrors pbkdf2Onepassword8LaneHasher.Run's shape exactly.
func (h *pbkdf2LastpassCLILaneHasher) Run(pw [][]byte, out []bool) {
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
		derived := pbkdf2HMACSHA256DeriveBatch(&lanes, []byte(h.rec.email), h.rec.iterations)
		for k := 0; k < n; k++ {
			ok, err := lastpassCLIMatches(&h.rec, derived[k][:])
			out[i+k] = err == nil && ok
		}
		i += n
	}
}
