package smith

import "github.com/xdg-go/stringprep"

// pbkdf2MongoDBSCRAM256LaneHasher implements laneHasher for MongoDB's
// SCRAM-SHA-256 records (versions 1 and 2, crack_mongodb.go), batching
// pbkdf2Sha256Lanes candidate passwords through the shared
// pbkdf2HMACSHA256DeriveBatch primitive. The legacy MONGODB-CR and
// SCRAM-SHA-1 shapes are not accelerated here — parseMongoDBSCRAM256
// refuses them, so they fall back to the scalar path.
//
// SASLprep (RFC 4013) runs once per lane before the batch call, exactly
// where the scalar verifyMongoDB already runs it inline — a per-candidate
// normalization, not a KDF input, so it cannot itself be batched, only the
// PBKDF2 that follows it. A candidate SASLprep rejects (invalid UTF-8, a
// prohibited codepoint) can never be the right password, so it is marked
// as no match without being fed into the batch at all.
type pbkdf2MongoDBSCRAM256LaneHasher struct {
	rec mongoDBSCRAM256Record
}

// newPBKDF2MongoDBSCRAM256LaneHasher parses targetHash via the same
// parseMongoDBSCRAM256 verifyMongoDB's SCRAM-SHA-256 case reaches,
// returning nil (caller falls back to the scalar path) for anything else.
func newPBKDF2MongoDBSCRAM256LaneHasher(targetHash string) *pbkdf2MongoDBSCRAM256LaneHasher {
	rec, err := parseMongoDBSCRAM256(targetHash)
	if err != nil {
		return nil
	}
	return &pbkdf2MongoDBSCRAM256LaneHasher{rec: rec}
}

// Run mirrors pbkdf2DogechainLaneHasher.Run's shape — a per-lane
// pre-transform, then a shared-salt batch — except a transform failure
// here (SASLprep, not always total) marks its lane a non-match instead of
// being applied unconditionally.
func (h *pbkdf2MongoDBSCRAM256LaneHasher) Run(pw [][]byte, out []bool) {
	i := 0
	for i < len(pw) {
		n := len(pw) - i
		if n > pbkdf2Sha256Lanes {
			n = pbkdf2Sha256Lanes
		}
		var lanes [pbkdf2Sha256Lanes][]byte
		var saslFailed [pbkdf2Sha256Lanes]bool
		for k := 0; k < n; k++ {
			prepared, err := stringprep.SASLprep.Prepare(string(pw[i+k]))
			if err != nil {
				saslFailed[k] = true
				lanes[k] = pw[i+k] // placeholder; this lane's result is discarded below
				continue
			}
			lanes[k] = []byte(prepared)
		}
		for k := n; k < pbkdf2Sha256Lanes; k++ {
			lanes[k] = lanes[n-1]
		}
		derived := pbkdf2HMACSHA256DeriveBatch(&lanes, h.rec.salt, h.rec.iter)
		for k := 0; k < n; k++ {
			if saslFailed[k] {
				out[i+k] = false
				continue
			}
			out[i+k] = mongoDBSCRAM256Matches(&h.rec, derived[k][:])
		}
		i += n
	}
}
