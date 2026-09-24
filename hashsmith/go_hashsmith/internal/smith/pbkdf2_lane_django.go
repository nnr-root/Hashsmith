package smith

// pbkdf2DjangoLaneHasher implements laneHasher for Django's pbkdf2_sha256
// password records (crack_django.go), batching pbkdf2Sha256Lanes candidate
// passwords through the shared pbkdf2HMACSHA256DeriveBatch primitive. A
// pbkdf2_sha1 (or any other Django algorithm) record is not accelerated
// here — parseDjangoPBKDF2SHA256Record refuses it, so it falls back to the
// scalar path, which already handles every Django variant.
type pbkdf2DjangoLaneHasher struct {
	rec djangoPBKDF2SHA256Record
}

// newPBKDF2DjangoLaneHasher parses targetHash via the same
// parseDjangoPBKDF2SHA256Record verifyDjangoPBKDF2's own sha256 case uses,
// returning nil (caller falls back to the scalar path) for anything that is
// not a pbkdf2_sha256 record.
func newPBKDF2DjangoLaneHasher(targetHash string) *pbkdf2DjangoLaneHasher {
	rec, err := parseDjangoPBKDF2SHA256Record(targetHash)
	if err != nil {
		return nil
	}
	return &pbkdf2DjangoLaneHasher{rec: rec}
}

// Run mirrors pbkdf2Onepassword8LaneHasher.Run's shape exactly.
func (h *pbkdf2DjangoLaneHasher) Run(pw [][]byte, out []bool) {
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
		derived := pbkdf2HMACSHA256DeriveBatch(&lanes, h.rec.salt, h.rec.iter)
		for k := 0; k < n; k++ {
			out[i+k] = bytesEqualCT(derived[k][:], h.rec.want)
		}
		i += n
	}
}
