package smith

// pbkdf2Onepassword8LaneHasher implements laneHasher for 1Password 8's
// mobile keychain format (crack_onepassword8.go), batching
// pbkdf2Sha256Lanes candidate passwords through the shared
// pbkdf2HMACSHA256DeriveBatch primitive per call — the same core
// pbkdf2Sha256LaneHasher (pbkdf2_lane_sha256.go) uses for the generic
// "-t pbkdf2" crack type, reused here for a format-specific one.
//
// This is the first of what the design doc's own non-goals called a
// "separate, lower-risk follow-up once this core is proven": wiring the
// validated SHA-256 win into the format-specific crack_*.go files that
// call golang.org/x/crypto/pbkdf2.Key directly, rather than only the
// generic record shape. 1Password 8 is a clean first case — one PBKDF2
// call, a 32-byte (one-block) derived key, and a shared salt across every
// candidate in a batch — exactly what pbkdf2HMACSHA256DeriveBatch already
// computes; only the per-lane tail (XOR the second key in, attempt an
// AES-256-GCM open) is specific to this format, and it is cheap compared
// to the PBKDF2 iterations that dominate real records.
type pbkdf2Onepassword8LaneHasher struct {
	rec onePassword8Record
}

// newPBKDF2Onepassword8LaneHasher parses targetHash via the same
// parseOnePassword8Record verifyOnePassword8 uses — see that type's own
// comment for why sharing the parser matters — and returns nil (caller
// falls back to the scalar verifyOnePassword8) for anything that does not
// parse as a valid record.
func newPBKDF2Onepassword8LaneHasher(targetHash string) *pbkdf2Onepassword8LaneHasher {
	rec, err := parseOnePassword8Record(targetHash)
	if err != nil {
		return nil
	}
	return &pbkdf2Onepassword8LaneHasher{rec: rec}
}

// Run mirrors pbkdf2Sha256LaneHasher.Run's partial-group handling exactly
// (see that method's own comment), batching through
// pbkdf2HMACSHA256DeriveBatch and then, per lane, doing this format's own
// cheap post-processing instead of a plain byte comparison.
func (h *pbkdf2Onepassword8LaneHasher) Run(pw [][]byte, out []bool) {
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
			ok, err := onePassword8Decrypts(&h.rec, derived[k][:])
			out[i+k] = err == nil && ok
		}
		i += n
	}
}
