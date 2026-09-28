package smith

// pbkdf2AzureSyncLaneHasher implements laneHasher for MS-AzureSync /
// Azure AD Connect password blobs (crack_vendor.go), batching
// pbkdf2Sha256Lanes candidates through the shared
// pbkdf2HMACSHA256DeriveBatch primitive.
//
// The wrinkle relative to a plain format like 1Password 8: PBKDF2's
// password is not the candidate itself but azureSyncKeyMaterial(candidate)
// — an MD4-then-hex-then-UTF16LE transform that depends only on the
// candidate, never on the target record's salt. That transform runs once
// per lane before the batch call, exactly where the scalar verifyAzureSync
// already runs it inline (see azureSyncKeyMaterial's own comment).
type pbkdf2AzureSyncLaneHasher struct {
	salt []byte
	iter int
	want []byte
}

// newPBKDF2AzureSyncLaneHasher parses targetHash via the same parseAzureSync
// verifyAzureSync uses, refusing (returning nil, caller falls back to the
// scalar path) a digest longer than one PBKDF2 block (32 bytes) — the batch
// primitive computes only single-block PBKDF2.
func newPBKDF2AzureSyncLaneHasher(targetHash string) *pbkdf2AzureSyncLaneHasher {
	salt, iter, want, err := parseAzureSync(targetHash)
	if err != nil || len(want) > 32 {
		return nil
	}
	return &pbkdf2AzureSyncLaneHasher{salt: salt, iter: iter, want: want}
}

// Run applies azureSyncKeyMaterial per lane before batching, then compares
// each lane's derived key against the stored digest (see
// pbkdf2ASPNetIdentityLaneHasher.Run's own comment for why truncating the
// batch primitive's full-length output is correct when the stored digest is
// shorter than 32 bytes).
func (h *pbkdf2AzureSyncLaneHasher) Run(pw [][]byte, out []bool) {
	i := 0
	for i < len(pw) {
		n := len(pw) - i
		if n > pbkdf2Sha256Lanes {
			n = pbkdf2Sha256Lanes
		}
		var lanes [pbkdf2Sha256Lanes][]byte
		for k := 0; k < n; k++ {
			lanes[k] = azureSyncKeyMaterial(string(pw[i+k]))
		}
		for k := n; k < pbkdf2Sha256Lanes; k++ {
			lanes[k] = lanes[n-1]
		}
		derived := pbkdf2HMACSHA256DeriveBatch(&lanes, h.salt, h.iter)
		for k := 0; k < n; k++ {
			out[i+k] = bytesEqualCT(derived[k][:len(h.want)], h.want)
		}
		i += n
	}
}
