package smith

// pbkdf2AzureADLaneHasher implements laneHasher for John's "azuread"
// spelling of a synchronised Azure AD credential (crack_john_small_formats.go),
// batching pbkdf2Sha256Lanes candidates through the shared
// pbkdf2HMACSHA256DeriveBatch primitive.
//
// Like MS-AzureSync (pbkdf2_lane_azuresync.go), PBKDF2's password is not
// the candidate itself but a transform of its NTLM hash — and it is
// literally the SAME transform, computed via azureSyncKeyMaterial: both
// formats read "v1;PPH1_MD4,<salt>,<rounds>,<digest>", azuread being
// John's own spelling of what crack_vendor.go's azuresync reads as
// Hashcat's mode 12800. Reusing the one function keeps that identity
// explicit instead of re-deriving it.
type pbkdf2AzureADLaneHasher struct {
	salt   []byte
	rounds int
	digest []byte
}

// newPBKDF2AzureADLaneHasher parses targetHash via the same azureADFields
// verifyAzureAD uses, returning nil (caller falls back to the scalar path)
// for anything that does not parse.
func newPBKDF2AzureADLaneHasher(targetHash string) *pbkdf2AzureADLaneHasher {
	salt, rounds, digest, err := azureADFields(targetHash)
	if err != nil {
		return nil
	}
	return &pbkdf2AzureADLaneHasher{salt: salt, rounds: rounds, digest: digest}
}

// Run applies azureSyncKeyMaterial per lane before batching, exactly as
// pbkdf2AzureSyncLaneHasher.Run does.
func (h *pbkdf2AzureADLaneHasher) Run(pw [][]byte, out []bool) {
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
		derived := pbkdf2HMACSHA256DeriveBatch(&lanes, h.salt, h.rounds)
		for k := 0; k < n; k++ {
			out[i+k] = bytesEqualCT(derived[k][:], h.digest)
		}
		i += n
	}
}
