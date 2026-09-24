package smith

// Ansible Vault (AES256):
//
//	$ansible$0*0*<salt>*<hmac>*<ciphertext>
//
//	dk      = PBKDF2-HMAC-SHA256(password, salt, 10000, 80)
//	hmacKey = dk[32:64]
//	valid  ⇔ HMAC-SHA256(hmacKey, ciphertext) == stored hmac

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"strings"

	"golang.org/x/crypto/pbkdf2"
)

// ansibleIterations and ansibleDKLen are fixed by the format. Shared
// between the scalar path and the lane hasher (pbkdf2_lane_ansible.go) so
// the two never drift. dkLen exceeds one SHA-256 block, so this is the
// first format wired through the multi-block primitive
// (pbkdf2HMACSHA256DeriveBatchN) rather than the single-block one.
const (
	ansibleIterations = 10000
	ansibleDKLen      = 80
)

// ansibleRecord holds one parsed $ansible$ target, shared by the scalar
// verifyAnsible and the AVX2-batched lane hasher.
type ansibleRecord struct {
	salt []byte
	data []byte
	want []byte
}

// parseAnsible parses target, or returns an error identical in wording and
// condition to what verifyAnsible always returned before this was split
// out — including the two-field-order handling described above.
func parseAnsible(target string) (ansibleRecord, error) {
	if !strings.HasPrefix(target, "$ansible$") {
		return ansibleRecord{}, errors.New("invalid Ansible Vault hash (missing $ansible$ prefix)")
	}
	f := strings.Split(target[len("$ansible$"):], "*")
	if len(f) != 5 {
		return ansibleRecord{}, errors.New("invalid Ansible Vault hash (need type*cipher*salt*ciphertext*hmac)")
	}
	salt, err := hex.DecodeString(f[2])
	if err != nil {
		return ansibleRecord{}, errors.New("invalid Ansible salt")
	}
	a, errA := hex.DecodeString(f[3])
	b, errB := hex.DecodeString(f[4])
	if errA != nil || errB != nil {
		return ansibleRecord{}, errors.New("invalid Ansible ciphertext or HMAC")
	}
	data, want := a, b
	if len(b) != sha256.Size && len(a) == sha256.Size {
		data, want = b, a // the old salt*hmac*ciphertext spelling
	}
	if len(want) != sha256.Size {
		return ansibleRecord{}, errors.New("invalid Ansible HMAC (need 32 bytes)")
	}
	return ansibleRecord{salt: salt, data: data, want: want}, nil
}

// ansibleMatches is the shared "does this derived key authenticate the
// vault" check. Used by verifyAnsible for its single derived key and by
// the lane hasher for each of a batch's.
func ansibleMatches(r *ansibleRecord, dk []byte) bool {
	mac := hmac.New(sha256.New, dk[32:64])
	mac.Write(r.data)
	return hmac.Equal(mac.Sum(nil), r.want)
}

func verifyAnsible(targetHash, candidate string) (bool, error) {
	r, err := parseAnsible(targetHash)
	if err != nil {
		return false, err
	}
	dk := pbkdf2.Key([]byte(candidate), r.salt, ansibleIterations, ansibleDKLen, sha256.New)
	return ansibleMatches(&r, dk), nil
}
