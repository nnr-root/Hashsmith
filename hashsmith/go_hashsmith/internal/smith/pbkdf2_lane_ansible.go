package smith

// pbkdf2AnsibleLaneHasher implements laneHasher for Ansible Vault records
// (crack_ansible.go), batching pbkdf2Sha256Lanes candidate passwords
// through pbkdf2HMACSHA256DeriveBatchN — the multi-block primitive, since
// Ansible's 80-byte derived key needs three PBKDF2 blocks (T_1||T_2||T_3,
// truncated to 80), unlike every single-block format wired before it.
type pbkdf2AnsibleLaneHasher struct {
	rec ansibleRecord
}

// newPBKDF2AnsibleLaneHasher parses targetHash via the same parseAnsible
// verifyAnsible uses, returning nil (caller falls back to the scalar path)
// for anything that does not parse.
func newPBKDF2AnsibleLaneHasher(targetHash string) *pbkdf2AnsibleLaneHasher {
	rec, err := parseAnsible(targetHash)
	if err != nil {
		return nil
	}
	return &pbkdf2AnsibleLaneHasher{rec: rec}
}

// Run mirrors pbkdf2Onepassword8LaneHasher.Run's shape, calling the
// multi-block primitive in place of the single-block one.
func (h *pbkdf2AnsibleLaneHasher) Run(pw [][]byte, out []bool) {
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
		derived := pbkdf2HMACSHA256DeriveBatchN(&lanes, h.rec.salt, ansibleIterations, ansibleDKLen)
		for k := 0; k < n; k++ {
			out[i+k] = ansibleMatches(&h.rec, derived[k])
		}
		i += n
	}
}
