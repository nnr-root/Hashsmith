//go:build !amd64

package smith

// hasSHA512AVX2 reports whether this CPU supports AVX2. On non-amd64
// architectures there is no AVX2 to have.
func hasSHA512AVX2() bool { return false }

// sha512Group4AVX2 is the portable fallback for non-amd64 architectures:
// no AVX2 core here, so each of the 4 lanes is compressed individually via
// the same scalar core sha512avx2_amd64.go's real path is differential-
// tested against.
func sha512Group4AVX2(states *[8][4]uint64, schedules *[80][4]uint64) [8][4]uint64 {
	var out [8][4]uint64
	for lane := 0; lane < 4; lane++ {
		var state [8]uint64
		var w [80]uint64
		for word := 0; word < 8; word++ {
			state[word] = states[word][lane]
		}
		for step := 0; step < 80; step++ {
			w[step] = schedules[step][lane]
		}
		sha512ScalarCompress(&state, &w)
		for word := 0; word < 8; word++ {
			out[word][lane] = state[word]
		}
	}
	return out
}
