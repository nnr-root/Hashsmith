//go:build !amd64

package smith

// hasSHA1AVX2 reports whether this CPU supports AVX2. On non-amd64
// architectures there is no AVX2 to have.
func hasSHA1AVX2() bool { return false }

// sha1Group16AVX2 is the portable fallback for non-amd64 architectures: no
// AVX2 core here, so each of the 16 lanes is compressed individually via
// the same scalar core sha1avx2_amd64.go's real path is differential-
// tested against. Same input/output shape as the amd64 build's
// sha1Group16AVX2 so sha1avx2_test.go's test bodies run unmodified on
// either build.
func sha1Group16AVX2(states *[5][16]uint32, schedules *[80][16]uint32) [5][16]uint32 {
	var out [5][16]uint32
	for lane := 0; lane < 16; lane++ {
		var state [5]uint32
		var w [80]uint32
		for word := 0; word < 5; word++ {
			state[word] = states[word][lane]
		}
		for step := 0; step < 80; step++ {
			w[step] = schedules[step][lane]
		}
		sha1ScalarCompress(&state, &w)
		for word := 0; word < 5; word++ {
			out[word][lane] = state[word]
		}
	}
	return out
}
