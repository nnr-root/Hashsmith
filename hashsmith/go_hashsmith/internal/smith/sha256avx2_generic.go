//go:build !amd64

package smith

// hasSHA256AVX2 reports whether this CPU supports AVX2. On non-amd64
// architectures there is no AVX2 to have — matching hasAVX2's role
// (md5avx2_generic.go) for the MD5 core, so callers never need a build tag
// of their own.
func hasSHA256AVX2() bool { return false }

// sha256Group8Generic is the portable fallback for non-amd64 architectures:
// no AVX2 core here, so each of the 8 lanes is compressed individually via
// the same scalar core sha256avx2_amd64.go's real path is differential-
// tested against. Same input/output shapes as sha256Group8AVX2 so
// sha256avx2_test.go's test bodies run unmodified on either build.
func sha256Group8Generic(states *[8][8]uint32, schedules *[64][8]uint32) [8][8]uint32 {
	var out [8][8]uint32
	for lane := 0; lane < 8; lane++ {
		var state [8]uint32
		var w [64]uint32
		for word := 0; word < 8; word++ {
			state[word] = states[word][lane]
		}
		for step := 0; step < 64; step++ {
			w[step] = schedules[step][lane]
		}
		sha256ScalarCompress(&state, &w)
		for word := 0; word < 8; word++ {
			out[word][lane] = state[word]
		}
	}
	return out
}

// sha256Group8AVX2 is generic-build sha256Group8Generic under the name the
// amd64 build exports, so a caller can write sha256Group8AVX2(...) once and
// get the real AVX2 core on amd64 or this scalar loop everywhere else —
// exactly like md5GroupAVX2 does not need a build tag at its call sites.
func sha256Group8AVX2(states *[8][8]uint32, schedules *[64][8]uint32) [8][8]uint32 {
	return sha256Group8Generic(states, schedules)
}
