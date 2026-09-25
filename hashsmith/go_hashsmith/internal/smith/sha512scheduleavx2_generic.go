//go:build !amd64

package smith

// sha512ScheduleExpand4AVX2 is the portable fallback for non-amd64
// architectures: no AVX2 core here, so each of the 4 lanes is expanded
// individually via the same scalar recurrence sha512scheduleavx2_amd64.s's
// real path is differential-tested against (sha512ExpandRemainingWords).
func sha512ScheduleExpand4AVX2(w *[80][4]uint64) {
	for lane := 0; lane < 4; lane++ {
		var lw [80]uint64
		for step := 0; step < 16; step++ {
			lw[step] = w[step][lane]
		}
		sha512ExpandRemainingWords(&lw)
		for step := 16; step < 80; step++ {
			w[step][lane] = lw[step]
		}
	}
}
