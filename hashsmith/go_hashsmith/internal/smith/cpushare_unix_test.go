//go:build unix

package smith

import "syscall"

// processCPUSeconds returns the CPU time this process has consumed, summed
// over every thread, and whether the platform could report it.
//
// This is the measurement that makes the feasibility timings trustworthy: wall
// clock says how long something took, and this says how much of that time was
// actually spent running rather than waiting for a core. See
// measuredCPUShare.
func processCPUSeconds() (float64, bool) {
	var ru syscall.Rusage
	if err := syscall.Getrusage(syscall.RUSAGE_SELF, &ru); err != nil {
		return 0, false
	}
	seconds := func(t syscall.Timeval) float64 {
		return float64(t.Sec) + float64(t.Usec)/1e6
	}
	return seconds(ru.Utime) + seconds(ru.Stime), true
}
