//go:build linux

package main

import (
	"os"
	"strconv"
	"strings"
)

// systemMemoryBytes reports physical RAM, or 0 when it cannot be determined.
//
// /proc/meminfo is authoritative on Linux and needs no syscall wrapper, which
// is also why this cannot share a file with the Darwin reading: the sysctl
// that answers the same question there is not defined on Linux at all, so a
// single "unix" file naming both does not compile for either.
func systemMemoryBytes() uint64 {
	b, err := os.ReadFile("/proc/meminfo")
	if err != nil {
		return 0
	}
	for _, line := range strings.Split(string(b), "\n") {
		if !strings.HasPrefix(line, "MemTotal:") {
			continue
		}
		// "MemTotal:       16070324 kB"
		fields := strings.Fields(line)
		if len(fields) >= 2 {
			if kib, err := strconv.ParseUint(fields[1], 10, 64); err == nil {
				return kib * 1024
			}
		}
	}
	return 0
}
