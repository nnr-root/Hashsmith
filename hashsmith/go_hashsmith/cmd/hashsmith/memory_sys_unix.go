//go:build darwin || linux

package main

import (
	"os"
	"strconv"
	"strings"

	"golang.org/x/sys/unix"
)

// systemMemoryBytes reports physical RAM, or 0 when it cannot be determined.
func systemMemoryBytes() uint64 {
	// Linux: /proc/meminfo is authoritative and needs no syscall wrapper.
	if b, err := os.ReadFile("/proc/meminfo"); err == nil {
		for _, line := range strings.Split(string(b), "\n") {
			if !strings.HasPrefix(line, "MemTotal:") {
				continue
			}
			fields := strings.Fields(line)
			if len(fields) >= 2 {
				if kib, err := strconv.ParseUint(fields[1], 10, 64); err == nil {
					return kib * 1024
				}
			}
		}
	}
	// Darwin.
	if n, err := unix.SysctlUint64("hw.memsize"); err == nil {
		return n
	}
	return 0
}
