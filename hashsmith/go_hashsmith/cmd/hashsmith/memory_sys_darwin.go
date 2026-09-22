//go:build darwin

package main

import "golang.org/x/sys/unix"

// systemMemoryBytes reports physical RAM, or 0 when it cannot be determined.
func systemMemoryBytes() uint64 {
	n, err := unix.SysctlUint64("hw.memsize")
	if err != nil {
		return 0
	}
	return n
}
