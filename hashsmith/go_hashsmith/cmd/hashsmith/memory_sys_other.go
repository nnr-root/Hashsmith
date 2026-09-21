//go:build !darwin && !linux

package main

// systemMemoryBytes reports physical RAM. On platforms without a portable way
// to ask, it reports 0 and the caller falls back to a fixed budget.
func systemMemoryBytes() uint64 { return 0 }
