//go:build !race

package main

// racing is racing_on.go's !race twin: see its doc comment.
func racing() bool { return false }
