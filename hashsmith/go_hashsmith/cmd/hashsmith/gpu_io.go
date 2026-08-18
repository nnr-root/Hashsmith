package main

import "os"

// stderr returns the process stderr; a tiny indirection so GPU/status helpers
// read naturally and remain easy to redirect in tests.
func stderr() *os.File { return os.Stderr }
