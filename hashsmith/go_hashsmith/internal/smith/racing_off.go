//go:build !race

package smith

// racing is racing_on.go's !race twin: see its doc comment.
func racing() bool { return false }
