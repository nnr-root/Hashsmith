//go:build slowtest

package main

import "testing"

// The high-iteration and memory-hard KDF vectors. Excluded from the default
// suite because they take minutes; run nightly with:
//   go test -tags slowtest -timeout 60m ./cmd/hashsmith
func TestSelfTestVectorsSlow(t *testing.T) {
	ran := 0
	for _, v := range universalHashRegistry.vectors {
		if !universalHashRegistry.isSlow(v.typ) {
			continue
		}
		checkSelfTestVector(t, v)
		ran++
	}
	if ran == 0 {
		t.Fatal("no slow vectors ran")
	}
	t.Logf("slow vectors run: %d", ran)
}
