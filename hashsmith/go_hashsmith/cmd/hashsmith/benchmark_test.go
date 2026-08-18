package main

import (
	"testing"
	"time"
)

func TestBenchType(t *testing.T) {
	rate, ok := benchType("md5", 2, 100*time.Millisecond)
	if !ok || rate <= 0 {
		t.Errorf("md5 benchmark: ok=%v rate=%v", ok, rate)
	}
	if _, ok := benchSeed("not-a-real-type"); ok {
		t.Error("bogus type should not be seedable")
	}
	if _, ok := benchType("not-a-real-type", 2, 10*time.Millisecond); ok {
		t.Error("bogus type should not be benchmarkable")
	}
	// bcrypt is seedable (KDF reference)
	if _, ok := benchSeed("bcrypt"); !ok {
		t.Error("bcrypt should be seedable")
	}
}
