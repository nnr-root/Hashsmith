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

// A slow KDF must not overrun its time budget. The old loop checked the
// deadline every 1024 iterations, so bcrypt (~60ms/op) ran ~61s against a
// 1s budget.
func TestBenchTypeRespectsBudgetForSlowKDF(t *testing.T) {
	budget := 300 * time.Millisecond
	start := time.Now()
	if _, ok := benchType("bcrypt", 2, budget); !ok {
		t.Skip("bcrypt not benchmarkable in this build")
	}
	elapsed := time.Since(start)
	// One in-flight op per worker may still complete after the deadline;
	// bcrypt cost 10 is ~60ms, so allow generous slack but nothing like 61s.
	if elapsed > budget+2*time.Second {
		t.Errorf("bcrypt benchmark overran its %v budget: took %v", budget, elapsed)
	}
}

// matchBytes exists to remove the string conversion the measurement loop was
// paying per candidate. It must allocate strictly less than the string path.
//
// Note it is NOT expected to reach zero: the local digest buffer escapes
// because buf[:] is passed to a func-typed struct field the compiler cannot
// see through (measured: match() is 64 B/op, 1 allocs/op). Removing that last
// allocation would need a verifier-owned scratch field, and fastVerifier is
// shared across workers on the non-batch path, where a mutable field would
// race. The win being asserted here is the string conversion, nothing more.
func TestMatchBytesAllocatesLessThanMatch(t *testing.T) {
	fv, ok := newFastVerifier("md5", "5f4dcc3b5aa765d61d8327deb882cf99")
	if !ok {
		t.Fatal("md5 must have a fast verifier")
	}
	buf := []byte("benchAAAA")
	viaString := testing.AllocsPerRun(1000, func() { fv.match(string(buf)) })
	viaBytes := testing.AllocsPerRun(1000, func() { fv.matchBytes(buf) })
	if viaBytes >= viaString {
		t.Errorf("matchBytes allocated %v/run, match(string) allocated %v/run; "+
			"matchBytes must allocate strictly less", viaBytes, viaString)
	}
	t.Logf("allocs per run: match(string)=%v matchBytes=%v", viaString, viaBytes)
}
