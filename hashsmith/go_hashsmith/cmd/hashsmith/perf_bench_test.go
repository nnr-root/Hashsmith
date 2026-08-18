package main

import "testing"

// Benchmarks the candidate-generation hot paths to locate allocation pressure.

func BenchmarkRuleEngineFile(b *testing.B) {
	// A representative ~30-rule set touching most op classes.
	lines := []string{
		"l", "u", "c", "C", "t", "r", "d", "f", "{", "}", "[", "]",
		"$1", "$2", "$3", "^!", "so0", "sa@", "se3", "$1$2$3",
		"c $1", "c $2 $0 $2 $4", "so0 sa@ c", "r $9", "u $!",
		"l r", "T0 $1", "d '6", "y2 $x",
	}
	e := &ruleEngine{}
	for _, ln := range lines {
		p, err := compileRuleLine(ln)
		if err != nil {
			b.Fatalf("%q: %v", ln, err)
		}
		e.programs = append(e.programs, p)
	}
	words := []string{"password", "summer2024", "qwerty", "dragon", "letmein"}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = e.expand(words[i%len(words)])
	}
}

func BenchmarkMD5Verify(b *testing.B) {
	target := rawDigest("md5")("zzzzzz")
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = verifyCandidate("candidate", target, "md5", "", "prefix")
	}
}

func BenchmarkMD5Fast(b *testing.B) {
	f, _ := newFastVerifier("md5", rawDigest("md5")("zzzzzz"))
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = f.match("candidate")
	}
}
