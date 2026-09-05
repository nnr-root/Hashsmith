package main

import (
	"strings"
	"testing"
)

func BenchmarkIdentifySingle(b *testing.B) {
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_ = identifyCandidates("5f4dcc3b5aa765d61d8327deb882cf99")
	}
}

func BenchmarkIdentifySignature(b *testing.B) {
	b.ReportAllocs()
	const h = "$2y$10$3sBoTsNRXqMqQyvIsIWKPuJTfBjZTUgKBHVYPPYHIWpDXHJcaqTZS"
	for i := 0; i < b.N; i++ {
		_ = identifyCandidates(h)
	}
}

func BenchmarkDetectHashTypes(b *testing.B) {
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_ = detectHashTypes("5f4dcc3b5aa765d61d8327deb882cf99")
	}
}

func BenchmarkScanBatch100k(b *testing.B) {
	dump := strings.Repeat("5f4dcc3b5aa765d61d8327deb882cf99\n", 100000)
	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_, _ = scanBatch(strings.NewReader(dump))
	}
}
