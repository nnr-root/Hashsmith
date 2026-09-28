package smith

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// benchWordlist writes a wordlist of n words whose lengths repeat over the
// given widths, which is what makes the length-bucketing in dictVectorLanes
// behave like it does on a real list rather than on a single bucket.
func benchWordlist(tb testing.TB, n int, widths []int) string {
	tb.Helper()
	dir := tb.TempDir()
	path := filepath.Join(dir, "words.txt")
	var b strings.Builder
	b.Grow(n * 10)
	for i := 0; i < n; i++ {
		w := widths[i%len(widths)]
		b.WriteString(strings.Repeat(string(rune('a'+i%26)), w))
		b.WriteByte('\n')
	}
	if err := os.WriteFile(path, []byte(b.String()), 0o600); err != nil {
		tb.Fatal(err)
	}
	return path
}

// BenchmarkDictWorkerScaling answers a question the end-to-end number cannot:
// is the reader or the hashing the ceiling? If throughput barely moves from
// one worker to eight, the single reader goroutine is saturated and no amount
// of making the workers faster will show up.
func BenchmarkDictWorkerScaling(b *testing.B) {
	const n = 400000
	target, err := hashText("nomatchhere", "md5", "", "")
	if err != nil {
		b.Fatal(err)
	}
	path := benchWordlist(b, n, []int{6})
	verify := func(pw string) bool {
		ok, _ := verifyCandidate(pw, target, "md5", "", "")
		return ok
	}
	for _, workers := range []int{1, 2, 4, 8} {
		b.Run(fmt.Sprint(workers), func(b *testing.B) {
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				var attempts int64
				if _, err := dictAttack(context.Background(), path, 0, 0, workers,
					&attempts, nil, verify, target, "md5", "", ""); err != nil {
					b.Fatal(err)
				}
			}
			b.ReportMetric(float64(n)*float64(b.N)/b.Elapsed().Seconds()/1e6, "MH/s")
		})
	}
}

// BenchmarkDictReaderOnly is the reader's own ceiling: the same scan-and-batch
// loop with no hashing at all, so the number it reports is the most a
// dictionary run could ever reach with this pipeline shape.
func BenchmarkDictReaderOnly(b *testing.B) {
	const n = 400000
	path := benchWordlist(b, n, []int{6})
	target, err := hashText("nomatchhere", "md5", "", "")
	if err != nil {
		b.Fatal(err)
	}
	neverMatches := func(string) bool { return false }
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		var attempts int64
		// "nosuchtype" has no vector plan and no fast verifier, but the
		// closure above short-circuits, so this times the pipeline rather
		// than any digest.
		if _, err := dictAttack(context.Background(), path, 0, 0, 8,
			&attempts, nil, neverMatches, target, "nosuchtype", "", ""); err != nil {
			b.Fatal(err)
		}
	}
	b.ReportMetric(float64(n)*float64(b.N)/b.Elapsed().Seconds()/1e6, "MH/s")
}

// BenchmarkDictAttack measures the dictionary pipeline end to end, which is
// the number that matters: a faster core is worth nothing if the reader is
// the ceiling. Run the uniform and mixed cases together — bucketing by length
// is free on the first and is the whole cost model on the second.
func BenchmarkDictAttack(b *testing.B) {
	const n = 400000
	target, err := hashText("nomatchhere", "md5", "", "")
	if err != nil {
		b.Fatal(err)
	}
	for _, c := range []struct {
		name   string
		widths []int
	}{
		{"uniform6", []int{6}},
		{"mixed4to10", []int{4, 5, 6, 7, 8, 9, 10}},
	} {
		path := benchWordlist(b, n, c.widths)
		for _, fast := range []bool{true, false} {
			label := c.name
			if fast {
				label += "/vector"
			} else {
				label += "/scalar"
			}
			b.Run(label, func(b *testing.B) {
				if !fast {
					b.Setenv("HASHSMITH_NO_FASTPATH", "1")
				}
				verify := func(pw string) bool {
					ok, _ := verifyCandidate(pw, target, "md5", "", "")
					return ok
				}
				b.SetBytes(int64(n))
				b.ResetTimer()
				for i := 0; i < b.N; i++ {
					var attempts int64
					if _, err := dictAttack(context.Background(), path, 0, 0, 4,
						&attempts, nil, verify, target, "md5", "", ""); err != nil {
						b.Fatal(err)
					}
					if attempts != int64(n) {
						b.Fatalf("attempts = %d, want %d", attempts, n)
					}
				}
				b.ReportMetric(float64(n)*float64(b.N)/b.Elapsed().Seconds()/1e6, "MH/s")
			})
		}
	}
	_ = fmt.Sprint()
}

// BenchmarkBatchDictAttack is the multi-hash dictionary engine, which shares
// the reader with the single-target one. It exists so the shared reader's cost
// is measured on both callers rather than only the one it was tuned against.
func BenchmarkBatchDictAttack(b *testing.B) {
	const n = 400000
	path := benchWordlist(b, n, []int{4, 5, 6, 7, 8, 9, 10})
	// The verifier is deliberately trivial. This benchmark exists to measure
	// the READER and the batch pipeline, and a verify that hashes and
	// hex-encodes would allocate several times per word and bury exactly what
	// is being measured — the first version of this benchmark did, reporting
	// four allocations per word that had nothing to do with the reader.
	verify := func(string) bool { return false }
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		var attempts int64
		batchDictAttack(context.Background(), path, 0, 0, verify, 4, nil, &attempts, nil)
		if attempts != int64(n) {
			b.Fatalf("attempts = %d, want %d", attempts, n)
		}
	}
	b.ReportMetric(float64(n)*float64(b.N)/b.Elapsed().Seconds()/1e6, "MH/s")
}

// BenchmarkBatchDictVector exercises the multi-hash dictionary engine WITH the
// vector cores wired, against the same engine without them. The plain
// BenchmarkBatchDictAttack above passes a nil bundle and a trivial verifier,
// so it measures the reader; this one measures the hashing.
func BenchmarkBatchDictVector(b *testing.B) {
	const n = 200000
	const targets = 50
	path := benchWordlist(b, n, []int{4, 5, 6, 7, 8})

	hexes := make([]string, targets)
	idxs := make([]int, targets)
	for i := range hexes {
		h, err := hashText(fmt.Sprintf("nomatch-%d", i), "md5", "", "")
		if err != nil {
			b.Fatal(err)
		}
		hexes[i], idxs[i] = h, i
	}
	// None of the wordlist matches, so every run is exhaustive and the
	// measurement is of throughput rather than of how early it stopped.
	byHex := make(map[string]bool, targets)
	for _, h := range hexes {
		byHex[h] = true
	}
	verify := func(pw string) bool {
		h, err := hashText(pw, "md5", "", "")
		return err == nil && byHex[h]
	}
	record := func(string, []int) bool { return false }

	for _, useVector := range []bool{true, false} {
		name := "vector"
		if !useVector {
			name = "scalar"
		}
		b.Run(name, func(b *testing.B) {
			if !useVector {
				b.Setenv("HASHSMITH_NO_FASTPATH", "1")
			}
			var vec *batchDictVector
			if probe := newDictVectorLanesMulti("md5", hexes, idxs, "", ""); probe != nil {
				vec = &batchDictVector{
					newLanes: func() *dictVectorLanes {
						return newDictVectorLanesMulti("md5", hexes, idxs, "", "")
					},
					record: record,
				}
			}
			if useVector && vec == nil {
				b.Skip("no md5 vector plan on this backend")
			}
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				var attempts int64
				batchDictAttack(context.Background(), path, 0, 0, verify, 4, nil, &attempts, vec)
				if attempts != int64(n) {
					b.Fatalf("attempts = %d, want %d", attempts, n)
				}
			}
			b.ReportMetric(float64(n)*float64(b.N)/b.Elapsed().Seconds()/1e6, "MH/s")
		})
	}
}

// BenchmarkDictByType measures the dictionary engine per hash type, with and
// without the batched cores, so the vector path (md5/md4/ntlm) and the
// contiguous path (sha1/sha256) are each measured against their own scalar
// baseline rather than against each other.
func BenchmarkDictByType(b *testing.B) {
	const n = 200000
	path := benchWordlist(b, n, []int{4, 5, 6, 7, 8})
	for _, tc := range []struct{ typ, salt string }{
		{"md5", ""}, {"ntlm", ""}, {"sha1", ""}, {"sha256", ""}, {"sha512", ""},
		// The UTF-16LE salted constructions, which the dictionary engine
		// reaches and the mask runners deliberately do not.
		{"sha1-utf16le-pass-salt", "s4lt"},
		{"sha256-utf16le-pass-salt", "s4lt"},
	} {
		typ, salt := tc.typ, tc.salt
		var target string
		var err error
		if salt == "" {
			target, err = hashText("nomatchhere", typ, "", "")
		} else {
			target, err = hashCompatSaltedDigest("nomatchhere", typ, salt)
		}
		if err != nil {
			b.Fatal(err)
		}
		verify := func(pw string) bool {
			ok, _ := verifyCandidate(pw, target, typ, salt, "prefix")
			return ok
		}
		for _, fast := range []bool{true, false} {
			label := typ + "/batched"
			if !fast {
				label = typ + "/scalar"
			}
			b.Run(label, func(b *testing.B) {
				if !fast {
					b.Setenv("HASHSMITH_NO_FASTPATH", "1")
				}
				b.ResetTimer()
				for i := 0; i < b.N; i++ {
					var attempts int64
					if _, err := dictAttack(context.Background(), path, 0, 0, 4,
						&attempts, nil, verify, target, typ, salt, "prefix"); err != nil {
						b.Fatal(err)
					}
				}
				b.ReportMetric(float64(n)*float64(b.N)/b.Elapsed().Seconds()/1e6, "MH/s")
			})
		}
	}
}

// BenchmarkGeneratedKeyspace measures a generator-backed layout — the shape
// hybrid, combinator, markov and prince all produce — through the batched
// runner and through the scalar one. Those modes had no batched core at all
// until runLayoutBatched, so this is the number that says whether drawing
// candidates positionally and bucketing them by length was worth it.
func BenchmarkGeneratedKeyspace(b *testing.B) {
	const n = 200000
	words := make([]string, n)
	for i := range words {
		words[i] = strings.Repeat(string(rune('a'+i%26)), 4+i%5) + fmt.Sprint(i%1000)
	}
	target, err := hashText("absent-from-this-keyspace", "md5", "", "")
	if err != nil {
		b.Fatal(err)
	}
	verify := func(pw string) bool {
		ok, _ := verifyCandidate(pw, target, "md5", "", "")
		return ok
	}
	lay := func() *keyspaceLayout {
		return &keyspaceLayout{total: int64(n), gen: func(i int64) string { return words[i] }}
	}
	b.Run("batched", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			var attempts int64
			if _, err := runLayoutBatched(context.Background(), lay(), 0, 0, 4, &attempts, nil,
				func() *dictVectorLanes {
					return newDictVectorLanesMulti("md5", []string{target}, []int{0}, "", "")
				}, verify); err != nil {
				b.Fatal(err)
			}
		}
		b.ReportMetric(float64(n)*float64(b.N)/b.Elapsed().Seconds()/1e6, "MH/s")
	})
	b.Run("scalar", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			var attempts int64
			if _, err := runLayout(context.Background(), lay(), 0, 0, 4, &attempts, nil, verify); err != nil {
				b.Fatal(err)
			}
		}
		b.ReportMetric(float64(n)*float64(b.N)/b.Elapsed().Seconds()/1e6, "MH/s")
	})
}
