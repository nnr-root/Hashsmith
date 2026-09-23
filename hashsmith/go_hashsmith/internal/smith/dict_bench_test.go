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
