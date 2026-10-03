//go:build amd64

package smith

// Temporary A/B comparison scaffolding — NOT production code. Declares and
// wraps the pre-fix sha1g16AVX2Old (sha1avx2_oldcompare_amd64.s) so it can
// be benchmarked directly against the current sha1g16AVX2 in the SAME CI
// job on the SAME machine, avoiding the cross-run/cross-machine noise that
// made two separate CI runs on different EPYC models hard to compare.
// Removed, along with its .s file and the benchmark in
// sha1avx2_oldcompare_bench_test.go, once that comparison is done.
func sha1g16AVX2Old(out0, out1 *[5][8]uint32, msg0, msg1 *[80][8]uint32, ivvec0, ivvec1 *[5][8]uint32, kvec *[80][8]uint32)

func sha1Group16AVX2Old(states *[5][16]uint32, schedules *[80][16]uint32) [5][16]uint32 {
	var iv0, iv1 [5][8]uint32
	var msg0, msg1 [80][8]uint32
	for w := 0; w < 5; w++ {
		for l := 0; l < 8; l++ {
			iv0[w][l] = states[w][l]
			iv1[w][l] = states[w][l+8]
		}
	}
	for step := 0; step < 80; step++ {
		for l := 0; l < 8; l++ {
			msg0[step][l] = schedules[step][l]
			msg1[step][l] = schedules[step][l+8]
		}
	}
	var out0, out1 [5][8]uint32
	sha1g16AVX2Old(&out0, &out1, &msg0, &msg1, &iv0, &iv1, &sha1AVX2Kvec)

	var out [5][16]uint32
	for w := 0; w < 5; w++ {
		for l := 0; l < 8; l++ {
			out[w][l] = out0[w][l]
			out[w][l+8] = out1[w][l]
		}
	}
	return out
}
