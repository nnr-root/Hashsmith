package smith

import (
	"bytes"
	"encoding/hex"
	"testing"
)

// The eight vectors published in section 5 of RFC 2268. They exercise the one
// thing that is easy to get wrong — the split between key length and effective
// key length — from both sides: the same sixteen-byte key gives two different
// ciphertexts at 64 and 128 effective bits.
func TestRC2Vectors(t *testing.T) {
	cases := []struct {
		key, bits, plain, want string
		effective              int
	}{
		{key: "0000000000000000", effective: 63, plain: "0000000000000000", want: "ebb773f993278eff"},
		{key: "ffffffffffffffff", effective: 64, plain: "ffffffffffffffff", want: "278b27e42e2f0d49"},
		{key: "3000000000000000", effective: 64, plain: "1000000000000001", want: "30649edf9be7d2c2"},
		{key: "88", effective: 64, plain: "0000000000000000", want: "61a8a244adacccf0"},
		{key: "88bca90e90875a", effective: 64, plain: "0000000000000000", want: "6ccf4308974c267f"},
		{key: "88bca90e90875a7f0f79c384627bafb2", effective: 64, plain: "0000000000000000", want: "1a807d272bbe5db1"},
		{key: "88bca90e90875a7f0f79c384627bafb2", effective: 128, plain: "0000000000000000", want: "2269552ab0f85ca6"},
		{
			key:       "88bca90e90875a7f0f79c384627bafb216f80a6f85920584c42fceb0be255daf1e",
			effective: 129,
			plain:     "0000000000000000",
			want:      "5b78d3a43dfff1f1",
		},
	}
	for _, c := range cases {
		key, _ := hex.DecodeString(c.key)
		plain, _ := hex.DecodeString(c.plain)
		want, _ := hex.DecodeString(c.want)

		block, err := newRC2Cipher(key, c.effective)
		if err != nil {
			t.Fatalf("newRC2Cipher(%s, %d): %v", c.key, c.effective, err)
		}
		got := make([]byte, 8)
		block.Encrypt(got, plain)
		if !bytes.Equal(got, want) {
			t.Errorf("RC2(%s, %d bits) = %x, want %s", c.key, c.effective, got, c.want)
		}
		back := make([]byte, 8)
		block.Decrypt(back, want)
		if !bytes.Equal(back, plain) {
			t.Errorf("RC2 decrypt(%s, %d bits) = %x, want %s", c.key, c.effective, back, c.plain)
		}
	}
}

// The PI table is a permutation; a transcription slip that duplicates a byte
// would leave most vectors passing and the schedule subtly wrong.
func TestRC2PITableIsAPermutation(t *testing.T) {
	var seen [256]bool
	for _, b := range rc2PITable {
		if seen[b] {
			t.Fatalf("rc2PITable repeats %#02x", b)
		}
		seen[b] = true
	}
}
