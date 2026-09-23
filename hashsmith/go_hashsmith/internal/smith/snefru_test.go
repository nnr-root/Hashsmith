package smith

import (
	"encoding/hex"
	"strings"
	"testing"
)

// Snefru's published vectors at both widths, John's own for its Snefru-128
// and Snefru-256 formats ("mystrongpassword"), and two longer messages that
// were checked the other way round: Hashsmith computed them and John
// recovered both plaintexts from them at both widths.
//
// The two widths use different block sizes — 48 bytes of message per block at
// 128 bits, 32 at 256 — so they are not two settings of one code path; each
// is its own test of the padding. The fox sentence is 43 bytes, which spans
// two blocks at 256 bits and one at 128, and so exercises both sides of that.
func TestSnefru(t *testing.T) {
	for _, tc := range []struct {
		size      int
		msg, want string
	}{
		{16, "", "8617f366566a011837f4fb4ba5bedea2"},
		{16, "\n", "d9fcb3171c097fbba8c8f12aa0906bad"},
		{16, "1\n", "44ec420ce99c1f62feb66c53c24ae453"},
		{16, "abc", "553d0648928299a0f22a275a02c83b10"},
		{16, "mystrongpassword", "53b8a9b1c9ed00174d88d705fb7bae30"},
		{16, "The quick brown fox jumps over the lazy dog",
			"59d9539d0dd96d635b5bdbd1395bb86c"},
		{32, "abc", "7d033205647a2af3dc8339f6cb25643c33ebc622d32979c4b612b02c4903031b"},
		{32, "mystrongpassword", "4170e04e900e6221562ceb5ff6ea27fa9b9b0d9587add44a4379a02619c5a106"},
		{32, "The quick brown fox jumps over the lazy dog",
			"674caa75f9d8fd2089856b95e93a4fb42fa6c8702f8980e11d97a142d76cb358"},
	} {
		h := newSnefru(tc.size)
		_, _ = h.Write([]byte(tc.msg))
		if got := hex.EncodeToString(h.Sum(nil)); got != tc.want {
			t.Errorf("Snefru-%d(%.20q) = %s, want %s", tc.size*8, tc.msg, got, tc.want)
		}
	}
}

func TestSnefruStreaming(t *testing.T) {
	msg := strings.Repeat("The quick brown fox jumps over the lazy dog. ", 40)
	for _, size := range []int{16, 32} {
		whole := newSnefru(size)
		_, _ = whole.Write([]byte(msg))
		piecemeal := newSnefru(size)
		for i := 0; i < len(msg); i++ {
			_, _ = piecemeal.Write([]byte(msg[i : i+1]))
		}
		if a, b := hex.EncodeToString(whole.Sum(nil)), hex.EncodeToString(piecemeal.Sum(nil)); a != b {
			t.Errorf("Snefru-%d byte-at-a-time = %s, all at once = %s", size*8, b, a)
		}
	}
}
