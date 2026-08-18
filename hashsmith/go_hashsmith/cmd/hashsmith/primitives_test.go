package main

import (
	"encoding/hex"
	"testing"
)

// Whirlpool against the ISO/IEC 10118-3 test vectors.
func TestWhirlpoolVectors(t *testing.T) {
	cases := map[string]string{
		"":    "19fa61d75522a4669b44e39c1d2e1726c530232130d407f89afee0964997f7a73e83be698b288febcf88e3e03c4f0757ea8964e59b63d93708b138cc42a66eb3",
		"abc": "4e2448a4c6f486bb16b6562c73b4020bf3043e3a731bce721ae1b303d97e6d4c7181eebdb6c57e277d0e34957114cbd6c797fc9d95d8b582d225292076d4eef5",
		"The quick brown fox jumps over the lazy dog": "b97de512e91e3828b40d2b0fdce9ceb3c4a71f9bea8d88e75c4fa854df36725fd2b52eb6544edcacd6f8beddfea403cb55ae31f03ad62a5ef54e42ee82c3fb35",
	}
	for in, want := range cases {
		got, _ := hashText(in, "whirlpool", "", "")
		if got != want {
			t.Errorf("whirlpool(%q):\n got  %s\n want %s", in, got, want)
		}
	}
}

// Streebog against the GOST R 34.11-2012 / RFC 6986 example M1.
func TestStreebogVectors(t *testing.T) {
	m1 := "012345678901234567890123456789012345678901234567890123456789012"
	if got, _ := hashText(m1, "streebog512", "", ""); got != "486f64c1917879417fef082b3381a4e211c324f074654c38823a7b76f830ad00fa1fbae42b1285c0352f227524bc9ab16254288dd6863dccd5b9f54a1ad0541b" {
		t.Errorf("streebog512: got %s", got)
	}
	if got, _ := hashText(m1, "streebog256", "", ""); got != "00557be5e584fd52a449b16b0251d05d27f94ab76cbaa6da890b59d8ef1e159d" {
		t.Errorf("streebog256: got %s", got)
	}
}

// Serpent against the reference AES-submission ECB known-answer vector (256-bit
// key with the MSB set), plus a round-trip. The LUKS/VeraCrypt tests also cover
// it end to end against real volumes.
func TestSerpentCipher(t *testing.T) {
	key, _ := hex.DecodeString("8000000000000000000000000000000000000000000000000000000000000000")
	c, err := newSerpentCipher(key)
	if err != nil {
		t.Fatalf("serpent: %v", err)
	}
	pt := make([]byte, 16)
	ct := make([]byte, 16)
	c.Encrypt(ct, pt)
	const want = "a223aa1288463c0e2be38ebd825616c0"
	if hex.EncodeToString(ct) != want {
		t.Errorf("serpent ECB:\n got  %s\n want %s", hex.EncodeToString(ct), want)
	}
	back := make([]byte, 16)
	c.Decrypt(back, ct)
	if hex.EncodeToString(back) != hex.EncodeToString(pt) {
		t.Errorf("serpent decrypt round-trip failed: %x", back)
	}
}
