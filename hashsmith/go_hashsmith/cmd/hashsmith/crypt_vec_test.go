package main

import "testing"

func TestCryptVectors(t *testing.T) {
	// md5crypt / sha256crypt / sha512crypt vectors from `openssl passwd`.
	if got := md5cryptRaw("password", "abcdefgh"); got != "$1$abcdefgh$G//4keteveJp0qb8z2DxG/" {
		t.Errorf("md5crypt: got %q", got)
	}
	if got := shaCryptRaw(sha256Params, "password", "abcdefgh", 0, false); got != "$5$abcdefgh$ZLdkj8mkc2XVSrPVjskDAgZPGjtj1VGVaa1aUkrMTU/" {
		t.Errorf("sha256crypt: got %q", got)
	}
	if got := shaCryptRaw(sha512Params, "password", "abcdefgh", 0, false); got != "$6$abcdefgh$yVfUwsw5T.JApa8POvClA1pQ5peiq97DUNyXCZN5IrF.BMSkiaLQ5kvpuEm/VQ1Tvh/KV2TcaWh8qinoW5dhA1" {
		t.Errorf("sha512crypt: got %q", got)
	}
	// Traditional DES crypt vector from Perl: crypt("password","ab").
	got, err := descryptRaw("password", "ab")
	if err != nil {
		t.Fatalf("descrypt error: %v", err)
	}
	if got != "abJnggxhB/yWI" {
		t.Errorf("descrypt: got %q, want abJnggxhB/yWI", got)
	}
}
