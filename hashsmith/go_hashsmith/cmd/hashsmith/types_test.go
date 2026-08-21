package main

import (
	"strings"
	"testing"
)

// Reference vectors for password "hashsmith", salt "s4lt1234", generated with
// Python's hashlib/hmac. They pin the digest, salted, nested, and HMAC types.
func TestHashTypeVectors(t *testing.T) {
	const pw, salt = "hashsmith", "s4lt1234"

	// {type, salt, saltMode, expected}
	cases := []struct {
		typ, salt, mode, want string
	}{
		// Raw digests (spot-checks incl. the newly added SHA3-384/224).
		{"md5", "", "", "ed1a4cb602d450909991fa0ee6bad099"},
		{"sha256", "", "", "3b78772f6663c0e081cc5e5f83f059a4a852426a8a899020d41887ef647f2303"},
		{"sha3_224", "", "", "b053f141758824131c37ce665983a09c1bf8c0e411b85d8145eb7330"},
		{"sha3_384", "", "", "b9bb98b7e66b3e36f75b485d850c71634c15ecc3c7fbefdc2e1600a4fb3c289896bbfce6b77e26bf7b5783e96b5f57a2"},
		// Salted placements via -s / -S.
		{"md5", salt, "suffix", "f192ee9522371949f781af26761a2849"}, // md5($pass.$salt)
		{"md5", salt, "prefix", "19a68b23f8139acb4cb51ebf692576f8"}, // md5($salt.$pass)
		{"sha1", salt, "suffix", "91ff0169f1431d27f3c8111442212af9683d9cd8"},
		{"sha256", salt, "suffix", "84f1e8acd579160447aee3e9079927c9ca802bf2b6e282b67153c60c7d4035e2"},
		{"sha512", salt, "suffix", "70ebcbbbd0faa466e98292ad5b4d8cbb7843316f3db1f22ef86775ceaed6128003118bb4c62b01e5e593b8c0749f19400f3656e59abe984f68807dcc26e08cbe"},
		// Nested digests.
		{"md5-md5", "", "", "096d2efcb9fd757c66350cc3a6947297"},
		{"sha1-sha1", "", "", "533b3609ddd49c6a4b895a9085f5010612e9638b"},
		{"sha256-sha256", "", "", "d65772770fcf4f0e1360fe1aea4059cd2798e7a4676de46e678718cf8273ee64"},
		{"sha512-sha512", "", "", "9406af85e11867ef61a04bde222618ae7939a6c7558db74979c3cb6ac56647e4fc62badc995f4194cb581898fc4ebec2fb8c7223405516c4a532dd9ec7e4018a"},
		{"sha3_256-sha3_256", "", "", "c79e0b18d2834b20ff4fbfbc3b7e5c265898cd3876b004ef37d09a4b46ed2d05"},
		// HMAC — key = password (message is the salt).
		{"hmac-md5", salt, "", "4280c04958cc9edb5583e01e49d78e53"},
		{"hmac-sha1", salt, "", "ece79aa2c3183a618d68ef180f10167e26e140ef"},
		{"hmac-sha224", salt, "", "dc2da7142b595d4ac5f481adc55f98dbc17c3bf8e47de7318144354f"},
		{"hmac-sha256", salt, "", "ed98cce4eb56a6c6d5072d1d1e2f1ba875ce716f74a433a0de3feb848c96d465"},
		{"hmac-sha384", salt, "", "86ac4e39762027c7bf315674d0899570ff61048328feb0305f4a74bb4e34cbcef80e1dfc06f450901203b5027d68c9e0"},
		{"hmac-sha512", salt, "", "ed87614bfeadac22d8b7e8e49c8cc8dbfd2f8b4d7ecc0a01bf07c2fdb4d8b70011be3ce12fb1f64098d0d22c8359b98662eb55a85a07bbac8f145fabb05c2299"},
		{"hmac-sha3_224", salt, "", "05b6fe41a01ab002487c75627bef23c0519380ba4e11561611f98ee1"},
		{"hmac-sha3_256", salt, "", "1954ac56b5b8a3af6501e3c363b02f0346f600b1bc0863b15caa3e51fab359c3"},
		{"hmac-sha3_384", salt, "", "dca598c28681fa4f1675e46ebc77682cc903f200168b940137ff60ed4c24e0e404422bb1053422721e740b50bf7ac148"},
		{"hmac-sha3_512", salt, "", "8494291a22d2799827a03014a47f2f56b28d25d53827271cd31202336ad83cefae78a78914263c57fab3ba6f9cc77eb8b2bbcfc0c480f34b462cf3b08fad1f52"},
		{"hmac-ripemd160", salt, "", "70617dc57d080a0485889cad4d7e9fb2c30d88bf"},
		// HMAC — key = salt (message is the password).
		{"hmac-md5-saltkey", salt, "", "3e47c2e89e6f3ae6be2b4838d7b90c5e"},
		{"hmac-sha1-saltkey", salt, "", "c8d35b1bef34a241900c37ff098b6d269291bc30"},
		{"hmac-sha224-saltkey", salt, "", "2255e6e35397f95630524f8dca414aa485bd38bff60b0e3363c599a7"},
		{"hmac-sha256-saltkey", salt, "", "2ddfacc146d8c75950a8789b39d70230bebbc4d48ba29b64964870519473a356"},
		{"hmac-sha384-saltkey", salt, "", "0baf71720a3382fc9e73d610796e8f3348c6d513f0ed5d6bf1b3de75f5c1377359ed3d1958cde44d499c1b3e919fb2d6"},
		{"hmac-sha512-saltkey", salt, "", "00e58824267ae4497b52a7d5e0953e44be340096b24a67a6c933dc5ecd8bd646fb73d5e4788db0a7d448c1b0d71ebb840067183178b719268711c3d01c09cdbe"},
		{"hmac-sha3_224-saltkey", salt, "", "d420a3fc3f9f8bf1deed6adb322c0f963e666973408f7b26d5bc7c61"},
		{"hmac-sha3_256-saltkey", salt, "", "a4f4dae6f7703ee3ba4573c6b306562a7647fdc6cd1686e7f0a5c80de7229c1d"},
		{"hmac-sha3_384-saltkey", salt, "", "c3a4ca47f0cca35dd1f34c398a16d867f234423a99115104f806cbaf706e6ee63bed4f86a76e8cbb0fa429dd440e8e4b"},
		{"hmac-sha3_512-saltkey", salt, "", "05cea041f766e41c896a6a9b66c3b0da9148ca224620bc8615fbe13309e86e20a33fb0adb3956e709b8c63ed6eba80dfe6908205efe5ab2a4e8318e972a99fca"},
		{"hmac-ripemd160-saltkey", salt, "", "e9bf2f653a33d1e89789a47d7f7b1dc188a668aa"},
	}

	for _, c := range cases {
		got, err := hashText(pw, c.typ, c.salt, c.mode)
		if err != nil {
			t.Errorf("hashText(-t %s): %v", c.typ, err)
			continue
		}
		if got != c.want {
			t.Errorf("-t %s (salt=%q mode=%q):\n  got  %s\n  want %s", c.typ, c.salt, c.mode, got, c.want)
		}
	}
}

// TestHmacHashSaltCrack checks the "hash:salt" convenience for HMAC types.
func TestHmacHashSaltCrack(t *testing.T) {
	// HMAC-SHA256(key="hashsmith", msg="s4lt1234").
	target := "ed98cce4eb56a6c6d5072d1d1e2f1ba875ce716f74a433a0de3feb848c96d465:s4lt1234"
	ok, err := verifyCandidate("hashsmith", target, "hmac-sha256", "", "prefix")
	if err != nil {
		t.Fatalf("verifyCandidate: %v", err)
	}
	if !ok {
		t.Error("expected hash:salt HMAC target to verify")
	}
	if bad, _ := verifyCandidate("wrong", target, "hmac-sha256", "", "prefix"); bad {
		t.Error("wrong candidate should not verify")
	}
}

func TestExpandedHashTypeVectors(t *testing.T) {
	cases := []struct {
		text, typ, want string
	}{
		{"hashsmith", "sha512_224", "0435e39d17ae73fd42cecbda1ac3efb943751b1b05251cc5bfde0848"},
		{"hashsmith", "sha512_256", "9121932be2e599d11d225d1a66530459a7d08399ff7e64937a840504f852ce44"},
		{"hashsmith", "shake128-256", "2301fd16057dec3fcb1d0920ba89dea9bb70f47517eca2a300e7dd95c9c1c92a"},
		{"hashsmith", "shake256-512", "04a1c20f55ff83e600320342518073161983b8c1953c9c7fe0ef764d3efac6b98ac244a9231cc92491ca1c3aa8a0a2975f2d414a6da2033354c77e019b7de74a"},
		{"hashsmith", "blake2b256", "1675441a904df18acca10e1852d4e7a02eb52f0e0eb0880c0b38110cd99d0fd1"},
		{"hashsmith", "blake2b384", "5b723d26c12341028764f64e23450686739ef05fd2d1c678036539fef6adb43c7c779556618d1758f9fb8a754a97def0"},
		{"", "keccak256", "c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470"},
		{"", "keccak512", "0eab42de4c3ceb9235fc91acffe746b29c29a8c366b7c60e4e67c466f36a4304c00fa9caf9d87976ba469bcbe06713b435f091ef2769fb160cdab33d3670680e"},
		{"PASSWORD", "lm", "E52CAC67419A9A224A3B108F3FA6CB6D"},
		{"123456789", "crc32", "cbf43926"},
		{"123456789", "crc32c", "e3069283"},
		{"123456789", "crc64", "995dc9bbdf1939fa"},
		{"123456789", "adler32", "091e01de"},
		{"hashsmith", "fnv1a32", "3e685394"},
		{"hashsmith", "fnv1a64", "7119f4746574a3f4"},
	}
	for _, tc := range cases {
		got, err := hashText(tc.text, tc.typ, "", "prefix")
		if err != nil {
			t.Errorf("hashText(%s): %v", tc.typ, err)
			continue
		}
		if got != tc.want {
			t.Errorf("%s(%q): got %s, want %s", tc.typ, tc.text, got, tc.want)
		}
		ok, err := verifyCandidate(tc.text, tc.want, tc.typ, "", "prefix")
		if err != nil || !ok {
			t.Errorf("verifyCandidate(%s): ok=%v err=%v", tc.typ, ok, err)
		}
	}
}

func TestHashAliasesAndOutputEncodings(t *testing.T) {
	got, err := hashText("hashsmith", "SHA-512/256", "", "prefix")
	if err != nil || got != "9121932be2e599d11d225d1a66530459a7d08399ff7e64937a840504f852ce44" {
		t.Fatalf("SHA-512/256 alias: got %q, err=%v", got, err)
	}
	const md5Digest = "ed1a4cb602d450909991fa0ee6bad099"
	for _, tc := range []struct{ enc, want string }{
		{"base64", "7RpMtgLUUJCZkfoO5rrQmQ=="},
		{"base64url", "7RpMtgLUUJCZkfoO5rrQmQ"},
		{"base32", "5UNEZNQC2RIJBGMR7IHONOWQTE======"},
	} {
		encoded, err := encodeHashOutput(md5Digest, tc.enc)
		if err != nil || encoded != tc.want {
			t.Errorf("hash -e %s: got %q, err=%v; want %q", tc.enc, encoded, err, tc.want)
		}
	}
	if _, err := encodeHashOutput("$2b$...", "base64"); err == nil {
		t.Error("structured hashes must reject binary output encoding")
	}
}

func TestExpandedRawHashDetection(t *testing.T) {
	cases := []struct {
		length int
		want   []string
	}{
		{32, []string{"lm"}},
		{56, []string{"sha512_224", "sha3_224"}},
		{64, []string{"sha512_256", "keccak256", "shake128-256", "blake2b256"}},
		{96, []string{"sha3_384", "blake2b384"}},
		{128, []string{"keccak512", "shake256-512"}},
	}
	for _, tc := range cases {
		got := detectHashTypes(strings.Repeat("a", tc.length))
		for _, want := range tc.want {
			found := false
			for _, item := range got {
				if item == want {
					found = true
					break
				}
			}
			if !found {
				t.Errorf("%d-char detection omitted %q: %v", tc.length, want, got)
			}
		}
	}
	if got := identifyText("deadbeef"); !strings.Contains(got, "CRC-32") {
		t.Errorf("checksum identification missing: %s", got)
	}
}
