package main

import "testing"

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
		// HMAC — key = password (message is the salt).
		{"hmac-md5", salt, "", "4280c04958cc9edb5583e01e49d78e53"},
		{"hmac-sha1", salt, "", "ece79aa2c3183a618d68ef180f10167e26e140ef"},
		{"hmac-sha256", salt, "", "ed98cce4eb56a6c6d5072d1d1e2f1ba875ce716f74a433a0de3feb848c96d465"},
		{"hmac-sha512", salt, "", "ed87614bfeadac22d8b7e8e49c8cc8dbfd2f8b4d7ecc0a01bf07c2fdb4d8b70011be3ce12fb1f64098d0d22c8359b98662eb55a85a07bbac8f145fabb05c2299"},
		// HMAC — key = salt (message is the password).
		{"hmac-md5-saltkey", salt, "", "3e47c2e89e6f3ae6be2b4838d7b90c5e"},
		{"hmac-sha1-saltkey", salt, "", "c8d35b1bef34a241900c37ff098b6d269291bc30"},
		{"hmac-sha256-saltkey", salt, "", "2ddfacc146d8c75950a8789b39d70230bebbc4d48ba29b64964870519473a356"},
		{"hmac-sha512-saltkey", salt, "", "00e58824267ae4497b52a7d5e0953e44be340096b24a67a6c933dc5ecd8bd646fb73d5e4788db0a7d448c1b0d71ebb840067183178b719268711c3d01c09cdbe"},
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
