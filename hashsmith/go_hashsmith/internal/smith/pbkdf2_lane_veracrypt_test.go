package smith

import "testing"

// veraCryptSHA256BootXTS512HashcatVector mirrors
// selftest_vectors_crypt_cascades.go's own published vector for the
// cheapest SHA-256 mode (boot, xts512 — 200000 iterations, a 64-byte
// derived key). Its own record shape (a valid 512-byte hex/$veracrypt$
// header) is enough to exercise parsing and malformed-record refusal
// without running any PBKDF2 iterations — the real correctness checks,
// which cannot avoid VeraCrypt's fixed 200000/500000 iteration counts, live
// in pbkdf2_lane_veracrypt_slow_test.go under the project's existing
// slowtest build tag (see crack_hashcat_crypt_cascades_slow_test.go).
const veraCryptSHA256BootXTS512HashcatVector = "$veracrypt$c8a5f07efc320ecd797ac2c5b911b0f7ee688f859890dd3fa39b4808eb3113219e2bf1517f46a20feba286a3f3e997c80361132262bc0dacb6e9f7088bec9f56$89a0b989ad9d4cc847170422ecd3384c9ee5ccf813fa8fe8ba4d2e6a993c99032337032b83471e9e0aa2531d85481c6d66f3a0d24688e1a17b5e81b3f68736ed05279ac05bcb83bea0c813d807e8c5547f11774c93a0e9de280c1ac5b5f170c0a4b5234f7d0d35a8ec7ec69454607cd35be24428a7be1799beed0ccd6a2af49b920446ebb0cb0bebda4a86c386fcffbb61cb93894ad74819a288c6e5b2e12111011e9f149d165b91f79897f71a96bc17c2b7a5e184147a90e9289d143b597ea98797c560e91b454461d03182f1a6c0bfd2b332829f30f0f18c8253d3194aac7996d4c401a3c1de7b266962a7dd8bc0b071a357121f00bafda835584a119f8fa23306545c413856ad3b2784b8de8ce9377f180baeb0f41590eb603110ff0a82f67349711d6f1b5d707f9c655318af88530962b9127fcf3c73b4d26319a9760cd795cd5ecba203dade9e1c79af14a9e06b9b56ce0af024e6ac582bd3ced1051fb865b55b4b6eaa65789a0c31c04cc4f2fc7b458fda188907f16810f4ce6e12a264cdcb264f1c26533758b92f585a3bbc2cac84731d74e9603d1c43b321ca36b01e5724e0e5558bcba56b57c8d59ded93c12d2664350cf6a048bcfc5d62aa85c590"

func TestNewPBKDF2VeraCryptSHA256LaneHasherRefusesNonSHA256AndMalformedRecords(t *testing.T) {
	sha256Mode := cryptCascadeModes["veracrypt-sha256-boot-xts512"]
	ripemdMode := cryptCascadeModes["veracrypt-ripemd160-boot-xts512"]

	cases := []struct {
		target string
		mode   cryptCascadeMode
	}{
		{"", sha256Mode},
		{"not a record", sha256Mode},
		{veraCryptSHA256BootXTS512HashcatVector, ripemdMode}, // wrong KDF for this mode
	}
	for _, c := range cases {
		if h := newPBKDF2VeraCryptSHA256LaneHasher(c.target, c.mode); h != nil {
			t.Errorf("newPBKDF2VeraCryptSHA256LaneHasher(%q, %+v) should have been refused", c.target, c.mode)
		}
	}
}

func TestNewLaneHasherVeraCryptSHA256RefusesNonSHA256Modes(t *testing.T) {
	// A RIPEMD-160 mode must never be accelerated by the SHA-256 core.
	ripemdVector := "$veracrypt$c8a5f07efc320ecd797ac2c5b911b0f7ee688f859890dd3fa39b4808eb3113219e2bf1517f46a20feba286a3f3e997c80361132262bc0dacb6e9f7088bec9f5689a0b989ad9d4cc847170422ecd3384c9ee5ccf813fa8fe8ba4d2e6a993c99032337032b83471e9e0aa2531d85481c6d66f3a0d24688e1a17b5e81b3f68736ed05279ac05bcb83bea0c813d807e8c5547f11774c93a0e9de280c1ac5b5f170c0a4b5234f7d0d35a8ec7ec69454607cd35be24428a7be1799beed0ccd6a2af49b920446ebb0cb0bebda4a86c386fcffbb61cb93894ad74819a288c6e5b2e12111011e9f149d165b91f79897f71a96bc17c2b7a5e184147a90e9289d143b597ea98797c560e91b454461d03182f1a6c0bfd2b332829f30f0f18c8253d3194aac7996d4c401a3c1de7b266962a7dd8bc0b071a357121f00bafda835584a119f8fa23306545c413856ad3b2784b8de8ce9377f180baeb0f41590eb603110ff0a82f67349711d6f1b5d707f9c655318af88530962b9127fcf3c73b4d26319a9760cd795cd5ecba203dade9e1c79af14a9e06b9b56ce0af024e6ac582bd3ced1051fb865b55b4b6eaa65789a0c31c04cc4f2fc7b458fda188907f16810f4ce6e12a264cdcb264f1c26533758b92f585a3bbc2cac84731d74e9603d1c43b321ca36b01e5724e0e5558bcba56b57c8d59ded93c12d2664350cf6a048bcfc5d62aa85c590"
	if _, _, ok := newLaneHasher("veracrypt-ripemd160-boot-xts512", ripemdVector, "", ""); ok {
		t.Fatal("newLaneHasher(\"veracrypt-ripemd160-boot-xts512\", ...) was unexpectedly eligible")
	}
}
