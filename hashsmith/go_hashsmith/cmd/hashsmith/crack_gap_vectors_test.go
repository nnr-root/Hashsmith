package main

import "testing"

// Published self-test records from Hashcat's corresponding module_*.c files.
// These pin both the canonical record syntax and the verifier result.
func TestHashcatGapVectors(t *testing.T) {
	cases := []struct {
		typ, target string
	}{
		{"mssql2012", "0x02003788006711b2e74e7d8cb4be96b1d187c962c5591a02d5a6ae81b3a4a094b26b7877958b26733e45016d929a756ed30d0a5ee65d3ce1970f9b7bf946e705c595f07625b1"},
		{"cisco-pix", "dRRVnUmUHXOTt9nk"},
		{"ethereum", "$ethereum$p*1024*38353131353831333338313138363430*a8b4dfe92687dbc0afeb5dae7863f18964241e96b264f09959903c8c924583fc*0a9252861d1e235994ce33dbca91c98231764d8ecb4950015a8ae20d6415b986"},
		{"netntlmv1", "::5V4T:ada06359242920a500000000000000000000000000000000:0556d5297b5daa70eaffde82ef99293a3f3bb59b7c9704ea:9c23f6c094853920"},
		{"netntlmv2", "0UL5G37JOI0SX::6VB1IS0KA74:ebe1afa18b7fbfa6:aab8bf8675658dd2a939458a1077ba08:010100000000000031c8aa092510945398b9f7b7dde1a9fb00000000f7876f2b04b700"},
		{"office", "$office$*2007*20*128*16*18410007331073848057180885845227*944c70a5ee6e5ab2a6a86ff54b5f621a*e6650f1f2630c27fd8fc0f5e56e2e01f99784b9f"},
		{"pbkdf1", "PBKDF1:sha1:1000:cGVuZ3VpbmtlZXBlcg==:J4BrIhXDUHNQ9lPPrWKn4V7Of9Y="},
		{"pdf", "$pdf$1*2*40*-1*0*16*01221086741440841668371056103222*32*27c3fecef6d46a78eb61b8b4dbc690f5f8a2912bbb9afc842c12d79481568b74*32*0000000000000000000000000000000000000000000000000000000000000000"},
		{"rar4", "$RAR3$*0*45109af8ab5f297a*adbf6c5385d7a40373e8f77d7b89d317"},
		{"shiro1-sha512", "$shiro1$SHA-512$1024$WobJGSjbUhsMdaILomMOdw==$9uptGJ24vzZCqZI55F77N7xjUxGlVrK5aCmAwIrV1vwDmFM4akE6Hmd23Aj8ANLSUdIEkHLZ6SnoitZbOsoQNQ=="},
		{"7z", "$7z$0$14$0$$11$33363437353138333138300000000000$2365089182$16$12$d00321533b483f54a523f624a5f63269"},
		{"truecrypt", tcRIPEMD160AESHeader},
	}
	for _, tc := range cases {
		t.Run(tc.typ, func(t *testing.T) {
			ok, err := verifyCandidate("hashcat", tc.target, tc.typ, "", "prefix")
			if err != nil || !ok {
				t.Fatalf("correct password: ok=%v err=%v", ok, err)
			}
			if bad, err := verifyCandidate("wrong", tc.target, tc.typ, "", "prefix"); err != nil || bad {
				t.Fatalf("wrong password: ok=%v err=%v", bad, err)
			}
		})
	}
}
