package main

import "testing"

const (
	krb5ASREPAES128Vector  = "$krb5asrep$17$user$EXAMPLE.COM$a419c4030e555734b06c2629$c09a1421f96eb126c757a4b87830381f142477d9a85b2beb3093dbfd44f38ddb6016a479537fb7b36e046315869fe79187217971ff6a12c1e0a2df3f68045e03814b21f756d8981f781803d65e8572823c88979581d93cf7d768f2efced16f3719b8d1004d9e73d798de255383476bced47d1982f16be77d0feb55a1f44f58bd013fa4caee58ac614caf0f1cf9101ec9623c5b8c2a1491b73f134f074790088fdb360b5ebce0d32a8145ed00a81ddf77188e150b92d8e8ddd0285d27f1514253e5546e6bba864b362bb1e6483b26d08fa4cc268bfbefe0f690039bcc524b774599df3680c1c3431d891bfa99514a877f964e"
	krb5ASREPAES256Vector  = "$krb5asrep$18$user$EXAMPLE.COM$aa4c494f520b27873a4de8f7$ebc9976a77f62e8ccca02d43d68bafcc66a81fcbb44a336b00ce401982f32975a5f9bcdc752643252185866685b0a30aaf50e449e392a5994e6979f23aba25f7704c90b2efa03b703c3c2f9e3617cc588ed226d0417e7742d45407878fd946d046b4a9732b9a203cb857811714b009c195b7c96b9bccb7e48832b11a4e92ecf24c49e54de8d0d5d5351445b5126db90bb7eebc7861db1e61de1175824b0a45023a6fa06c2a9d3035fdcf863bea922648e3dc28b48e39b1dec0869e7fe4de399cb52dfcf2596599da54a4bb0169c72d9496de2e137a4594e0e8a69082fc558ac9ace65d32eae5e260a65ca3f2f5871aaeee7a3b090b50f39321d120c144421e0abe7d"
	krb5TGSNTVector        = "$krb5tgs$23$*user$realm$test/spn*$b548e10f5694ae018d7ad63c257af7dc$35e8e45658860bc31a859b41a08989265f4ef8afd75652ab4d7a30ef151bf6350d879ae189a8cb769e01fa573c6315232b37e4bcad9105520640a781e5fd85c09615e78267e494f433f067cc6958200a82f70627ce0eebc2ac445729c2a8a0255dc3ede2c4973d2d93ac8c1a56b26444df300cb93045d05ff2326affaa3ae97f5cd866c14b78a459f0933a550e0b6507bf8af27c2391ef69fbdd649dd059a4b9ae2440edd96c82479645ccdb06bae0eead3b7f639178a90cf24d9a"
	krb5ASREPNTVector      = "$krb5asrep$23$user@domain.com:3e156ada591263b8aab0965f5aebd837$007497cb51b6c8116d6407a782ea0e1c5402b17db7afa6b05a6d30ed164a9933c754d720e279c6c573679bd27128fe77e5fea1f72334c1193c8ff0b370fadc6368bf2d49bbfdba4c5dccab95e8c8ebfdc75f438a0797dbfb2f8a1a5f4c423f9bfc1fea483342a11bd56a216f4d5158ccc4b224b52894fadfba3957dfe4b6b8f5f9f9fe422811a314768673e0c924340b8ccb84775ce9defaa3baa0910b676ad0036d13032b0dd94e3b13903cc738a7b6d00b0b3c210d1f972a6c7cae9bd3c959acf7565be528fc179118f28c679f6deeee1456f0781eb8154e18e49cb27b64bf74cd7112a0ebae2102ac"
	blockchainLegacyVector = "$blockchain$269$0349575305940509451603791869345994679e29d1618f26ed65ee15ad65d1af046f51ffcfbfa82dcccea07bb0f0fff725af53b96910646440b361453addc5caeb2a09479dc6cce3a1ebf138e2649689ab286ba2db6bd5edef310cac8f9386f002a534e9346cdc61bd0e21ca738eb2418a8158c83a43517981c43d8792cad6f290cbf40d5a3c1bb20283fcb44c59cae2dc90c898dbc4e960ca666653a08d90471610a8b9bf590752e8d8bee27e7aa58d015324dae83c87a46384ed8f947e37e65d4572018b5bfd8fd8ea70df777c8b692bc613ccb528356d1844490ac2b3be2dd8927fbf1aabf9b6cedec39742ed92a03220f4468bd32c1eed5d5c3c3aa0be459e06466c94991df97f335bd661"
)

func TestHashcatStateExpansionPublishedVectors(t *testing.T) {
	tests := []struct {
		mode, password, target string
	}{
		{"32100", "hashcat", krb5ASREPAES128Vector},
		{"32200", "hashcat", krb5ASREPAES256Vector},
		{"33000", "hashcat", "036a81bc84e01700faf965c3caaa3954:0243402616975530019305541949338903179746132451440267505028190519468680111713847350899833009965414425621884797638402856957040435715380438220464016:0757380776148401126145133134435506200715895167468508855794708942913462135276430452032928239699197100625556660484150983610760766285767453357925167463064045123083116191440783332986105343359475417787249790516137833723344398087127577224833364437305770807742238"},
		{"33500", "hashc", "$rc4$40$0$e9a41693b759cf88929ca31203694f$0$48656c6c6f"},
		{"33501", "hashcat12", "$rc4$72$0$90eaa8d71c$0$48656c6c6f"},
		{"33502", "hashcat123456", "$rc4$104$0$a04245c3d7$0$48656c6c6f"},
		{"34700", "hashcat", blockchainLegacyVector},
		{"35300", "b4b9b02e6f09a9bd760f388b67351e2b", krb5TGSNTVector},
		{"35400", "b4b9b02e6f09a9bd760f388b67351e2b", krb5ASREPNTVector},
		{"35700", "hashcat", "$H$9ZtU3uM7Twc8X53ImNRhaec4b3QHJ91"},
		{"35800", "hashcat", "e65e9e4f3cd2f28dd8f18de72a465b3a8cd982ba615fada61842ecea05ca0c9c:3fd6486e7c9d4eb920275412198bb7f8ed7eacd53ba953dd50f1e481952c15b5"},
	}
	for _, tc := range tests {
		t.Run(tc.mode, func(t *testing.T) {
			ok, err := verifyCandidate(tc.password, tc.target, tc.mode, "", "prefix")
			if err != nil || !ok {
				t.Fatalf("published vector: ok=%v err=%v", ok, err)
			}
			if bad, err := verifyCandidate(wrongPassword(tc.password), tc.target, tc.mode, "", "prefix"); err != nil || bad {
				t.Fatalf("wrong password: ok=%v err=%v", bad, err)
			}
		})
	}
}

func TestHashcatStateExpansionRejectsMalformedRecords(t *testing.T) {
	tests := map[string]string{
		"33000": "abcd:left:right",
		"33500": "$rc4$40$bad$cipher$0$plain",
		"34700": "$blockchain$10$abcd",
		"35300": "$krb5tgs$18$bad",
		"35400": "$krb5asrep$18$bad",
		"35700": "$H$bad",
		"35800": "abcd:salt",
	}
	for mode, target := range tests {
		if _, err := verifyCandidate("hashcat", target, mode, "", "prefix"); err == nil {
			t.Errorf("mode %s accepted malformed record %q", mode, target)
		}
	}
}

func TestHashcatStateExpansionAutoDetection(t *testing.T) {
	tests := []struct {
		target string
		want   string
	}{
		{"$rc4$40$0$e9a41693b759cf88929ca31203694f$0$48656c6c6f", "rc4-dropn"},
		{blockchainLegacyVector, "blockchain-legacy"},
		{"$H$9ZtU3uM7Twc8X53ImNRhaec4b3QHJ91", "phpass-md5"},
		{krb5ASREPNTVector, "krb5asrep-nt"},
		{krb5TGSNTVector, "krb5tgs-nt"},
		{"e65e9e4f3cd2f28dd8f18de72a465b3a8cd982ba615fada61842ecea05ca0c9c:3fd6486e7c9d4eb920275412198bb7f8ed7eacd53ba953dd50f1e481952c15b5", "symfony-legacy"},
	}
	for _, tc := range tests {
		got := detectHashTypes(tc.target)
		found := false
		for _, typ := range got {
			if typ == tc.want {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("detectHashTypes(%q) = %v, missing %s", tc.target, got, tc.want)
		}
	}
}
