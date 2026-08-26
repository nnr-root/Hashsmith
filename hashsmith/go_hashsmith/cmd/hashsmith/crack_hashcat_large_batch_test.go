package main

import "testing"

func publishedVectorForType(t *testing.T, typ string) selfTestVector {
	t.Helper()
	for _, vector := range selfTestVectors {
		if vector.typ == typ {
			return vector
		}
	}
	t.Fatalf("missing vector for %s", typ)
	return selfTestVector{}
}

func TestHashcatLargeBatchPublishedVectorsAndAliases(t *testing.T) {
	cases := []struct{ mode, typ string }{
		{"28501", "bitcoin-wif-p2pkh-compressed"}, {"28502", "bitcoin-wif-p2pkh-uncompressed"},
		{"28503", "bitcoin-wif-p2wpkh-compressed"}, {"28504", "bitcoin-wif-p2wpkh-uncompressed"},
		{"28505", "bitcoin-wif-p2sh-p2wpkh-compressed"}, {"28506", "bitcoin-wif-p2sh-p2wpkh-uncompressed"},
		{"30901", "bitcoin-raw-p2pkh-compressed"}, {"30902", "bitcoin-raw-p2pkh-uncompressed"},
		{"30903", "bitcoin-raw-p2wpkh-compressed"}, {"30904", "bitcoin-raw-p2wpkh-uncompressed"},
		{"30905", "bitcoin-raw-p2sh-p2wpkh-compressed"}, {"30906", "bitcoin-raw-p2sh-p2wpkh-uncompressed"},
		{"24410", "pkcs8-pem-sha1"}, {"24420", "pkcs8-pem-sha256"},
		{"15500", "jks-private-key"}, {"27400", "vmware-vmx"},
		{"27500", "virtualbox-aes128"}, {"27600", "virtualbox-aes256"},
		{"26600", "metamask"}, {"26610", "metamask-short"}, {"28200", "exodus"},
	}
	for _, tc := range cases {
		t.Run(tc.mode, func(t *testing.T) {
			if got := canonicalHashType(tc.mode); got != tc.typ {
				t.Fatalf("canonicalHashType(%q) = %q, want %q", tc.mode, got, tc.typ)
			}
			v := publishedVectorForType(t, tc.typ)
			ok, err := verifyCandidate(v.password, v.target, tc.mode, "", "prefix")
			if err != nil || !ok {
				t.Fatalf("official vector failed: ok=%v err=%v", ok, err)
			}
			if bad, _ := verifyCandidate("definitely-wrong", v.target, tc.mode, "", "prefix"); bad {
				t.Fatal("accepted wrong candidate")
			}
		})
	}
}

func TestHashcatLargeBatchDetection(t *testing.T) {
	cases := []struct {
		target string
		want   string
	}{
		{"$PEM$1$4$00", "pkcs8-pem-sha1"},
		{"$PEM$2$4$00", "pkcs8-pem-sha256"},
		{"$jksprivk$*00", "jks-private-key"},
		{"$vmx$0$10000$00", "vmware-vmx"},
		{"$vbox$0$1$00$8$00", "virtualbox-aes128"},
		{"$vbox$0$1$00$16$00", "virtualbox-aes256"},
		{"$metamask$AA==$AA==$AA==", "metamask"},
		{"$metamask-short$AA==$AA==$AA==", "metamask-short"},
		{"EXODUS:16384:8:1:x", "exodus"},
	}
	for _, tc := range cases {
		got := detectHashTypes(tc.target)
		if len(got) == 0 || got[0] != tc.want {
			t.Fatalf("detectHashTypes(%q) = %v, want first %q", tc.target, got, tc.want)
		}
	}
	for _, target := range []string{
		"1Jv6EonXm9x4Dw4QjEPAhGfmzFxTL7b3Zj",
		"bc1qxd76a5zamfyw0g2d2rxkdh0zt9m0uzmxmwjf0q",
		"3H1YvmSdrjEfj9LvtiKJ8XiYq5htJRuejA",
	} {
		if got := detectHashTypes(target); len(got) != 4 {
			t.Fatalf("Bitcoin address detection returned %v", got)
		}
	}
}

func TestHashcatLargeBatchRejectsMalformedRecords(t *testing.T) {
	cases := []struct{ typ, target string }{
		{"pkcs8-pem-sha1", "$PEM$1$9$00$1$00$1$00"},
		{"jks-private-key", "$jksprivk$*00"},
		{"vmware-vmx", "$vmx$0$10000$00$00"},
		{"virtualbox-aes128", "$vbox$0$1$00$8$00$1$00$00"},
		{"metamask", "$metamask$not-base64$x$y"},
		{"metamask-short", "$metamask-short$AA==$AA==$AA=="},
		{"exodus", "EXODUS:3:8:1:x:x:x:x"},
	}
	for _, tc := range cases {
		if ok, err := verifyCandidate("hashcat", tc.target, tc.typ, "", "prefix"); ok || err == nil {
			t.Fatalf("%s malformed record: ok=%v err=%v", tc.typ, ok, err)
		}
	}
}
