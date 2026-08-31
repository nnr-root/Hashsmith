package main

import "testing"

// Real VeraCrypt volume header (hashcat mode 13721 example, PBKDF2-HMAC-SHA512 +
// AES-XTS), passphrase "hashcat". A genuine container header, so a true result
// validates the full PBKDF2 + AES-XTS + magic/CRC pipeline end to end.
const vcSHA512Header = "9ecdaf95d05ccf063e8450725b53aa7a1eab419b1b60057a97e8f1ac3c70705c7b298c5443acbdb3507281348fb059cbe7c797877af7fb780454e58595da13aa41ef9346b7601aeac99f4a478d3f0274a9c905d6f46d462d5da920e149f4613e6d80605013b880e9a2c3421fe685beef4916fd09baabacfee14f6d3335675586fb6735484f059fc51f118ae3bd02e888d092b1078a640d235daf8182c8c9d3182359d8a860f00584ce5bfe8f579758ad7196559b6e436e9914a86bad66e237a724999250ed2ded10cabe8f0a3e618194287b2d6e19cf9b83c7b00489876d418460c9c9cbacaa1d26637e0cb6c34df43b17acdd7f6dff18122e8f791b6db5eea14f4cacc4d5e9bd4d8c3c689a1c541e5f650e17788b8e62aa8b77074e0169564af47dc9de64fedf274d373cac7b684cfd03a782da20d0fde4b980c397cbecbf5e15e6effd12940a7f275878c427869be36031eac319dcccc01d0c7de25fd4f10ad4f3f76990e1ec46055529971cb81ce868d9e5179bb7c1be4388b4132e198b3b295a2e96bf777ecfc1e30e263aec5eab79e0c1f6504a93a53c64ade9d51ab11550696c70e19df0c1e956f1c544de73f35f93bfdcb11b0a2f5052840837e34e349d16a8206a2d13d769078356b91828bc1ac077d9ac54a9f2c25c5b3470143c2a8c1309492f356aef20bd289f35333c631d06e79961e98b8e96ec1149977383d3"

// The fast half of the TestVeraCryptVector split: detection must resolve
// this header to "veracrypt" without running the slow PBKDF2 + AES-XTS
// verification. See crack_veracrypt_slow_test.go (slowtest tag) for the KDF
// verification half.
func TestVeraCryptVectorDetection(t *testing.T) {
	if got := detectHashTypes("veracrypt:" + vcSHA512Header); len(got) != 1 || got[0] != "veracrypt" {
		t.Errorf("detectHashTypes = %v, want [veracrypt]", got)
	}
}
