package main

import "testing"

// Blockchain.info My Wallet v2 (hashcat mode 15200 example), password "hashcat".
func TestBlockchainVector(t *testing.T) {
	h := "$blockchain$v2$5000$288$06063152445005516247820607861028813ccf6dcc5793dc0c7a82dcd604c5c3e8d91bea9531e628c2027c56328380c87356f86ae88968f179c366da9f0f11b09492cea4f4d591493a06b2ba9647faee437c2f2c0caaec9ec795026af51bfa68fc713eaac522431da8045cc6199695556fc2918ceaaabbe096f48876f81ddbbc20bec9209c6c7bc06f24097a0e9a656047ea0f90a2a2f28adfb349a9cd13852a452741e2a607dae0733851a19a670513bcf8f2070f30b115f8bcb56be2625e15139f2a357cf49d72b1c81c18b24c7485ad8af1e1a8db0dc04d906935d7475e1d3757aba32428fdc135fee63f40b16a5ea701766026066fb9fb17166a53aa2b1b5c10b65bfe685dce6962442ece2b526890bcecdeadffbac95c3e3ad32ba57c9e"
	if ok, err := verifyBlockchain(h, "hashcat"); err != nil || !ok {
		t.Errorf("Blockchain verify failed: ok=%v err=%v", ok, err)
	}
	if ok, _ := verifyBlockchain(h, "wrong"); ok {
		t.Error("Blockchain should reject the wrong passphrase")
	}
	if got := detectHashTypes(h); len(got) != 1 || got[0] != "blockchain" {
		t.Errorf("detectHashTypes(blockchain) = %v", got)
	}
}
