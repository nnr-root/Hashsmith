package main

import "testing"

// AIX {ssha256}/{ssha512} (hashcat modes 6400/6500), password "hashcat".
func TestAIXVectors(t *testing.T) {
	for _, h := range []string{
		"{ssha256}06$aJckFGJAB30LTe10$ohUsB7LBPlgclE3hJg9x042DLJvQyxVCX.nZZLEz.g2",
		"{ssha512}06$bJbkFGJAB30L2e23$bXiXjyH5YGIyoWWmEVwq67nCU5t7GLy9HkCzrodRCQCx3r9VvG98o7O3V0r9cVrX3LPPGuHqT5LLn0oGCuI1..",
	} {
		if ok, err := verifyAIX(h, "hashcat"); err != nil || !ok {
			t.Errorf("AIX verify failed for %.20s: ok=%v err=%v", h, ok, err)
		}
		if ok, _ := verifyAIX(h, "wrong"); ok {
			t.Errorf("AIX should reject wrong pass for %.20s", h)
		}
		if got := detectHashTypes(h); len(got) != 1 || got[0] != "aix" {
			t.Errorf("detectHashTypes = %v, want [aix]", got)
		}
	}
}
