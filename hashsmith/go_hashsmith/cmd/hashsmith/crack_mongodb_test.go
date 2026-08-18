package main

import "testing"

// MongoDB SCRAM-SHA-1 vector (user "admin", passphrase "hashsmith"), Python-generated.
func TestMongoDBVector(t *testing.T) {
	h := "$mongodb-scram$0$admin$10000$ABEiM0RVZnc=$LQB5XFSjMV1evSGM1T44f917wkM="
	if ok, err := verifyMongoDB(h, "hashsmith"); err != nil || !ok {
		t.Errorf("MongoDB verify failed: ok=%v err=%v", ok, err)
	}
	if ok, _ := verifyMongoDB(h, "wrong"); ok {
		t.Error("MongoDB should reject the wrong passphrase")
	}
	if got := detectHashTypes(h); len(got) != 1 || got[0] != "mongodb" {
		t.Errorf("detectHashTypes(mongodb) = %v", got)
	}
}
