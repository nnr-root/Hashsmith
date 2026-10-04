package smith

import (
	"reflect"
	"testing"
)

func TestBuildCrackArgsMask(t *testing.T) {
	req := chunkRequest{
		Type: "md5", Target: "5f4dcc3b5aa765d61d8327deb882cf99",
		Mode: "mask", Mask: "?l?l?l?l?l?l",
		Skip: 1000, Limit: 500,
	}
	got, err := buildCrackArgs(req, "/tmp/out.txt")
	if err != nil {
		t.Fatal(err)
	}
	want := []string{
		"-t", "md5",
		"--skip", "1000", "--limit", "500",
		"--no-pot", "-o", "/tmp/out.txt",
		"-M", "mask", "--mask", "?l?l?l?l?l?l",
		"5f4dcc3b5aa765d61d8327deb882cf99",
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got  %v\nwant %v", got, want)
	}
}

func TestBuildCrackArgsMaskWithCustomCharsetsAndSalt(t *testing.T) {
	req := chunkRequest{
		Type: "md5", Target: "deadbeef", Salt: "abcd", SaltMode: "suffix",
		Mode: "mask", Mask: "?1?1?1", Charset1: "xyz",
		Skip: 0, Limit: 27,
	}
	got, err := buildCrackArgs(req, "/tmp/out.txt")
	if err != nil {
		t.Fatal(err)
	}
	want := []string{
		"-t", "md5", "-s", "abcd", "-S", "suffix",
		"--skip", "0", "--limit", "27",
		"--no-pot", "-o", "/tmp/out.txt",
		"-M", "mask", "--mask", "?1?1?1", "-1", "xyz",
		"deadbeef",
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got  %v\nwant %v", got, want)
	}
}

func TestBuildCrackArgsBrute(t *testing.T) {
	req := chunkRequest{
		Type: "md5", Target: "deadbeef",
		Mode: "brute", Charset: "abc", MinLen: 1, MaxLen: 3,
		Skip: 0, Limit: 39,
	}
	got, err := buildCrackArgs(req, "/tmp/out.txt")
	if err != nil {
		t.Fatal(err)
	}
	want := []string{
		"-t", "md5",
		"--skip", "0", "--limit", "39",
		"--no-pot", "-o", "/tmp/out.txt",
		"-M", "brute", "-C", "abc", "-n", "1", "-x", "3",
		"deadbeef",
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got  %v\nwant %v", got, want)
	}
}

func TestBuildCrackArgsDict(t *testing.T) {
	req := chunkRequest{
		Type: "md5", Target: "deadbeef",
		Mode: "dict", Wordlist: "/shared/words.txt",
		Skip: 0, Limit: 100,
	}
	got, err := buildCrackArgs(req, "/tmp/out.txt")
	if err != nil {
		t.Fatal(err)
	}
	want := []string{
		"-t", "md5",
		"--skip", "0", "--limit", "100",
		"--no-pot", "-o", "/tmp/out.txt",
		"-M", "dict", "-w", "/shared/words.txt",
		"deadbeef",
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got  %v\nwant %v", got, want)
	}
}

func TestBuildCrackArgsRejectsMissingRequiredFields(t *testing.T) {
	cases := []struct {
		name string
		req  chunkRequest
	}{
		{"missing type", chunkRequest{Target: "x", Mode: "mask", Mask: "?l", Limit: 1}},
		{"missing target", chunkRequest{Type: "md5", Mode: "mask", Mask: "?l", Limit: 1}},
		{"negative skip", chunkRequest{Type: "md5", Target: "x", Mode: "mask", Mask: "?l", Skip: -1, Limit: 1}},
		{"zero limit", chunkRequest{Type: "md5", Target: "x", Mode: "mask", Mask: "?l", Limit: 0}},
		{"mask mode missing mask", chunkRequest{Type: "md5", Target: "x", Mode: "mask", Limit: 1}},
		{"brute mode missing charset", chunkRequest{Type: "md5", Target: "x", Mode: "brute", MinLen: 1, MaxLen: 2, Limit: 1}},
		{"dict mode missing wordlist", chunkRequest{Type: "md5", Target: "x", Mode: "dict", Limit: 1}},
		{"unknown mode", chunkRequest{Type: "md5", Target: "x", Mode: "nonsense", Limit: 1}},
	}
	for _, c := range cases {
		if _, err := buildCrackArgs(c.req, "/tmp/out.txt"); err == nil {
			t.Errorf("%s: expected an error, got none", c.name)
		}
	}
}
