package smith

import "testing"

func TestDecodeHCStat2MatchesKnownFixtureCounts(t *testing.T) {
	tbl, err := loadHCStat2Tables("testdata/hcstat2_sample.hcstat2")
	if err != nil {
		t.Fatalf("loadHCStat2Tables: %v", err)
	}
	cases := []struct {
		name string
		got  uint64
		want uint64
	}{
		{"root[0]['a']", tbl.root[0]['a'], 3},
		{"root[0]['z']", tbl.root[0]['z'], 1},
		{"root[1]['a']", tbl.root[1]['a'], 3},
		{"root[2]['b']", tbl.root[2]['b'], 1},
		{"root[2]['c']", tbl.root[2]['c'], 1},
		{"root[2]['d']", tbl.root[2]['d'], 1},
		{"root[2]['z']", tbl.root[2]['z'], 1},
		{"markov[0]['a']['a']", tbl.markov[0]['a']['a'], 3},
		{"markov[1]['a']['b']", tbl.markov[1]['a']['b'], 1},
		{"markov[1]['a']['c']", tbl.markov[1]['a']['c'], 1},
		{"markov[1]['a']['d']", tbl.markov[1]['a']['d'], 1},
		{"markov[2]['b']['b']", tbl.markov[2]['b']['b'], 0},
	}
	for _, c := range cases {
		if c.got != c.want {
			t.Errorf("%s = %d, want %d", c.name, c.got, c.want)
		}
	}
}

func TestDecodeHCStat2RejectsGarbage(t *testing.T) {
	if _, err := decodeHCStat2([]byte("not a real hcstat2 file")); err == nil {
		t.Fatal("decodeHCStat2 accepted garbage input")
	}
}

func TestLoadHCStat2TablesRejectsMissingFile(t *testing.T) {
	if _, err := loadHCStat2Tables("testdata/does-not-exist.hcstat2"); err == nil {
		t.Fatal("loadHCStat2Tables accepted a missing path")
	}
}
