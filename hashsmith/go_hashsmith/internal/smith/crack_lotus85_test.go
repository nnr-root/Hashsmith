package smith

import "testing"

// Both records come from John's lotus85_fmt_plug.c.
func TestVerifyLotus85(t *testing.T) {
	cases := []struct{ record, password string }{
		{"0040B2B17C344C236953F955B28E4865014034D1F664489D7F42B35FB6928A94DCFFEF7750CE029F94C83A582A80B4662D49B3FA45816143", "notesisterrible"},
		{"CBCFC612FAE3154316223787C7CD29AD39BEDF4288FCDE310B32FD809C75F5FDC521667D5F6E7A047766F0E60952F7891593FFAF45AD0C15", "openwall"},
	}
	for _, c := range cases {
		ok, err := verifyLotus85(c.record, c.password)
		if err != nil {
			t.Fatalf("verifyLotus85(%.16s..., %q): %v", c.record, c.password, err)
		}
		if !ok {
			t.Errorf("verifyLotus85(%.16s..., %q) = false, want true", c.record, c.password)
		}
		if bad, err := verifyLotus85(c.record, c.password+"x"); err != nil || bad {
			t.Errorf("verifyLotus85(%.16s..., wrong password) = %v, %v; want false, nil", c.record, bad, err)
		}
	}
}
