package smith

import "testing"

func TestRunCoordinateRequiresType(t *testing.T) {
	err := runCoordinate([]string{"--workers", "http://x", "--token", "t", "--chunk-size", "100", "--mask", "?l", "x"})
	if err == nil {
		t.Fatal("expected an error when -t is missing")
	}
}

func TestRunCoordinateRequiresWorkers(t *testing.T) {
	err := runCoordinate([]string{"-t", "md5", "--token", "t", "--chunk-size", "100", "--mask", "?l", "x"})
	if err == nil {
		t.Fatal("expected an error when --workers is missing")
	}
}

func TestRunCoordinateRequiresToken(t *testing.T) {
	err := runCoordinate([]string{"-t", "md5", "--workers", "http://x", "--chunk-size", "100", "--mask", "?l", "x"})
	if err == nil {
		t.Fatal("expected an error when --token is missing")
	}
}

func TestRunCoordinateRequiresChunkSize(t *testing.T) {
	err := runCoordinate([]string{"-t", "md5", "--workers", "http://x", "--token", "t", "--mask", "?l", "x"})
	if err == nil {
		t.Fatal("expected an error when --chunk-size is missing (there is no safe default)")
	}
}

func TestRunCoordinateRequiresExactlyOneTarget(t *testing.T) {
	err := runCoordinate([]string{"-t", "md5", "--workers", "http://x", "--token", "t", "--chunk-size", "100", "--mask", "?l"})
	if err == nil {
		t.Fatal("expected an error when no target is given")
	}
}
