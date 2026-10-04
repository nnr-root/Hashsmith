package smith

import (
	"errors"
	"fmt"
	"strconv"
)

// chunkRequest is the JSON body of a worker's POST /chunk — see
// docs/superpowers/specs/2026-10-03-distributed-coordinator-design.md.
type chunkRequest struct {
	Type     string `json:"type"`
	Target   string `json:"target"`
	Salt     string `json:"salt,omitempty"`
	SaltMode string `json:"saltMode,omitempty"`
	Mode     string `json:"mode"` // "mask" | "brute" | "dict"
	// mode == "mask"
	Mask     string `json:"mask,omitempty"`
	Charset1 string `json:"charset1,omitempty"`
	Charset2 string `json:"charset2,omitempty"`
	Charset3 string `json:"charset3,omitempty"`
	Charset4 string `json:"charset4,omitempty"`
	// mode == "brute"
	Charset string `json:"charset,omitempty"`
	MinLen  int    `json:"minLen,omitempty"`
	MaxLen  int    `json:"maxLen,omitempty"`
	// mode == "dict" — must already exist at this same path on the worker.
	Wordlist string `json:"wordlist,omitempty"`
	Skip     int64  `json:"skip"`
	Limit    int64  `json:"limit"`
}

// chunkResponse is the JSON body of a successful (200) /chunk response.
type chunkResponse struct {
	Found    bool   `json:"found"`
	Password string `json:"password,omitempty"`
}

// buildCrackArgs turns a validated chunkRequest into the exact []string a
// human would type for an equivalent local `hashsmith crack` invocation,
// writing its result to outFile via the existing -o mechanism. Returns an
// error for anything a caller should treat as a malformed request (HTTP
// 400), never for a "not found" outcome, which this function cannot see —
// that is determined later by whether outFile exists after runCrack runs.
func buildCrackArgs(req chunkRequest, outFile string) ([]string, error) {
	if req.Type == "" {
		return nil, errors.New("missing type")
	}
	if req.Target == "" {
		return nil, errors.New("missing target")
	}
	if req.Skip < 0 {
		return nil, errors.New("skip must be >= 0")
	}
	if req.Limit <= 0 {
		return nil, errors.New("limit must be > 0")
	}
	args := []string{"-t", req.Type}
	if req.Salt != "" {
		args = append(args, "-s", req.Salt)
	}
	if req.SaltMode != "" {
		args = append(args, "-S", req.SaltMode)
	}
	args = append(args,
		"--skip", strconv.FormatInt(req.Skip, 10),
		"--limit", strconv.FormatInt(req.Limit, 10),
		"--no-pot", "-o", outFile,
	)
	switch req.Mode {
	case "mask":
		if req.Mask == "" {
			return nil, errors.New("mode mask requires mask")
		}
		args = append(args, "-M", "mask", "--mask", req.Mask)
		if req.Charset1 != "" {
			args = append(args, "-1", req.Charset1)
		}
		if req.Charset2 != "" {
			args = append(args, "-2", req.Charset2)
		}
		if req.Charset3 != "" {
			args = append(args, "-3", req.Charset3)
		}
		if req.Charset4 != "" {
			args = append(args, "-4", req.Charset4)
		}
	case "brute":
		if req.Charset == "" || req.MinLen <= 0 || req.MaxLen <= 0 {
			return nil, errors.New("mode brute requires charset, minLen, and maxLen")
		}
		args = append(args, "-M", "brute", "-C", req.Charset,
			"-n", strconv.Itoa(req.MinLen), "-x", strconv.Itoa(req.MaxLen))
	case "dict":
		if req.Wordlist == "" {
			return nil, errors.New("mode dict requires wordlist")
		}
		args = append(args, "-M", "dict", "-w", req.Wordlist)
	default:
		return nil, fmt.Errorf("unknown mode %q: use mask, brute, or dict", req.Mode)
	}
	args = append(args, req.Target)
	return args, nil
}
