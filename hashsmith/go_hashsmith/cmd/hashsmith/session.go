package main

// A session persists the parameters and progress of a brute-force or mask run so
// an interrupted attack can pick up where it stopped. State lives in
// ~/.hashsmith/sessions/<name>.json and is flushed periodically during the run;
// on a clean finish (found or keyspace exhausted) the file is removed.
//
// The checkpoint is a global keyspace index (see keyspace.go). Because the
// candidate stream is deterministic, resuming from the saved index reproduces
// the exact remaining keyspace — at worst re-testing one chunk per worker.

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync/atomic"
	"time"
)

type sessionState struct {
	Name       string    `json:"name"`
	Mode       string    `json:"mode"`
	Type       string    `json:"type"`
	Target     string    `json:"target"`
	Charset    string    `json:"charset,omitempty"`
	MinLen     int       `json:"min_len,omitempty"`
	MaxLen     int       `json:"max_len,omitempty"`
	Mask       string    `json:"mask,omitempty"`
	Custom     [4]string `json:"custom,omitempty"`
	Increment  bool      `json:"increment,omitempty"`
	Salt       string    `json:"salt,omitempty"`
	SaltMode   string    `json:"salt_mode,omitempty"`
	Wordlist   string    `json:"wordlist,omitempty"`
	Wordlist2  string    `json:"wordlist2,omitempty"`
	Checkpoint int64     `json:"checkpoint"`
	Total      int64     `json:"total,omitempty"`
	Updated    string    `json:"updated"`

	path string
}

func sessionsDir() string { return filepath.Join(hashsmithDir(), "sessions") }

func sessionPath(name string) string {
	return filepath.Join(sessionsDir(), name+".json")
}

// loadSession reads a saved session by name, or returns (nil, nil) when none
// exists yet (a fresh session will be created on first checkpoint).
func loadSession(name string) (*sessionState, error) {
	path := sessionPath(name)
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	var s sessionState
	if err := json.Unmarshal(data, &s); err != nil {
		return nil, fmt.Errorf("corrupt session %q: %w", name, err)
	}
	s.path = path
	return &s, nil
}

// matches reports whether a saved session describes the same attack as the one
// about to run, so its checkpoint can be safely resumed.
func (s *sessionState) matches(mode, typ, target, charset string, minLen, maxLen int,
	mask string, custom [4]string, increment bool, salt, saltMode, wordlist, wordlist2 string) bool {
	return s != nil &&
		s.Mode == mode && s.Type == typ && s.Target == target &&
		s.Charset == charset && s.MinLen == minLen && s.MaxLen == maxLen &&
		s.Mask == mask && s.Custom == custom && s.Increment == increment &&
		s.Salt == salt && s.SaltMode == saltMode &&
		s.Wordlist == wordlist && s.Wordlist2 == wordlist2
}

func (s *sessionState) save() error {
	if err := os.MkdirAll(filepath.Dir(s.path), 0700); err != nil {
		return err
	}
	s.Updated = time.Now().Format(time.RFC3339)
	data, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return err
	}
	tmp := s.path + ".tmp"
	if err := os.WriteFile(tmp, data, 0600); err != nil {
		return err
	}
	return os.Rename(tmp, s.path)
}

func (s *sessionState) remove() {
	if s != nil && s.path != "" {
		_ = os.Remove(s.path)
	}
}

// runSessionLayout drives a layout run with session resume + periodic
// checkpointing. It resolves the resume index from a matching saved session,
// spins a watermark-flushing goroutine, and returns the result plus whether the
// run was interrupted (ctx cancelled) rather than completing. limit (0 =
// unbounded) is --limit's candidate-count bound, applied on top of resumeFrom.
func runSessionLayout(ctx context.Context, layout *keyspaceLayout, s *sessionState,
	resumeFrom, limit int64, workers int, atomicAttempts *int64,
	verify func(string) bool) (string, bool, error) {

	if s == nil {
		pw, err := runLayout(ctx, layout, resumeFrom, limit, workers, atomicAttempts, nil, verify)
		return pw, ctx.Err() != nil, err
	}

	s.Total = layout.total
	var watermark int64
	atomic.StoreInt64(&watermark, resumeFrom)

	flushCtx, stopFlush := context.WithCancel(context.Background())
	defer stopFlush()
	go func() {
		t := time.NewTicker(2 * time.Second)
		defer t.Stop()
		for {
			select {
			case <-flushCtx.Done():
				return
			case <-t.C:
				s.Checkpoint = atomic.LoadInt64(&watermark)
				_ = s.save()
			}
		}
	}()

	pw, err := runLayout(ctx, layout, resumeFrom, limit, workers, atomicAttempts, &watermark, verify)
	stopFlush()
	s.Checkpoint = atomic.LoadInt64(&watermark)
	interrupted := ctx.Err() != nil
	return pw, interrupted, err
}
