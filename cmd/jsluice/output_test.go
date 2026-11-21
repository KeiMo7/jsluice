package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// A completed write must produce the target file with the expected
// content and leave no temporary files behind.
func TestOutputSinkWritesAtomically(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "out.jsonl")

	sink, err := newOutputSink(target)
	if err != nil {
		t.Fatal(err)
	}

	if err := sink.WriteLine(`{"one":1}`); err != nil {
		t.Fatal(err)
	}
	if err := sink.WriteLine(`{"two":2}`); err != nil {
		t.Fatal(err)
	}

	// before Close the target must not exist yet
	if _, err := os.Stat(target); !os.IsNotExist(err) {
		t.Error("target file should not exist before Close")
	}

	if err := sink.Close(); err != nil {
		t.Fatal(err)
	}

	content, err := os.ReadFile(target)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(content), `{"one":1}`) || !strings.Contains(string(content), `{"two":2}`) {
		t.Errorf("unexpected content: %q", content)
	}

	// no temporary files left behind
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 {
		t.Errorf("expected only the target file, found %d entries", len(entries))
	}
}

// Aborting a sink must leave no file at the target path at all.
func TestOutputSinkAbortLeavesNoFile(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "out.jsonl")

	sink, err := newOutputSink(target)
	if err != nil {
		t.Fatal(err)
	}
	if err := sink.WriteLine(`{"partial":true}`); err != nil {
		t.Fatal(err)
	}
	sink.Abort()

	if _, err := os.Stat(target); !os.IsNotExist(err) {
		t.Error("target file should not exist after Abort")
	}

	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 0 {
		t.Errorf("expected no files after Abort, found %d", len(entries))
	}
}

// With no target the sink writes to stdout; Close must not fail.
func TestOutputSinkStdout(t *testing.T) {
	sink, err := newOutputSink("")
	if err != nil {
		t.Fatal(err)
	}
	if err := sink.WriteLine("hello"); err != nil {
		t.Fatal(err)
	}
	if err := sink.Close(); err != nil {
		t.Fatal(err)
	}
}

// Kind flag parsing
func TestParseKinds(t *testing.T) {
	kinds, err := parseKinds("endpoint, credential")
	if err != nil {
		t.Fatal(err)
	}
	if len(kinds) != 2 {
		t.Errorf("expected 2 kinds, got %d", len(kinds))
	}

	if kinds, err = parseKinds(""); kinds != nil || err != nil {
		t.Errorf("expected nil map and no error for empty input, got %v %v", kinds, err)
	}

	if _, err = parseKinds("endpoint,bogus"); err == nil {
		t.Error("expected error for unknown kind")
	}
}
