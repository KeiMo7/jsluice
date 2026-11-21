package main

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
)

// outputSink receives lines of output. When a target file is configured
// it writes to a temporary file in the same directory and only renames
// it into place on Close, so a failed run never leaves a half-written
// output file. With no target file it writes straight to stdout.
type outputSink struct {
	target  string // final path, or "" for stdout
	tmpPath string
	file    *os.File
	w       *bufio.Writer
}

func newOutputSink(target string) (*outputSink, error) {
	if target == "" {
		return &outputSink{w: bufio.NewWriter(os.Stdout)}, nil
	}

	dir := filepath.Dir(target)
	tmp, err := os.CreateTemp(dir, ".jsluice-output-*")
	if err != nil {
		return nil, fmt.Errorf("failed to create temporary output file: %w", err)
	}

	return &outputSink{
		target:  target,
		tmpPath: tmp.Name(),
		file:    tmp,
		w:       bufio.NewWriter(tmp),
	}, nil
}

// WriteLine writes a single line of output.
func (s *outputSink) WriteLine(line string) error {
	_, err := fmt.Fprintln(s.w, line)
	return err
}

// Close flushes and, for file targets, atomically moves the temporary
// file to its final path. If flushing or closing fails the temporary
// file is removed and the target is left untouched.
func (s *outputSink) Close() error {
	if err := s.w.Flush(); err != nil {
		s.Abort()
		return err
	}

	if s.file == nil {
		return nil
	}

	if err := s.file.Close(); err != nil {
		os.Remove(s.tmpPath)
		return err
	}

	if err := os.Rename(s.tmpPath, s.target); err != nil {
		os.Remove(s.tmpPath)
		return err
	}
	return nil
}

// Abort discards any buffered data and removes the temporary file,
// leaving the target path untouched.
func (s *outputSink) Abort() {
	if s.file != nil {
		s.file.Close()
		os.Remove(s.tmpPath)
	}
}
