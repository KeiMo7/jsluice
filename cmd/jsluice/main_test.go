package main

import (
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

func TestExpandDirectoriesSortedAndRecursive(t *testing.T) {
	dir := t.TempDir()
	mustWrite := func(name, body string) {
		p := filepath.Join(dir, name)
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	mustWrite("b.js", "")
	mustWrite("a.js", "")
	mustWrite("note.txt", "")
	mustWrite("sub/c.js", "")
	mustWrite("sub/noext", "")

	got, err := expandDirectories([]string{dir})
	if err != nil {
		t.Fatal(err)
	}
	want := []string{
		filepath.Join(dir, "a.js"),
		filepath.Join(dir, "b.js"),
		filepath.Join(dir, "sub", "c.js"),
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("want %v, have %v", want, got)
	}

	// Repeated expansion must be identical (deterministic ordering).
	again, err := expandDirectories([]string{dir})
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(got, again) {
		t.Errorf("non-deterministic expansion:\n%v\n%v", got, again)
	}
}

func TestExpandDirectoriesPassesFilesThrough(t *testing.T) {
	got, err := expandDirectories([]string{"x.js", "https://example.com/a.js", "missing.js"})
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"x.js", "https://example.com/a.js", "missing.js"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("want %v, have %v", want, got)
	}
}

func TestIsJavaScriptFile(t *testing.T) {
	cases := map[string]bool{
		"a.js": true, "a.mjs": true, "a.cjs": true, "a.jsx": true,
		"a.JS": true, "a.ts": false, "a.txt": false, "noext": false,
	}
	for in, want := range cases {
		if got := isJavaScriptFile(in); got != want {
			t.Errorf("isJavaScriptFile(%q)=%v, want %v", in, got, want)
		}
	}
}
