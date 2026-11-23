package main

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// buildCLI compiles the jsluice command once per test binary run.
func buildCLI(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	bin := filepath.Join(dir, "jsluice")
	cmd := exec.Command("go", "build", "-o", bin, ".")
	cmd.Env = os.Environ()
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("build failed: %v\n%s", err, out)
	}
	return bin
}

// runCLI runs the built binary and returns stdout, stderr and the exit code.
func runCLI(t *testing.T, bin string, args ...string) (string, string, int) {
	t.Helper()
	cmd := exec.Command(bin, args...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	err := cmd.Run()
	code := 0
	if err != nil {
		if ee, ok := err.(*exec.ExitError); ok {
			code = ee.ExitCode()
		} else {
			t.Fatalf("run failed: %v", err)
		}
	}
	return stdout.String(), stderr.String(), code
}

func TestCLIReconstructsImportedConstant(t *testing.T) {
	if testing.Short() {
		t.Skip("builds the binary")
	}
	bin := buildCLI(t)

	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "config.js"), []byte(
		`export const API_BASE = "https://internal.example.com"; export const V = "v9";`,
	), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "app.js"), []byte(
		`import { API_BASE, V } from "./config.js";`+"\n"+
			`function load() { fetch(API_BASE + "/api/" + V + "/items"); }`+"\n",
	), 0o644); err != nil {
		t.Fatal(err)
	}

	stdout, stderr, code := runCLI(t, bin, "urls", filepath.Join(dir, "app.js"))
	if code != 0 {
		t.Fatalf("exit %d, stderr: %s", code, stderr)
	}
	want := "https://internal.example.com/api/v9/items"
	if !strings.Contains(stdout, want) {
		t.Errorf("expected reconstructed URL %q in output; got:\n%s", want, stdout)
	}
	if strings.Contains(stdout, `"url":"https://internal.example.com/api/EXPR`) {
		t.Errorf("URL still contains a placeholder:\n%s", stdout)
	}
}

func TestCLIDirectoryInputDeterministic(t *testing.T) {
	if testing.Short() {
		t.Skip("builds the binary")
	}
	bin := buildCLI(t)
	dir := t.TempDir()
	for _, name := range []string{"a.js", "b.js", "c.js"} {
		body := `const H = "https://` + strings.TrimSuffix(name, ".js") + `.example.com"; fetch(H + "/p")`
		if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}

	first, errOut, code := runCLI(t, bin, "urls", dir)
	if code != 0 {
		t.Fatalf("exit %d, stderr: %s", code, errOut)
	}
	second, _, code := runCLI(t, bin, "urls", dir)
	if code != 0 {
		t.Fatalf("second run exit %d", code)
	}
	if first != second {
		t.Errorf("directory runs differ byte-for-byte:\nfirst:\n%s\nsecond:\n%s", first, second)
	}
	for _, want := range []string{
		"https://a.example.com/p",
		"https://b.example.com/p",
		"https://c.example.com/p",
	} {
		if !strings.Contains(first, want) {
			t.Errorf("missing %q in directory output:\n%s", want, first)
		}
	}
}

func TestCLIExitCodesUnchanged(t *testing.T) {
	if testing.Short() {
		t.Skip("builds the binary")
	}
	bin := buildCLI(t)

	if _, _, code := runCLI(t, bin, "--help"); code != 0 {
		t.Errorf("--help exit = %d, want 0", code)
	}
	if _, _, code := runCLI(t, bin, "nosuchmode", "x"); code != 2 {
		t.Errorf("bad mode exit = %d, want 2", code)
	}
	if _, _, code := runCLI(t, bin); code != 1 {
		t.Errorf("no args exit = %d, want 1", code)
	}
}
