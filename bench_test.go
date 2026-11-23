package jsluice

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

// BenchmarkGetURLsTestdata measures analysis of the bundled sample scripts.
func BenchmarkGetURLsTestdata(b *testing.B) {
	var sb strings.Builder
	matches, _ := filepath.Glob("cmd/jsluice/testdata/*.js")
	for _, m := range matches {
		data, err := os.ReadFile(m)
		if err == nil {
			sb.Write(data)
			sb.WriteByte('\n')
		}
	}
	src := []byte(sb.String())
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		NewAnalyzer(src).GetURLs()
	}
}

// BenchmarkGetURLsBig measures a pathological file with thousands of
// independent URL constants.
func BenchmarkGetURLsBig(b *testing.B) {
	var sb strings.Builder
	for i := 0; i < 4000; i++ {
		n := strconv.Itoa(i)
		sb.WriteString(`const BASE_` + n + ` = "https://example.com/api"; fetch(BASE_` + n + ` + "/v1/items?id=" + userId);`)
		sb.WriteByte('\n')
	}
	src := []byte(sb.String())
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		NewAnalyzer(src).GetURLs()
	}
}
