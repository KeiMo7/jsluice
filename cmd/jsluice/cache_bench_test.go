package main

import (
	"testing"

	"github.com/BishopFox/jsluice"
)

// BenchmarkAnalysisOnly measures the tree-sitter analysis cost that
// caching is meant to avoid.
func BenchmarkAnalysisOnly(b *testing.B) {
	source := makeBenchSource()
	b.SetBytes(int64(len(source)))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		a := jsluice.NewAnalyzer(source)
		_ = a.GetURLs()
	}
}

// BenchmarkCacheRoundTrip measures write-then-read of one entry, the
// cost a cache hit pays instead of analysis.
func BenchmarkCacheRoundTrip(b *testing.B) {
	dir := b.TempDir()
	c := OpenCache(dir, 0, discardWarn, nil)
	opts := urlsOptions(dir)
	opts.cacheConfigHash = ConfigHash(modeURLs, jsluice.ExpressionPlaceholder, nil)

	source := makeBenchSource()
	hash := ContentHash(source)
	raw, err := analyze(opts, source)
	if err != nil {
		b.Fatal(err)
	}
	if err := c.Store(modeURLs, hash, opts.cacheConfigHash, raw); err != nil {
		b.Fatal(err)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, ok := c.Lookup(modeURLs, hash, opts.cacheConfigHash); !ok {
			b.Fatal("expected hit")
		}
	}
}

func makeBenchSource() []byte {
	src := `fetch("/api/v1/entity/1");
location.href = "/login";
$.ajax({url:"/api/x", method:"POST", data:{id:1}});
`
	for j := 0; j < 120; j++ {
		src += `function f` + itoa(j) + `(){ return "prefix_1_` + itoa(j) + `_suffix"; }
`
	}
	return []byte(src)
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var buf [20]byte
	i := len(buf)
	for n > 0 {
		i--
		buf[i] = byte('0' + n%10)
		n /= 10
	}
	return string(buf[i:])
}
