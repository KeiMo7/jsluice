package main

// Extract URLs and related stuff out of JavaScript files

import (
	"bufio"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"os"
	"strings"
	"sync"

	"github.com/BishopFox/jsluice"
	"github.com/pkg/profile"
	"github.com/slyrz/warc"
	flag "github.com/spf13/pflag"
)

type options struct {
	// global
	profile     bool
	cookie      string
	headers     []string
	concurrency int
	placeholder string
	help        bool
	warc        bool
	rawInput    bool
	certCheck   bool

	// mode is the active analysis mode set once at startup
	mode string

	// urls
	includeSource bool
	ignoreStrings bool
	resolvePaths  string
	unique        bool

	// secrets
	patternsFile string

	// query
	query           string
	rawOutput       bool
	includeFilename bool
	format          bool

	// cache (urls/secrets modes only; opt-in)
	cacheDir        string
	cacheMaxEntries int
	cacheStats      bool
	cacheDiff       bool
	invalidate      []string

	// runtime cache state; not populated from flags
	cache           *Cache
	cacheConfigHash string
}

const (
	modeURLs    = "urls"
	modeSecrets = "secrets"
	modeTree    = "tree"
	modeQuery   = "query"
	modeFormat  = "format"
)

type stringSlice []string

func (ss *stringSlice) String() string {
	return strings.Join(*ss, ", ")
}

func (ss *stringSlice) Set(value string) error {
	*ss = append(*ss, value)
	return nil
}

func (ss *stringSlice) Type() string {
	return "string"
}

type cmdFn func(options, string, []byte, chan string, chan error)

func init() {
	flag.Usage = func() {
		lines := []string{
			"jsluice - Extract URLs, paths, and secrets from JavaScript files",
			"",
			"Usage:",
			"  jsluice <mode> [options] [file...]",
			"",
			"Modes:",
			"  urls      Extract URLs and paths",
			"  secrets   Extract secrets and other interesting bits",
			"  tree      Print syntax trees for input files",
			"  query     Run tree-sitter a query against input files",
			"  format    Format JavaScript source using jsbeautifier-go",
			"",
			"Global options:",
			"  -c, --concurrency int        Number of files to process concurrently (default 1)",
			"  -C, --cookie string          Cookies to use when making requests to the specified HTTP based arguments",
			"  -H, --header string          Headers to use when making requests to the specified HTTP based arguments (can be specified multiple times)",
			"  -P, --placeholder string     Set the expression placeholder to a custom string (default 'EXPR')",
			"  -j, --raw-input              Read raw JavaScript source from stdin",
			"  -w, --warc                   Treat the input files as WARC (Web ARChive) files",
			"  -i, --no-check-certificate	Ignore validation of server certificates",
			"",
			"URLs mode:",
			"  -I, --ignore-strings         Ignore matches from string literals",
			"  -S, --include-source         Include the source code where the URL was found",
			"  -R, --resolve-paths <url>    Resolve relative paths using the absolute URL provided",
			"  -u, --unique                 Only output each URL once per input file",
			"",
			"Secrets mode:",
			"  -p, --patterns <file>        JSON file containing user-defined secret patterns to look for",
			"",
			"Query mode:",
			"  -q, --query <query>          Tree sitter query to run; e.g. '(string) @matches'",
			"  -r, --raw-output             Do not convert values to native types",
			"  -f, --include-filename       Include the filename in the output",
			"  -F, --format                 Format source code in the output",
			"",
			"Cache options (urls and secrets modes only; off by default):",
			"      --cache <dir>            Reuse analysis results stored in <dir>; created if missing",
			"      --cache-max-entries <n>  Keep at most <n> entries, LRU eviction beyond that (default 5000; 0 disables)",
			"      --cache-stats            Print reuse statistics to stderr after the run",
			"      --cache-diff             Print per-script result diffs for changed scripts to stderr",
			"      --invalidate <hash>      Force recomputation of one content hash (repeatable)",
			"",
			"Examples:",
			"  jsluice urls -C 'auth=true; user=admin;' -H 'Specific-Header-One: true' -H 'Specific-Header-Two: false' local_file.js https://remote.host/example.js",
			"  jsluice query -q '(object) @m' one.js two.js",
			"  find . -name '*.js' | jsluice secrets -c 5 --patterns=apikeys.json",
		}
		fmt.Fprintf(os.Stderr, "%s\n", strings.Join(lines, "\n"))
	}
}

func main() {
	var opts options
	var headers stringSlice

	// global options
	flag.BoolVar(&opts.profile, "profile", false, "Profile CPU usage and save a cpu.pprof file in the current dir")
	flag.IntVarP(&opts.concurrency, "concurrency", "c", 1, "Number of files to process concurrently")
	flag.StringVarP(&opts.cookie, "cookie", "C", "", "Cookie(s) to use when making HTTP requests")
	flag.VarP(&headers, "header", "H", "Headers to use when making HTTP requests")
	flag.BoolVarP(&opts.rawInput, "raw-input", "j", false, "Read raw JavaScript source from stdin")
	flag.StringVarP(&opts.placeholder, "placeholder", "P", "EXPR", "Set the expression placeholder to a custom string")
	flag.BoolVarP(&opts.help, "help", "h", false, "")
	flag.BoolVarP(&opts.warc, "warc", "w", false, "")
	flag.BoolVarP(&opts.certCheck, "no-check-certificate", "i", false, "Ignore validation of server certificates")

	// url options
	flag.BoolVarP(&opts.includeSource, "include-source", "S", false, "Include the source code where the URL was found")
	flag.BoolVarP(&opts.ignoreStrings, "ignore-strings", "I", false, "Ignore matches from string literals")
	flag.StringVarP(&opts.resolvePaths, "resolve-paths", "R", "", "Resolve relative paths using the absolute URL provided")
	flag.BoolVarP(&opts.unique, "unique", "u", false, "")

	// secrets options
	flag.StringVarP(&opts.patternsFile, "patterns", "p", "", "JSON file containing user-defined secret patterns to look for")

	// query options
	flag.StringVarP(&opts.query, "query", "q", "", "Tree sitter query to run; e.g. '(string) @matches'")
	flag.BoolVarP(&opts.rawOutput, "raw-output", "r", false, "Do not convert values to native types")
	flag.BoolVarP(&opts.includeFilename, "include-filename", "f", false, "Include the filename in the output")
	flag.BoolVarP(&opts.format, "format", "F", false, "Format source code in the output")

	// cache options
	flag.StringVar(&opts.cacheDir, "cache", "", "Directory in which to cache analysis results (urls/secrets modes only); caching is off unless set")
	flag.IntVar(&opts.cacheMaxEntries, "cache-max-entries", 5000, "Maximum number of cache entries to retain; least recently used entries beyond this are evicted (0 disables eviction)")
	flag.BoolVar(&opts.cacheStats, "cache-stats", false, "Print cache reuse statistics to stderr after the run")
	flag.BoolVar(&opts.cacheDiff, "cache-diff", false, "Print per-script result diffs for changed scripts to stderr")
	flag.StringArrayVar(&opts.invalidate, "invalidate", nil, "Content hash whose cache entry must be recomputed (repeatable)")

	flag.Parse()

	opts.headers = headers

	if opts.help {
		flag.Usage()
		return
	}

	if opts.profile {
		defer profile.Start(profile.ProfilePath(".")).Stop()
	}

	args := flag.Args()
	if len(args) == 0 {
		fmt.Fprintln(os.Stderr, "usage: jsluice <mode> [...flags]")
		os.Exit(1)
	}

	jsluice.ExpressionPlaceholder = opts.placeholder

	mode := args[0]
	files := args[1:]
	opts.mode = mode

	// spin up an output worker
	output := make(chan string)
	errs := make(chan error)
	done := make(chan any)

	go func() {

		for {
			select {
			case out := <-output:
				if out == "" {
					continue
				}
				fmt.Println(out)
			case err := <-errs:
				fmt.Fprintf(os.Stderr, "error: %s\n", err)
			case <-done:
				return
			}
		}
	}()

	// now the process workers
	var modeFn cmdFn
	modes := map[string]cmdFn{
		modeURLs:    extractURLs,
		modeSecrets: extractSecrets,
		modeTree:    printTree,
		modeQuery:   runQuery,
		modeFormat:  format,
	}

	if _, exists := modes[mode]; !exists {
		fmt.Fprintf(os.Stderr, "no such mode: %s\n", mode)
		os.Exit(2)
	}
	modeFn = modes[mode]

	// Caching only applies to the two analysis modes. In any other
	// mode the flag is rejected rather than silently ignored, so a user
	// expecting cached tree/query output is not misled.
	if opts.cacheDir != "" && mode != modeURLs && mode != modeSecrets {
		fmt.Fprintf(os.Stderr, "cache: --cache is only supported by the %s and %s modes\n", modeURLs, modeSecrets)
		os.Exit(2)
	}

	if opts.cacheDir != "" {
		opts.cache = OpenCache(opts.cacheDir, opts.cacheMaxEntries, warnf, opts.invalidate)

		// The config hash covers every option that changes analysis
		// output. For secrets mode that includes the patterns file.
		var patternsPayload []byte
		if mode == modeSecrets && opts.patternsFile != "" {
			payload, err := ioutil.ReadFile(opts.patternsFile)
			if err != nil {
				// Preserve the existing error semantics: the worker
				// re-opens the file and emits the same error it always
				// did. We simply cannot fold it into the config hash.
				warnf("cache: could not read patterns file %s for config hashing (%v)", opts.patternsFile, err)
			} else {
				patternsPayload = payload
			}
		}
		opts.cacheConfigHash = ConfigHash(mode, jsluice.ExpressionPlaceholder, patternsPayload)
		opts.cache.BeginScope(mode + "|" + opts.cacheConfigHash)
		defer opts.cache.Close()
	}

	jobs := make(chan string)

	var wg sync.WaitGroup
	for i := 0; i < opts.concurrency; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for filename := range jobs {

				if opts.warc {
					responses, err := readWARCFile(filename)
					if err != nil {
						errs <- err
						continue
					}

					for _, response := range responses {
						runOne(opts, modeFn, response.url, response.source, output, errs)
					}
					continue
				}

				source, err := readFromFileOrURL(filename, opts.cookie, opts.headers, opts.certCheck)
				if err != nil {
					errs <- err
					continue
				}

				runOne(opts, modeFn, filename, source, output, errs)
			}
		}()
	}

	// If we're reading JS source straight from stdin, throw
	// it into a temp file that we'll clean up later
	if opts.rawInput {
		tmpfile, err := os.CreateTemp("", "jsluice-raw-input")

		if err != nil {
			fmt.Fprintf(os.Stderr, "failed to create temp file for raw input: %s\n", err)
			os.Exit(3)
		}
		defer os.Remove(tmpfile.Name())

		_, err = io.Copy(tmpfile, os.Stdin)
		if err != nil {
			fmt.Fprintf(os.Stderr, "failed to write raw input to temp file: %s\n", err)
			os.Exit(3)
		}

		err = tmpfile.Close()
		if err != nil {
			fmt.Fprintf(os.Stderr, "failed to close temp file: %s\n", err)
			os.Exit(3)
		}

		// overwrite the files slice so we read only the raw input
		files = []string{tmpfile.Name()}
	}

	// default to reading filenames from stdin, fall back
	// to treating the argument list as filenames
	var r io.Reader = os.Stdin
	if len(files) > 0 {
		r = strings.NewReader(strings.Join(files, "\n"))
	}
	input := bufio.NewScanner(r)

	for input.Scan() {
		jobs <- input.Text()
	}
	close(jobs)

	wg.Wait()

	if opts.cache.Enabled() {
		opts.cache.Commit()
		opts.cache.Evict()

		if opts.cacheStats {
			printCacheStats(opts.cache)
		}
		if opts.cacheDiff {
			printCacheDiff(opts.cache)
		}
	}

	done <- struct{}{}
	close(output)
	close(errs)

}

// warnf emits a cache-related warning to stderr. Warnings never alter
// stdout or the exit code.
func warnf(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "warning: "+format+"\n", args...)
}

// printCacheStats writes the run's reuse statistics as one JSON object
// on stderr, so it can never be confused with the JSONL results on
// stdout.
func printCacheStats(c *Cache) {
	b, err := json.Marshal(c.SnapshotStats())
	if err != nil {
		warnf("cache: could not marshal stats: %v", err)
		return
	}
	fmt.Fprintf(os.Stderr, "cache stats: %s\n", b)
}

// printCacheDiff writes one JSON object per changed script on stderr.
func printCacheDiff(c *Cache) {
	for _, ch := range c.SnapshotChanges() {
		b, err := json.Marshal(ch)
		if err != nil {
			continue
		}
		fmt.Fprintf(os.Stderr, "cache diff: %s\n", b)
	}
}

// runOne invokes the active mode for one script, routing through the
// cache when it is enabled. With caching disabled it is a direct call
// to modeFn, i.e. the original single-shot path unchanged.
//
// Concurrent-modification handling: for a real local file, the file is
// re-read after analysis and its content hash compared with the bytes
// that were analysed. A mismatch means the script changed underneath
// us. The buffered (not yet emitted) results are discarded, the file is
// re-read once and re-analysed; a second mismatch is reported as an
// explicit error rather than emitting a result for the wrong content.
// Non-file inputs (HTTP, WARC records) are in-memory snapshots and so
// cannot change out from under the analysis.
func runOne(opts options, modeFn cmdFn, name string, source []byte, output chan string, errs chan error) {
	if !opts.cache.Enabled() {
		modeFn(opts, name, source, output, errs)
		return
	}
	hash := ContentHash(source)
	results, hit := opts.cache.LookupCached(opts, hash)

	if hit {
		// Replay the cached raw matches through the unchanged
		// presentation layer. No analysis runs, and the file need not
		// be re-statted: the cached bytes are what the result
		// describes.
		emitCached(opts, name, results, output, errs)
		opts.cache.RecordInput(name, hash, true)
		return
	}

	// Cache miss: run analysis once. The clean raw matches are stored
	// BEFORE presentation, because the presentation layer mutates them
	// (assigns Filename, clears Source); it runs on a deep copy instead.
	raw, analyzeErr := analyze(opts, source)
	if analyzeErr != nil {
		errs <- analyzeErr
		return
	}

	// Buffers are sized to the match count so presentation can never
	// block: they are drained only after presentation returns, so a
	// fixed-size buffer would deadlock on scripts with many matches.
	buffered, localErrs := bufferFor(raw)
	present(opts, name, deepCopyResult(raw), buffered, localErrs)
	close(buffered)
	close(localErrs)

	if changed, _ := fileChanged(name, hash); changed {
		retryAfterChange(opts, name, output, errs)
		return
	}

	opts.cache.StoreCachedResult(opts, hash, raw)
	opts.cache.RecordInput(name, hash, false)
	flushBuffers(buffered, localErrs, output, errs)
}

// retryAfterChange re-reads a local file once and re-analyses it after
// a concurrent modification was detected. A further mismatch is an
// error, never a half-result.
func retryAfterChange(opts options, name string, output chan string, errs chan error) {
	warnf("cache: %s changed during analysis; re-reading and re-analysing", name)

	fresh, err := readFromFileOrURL(name, opts.cookie, opts.headers, opts.certCheck)
	if err != nil {
		errs <- err
		return
	}
	hash := ContentHash(fresh)

	raw, analyzeErr := analyze(opts, fresh)
	if analyzeErr != nil {
		errs <- analyzeErr
		return
	}

	buffered, localErrs := bufferFor(raw)
	present(opts, name, deepCopyResult(raw), buffered, localErrs)
	close(buffered)
	close(localErrs)

	if changed, _ := fileChanged(name, hash); changed {
		errs <- fmt.Errorf("cache: %s changed again during re-analysis; refusing to emit a result for stale content", name)
		return
	}

	opts.cache.StoreCachedResult(opts, hash, raw)
	opts.cache.RecordInput(name, hash, false)
	flushBuffers(buffered, localErrs, output, errs)
}

// bufferFor creates per-script result/error channels sized so that
// present() cannot block: each raw match emits at most one line.
// Presentation errors are rare (JSON marshalling), so the error channel
// gets a small fixed allowance in addition to the match capacity.
func bufferFor(raw cachedResult) (chan string, chan error) {
	n := len(raw.URLs) + len(raw.Secrets)
	return make(chan string, n+1), make(chan error, n+8)
}

// flushBuffers forwards a completed per-script buffer to the shared
// output/error channels in order.
func flushBuffers(buffered chan string, localErrs chan error, output chan string, errs chan error) {
	for e := range localErrs {
		errs <- e
	}
	for line := range buffered {
		output <- line
	}
}

// fileChanged reports whether name is a regular local file whose
// current content hash differs from want. Non-file names (HTTP URLs,
// stdin temp files handled by their caller) report false.
func fileChanged(name string, want string) (bool, error) {
	if strings.HasPrefix(name, "http://") || strings.HasPrefix(name, "https://") {
		return false, nil
	}
	info, err := os.Stat(name)
	if err != nil {
		// If it no longer exists or cannot be stated, treat the input
		// as changed so the caller recomputes/errors rather than trusts
		// a possibly stale result.
		return true, err
	}
	if !info.Mode().IsRegular() {
		return false, nil
	}
	current, err := ioutil.ReadFile(name)
	if err != nil {
		return true, err
	}
	return ContentHash(current) != want, nil
}

func readFromFileOrURL(path string, cookie string, headers []string, ignoreCert bool) ([]byte, error) {
	if strings.HasPrefix(path, "http://") || strings.HasPrefix(path, "https://") {
		client := &http.Client{}

		if ignoreCert {
			client.Transport = &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}
		}

		req, err := http.NewRequest("GET", path, nil)
		if err != nil {
			return nil, err
		}

		// Add cookie to the request if specified
		if cookie != "" {
			req.Header.Set("Cookie", cookie)
		}

		// Add headers to the request if specified
		for _, header := range headers {
			parts := strings.SplitN(header, ":", 2)
			if len(parts) == 2 {
				req.Header.Set(strings.TrimSpace(parts[0]), strings.TrimSpace(parts[1]))
			}
		}

		resp, err := client.Do(req)
		if err != nil {
			return nil, err
		}
		defer resp.Body.Close()

		// Check if the request was successful
		if resp.StatusCode != http.StatusOK {
			return nil, fmt.Errorf("GET request failed with status code %d", resp.StatusCode)
		}

		return ioutil.ReadAll(resp.Body)
	}

	return ioutil.ReadFile(path)
}

type warcResponse struct {
	url    string
	source []byte
}

func readWARCFile(filename string) ([]warcResponse, error) {
	out := make([]warcResponse, 0)

	f, err := os.Open(filename)
	if err != nil {
		return out, err
	}
	defer f.Close()

	r, err := warc.NewReader(f)
	if err != nil {
		return out, err
	}
	defer r.Close()

	for {
		record, err := r.ReadRecord()
		if err != nil {
			break
		}

		if record.Header.Get("content-type") != "application/http; msgtype=response" {
			continue
		}

		buf := bufio.NewReader(record.Content)
		response, err := http.ReadResponse(buf, nil)
		if err != nil {
			return out, err
		}

		ct := strings.ToLower(response.Header.Get("content-type"))
		if !strings.Contains(ct, "javascript") && !strings.Contains(ct, "html") {
			continue
		}

		body, err := ioutil.ReadAll(response.Body)
		if err != nil {
			return out, err
		}
		response.Body.Close()

		out = append(out, warcResponse{
			url:    record.Header.Get("WARC-Target-URI"),
			source: body,
		})
	}

	return out, nil
}
