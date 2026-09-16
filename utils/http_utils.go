package utils

import (
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"
	"sync"
	"time"
)

// SNI modes accepted by -sni.
const (
	// SNIAuto sends the virtual host being fuzzed as the TLS server name, so
	// the TLS layer and the Host header agree.
	SNIAuto = "auto"
	// SNINone sends no server name at all. This was the behaviour before the
	// -sni flag existed; it is kept so results can be compared against it.
	SNINone = "none"
)

// DefaultMaxBody caps how much of a response body is read into memory. The
// similarity comparison does not get meaningfully better with more, and an
// uncapped read is an out-of-memory waiting to happen on a hostile target.
const DefaultMaxBody int64 = 1 << 20

// maxCachedClients bounds the per-SNI client cache. Keep-alives are disabled, so
// a cached client holds no connections and dropping the cache costs nothing.
const maxCachedClients = 512

// Fuzzer issues the requests for one run.
type Fuzzer struct {
	Options  *Options
	Reporter *Reporter

	headers http.Header
	sim     *Similarity

	mu      sync.Mutex
	clients map[string]*http.Client
	proxy   func(*http.Request) (*url.URL, error)
}

// FuzzResult is one response, reduced to what detection and filtering need.
type FuzzResult struct {
	// Response is the status line, headers and (capped) body, as compared
	// against the baseline.
	Response string
	// Body is the response body alone, for regex filters.
	Body string
	// ContentLength is the number of body bytes actually read. The
	// Content-Length header is -1 on chunked responses, which made the old
	// output column meaningless.
	ContentLength int64
	Status        int
	Words         int
	Lines         int
	Truncated     bool
}

// ParseHeaders turns "Name: value" strings into a header set. A header without
// a colon is rejected rather than crashing the process, and Host is refused
// because the Host header is what the tool fuzzes.
func ParseHeaders(raw []string) (http.Header, error) {
	headers := http.Header{}
	headers.Set("User-Agent", "VhostFinder")

	for _, h := range raw {
		name, value, found := strings.Cut(h, ":")
		if !found {
			return nil, fmt.Errorf("header %q is not in \"Name: value\" form", h)
		}
		name = strings.TrimSpace(name)
		value = strings.TrimSpace(value)
		if name == "" {
			return nil, fmt.Errorf("header %q has an empty name", h)
		}
		if strings.EqualFold(name, "host") {
			return nil, errors.New("the Host header cannot be set with -H: it is the value being fuzzed")
		}
		headers.Set(name, value)
	}

	return headers, nil
}

// NewFuzzer builds a Fuzzer from validated options.
func NewFuzzer(opts *Options, reporter *Reporter) (*Fuzzer, error) {
	headers, err := ParseHeaders(opts.Headers)
	if err != nil {
		return nil, err
	}

	f := &Fuzzer{
		Options:  opts,
		Reporter: reporter,
		headers:  headers,
		sim:      &Similarity{Threshold: opts.Threshold},
		clients:  make(map[string]*http.Client),
	}

	if opts.Proxy != "" {
		proxyURL, err := url.Parse(opts.Proxy)
		if err != nil {
			return nil, fmt.Errorf("could not parse proxy %q: %w", opts.Proxy, err)
		}
		f.proxy = http.ProxyURL(proxyURL)
	}

	return f, nil
}

// sniFor resolves the TLS server name to present for a given virtual host.
//
// Go sends no SNI extension at all when the URL host is a bare IP literal
// (RFC 6066 forbids IP literals as SNI values), and Request.Host never reaches
// the TLS layer. Before -sni existed this tool therefore handshook with an empty
// SNI on every HTTPS request, so any target that routes on SNI -- a CDN, an
// ALB, Envoy, IIS -- served its default virtual host no matter which Host
// header was sent, and real virtual hosts went undetected.
func (f *Fuzzer) sniFor(target Target, domain string) string {
	if !target.TLS {
		return ""
	}
	switch f.Options.SNI {
	case SNINone:
		return ""
	case SNIAuto, "":
		return domain
	default:
		return f.Options.SNI
	}
}

// clientFor returns an HTTP client whose TLS handshake presents the given
// server name. Clients are cached per name because a scan reuses a handful of
// distinct names in -sni none and -sni <literal> modes, and the cache is bounded
// for -sni auto, where every request has its own.
func (f *Fuzzer) clientFor(serverName string) *http.Client {
	f.mu.Lock()
	defer f.mu.Unlock()

	if c, ok := f.clients[serverName]; ok {
		return c
	}
	if len(f.clients) >= maxCachedClients {
		f.clients = make(map[string]*http.Client)
	}

	timeout := time.Duration(f.Options.Timeout) * time.Second
	transport := &http.Transport{
		DialContext:       (&net.Dialer{Timeout: timeout}).DialContext,
		DisableKeepAlives: true,
		Proxy:             f.proxy,
		// Certificates are not validated: the whole point is to talk to hosts
		// that do not have a valid certificate for the name being tried.
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true, //nolint:gosec // see comment above
			ServerName:         serverName,
		},
		TLSHandshakeTimeout:   timeout,
		IdleConnTimeout:       timeout,
		ExpectContinueTimeout: 1 * time.Second,
	}

	client := &http.Client{
		Transport: transport,
		Timeout:   timeout,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	f.clients[serverName] = client
	return client
}

// do issues one request, retrying transient network failures. HTTP status codes
// are never retried: a 502 is a result, not a failure.
func (f *Fuzzer) do(ctx context.Context, client *http.Client, req *http.Request) (*http.Response, error) {
	var lastErr error
	attempts := f.Options.Retries + 1

	for attempt := 0; attempt < attempts; attempt++ {
		if attempt > 0 {
			backoff := time.Duration(1<<uint(attempt-1)) * 250 * time.Millisecond
			timer := time.NewTimer(backoff)
			select {
			case <-ctx.Done():
				timer.Stop()
				return nil, ctx.Err()
			case <-timer.C:
			}
		}

		resp, err := client.Do(req.Clone(ctx))
		if err == nil {
			return resp, nil
		}
		lastErr = err
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
	}

	return nil, lastErr
}

// readResult drains a response into a FuzzResult, capping the body.
func (f *Fuzzer) readResult(resp *http.Response) (*FuzzResult, error) {
	defer func() { _ = resp.Body.Close() }()

	head, err := httputil.DumpResponse(resp, false)
	if err != nil {
		return nil, err
	}

	limit := f.Options.MaxBody
	if limit <= 0 {
		limit = DefaultMaxBody
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, limit))
	if err != nil {
		return nil, err
	}
	truncated := int64(len(body)) == limit

	var buf bytes.Buffer
	buf.Grow(len(head) + len(body))
	buf.Write(head)
	buf.Write(body)

	return &FuzzResult{
		Response:      buf.String(),
		Body:          string(body),
		ContentLength: int64(len(body)),
		Status:        resp.StatusCode,
		Words:         len(bytes.Fields(body)),
		Lines:         bytes.Count(body, []byte("\n")),
		Truncated:     truncated,
	}, nil
}

// FuzzHost sends one request to target with the Host header set to domain.
func (f *Fuzzer) FuzzHost(ctx context.Context, target Target, domain, path string) (*FuzzResult, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, target.URL(path), nil)
	if err != nil {
		return nil, err
	}
	req.Header = f.headers.Clone()
	req.Host = domain

	// readResult closes the body; bodyclose cannot follow it through the helper.
	resp, err := f.do(ctx, f.clientFor(f.sniFor(target, domain)), req) //nolint:bodyclose
	if err != nil {
		return nil, err
	}
	return f.readResult(resp)
}

// TestDomain fuzzes one virtual host and reports whether it differs from every
// baseline sample, along with the closest similarity score.
func (f *Fuzzer) TestDomain(ctx context.Context, target Target, domain, path string, baselines []string) (bool, float64, *FuzzResult, error) {
	result, err := f.FuzzHost(ctx, target, domain, path)
	if err != nil {
		return false, 0, nil, err
	}
	differs, score := f.sim.DiffersFromAll(baselines, result.Response)
	return differs, score, result, nil
}

// getPublic fetches a domain over its own DNS name rather than the target IP.
func (f *Fuzzer) getPublic(ctx context.Context, domain, path string) (*FuzzResult, error) {
	scheme := "http"
	if f.Options.Tls {
		scheme = "https"
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, scheme+"://"+domain+path, nil)
	if err != nil {
		return nil, err
	}
	req.Header = f.headers.Clone()

	serverName := domain
	if f.Options.SNI == SNINone {
		serverName = ""
	}
	// readResult closes the body; bodyclose cannot follow it through the helper.
	resp, err := f.do(ctx, f.clientFor(serverName), req) //nolint:bodyclose
	if err != nil {
		return nil, err
	}
	return f.readResult(resp)
}

// CompareGeneric reports whether the virtual host served from the target differs
// from what the public DNS name serves. A finding that merely mirrors the public
// site is usually not interesting.
//
// When the public name cannot be reached at all -- no DNS record, connection
// refused -- the finding is kept: an internal-only virtual host is exactly the
// case worth reporting.
func (f *Fuzzer) CompareGeneric(ctx context.Context, domain, path, response string) bool {
	public, err := f.getPublic(ctx, domain, path)
	if err != nil {
		f.Reporter.Verbosef("%s is not reachable publicly (%s); keeping the finding", domain, err)
		return true
	}
	differs, _ := f.sim.Differs(public.Response, response)
	return differs
}
