package utils

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"
)

// selfSignedCert returns a throwaway certificate valid for 127.0.0.1. The
// fuzzer never validates certificates, so the contents barely matter; it only
// has to complete a handshake.
func selfSignedCert(t *testing.T) tls.Certificate {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "vhostfinder-test"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
	}
	der, err := x509.CreateCertificate(rand.Reader, &template, &template, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create certificate: %v", err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
}

// testTarget turns an httptest server URL into a Target.
func testTarget(t *testing.T, server *httptest.Server, useTLS bool) Target {
	t.Helper()

	trimmed := strings.TrimPrefix(strings.TrimPrefix(server.URL, "https://"), "http://")
	host, portStr, err := net.SplitHostPort(trimmed)
	if err != nil {
		t.Fatalf("split server address %q: %v", server.URL, err)
	}
	port, err := strconv.Atoi(portStr)
	if err != nil {
		t.Fatalf("parse port %q: %v", portStr, err)
	}
	return Target{Host: host, Port: port, TLS: useTLS}
}

// testOptions returns options with the defaults a scan would normally get.
func testOptions() *Options {
	return &Options{
		Timeout:         5,
		MaxBody:         DefaultMaxBody,
		SNI:             SNIAuto,
		Threshold:       DefaultThreshold,
		BaselineSamples: 2,
		Threads:         4,
		Tls:             true,
	}
}

func testFuzzer(t *testing.T, opts *Options) *Fuzzer {
	t.Helper()

	reporter, err := NewReporter("", "", true, false)
	if err != nil {
		t.Fatalf("new reporter: %v", err)
	}
	f, err := NewFuzzer(opts, reporter)
	if err != nil {
		t.Fatalf("new fuzzer: %v", err)
	}
	return f
}

// newSNIRoutedServer starts an HTTPS server that decides what to serve from the
// TLS server name alone, ignoring the Host header entirely. This is how CDNs,
// load balancers and IIS behave, and it is the configuration the tool used to be
// blind to.
func newSNIRoutedServer(t *testing.T, secret string) *httptest.Server {
	t.Helper()

	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.TLS != nil && r.TLS.ServerName == secret {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("<html><body><h1>Internal admin console</h1>" +
				"<p>Restricted staff tooling, deployment controls and audit logs.</p></body></html>"))
			return
		}
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte("<html><body>404 - no such site on this server</body></html>"))
	}))
	server.TLS = &tls.Config{Certificates: []tls.Certificate{selfSignedCert(t)}}
	server.StartTLS()
	t.Cleanup(server.Close)

	return server
}

// TestSNIRoutedVhostIsFound is the regression test for the defect that motivated
// the -sni flag: with SNI omitted, an SNI-routed virtual host is invisible.
func TestSNIRoutedVhostIsFound(t *testing.T) {
	t.Parallel()

	const secret = "secret.example.com"
	server := newSNIRoutedServer(t, secret)

	tests := []struct {
		name      string
		sni       string
		wantFound bool
	}{
		{
			name:      "auto presents the fuzzed vhost and finds it",
			sni:       SNIAuto,
			wantFound: true,
		},
		{
			// Documents the old behaviour. Without a server name the target
			// serves its default site, which is identical to the baseline, so
			// the vhost cannot be told apart from nothing.
			name:      "none sends no server name and misses it",
			sni:       SNINone,
			wantFound: false,
		},
		{
			// A pinned name is presented for the baseline probe too, so on a
			// purely SNI-routed target the baseline already sees the hidden
			// site and nothing stands out. Pinning is for the opposite case,
			// covered by TestLiteralSNIUnlocksHostRouting.
			name:      "a literal server name makes the baseline match",
			sni:       secret,
			wantFound: false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			opts := testOptions()
			opts.SNI = tc.sni
			fuzzer := testFuzzer(t, opts)
			target := testTarget(t, server, true)
			ctx := context.Background()

			baseline, err := fuzzer.FuzzHost(ctx, target, randomHost("example.com"), "/")
			if err != nil {
				t.Fatalf("baseline request: %v", err)
			}

			found, _, result, err := fuzzer.TestDomain(ctx, target, secret, "/", []string{baseline.Response})
			if err != nil {
				t.Fatalf("test domain: %v", err)
			}
			if found != tc.wantFound {
				t.Errorf("vhost found = %v, want %v (status %d, body %q)",
					found, tc.wantFound, result.Status, result.Body)
			}
		})
	}
}

// TestSNIServerNameSent checks the value that actually reaches the handshake,
// rather than inferring it from what the server chose to serve.
// TestLiteralSNIUnlocksHostRouting covers what -sni <literal> is for: a
// front end that will only serve a request whose TLS server name matches a
// certificate it holds, but which then routes on the Host header. Sending the
// fuzzed vhost as the server name gets the connection refused a layer too
// early, and the virtual hosts behind it never appear.
func TestLiteralSNIUnlocksHostRouting(t *testing.T) {
	t.Parallel()

	const frontend = "wildcard.example.com"
	const hidden = "internal.example.com"

	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.TLS == nil || r.TLS.ServerName != frontend {
			w.WriteHeader(http.StatusMisdirectedRequest)
			_, _ = w.Write([]byte("<html><body>421 unknown server name</body></html>"))
			return
		}
		if r.Host == hidden {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("<html><body><h1>Internal application</h1>" +
				"<p>Billing exports, staff directory and deployment history.</p></body></html>"))
			return
		}
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte("<html><body>404 - no such site</body></html>"))
	}))
	server.TLS = &tls.Config{Certificates: []tls.Certificate{selfSignedCert(t)}}
	server.StartTLS()
	t.Cleanup(server.Close)

	tests := []struct {
		name      string
		sni       string
		wantFound bool
	}{
		{name: "pinned to the front end name", sni: frontend, wantFound: true},
		{name: "auto is turned away at the handshake", sni: SNIAuto, wantFound: false},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			opts := testOptions()
			opts.SNI = tc.sni
			fuzzer := testFuzzer(t, opts)
			target := testTarget(t, server, true)
			ctx := context.Background()

			baseline, err := fuzzer.FuzzHost(ctx, target, randomHost("example.com"), "/")
			if err != nil {
				t.Fatalf("baseline request: %v", err)
			}

			found, _, result, err := fuzzer.TestDomain(ctx, target, hidden, "/", []string{baseline.Response})
			if err != nil {
				t.Fatalf("test domain: %v", err)
			}
			if found != tc.wantFound {
				t.Errorf("vhost found = %v, want %v (status %d)", found, tc.wantFound, result.Status)
			}
		})
	}
}

func TestSNIServerNameSent(t *testing.T) {
	t.Parallel()

	seen := make(chan string, 8)
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		name := ""
		if r.TLS != nil {
			name = r.TLS.ServerName
		}
		seen <- name
		w.WriteHeader(http.StatusOK)
	}))
	server.TLS = &tls.Config{Certificates: []tls.Certificate{selfSignedCert(t)}}
	server.StartTLS()
	t.Cleanup(server.Close)

	tests := []struct {
		name  string
		sni   string
		vhost string
		want  string
	}{
		{name: "auto follows the vhost", sni: SNIAuto, vhost: "shop.example.com", want: "shop.example.com"},
		{name: "none sends nothing", sni: SNINone, vhost: "shop.example.com", want: ""},
		{name: "literal overrides the vhost", sni: "pinned.example.com", vhost: "shop.example.com", want: "pinned.example.com"},
		{
			// RFC 6066 forbids IP literals as SNI values and Go drops them.
			name: "an IP vhost yields no server name", sni: SNIAuto, vhost: "127.0.0.1", want: "",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			opts := testOptions()
			opts.SNI = tc.sni
			fuzzer := testFuzzer(t, opts)

			if _, err := fuzzer.FuzzHost(context.Background(), testTarget(t, server, true), tc.vhost, "/"); err != nil {
				t.Fatalf("request: %v", err)
			}

			select {
			case got := <-seen:
				if got != tc.want {
					t.Errorf("server name = %q, want %q", got, tc.want)
				}
			case <-time.After(5 * time.Second):
				t.Fatal("handler was never reached")
			}
		})
	}
}

// TestSNINotSentOverPlainHTTP guards against keying the client cache on a server
// name for plaintext targets, which would create one client per vhost for no
// benefit.
func TestSNINotSentOverPlainHTTP(t *testing.T) {
	t.Parallel()

	opts := testOptions()
	fuzzer := testFuzzer(t, opts)

	if got := fuzzer.sniFor(Target{Host: "10.0.0.1", Port: 80, TLS: false}, "a.example.com"); got != "" {
		t.Errorf("sniFor over plain HTTP = %q, want empty", got)
	}
	if got := fuzzer.sniFor(Target{Host: "10.0.0.1", Port: 443, TLS: true}, "a.example.com"); got != "a.example.com" {
		t.Errorf("sniFor over TLS = %q, want the vhost", got)
	}
}

func TestParseHeaders(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		input   []string
		wantErr string
		check   func(*testing.T, http.Header)
	}{
		{
			name:  "default user agent",
			input: nil,
			check: func(t *testing.T, h http.Header) {
				if got := h.Get("User-Agent"); got != "VhostFinder" {
					t.Errorf("User-Agent = %q, want VhostFinder", got)
				}
			},
		},
		{
			name:  "name and value are trimmed",
			input: []string{"X-Forwarded-For :  127.0.0.1 "},
			check: func(t *testing.T, h http.Header) {
				if got := h.Get("X-Forwarded-For"); got != "127.0.0.1" {
					t.Errorf("X-Forwarded-For = %q, want 127.0.0.1", got)
				}
			},
		},
		{
			name:  "a value may contain colons",
			input: []string{"Referer: https://example.com:8443/x"},
			check: func(t *testing.T, h http.Header) {
				if got := h.Get("Referer"); got != "https://example.com:8443/x" {
					t.Errorf("Referer = %q", got)
				}
			},
		},
		{
			name:  "user agent can be overridden",
			input: []string{"User-Agent: curl/8.0"},
			check: func(t *testing.T, h http.Header) {
				if got := h.Get("User-Agent"); got != "curl/8.0" {
					t.Errorf("User-Agent = %q, want curl/8.0", got)
				}
			},
		},
		{
			// Regression: this used to panic with an index out of range,
			// taking the whole scan down on a typo.
			name:    "a header without a colon is rejected",
			input:   []string{"malformed-header"},
			wantErr: "Name: value",
		},
		{
			name:    "an empty name is rejected",
			input:   []string{": value"},
			wantErr: "empty name",
		},
		{
			name:    "the host header is refused",
			input:   []string{"Host: evil.example.com"},
			wantErr: "cannot be set",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			headers, err := ParseHeaders(tc.input)
			if tc.wantErr != "" {
				if err == nil {
					t.Fatalf("expected an error containing %q, got none", tc.wantErr)
				}
				if !strings.Contains(err.Error(), tc.wantErr) {
					t.Fatalf("error = %q, want it to contain %q", err, tc.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			tc.check(t, headers)
		})
	}
}

func TestMaxBodyCapsTheRead(t *testing.T) {
	t.Parallel()

	const bodySize = 512 * 1024
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(make([]byte, bodySize))
	}))
	t.Cleanup(server.Close)

	tests := []struct {
		name          string
		maxBody       int64
		wantLength    int64
		wantTruncated bool
	}{
		{name: "under the cap", maxBody: bodySize * 2, wantLength: bodySize, wantTruncated: false},
		{name: "at the cap", maxBody: 4096, wantLength: 4096, wantTruncated: true},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			opts := testOptions()
			opts.MaxBody = tc.maxBody
			fuzzer := testFuzzer(t, opts)

			result, err := fuzzer.FuzzHost(context.Background(), testTarget(t, server, false), "a.example.com", "/")
			if err != nil {
				t.Fatalf("request: %v", err)
			}
			if result.ContentLength != tc.wantLength {
				t.Errorf("ContentLength = %d, want %d", result.ContentLength, tc.wantLength)
			}
			if result.Truncated != tc.wantTruncated {
				t.Errorf("Truncated = %v, want %v", result.Truncated, tc.wantTruncated)
			}
		})
	}
}

// TestChunkedContentLength covers the old output column reading -1 whenever the
// target used chunked transfer encoding.
func TestChunkedContentLength(t *testing.T) {
	t.Parallel()

	const body = "chunked response body that carries no Content-Length header"
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Transfer-Encoding", "chunked")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(body))
		w.(http.Flusher).Flush()
	}))
	t.Cleanup(server.Close)

	fuzzer := testFuzzer(t, testOptions())
	result, err := fuzzer.FuzzHost(context.Background(), testTarget(t, server, false), "a.example.com", "/")
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	if result.ContentLength != int64(len(body)) {
		t.Errorf("ContentLength = %d, want %d", result.ContentLength, len(body))
	}
}

func TestFuzzHostSetsHostHeader(t *testing.T) {
	t.Parallel()

	seen := make(chan string, 1)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen <- r.Host
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(server.Close)

	fuzzer := testFuzzer(t, testOptions())
	if _, err := fuzzer.FuzzHost(context.Background(), testTarget(t, server, false), "vhost.example.com", "/"); err != nil {
		t.Fatalf("request: %v", err)
	}

	if got := <-seen; got != "vhost.example.com" {
		t.Errorf("Host header = %q, want vhost.example.com", got)
	}
}

func TestRetriesTransientErrors(t *testing.T) {
	t.Parallel()

	opts := testOptions()
	opts.Retries = 2
	opts.Timeout = 1
	fuzzer := testFuzzer(t, opts)

	// Nothing is listening, so every attempt fails and the call still returns
	// an error rather than hanging or panicking.
	_, err := fuzzer.FuzzHost(context.Background(), Target{Host: "127.0.0.1", Port: 1, TLS: false}, "a.example.com", "/")
	if err == nil {
		t.Fatal("expected a connection error")
	}
}

func TestContextCancellationStopsRequests(t *testing.T) {
	t.Parallel()

	release := make(chan struct{})
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		<-release
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(func() {
		close(release)
		server.Close()
	})

	fuzzer := testFuzzer(t, testOptions())
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	if _, err := fuzzer.FuzzHost(ctx, testTarget(t, server, false), "a.example.com", "/"); err == nil {
		t.Fatal("expected a cancellation error")
	}
}
