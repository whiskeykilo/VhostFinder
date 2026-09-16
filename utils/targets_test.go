package utils

import (
	"net/netip"
	"strings"
	"testing"
)

func TestParseTarget(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name        string
		spec        string
		defaultPort int
		defaultTLS  bool
		wantHost    string
		wantPort    int
		wantTLS     bool
		wantErr     bool
	}{
		{
			name:        "bare IPv4",
			spec:        "10.0.0.1",
			defaultPort: 80,
			defaultTLS:  false,
			wantHost:    "10.0.0.1",
			wantPort:    80,
			wantTLS:     false,
		},
		{
			name:        "bare hostname",
			spec:        "example.com",
			defaultPort: 8080,
			defaultTLS:  false,
			wantHost:    "example.com",
			wantPort:    8080,
			wantTLS:     false,
		},
		{
			name:        "host:port",
			spec:        "example.com:9000",
			defaultPort: 80,
			defaultTLS:  false,
			wantHost:    "example.com",
			wantPort:    9000,
			wantTLS:     false,
		},
		{
			name:        "bare IPv6 literal not misread as host:port",
			spec:        "::1",
			defaultPort: 443,
			defaultTLS:  true,
			wantHost:    "::1",
			wantPort:    443,
			wantTLS:     true,
		},
		{
			name:        "bracketed IPv6 with port",
			spec:        "[::1]:8443",
			defaultPort: 80,
			defaultTLS:  false,
			wantHost:    "::1",
			wantPort:    8443,
			wantTLS:     false,
		},
		{
			name:        "http URL defaults TLS false port 80",
			spec:        "http://h",
			defaultPort: 9999,
			defaultTLS:  true,
			wantHost:    "h",
			wantPort:    80,
			wantTLS:     false,
		},
		{
			name:        "https URL defaults TLS true port 443",
			spec:        "https://h",
			defaultPort: 9999,
			defaultTLS:  false,
			wantHost:    "h",
			wantPort:    443,
			wantTLS:     true,
		},
		{
			name:        "https URL with explicit port",
			spec:        "https://h:8443",
			defaultPort: 9999,
			defaultTLS:  false,
			wantHost:    "h",
			wantPort:    8443,
			wantTLS:     true,
		},
		{
			name:        "unsupported scheme",
			spec:        "ftp://h",
			defaultPort: 80,
			defaultTLS:  false,
			wantErr:     true,
		},
		{
			name:        "port zero out of range",
			spec:        "h:0",
			defaultPort: 80,
			defaultTLS:  false,
			wantErr:     true,
		},
		{
			name:        "port 65536 out of range",
			spec:        "https://h:65536",
			defaultPort: 80,
			defaultTLS:  false,
			wantErr:     true,
		},
		{
			name:        "negative port out of range via host:port",
			spec:        "h:-1",
			defaultPort: 80,
			defaultTLS:  false,
			wantErr:     true,
		},
		{
			name:        "negative port out of range via URL",
			spec:        "https://h:-1",
			defaultPort: 80,
			defaultTLS:  false,
			wantErr:     true,
		},
		{
			name:        "empty spec",
			spec:        "",
			defaultPort: 80,
			defaultTLS:  false,
			wantErr:     true,
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got, err := ParseTarget(tt.spec, tt.defaultPort, tt.defaultTLS)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("ParseTarget(%q) = %+v, want error", tt.spec, got)
				}
				return
			}
			if err != nil {
				t.Fatalf("ParseTarget(%q) unexpected error: %v", tt.spec, err)
			}
			if got.Host != tt.wantHost || got.Port != tt.wantPort || got.TLS != tt.wantTLS {
				t.Errorf("ParseTarget(%q) = %+v, want {Host:%s Port:%d TLS:%v}",
					tt.spec, got, tt.wantHost, tt.wantPort, tt.wantTLS)
			}
		})
	}
}

func TestTargetURL(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		tgt  Target
		path string
		want string
	}{
		{
			name: "https default port omitted",
			tgt:  Target{Host: "example.com", Port: 443, TLS: true},
			path: "/x",
			want: "https://example.com/x",
		},
		{
			name: "http default port omitted",
			tgt:  Target{Host: "example.com", Port: 80, TLS: false},
			path: "/x",
			want: "http://example.com/x",
		},
		{
			name: "https non-default port included",
			tgt:  Target{Host: "example.com", Port: 8443, TLS: true},
			path: "/x",
			want: "https://example.com:8443/x",
		},
		{
			name: "http non-default port included",
			tgt:  Target{Host: "example.com", Port: 8080, TLS: false},
			path: "/x",
			want: "http://example.com:8080/x",
		},
		{
			name: "IPv6 host bracketed with default port omitted",
			tgt:  Target{Host: "::1", Port: 443, TLS: true},
			path: "/x",
			want: "https://[::1]/x",
		},
		{
			name: "IPv6 host bracketed with non-default port",
			tgt:  Target{Host: "::1", Port: 8443, TLS: true},
			path: "/x",
			want: "https://[::1]:8443/x",
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := tt.tgt.URL(tt.path); got != tt.want {
				t.Errorf("URL(%q) = %q, want %q", tt.path, got, tt.want)
			}
		})
	}
}

func TestTargetAddrAndScheme(t *testing.T) {
	t.Parallel()

	tgt := Target{Host: "example.com", Port: 8080, TLS: true}
	if got, want := tgt.Addr(), "example.com:8080"; got != want {
		t.Errorf("Addr() = %q, want %q", got, want)
	}
	if got, want := tgt.Scheme(), "https"; got != want {
		t.Errorf("Scheme() = %q, want %q", got, want)
	}

	plain := Target{Host: "example.com", Port: 80, TLS: false}
	if got, want := plain.Scheme(), "http"; got != want {
		t.Errorf("Scheme() = %q, want %q", got, want)
	}

	v6 := Target{Host: "::1", Port: 443, TLS: true}
	if got, want := v6.Addr(), "[::1]:443"; got != want {
		t.Errorf("Addr() = %q, want %q", got, want)
	}
}

func TestParseTargetsDedupSkipAndBudget(t *testing.T) {
	t.Parallel()

	specs := []string{
		"10.0.0.1",
		"10.0.0.1", // duplicate
		"",
		"   ",
		"# a comment",
		"10.0.0.2",
	}
	got, err := ParseTargets(specs, 80, false, 0)
	if err != nil {
		t.Fatalf("ParseTargets unexpected error: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("ParseTargets returned %d targets, want 2: %+v", len(got), got)
	}
	want := []Target{
		{Host: "10.0.0.1", Port: 80, TLS: false},
		{Host: "10.0.0.2", Port: 80, TLS: false},
	}
	for i, w := range want {
		if got[i] != w {
			t.Errorf("targets[%d] = %+v, want %+v", i, got[i], w)
		}
	}

	// Exceeding maxTargets returns an error.
	_, err = ParseTargets([]string{"10.0.0.1", "10.0.0.2", "10.0.0.3"}, 80, false, 2)
	if err == nil {
		t.Fatalf("ParseTargets with count over maxTargets: want error, got nil")
	}
}

func TestExpandCIDR(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		prefix    string
		wantCount int
		wantErr   bool
	}{
		{
			name:      "/30 skips network and broadcast",
			prefix:    "10.0.0.0/30",
			wantCount: 2,
		},
		{
			name:      "/32 single host",
			prefix:    "10.0.0.1/32",
			wantCount: 1,
		},
		{
			name:      "/31 no edge skipping",
			prefix:    "10.0.0.0/31",
			wantCount: 2,
		},
		{
			name:      "IPv6 /126 no edge skipping",
			prefix:    "2001:db8::/126",
			wantCount: 4,
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			prefix, err := netip.ParsePrefix(tt.prefix)
			if err != nil {
				t.Fatalf("ParsePrefix(%q): %v", tt.prefix, err)
			}
			targets, err := ExpandCIDR(prefix, 80, false, DefaultMaxTargets)
			if err != nil {
				t.Fatalf("ExpandCIDR(%q) unexpected error: %v", tt.prefix, err)
			}
			if len(targets) != tt.wantCount {
				t.Errorf("ExpandCIDR(%q) returned %d targets, want %d: %+v", tt.prefix, len(targets), tt.wantCount, targets)
			}
		})
	}
}

func TestExpandCIDROverBudget(t *testing.T) {
	t.Parallel()

	// A /8 expands to far more hosts than a tiny budget allows.
	prefix := netip.MustParsePrefix("10.0.0.0/8")
	_, err := ExpandCIDR(prefix, 80, false, 10)
	if err == nil {
		t.Fatalf("ExpandCIDR over budget: want error, got nil")
	}
}

func TestReadLines(t *testing.T) {
	t.Parallel()

	input := "  foo  \n\n# a comment\nbar\n   # indented comment\nbaz   \n"
	got, err := ReadLines(strings.NewReader(input))
	if err != nil {
		t.Fatalf("ReadLines unexpected error: %v", err)
	}
	want := []string{"foo", "bar", "baz"}
	if len(got) != len(want) {
		t.Fatalf("ReadLines = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("ReadLines[%d] = %q, want %q", i, got[i], want[i])
		}
	}
}

func TestReadLinesEmpty(t *testing.T) {
	t.Parallel()

	got, err := ReadLines(strings.NewReader(""))
	if err != nil {
		t.Fatalf("ReadLines unexpected error: %v", err)
	}
	if len(got) != 0 {
		t.Errorf("ReadLines(\"\") = %v, want empty", got)
	}
}
