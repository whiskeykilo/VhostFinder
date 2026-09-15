package utils

import (
	"bufio"
	"fmt"
	"io"
	"net"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
)

// DefaultMaxTargets caps CIDR expansion. A stray /8 is 16 million hosts and
// almost always a typo; requiring an explicit override is cheaper than finding
// out after the scan starts.
const DefaultMaxTargets = 65536

// Target is one host to fuzz. Port and scheme travel with the host so that a
// single run can mix `10.0.0.1`, `10.0.0.2:8443` and `http://10.0.0.3:8080`.
type Target struct {
	Host string
	Port int
	TLS  bool
}

// Addr returns the host:port dial address, bracketing IPv6 literals.
func (t Target) Addr() string {
	return net.JoinHostPort(t.Host, strconv.Itoa(t.Port))
}

// Scheme returns "https" or "http".
func (t Target) Scheme() string {
	if t.TLS {
		return "https"
	}
	return "http"
}

// isDefaultPort reports whether the port is implied by the scheme and can be
// left out of a URL.
func (t Target) isDefaultPort() bool {
	return (t.TLS && t.Port == 443) || (!t.TLS && t.Port == 80)
}

// URL builds the request URL for a path, omitting the port when it is the
// scheme default so that the Host header is not second-guessed by the server.
func (t Target) URL(path string) string {
	host := t.Host
	if t.isDefaultPort() {
		if strings.Contains(host, ":") {
			host = "[" + host + "]"
		}
	} else {
		host = t.Addr()
	}
	return t.Scheme() + "://" + host + path
}

func (t Target) String() string {
	return t.Scheme() + "://" + t.Addr()
}

// ParseTarget turns one user-supplied target into a Target. It accepts a bare
// IP or hostname, host:port, or a full URL; a scheme or port in the spec wins
// over the defaults.
func ParseTarget(spec string, defaultPort int, defaultTLS bool) (Target, error) {
	spec = strings.TrimSpace(spec)
	if spec == "" {
		return Target{}, fmt.Errorf("empty target")
	}

	t := Target{Port: defaultPort, TLS: defaultTLS}

	if strings.Contains(spec, "://") {
		u, err := url.Parse(spec)
		if err != nil {
			return Target{}, fmt.Errorf("invalid target URL %q: %w", spec, err)
		}
		switch u.Scheme {
		case "http":
			t.TLS = false
			t.Port = 80
		case "https":
			t.TLS = true
			t.Port = 443
		default:
			return Target{}, fmt.Errorf("unsupported scheme %q in target %q", u.Scheme, spec)
		}
		t.Host = u.Hostname()
		if p := u.Port(); p != "" {
			port, err := strconv.Atoi(p)
			if err != nil {
				return Target{}, fmt.Errorf("invalid port in target %q: %w", spec, err)
			}
			t.Port = port
		}
		if t.Host == "" {
			return Target{}, fmt.Errorf("target %q has no host", spec)
		}
		return t, validatePort(t.Port, spec)
	}

	// A bare IPv6 literal has colons but no port; netip settles it before
	// SplitHostPort gets a chance to misread the last group as a port.
	if addr, err := netip.ParseAddr(spec); err == nil {
		t.Host = addr.String()
		return t, validatePort(t.Port, spec)
	}

	if host, port, err := net.SplitHostPort(spec); err == nil {
		parsed, convErr := strconv.Atoi(port)
		if convErr != nil {
			return Target{}, fmt.Errorf("invalid port in target %q: %w", spec, convErr)
		}
		if host == "" {
			return Target{}, fmt.Errorf("target %q has no host", spec)
		}
		t.Host = host
		t.Port = parsed
		return t, validatePort(t.Port, spec)
	}

	t.Host = spec
	return t, validatePort(t.Port, spec)
}

func validatePort(port int, spec string) error {
	if port < 1 || port > 65535 {
		return fmt.Errorf("port %d out of range in target %q", port, spec)
	}
	return nil
}

// ExpandCIDR returns every address in a prefix. For prefixes wider than /31 the
// network and broadcast addresses are skipped, matching what a scanner is
// actually able to talk to.
func ExpandCIDR(prefix netip.Prefix, defaultPort int, defaultTLS bool, remaining int) ([]Target, error) {
	prefix = prefix.Masked()
	hosts := prefixSize(prefix)
	if hosts > remaining {
		return nil, fmt.Errorf("%s expands to %d hosts, over the remaining budget of %d (raise -max-targets to allow it)", prefix, hosts, remaining)
	}

	var targets []Target
	addr := prefix.Addr()
	skipEdges := prefix.Addr().Is4() && prefix.Bits() < 31
	for prefix.Contains(addr) {
		isNetwork := addr == prefix.Addr()
		isBroadcast := !prefix.Contains(addr.Next())
		if !skipEdges || (!isNetwork && !isBroadcast) {
			targets = append(targets, Target{Host: addr.String(), Port: defaultPort, TLS: defaultTLS})
		}
		next := addr.Next()
		if !next.IsValid() {
			break
		}
		addr = next
	}
	return targets, nil
}

// prefixSize returns the usable host count for a prefix, saturating at maxInt
// so that an absurd prefix fails the budget check instead of overflowing.
func prefixSize(prefix netip.Prefix) int {
	bits := prefix.Addr().BitLen() - prefix.Bits()
	if bits > 31 {
		return int(^uint(0) >> 1)
	}
	size := 1 << bits
	if prefix.Addr().Is4() && prefix.Bits() < 31 {
		size -= 2
	}
	return size
}

// ParseTargets resolves every spec into Targets, expanding CIDR notation and
// enforcing an overall budget.
func ParseTargets(specs []string, defaultPort int, defaultTLS bool, maxTargets int) ([]Target, error) {
	if maxTargets <= 0 {
		maxTargets = DefaultMaxTargets
	}

	var targets []Target
	seen := make(map[Target]struct{})

	add := func(candidates ...Target) error {
		for _, t := range candidates {
			if _, dup := seen[t]; dup {
				continue
			}
			if len(targets) >= maxTargets {
				return fmt.Errorf("target list exceeds the maximum of %d (raise -max-targets to allow it)", maxTargets)
			}
			seen[t] = struct{}{}
			targets = append(targets, t)
		}
		return nil
	}

	for _, spec := range specs {
		spec = strings.TrimSpace(spec)
		if spec == "" || strings.HasPrefix(spec, "#") {
			continue
		}

		if prefix, err := netip.ParsePrefix(spec); err == nil {
			expanded, err := ExpandCIDR(prefix, defaultPort, defaultTLS, maxTargets-len(targets))
			if err != nil {
				return nil, err
			}
			if err := add(expanded...); err != nil {
				return nil, err
			}
			continue
		}

		t, err := ParseTarget(spec, defaultPort, defaultTLS)
		if err != nil {
			return nil, err
		}
		if err := add(t); err != nil {
			return nil, err
		}
	}

	return targets, nil
}

// ReadLines reads newline-separated entries, dropping blanks and # comments.
// It is used for wordlists and for targets piped in on stdin.
func ReadLines(r io.Reader) ([]string, error) {
	var lines []string
	scanner := bufio.NewScanner(r)
	scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		lines = append(lines, line)
	}
	return lines, scanner.Err()
}
