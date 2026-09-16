# VhostFinder

VhostFinder identifies virtual hosts by sending a fuzzed `Host` header to a target and comparing each response against a baseline of responses collected for hostnames that do not exist. A response that differs from every baseline sample is reported as a virtual host.

VhostFinder also supports fuzzing custom paths, but dedicated tools like ffuf are better suited for directory fuzzing once a vhost has been identified. A discovered vhost can be added to your `/etc/hosts` file or inserted into a DNS server so it can be used with other tools.

# Install

```
go install -v github.com/whiskeykilo/VhostFinder@latest
```

Requires Go 1.25 or newer.

Or build and run it with Docker:

```
docker build -t vhostfinder . && docker run --rm vhostfinder -ip 10.8.0.1 -wordlist ...
```

The wordlist and any other input files live outside the container, so mount them in:

```
docker run --rm -v $(pwd):/data vhostfinder -ip 10.8.0.1 -wordlist /data/words.txt
```

# Usage

```
VhostFinder discovers virtual hosts by fuzzing the HTTP Host header.

Usage:
  VhostFinder [flags]

Flags:
INPUT:
   -ip string[]          Target to fuzz: IP, hostname, CIDR, host:port or URL
   -ips string[]         File of targets, one per line (also read from stdin when piped)
   -wordlist string[]    File of FQDNs or subdomain prefixes to fuzz for
   -d, -domain string[]  Domain(s) to append to a subdomain wordlist (Ex: example1.com)
   -p, -path string[]    Custom path(s) to send during fuzzing
   -paths string[]       File list of custom paths

REQUEST:
   -port int             Default port, when a target does not carry one (default 443)
   -tls                  Use TLS (disable with -tls=false) (default true)
   -sni string           TLS server name: "auto" follows the fuzzed vhost, "none" sends none, or a literal name (default "auto")
   -H, -header string[]  Custom header(s) for each request
   -proxy string         Proxy (Ex: http://127.0.0.1:8080)
   -timeout int          Timeout per HTTP request, in seconds (default 8)
   -retries int          Retries for transient network errors (default 1)
   -max-body int         Maximum response body bytes to read (default 1048576)

DETECTION:
   -threshold string      Similarity below which a response counts as different (0.0-1.0) (default "0.5")
   -baseline-samples int  Baseline probes per target and path (default 3)
   -baseline-refresh int  Re-probe the baseline every N requests (0 disables)
   -force                 Scan even when the baseline fails, reporting every response
   -verify                Verify a vhost differs from the publicly resolved site

MATCHERS AND FILTERS:
   -mc string  Match status codes (Ex: 200,301-399)
   -fc string  Filter out status codes
   -ms string  Match response sizes
   -fs string  Filter out response sizes
   -mw string  Match response word counts
   -fw string  Filter out response word counts
   -ml string  Match response line counts
   -fl string  Filter out response line counts
   -mr string  Match responses whose body matches this regex
   -fr string  Filter out responses whose body matches this regex

PACING:
   -t, -threads int  Number of concurrent workers (default 10)
   -rate int         Maximum requests per second (0 is unlimited)
   -delay string     Delay before each request in seconds, fixed or a range (Ex: 0.1-2.0)
   -max-errors int   Abandon a host after N consecutive errors (0 disables) (default 20)
   -max-targets int  Maximum targets after CIDR expansion (default 65536)

OUTPUT:
   -o, -output string  Write results to a file
   -of string          Output file format: txt, json, jsonl or csv (default "txt")
   -silent             Print only discovered vhosts on stdout
   -v, -verbose        Verbose mode
   -resume string      Checkpoint file to resume from and append to
   -version            Show version and exit
```

# Examples

Every finding is printed in the same column shape, on stdout:

```
[+] [host] [path] [status] [content length] vhost
```

### Basic scan

```bash
$ VhostFinder -ip 10.8.0.1 -wordlist domains.txt
[!] Finding vhosts across 1 target(s) and 1 path(s)
[+] [10.8.0.1] [/] [200] [1337] host.example.com
[!] Done in 4.198s: 1 targets, 256 requests, 1 vhosts found, 0 errors, 0 skipped, 0 hosts abandoned
```

### Subdomain-prefix mode

`-wordlist` can hold subdomain prefixes instead of full hostnames, and `-d` supplies the domain to append to each one.

```bash
$ VhostFinder -ip 10.8.0.1 -wordlist subdomains.txt -d host1.example.com
[!] Finding vhosts across 1 target(s) and 1 path(s)
[+] [10.8.0.1] [/] [200] [31337] admin.host1.example.com
[!] Done in 5.804s: 1 targets, 128 requests, 1 vhosts found, 0 errors, 0 skipped, 0 hosts abandoned
```

### Multiple domains

Repeat `-d` to fuzz the same subdomain wordlist against several base domains in one run.

```bash
$ VhostFinder -ip 10.8.0.1 -wordlist subdomains.txt -d host1.example.com -d host2.example.com -d anotherdomain.net
[!] Finding vhosts across 1 target(s) and 1 path(s)
[+] [10.8.0.1] [/] [200] [31337] admin.host1.example.com
[+] [10.8.0.1] [/] [503] [1072] test.anotherdomain.net
[+] [10.8.0.1] [/] [200] [3749] admin.host2.example.com
[!] Done in 9.612s: 1 targets, 384 requests, 3 vhosts found, 0 errors, 0 skipped, 0 hosts abandoned
```

### Targets from stdin

`-ip` and `-ips` are read first; stdin is only consulted when neither is set, so VhostFinder composes with subfinder, httpx and similar tools.

```bash
$ cat ips.txt | VhostFinder -wordlist words.txt
[!] Finding vhosts across 12 target(s) and 1 path(s)
[+] [10.8.0.4] [/] [200] [942] internal.example.com
[!] Done in 22.114s: 12 targets, 3072 requests, 1 vhosts found, 0 errors, 0 skipped, 0 hosts abandoned
```

### CIDR input

`-ip` accepts CIDR notation and expands it, subject to `-max-targets` (default 65536).

```bash
$ VhostFinder -ip 10.8.0.0/24 -wordlist words.txt -t 50
[!] Finding vhosts across 254 target(s) and 1 path(s)
[+] [10.8.0.17] [/] [200] [942] internal.example.com
[!] Done in 41.307s: 254 targets, 65024 requests, 1 vhosts found, 3 errors, 0 skipped, 0 hosts abandoned
```

### JSONL output, piped onward

`-silent` narrows stdout to bare vhost names so it can feed straight into another tool, while `-o`/`-of` still write the full record to a file.

```bash
$ VhostFinder -ip 10.8.0.1 -wordlist words.txt -silent -o results.jsonl -of jsonl | tee found.txt
admin.example.com
api.example.com

$ cat results.jsonl
{"timestamp":"2026-09-15T10:04:21Z","host":"10.8.0.1","port":443,"scheme":"https","path":"/","vhost":"admin.example.com","status":200,"content_length":31337,"words":812,"lines":140,"similarity":0.31,"url":"https://10.8.0.1:443/"}
{"timestamp":"2026-09-15T10:04:23Z","host":"10.8.0.1","port":443,"scheme":"https","path":"/","vhost":"api.example.com","status":200,"content_length":204,"words":18,"lines":9,"similarity":0.12,"url":"https://10.8.0.1:443/"}
```

### Rate limiting

`-rate` caps requests per second across the whole run; `-delay` adds a further pause in front of every request, fixed or a random range.

```bash
$ VhostFinder -ip 10.8.0.1 -wordlist big-wordlist.txt -rate 20 -delay 0.1-0.5
[!] Finding vhosts across 1 target(s) and 1 path(s)
[+] [10.8.0.1] [/] [200] [1337] host.example.com
[!] Done in 3m21.402s: 1 targets, 4000 requests, 1 vhosts found, 0 errors, 0 skipped, 0 hosts abandoned
```

### Resuming a scan

`-resume` writes a checkpoint as the scan runs; interrupting with Ctrl-C stops dispatching new work but still flushes it. Passing the same checkpoint file to a later run skips whatever it already recorded.

```bash
$ VhostFinder -ip 10.8.0.1 -wordlist big-wordlist.txt -resume scan.checkpoint
[!] Finding vhosts across 1 target(s) and 1 path(s)
^C
[!] Done in 45.213s: 1 targets, 900 requests, 0 vhosts found, 0 errors, 0 skipped, 0 hosts abandoned
[!] Interrupted

$ VhostFinder -ip 10.8.0.1 -wordlist big-wordlist.txt -resume scan.checkpoint
[!] Finding vhosts across 1 target(s) and 1 path(s)
[!] Resuming: 900 jobs already completed
[+] [10.8.0.1] [/] [200] [1337] host.example.com
[!] Done in 2m14.098s: 1 targets, 3100 requests, 1 vhosts found, 0 errors, 0 skipped, 0 hosts abandoned
```

# TLS server name (SNI)

This is the part of VhostFinder most worth understanding before you trust a scan's results.

When a Go HTTP client requests `https://<IP>/`, it sends no TLS SNI extension at all. RFC 6066 forbids IP literals as SNI values, and `Request.Host` — the header VhostFinder fuzzes — never reaches the TLS layer; SNI and the Host header are two different things, set at two different protocol layers.

Before the `-sni` flag existed, this tool therefore handshook with an empty server name on every HTTPS request, regardless of which Host header it sent. Targets that route on SNI before they ever look at the Host header — CDNs, load balancers, Envoy, IIS — served their default site no matter what VhostFinder asked for, so real virtual hosts were silently missed. There was no error and nothing looked wrong: the scan just came back clean.

`-sni` controls what VhostFinder presents at the TLS layer:

- **`-sni auto` (the default)** presents the virtual host currently being fuzzed as the TLS server name, so the TLS layer and the Host header agree. This is what you want almost always.
- **`-sni none`** reproduces the old behaviour: no server name is sent. It is kept so a scan's results can be compared against a previous one, and for the minority of targets whose TLS stack mishandles SNI.
- **`-sni <name>`** pins one literal server name on every request. Use this against a front end that only completes a handshake for names it holds a certificate for, and *then* routes the decrypted request on the Host header — sending the fuzzed vhost itself as the server name gets you rejected at the handshake before the Host header is ever read. Pinning a name the front end will accept gets you past that handshake so the Host header comparison can happen at all.

  The trade-off: with a pinned name, the baseline probe presents that same name too. A target that routes purely on SNI, with no regard for the Host header, will then look uniform for every candidate, and VhostFinder will report nothing.

# Tuning detection and false positives

VhostFinder decides "different" by comparing a candidate response against several baseline probes made with random, non-existent hostnames — not against a single one.

- `-baseline-samples` (default 3) sets how many baseline probes are taken per target and path. A candidate has to differ from every one of them to be reported. This is what suppresses false positives on a page that carries a timestamp, a CSRF token, or a load-balanced backend. Against a single sample, such a page differs from itself on the next request, so every candidate looks like a find. Against several, the volatile part is present in each one and only a genuinely different response stands out.
- When the baseline samples disagree with each other, VhostFinder warns that the baseline is unstable — the target is varying its own responses independently of the Host header, and findings made against that baseline carry a high false-positive rate.
- `-baseline-refresh N` re-probes the baseline every N requests, for long scans against a target whose "non-vhost" response can legitimately drift over the course of the run.
- `-threshold` is the similarity cutoff, from 0.0 to 1.0, default 0.5. Lower is stricter: a candidate has to differ more from the baseline before it is reported, which means fewer findings.
- The matcher/filter flags — `-mc`/`-fc` (status), `-ms`/`-fs` (size), `-mw`/`-fw` (word count), `-ml`/`-fl` (line count), `-mr`/`-fr` (body regex) — take comma-separated values and inclusive ranges, e.g. `-mc 200,301-399`. They are applied after the similarity comparison: a match flag narrows what gets reported down to values you specify, a filter flag excludes values you specify, and when the same value satisfies both, the filter wins.
- `-verify` re-fetches the candidate vhost over its own public DNS name, rather than the target IP, and drops the finding if that response is indistinguishable from what the target IP served — a vhost that just mirrors the public site is usually not interesting. A vhost that is not reachable at all under its public name is kept, since that is typically the more interesting case: an internal-only virtual host.

# Output and composition

Findings are the only thing VhostFinder ever writes to stdout; every informational, verbose and warning line goes to stderr instead. That means `VhostFinder ... | other-tool` sees only the findings, in order, with nothing else mixed in.

- `-silent` narrows stdout further, to the bare vhost name, one per line.
- `-o <file>` writes full result records to a file, independent of stdout, and `-of` selects the format: `txt` (default, the same columns as stdout without the `[+]` prefix), `json` (one array, written when the file is closed), `jsonl` (one JSON object per line, written as each result is found), or `csv`.

# What is Virtual Host Fuzzing?

Essentially the following request is sent repeatedly to a particular IP:

```
GET / HTTP/1.1
Host: FUZZ
Connection: close


```

The host header is fuzzed based on user input, while all requests are sent to the same IP.

# Credit

This is a fork of [wdahlenburg/VhostFinder](https://github.com/wdahlenburg/VhostFinder) by Wes Dahlenburg.
