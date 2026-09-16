# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [Unreleased]

### Fixed

- **TLS SNI was never sent.** Go omits the SNI extension when the URL host is a
  bare IP literal (RFC 6066 forbids IP literals as SNI values), and
  `Request.Host` never reaches the TLS layer. Every HTTPS request therefore
  handshook with an empty server name, so targets that route on SNI — CDNs,
  load balancers, Envoy, IIS — served their default site regardless of the Host
  header and real virtual hosts went undetected with no error to show for it.
  See the new `-sni` flag.
- A custom header without a colon (`-H foo`) crashed the process with an index
  out of range. Headers are validated before the scan starts, and `-H Host` is
  now refused since the Host header is the value being fuzzed.
- Response bodies were read into memory without a limit. Capped by `-max-body`.
- The content length column showed `-1` for any chunked response.
- A flag parsing error was printed and the run continued with partial
  configuration. It now exits non-zero.
- Verbose mode printed a baseline URL that differed from the URL actually
  requested.
- The status line parse in the similarity comparison could panic on a malformed
  status line.

### Added

- `-sni` with three modes: `auto` (default) presents the fuzzed virtual host as
  the TLS server name, `none` reproduces the previous behaviour, or pin a
  literal name.
- `-baseline-samples` (default 3) takes several baseline probes and requires a
  candidate to differ from all of them, suppressing false positives on pages
  that carry a timestamp, CSRF token or rotating backend. The tool warns when
  the samples disagree with each other.
- `-baseline-refresh` re-probes the baseline periodically during long scans.
- `-threshold` exposes the similarity cutoff, previously hardcoded in two
  places.
- `-max-errors` abandons a host after N consecutive failures instead of burning
  the whole wordlist against a dead one.
- `-rate` and `-delay` for rate limiting and jitter; `-retries` for transient
  network errors.
- Match and filter flags: `-mc`/`-fc` (status), `-ms`/`-fs` (size), `-mw`/`-fw`
  (words), `-ml`/`-fl` (lines), `-mr`/`-fr` (body regex).
- `-o` with `-of txt|json|jsonl|csv`, and `-silent` for bare virtual host names.
- `-resume` checkpoints completed work to an append-only log, fingerprinted so
  a checkpoint cannot be replayed into a different scan.
- Targets accept CIDR ranges, `host:port` and full URLs, each carrying its own
  port and scheme. `-max-targets` guards against expanding a stray `/8`.
- Targets are read from stdin when none are given as flags.
- `-version`.
- Unit and integration tests, including a TLS server that routes on SNI as the
  regression test for the SNI defect.
- CI on Go 1.25, 1.26 and 1.27 with the race detector, golangci-lint,
  govulncheck, Dependabot, a Dockerfile and GoReleaser packaging.

### Changed

- Findings go to stdout and diagnostics to stderr; the two previously shared
  stdout, which made the output impossible to pipe. All console writes are
  serialised, so lines from concurrent workers no longer interleave.
- Baselines for multiple targets and paths are probed in parallel instead of
  serially before the first real request.
- `SIGINT` and `SIGTERM` cancel the scan, flush the checkpoint and print a
  summary.
- The end of a run prints a summary: targets, requests, findings, errors,
  skipped and abandoned hosts.
- `github.com/wdahlenburg/HttpComparison` is inlined as `utils/similarity.go`.
  It was six commits, dormant since 2023, and about thirty lines. Scoring is
  unchanged.
- Go directive raised from 1.16 to 1.25. Dependencies updated, closing three
  years of unpatched transitive advisories (`golang.org/x/net` v0.10.0 ->
  v0.55.0 among them).

## [0.1.0] - 2023-06-01

Initial release of the upstream project, from which this fork is derived.
