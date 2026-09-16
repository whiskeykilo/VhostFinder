package utils

import (
	"testing"

	"github.com/adrg/strutil"
	"github.com/adrg/strutil/metrics"
)

// simJaccard is the oracle used to verify Similarity.Score's weighting logic:
// it calls the exact same third-party metric similarity.go uses, so the
// tests below check VhostFinder's wiring (the statusMismatchWeight
// multiplication) rather than re-deriving the Jaccard algorithm by hand.
func simJaccard(a, b string) float64 {
	return strutil.Similarity(a, b, metrics.NewJaccard())
}

func simAlmostEqual(a, b float64) bool {
	const eps = 1e-9
	d := a - b
	if d < 0 {
		d = -d
	}
	return d < eps
}

// Realistic HTTP response dumps (status line + headers + body) used as
// fixtures below, standing in for what a real vhost probe would capture.
const (
	simRespBaselineOK = "HTTP/1.1 200 OK\r\n" +
		"Server: nginx/1.18.0\r\n" +
		"Date: Mon, 15 Sep 2026 10:00:00 GMT\r\n" +
		"Content-Type: text/html; charset=UTF-8\r\n" +
		"Connection: keep-alive\r\n" +
		"\r\n" +
		"<!DOCTYPE html><html><head><title>Welcome to example.com</title></head>" +
		"<body><h1>Welcome</h1><p>This is the default landing page for the site.</p></body></html>"

	// simRespVariantOK is near-identical to the baseline (same status, one
	// word changed in the body) - the kind of noise a real server produces
	// between two otherwise-matching requests.
	simRespVariantOK = "HTTP/1.1 200 OK\r\n" +
		"Server: nginx/1.18.0\r\n" +
		"Date: Mon, 15 Sep 2026 10:00:05 GMT\r\n" +
		"Content-Type: text/html; charset=UTF-8\r\n" +
		"Connection: keep-alive\r\n" +
		"\r\n" +
		"<!DOCTYPE html><html><head><title>Welcome to example.com</title></head>" +
		"<body><h1>Welcome</h1><p>This is the default landing page for the vhost.</p></body></html>"

	// simRespVariantNotFound has the exact same body as simRespVariantOK but
	// a different status line, isolating the statusMismatchWeight penalty.
	simRespVariantNotFound = "HTTP/1.1 404 Not Found\r\n" +
		"Server: nginx/1.18.0\r\n" +
		"Date: Mon, 15 Sep 2026 10:00:05 GMT\r\n" +
		"Content-Type: text/html; charset=UTF-8\r\n" +
		"Connection: keep-alive\r\n" +
		"\r\n" +
		"<!DOCTYPE html><html><head><title>Welcome to example.com</title></head>" +
		"<body><h1>Welcome</h1><p>This is the default landing page for the vhost.</p></body></html>"

	// simRespDisjoint shares only incidental HTTP boilerplate with the
	// baseline; its status, content type and body are all unrelated.
	simRespDisjoint = "HTTP/1.1 500 Internal Server Error\r\n" +
		"Content-Type: application/json\r\n" +
		"\r\n" +
		"{\"error\":\"qwzxjk flurbnicate zyxwvpq\",\"code\":9987654321,\"trace\":\"zzzzyyyyxxxxwwww\"}"

	// simRespOtherSite is a second, unrelated real-looking response (JSON
	// API status) sharing the baseline's 200 status but nothing else, so it
	// can stand in for "differs from a sample without a status penalty".
	simRespOtherSite = "HTTP/1.1 200 OK\r\n" +
		"Server: Apache/2.4.41\r\n" +
		"Content-Type: application/json\r\n" +
		"\r\n" +
		"{\"service\":\"payments-api\",\"version\":\"3.2.1\",\"status\":\"operational\",\"uptime_seconds\":8823991}"
)

func TestStatusToken(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name  string
		input string
		want  string
	}{
		{
			name:  "typical response with headers and body",
			input: "HTTP/1.1 200 OK\r\nX: y\r\n\r\nbody",
			want:  "200",
		},
		{
			name:  "empty response",
			input: "",
			want:  "",
		},
		{
			name:  "malformed status line with no space must not panic",
			input: "garbage",
			want:  "",
		},
		{
			name:  "status line with exactly one space (no reason phrase)",
			input: "HTTP/1.1 200",
			want:  "200",
		},
		{
			name:  "malformed first line, rest of response present",
			input: "garbage\r\nX: y\r\n\r\nbody",
			want:  "",
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			defer func() {
				if r := recover(); r != nil {
					t.Fatalf("statusToken(%q) panicked: %v", tt.input, r)
				}
			}()
			if got := statusToken(tt.input); got != tt.want {
				t.Errorf("statusToken(%q) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}

func TestSimilarityScore(t *testing.T) {
	t.Parallel()

	t.Run("identical strings score 1.0", func(t *testing.T) {
		t.Parallel()
		s := &Similarity{Threshold: DefaultThreshold}
		got := s.Score(simRespBaselineOK, simRespBaselineOK)
		if !simAlmostEqual(got, 1.0) {
			t.Errorf("Score(identical, identical) = %v, want 1.0", got)
		}
	})

	t.Run("status mismatch is penalised by statusMismatchWeight relative to a status match", func(t *testing.T) {
		t.Parallel()
		s := &Similarity{Threshold: DefaultThreshold}

		scoreMatch := s.Score(simRespBaselineOK, simRespVariantOK)
		scoreMismatch := s.Score(simRespBaselineOK, simRespVariantNotFound)

		matchJaccard := simJaccard(simRespBaselineOK, simRespVariantOK)
		mismatchJaccard := simJaccard(simRespBaselineOK, simRespVariantNotFound)

		// The formula is weight * jaccard; verify Score reproduces it exactly.
		if !simAlmostEqual(scoreMatch, matchJaccard) {
			t.Errorf("Score(status match) = %v, want %v (unweighted jaccard)", scoreMatch, matchJaccard)
		}
		if !simAlmostEqual(scoreMismatch, statusMismatchWeight*mismatchJaccard) {
			t.Errorf("Score(status mismatch) = %v, want %v (%v * jaccard)", scoreMismatch, statusMismatchWeight*mismatchJaccard, statusMismatchWeight)
		}

		// Directly check the weight applied in each case, independent of how
		// similar the two response bodies happen to be.
		if mismatchJaccard == 0 {
			t.Fatal("fixture produced a zero jaccard component; adjust simRespVariantNotFound")
		}
		if gotWeight := scoreMismatch / mismatchJaccard; !simAlmostEqual(gotWeight, statusMismatchWeight) {
			t.Errorf("effective weight on status mismatch = %v, want %v", gotWeight, statusMismatchWeight)
		}
		if matchJaccard == 0 {
			t.Fatal("fixture produced a zero jaccard component; adjust simRespVariantOK")
		}
		if gotWeight := scoreMatch / matchJaccard; !simAlmostEqual(gotWeight, 1.0) {
			t.Errorf("effective weight on status match = %v, want 1.0 (no penalty)", gotWeight)
		}

		// And, concretely, the mismatch scores strictly lower than the match
		// even though the underlying bodies are equally similar.
		if scoreMismatch >= scoreMatch {
			t.Errorf("scoreMismatch = %v, want < scoreMatch = %v", scoreMismatch, scoreMatch)
		}
	})

	t.Run("completely disjoint content scores near 0", func(t *testing.T) {
		t.Parallel()
		s := &Similarity{Threshold: DefaultThreshold}
		got := s.Score(simRespBaselineOK, simRespDisjoint)
		if got < 0 || got >= 0.2 {
			t.Errorf("Score(disjoint) = %v, want a small value in [0, 0.2)", got)
		}
	})
}

func TestDiffers(t *testing.T) {
	t.Parallel()
	s := &Similarity{Threshold: DefaultThreshold}

	tests := []struct {
		name        string
		baseline    string
		response    string
		wantDiffers bool
	}{
		{
			name:        "identical response is well above threshold: does not differ",
			baseline:    simRespBaselineOK,
			response:    simRespBaselineOK,
			wantDiffers: false,
		},
		{
			name:        "disjoint response is below threshold: differs",
			baseline:    simRespBaselineOK,
			response:    simRespDisjoint,
			wantDiffers: true,
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			gotDiffers, gotScore := s.Differs(tt.baseline, tt.response)

			// The score Differs returns must be the exact score that decided it.
			wantScore := s.Score(tt.baseline, tt.response)
			if gotScore != wantScore {
				t.Fatalf("Differs score = %v, want %v (== Score(baseline, response))", gotScore, wantScore)
			}

			if gotDiffers != tt.wantDiffers {
				t.Errorf("Differs = %v, want %v (score %v, threshold %v)", gotDiffers, tt.wantDiffers, gotScore, s.Threshold)
			}
			if wantThresholdSide := gotScore < s.Threshold; wantThresholdSide != tt.wantDiffers {
				t.Errorf("fixture score %v does not fall on the expected side of threshold %v", gotScore, s.Threshold)
			}
		})
	}
}

func TestDiffersFromAll(t *testing.T) {
	t.Parallel()
	s := &Similarity{Threshold: DefaultThreshold}

	t.Run("empty baseline slice returns (false, 1.0)", func(t *testing.T) {
		t.Parallel()
		differs, score := s.DiffersFromAll(nil, simRespDisjoint)
		if differs {
			t.Errorf("DiffersFromAll(nil, ...) differs = true, want false")
		}
		if score != 1.0 {
			t.Errorf("DiffersFromAll(nil, ...) score = %v, want 1.0", score)
		}
	})

	t.Run("response matching any sample is not a finding", func(t *testing.T) {
		t.Parallel()
		baselines := []string{simRespDisjoint, simRespBaselineOK, simRespOtherSite}
		response := simRespBaselineOK // matches the second sample exactly

		gotDiffers, gotScore := s.DiffersFromAll(baselines, response)

		wantScore := 0.0
		wantDiffers := true
		for _, b := range baselines {
			diff, score := s.Differs(b, response)
			if score > wantScore {
				wantScore = score
			}
			if !diff {
				wantDiffers = false
			}
		}

		if gotDiffers != false {
			t.Errorf("DiffersFromAll = %v, want false (response matches one sample)", gotDiffers)
		}
		if gotDiffers != wantDiffers {
			t.Errorf("DiffersFromAll = %v, want %v (derived from Differs over each sample)", gotDiffers, wantDiffers)
		}
		if gotScore != wantScore {
			t.Errorf("DiffersFromAll score = %v, want %v (the highest individual score)", gotScore, wantScore)
		}
		// The highest score should be the (near) perfect match against itself.
		if gotScore < s.Threshold {
			t.Errorf("DiffersFromAll score = %v, want it to reflect the exact-match sample (>= threshold)", gotScore)
		}
	})

	t.Run("response differing from every sample is a finding", func(t *testing.T) {
		t.Parallel()
		baselines := []string{simRespDisjoint, simRespOtherSite}
		response := simRespBaselineOK

		gotDiffers, gotScore := s.DiffersFromAll(baselines, response)

		wantScore := 0.0
		wantDiffers := true
		for _, b := range baselines {
			diff, score := s.Differs(b, response)
			if score > wantScore {
				wantScore = score
			}
			if !diff {
				wantDiffers = false
			}
		}

		if gotDiffers != true {
			t.Errorf("DiffersFromAll = %v, want true (response differs from every sample)", gotDiffers)
		}
		if gotDiffers != wantDiffers {
			t.Errorf("DiffersFromAll = %v, want %v (derived from Differs over each sample)", gotDiffers, wantDiffers)
		}
		if gotScore != wantScore {
			t.Errorf("DiffersFromAll score = %v, want %v (the highest individual score)", gotScore, wantScore)
		}
	})
}

func TestStable(t *testing.T) {
	t.Parallel()
	s := &Similarity{Threshold: DefaultThreshold}

	tests := []struct {
		name      string
		baselines []string
		want      bool
	}{
		{
			name:      "no samples is trivially stable",
			baselines: nil,
			want:      true,
		},
		{
			name:      "single sample is trivially stable",
			baselines: []string{simRespBaselineOK},
			want:      true,
		},
		{
			name:      "identical samples are stable",
			baselines: []string{simRespBaselineOK, simRespBaselineOK, simRespBaselineOK},
			want:      true,
		},
		{
			name:      "samples that differ from each other are not stable",
			baselines: []string{simRespBaselineOK, simRespDisjoint},
			want:      false,
		},
		{
			name:      "a later disagreeing sample makes the set unstable",
			baselines: []string{simRespBaselineOK, simRespBaselineOK, simRespOtherSite},
			want:      false,
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := s.Stable(tt.baselines); got != tt.want {
				t.Errorf("Stable(%d samples) = %v, want %v", len(tt.baselines), got, tt.want)
			}
		})
	}
}
