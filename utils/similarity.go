package utils

import (
	"strings"

	"github.com/adrg/strutil"
	"github.com/adrg/strutil/metrics"
)

// DefaultThreshold is the similarity score below which a response is treated as
// meaningfully different from the baseline. Scores run 0.0 (nothing in common)
// to 1.0 (identical).
const DefaultThreshold = 0.50

// statusMismatchWeight is applied to the similarity score when a response's
// status code differs from the baseline's, making a status change on its own
// enough to push a borderline response over the threshold.
const statusMismatchWeight = 0.75

// Similarity scores HTTP responses against a baseline using Jaccard distance.
//
// This was github.com/wdahlenburg/HttpComparison, inlined here: that module is
// six commits, dormant since 2023, and consists of the ~30 lines below. Vendoring
// it removes an unpatchable link in the supply chain of a tool that gets pointed
// at other people's infrastructure, and puts the scoring under test. The scoring
// itself is unchanged.
type Similarity struct {
	Threshold float64
}

// statusToken returns the status code token from an HTTP response dump, or ""
// when the response is empty or the status line is malformed. The original
// indexed into the split directly and panicked on a status line without a space.
func statusToken(response string) string {
	if response == "" {
		return ""
	}
	line, _, _ := strings.Cut(response, "\n")
	parts := strings.SplitN(line, " ", 3)
	if len(parts) < 2 {
		return ""
	}
	return parts[1]
}

// Score returns the weighted similarity of response to baseline.
func (s *Similarity) Score(baseline, response string) float64 {
	weight := 1.0
	if statusToken(baseline) != statusToken(response) {
		weight *= statusMismatchWeight
	}
	return weight * strutil.Similarity(baseline, response, metrics.NewJaccard())
}

// Differs reports whether response is different enough from baseline to be
// considered a distinct virtual host, along with the score that decided it.
func (s *Similarity) Differs(baseline, response string) (bool, float64) {
	score := s.Score(baseline, response)
	return score < s.Threshold, score
}

// DiffersFromAll reports whether response differs from every baseline sample.
// A candidate that matches any sample is not a finding: it returns the highest
// score seen, which is the one that came closest to explaining the response.
func (s *Similarity) DiffersFromAll(baselines []string, response string) (bool, float64) {
	if len(baselines) == 0 {
		return false, 1.0
	}
	highest := 0.0
	differs := true
	for _, baseline := range baselines {
		diff, score := s.Differs(baseline, response)
		if score > highest {
			highest = score
		}
		if !diff {
			differs = false
		}
	}
	return differs, highest
}

// Stable reports whether a set of baseline samples agree with each other. When
// they do not, the target is serving varying content for the same request and
// any finding against it is suspect.
func (s *Similarity) Stable(baselines []string) bool {
	for i := 1; i < len(baselines); i++ {
		if differs, _ := s.Differs(baselines[0], baselines[i]); differs {
			return false
		}
	}
	return true
}
