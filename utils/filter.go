package utils

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"
)

// RangeSet is a set of integers written as a comma-separated list of values and
// inclusive ranges, e.g. "200,301-399,404". It backs the status and size
// match/filter flags.
type RangeSet struct {
	spec   string
	ranges [][2]int
}

// ParseRangeSet parses a range specification. An empty spec yields nil, meaning
// "no opinion" rather than "matches nothing".
func ParseRangeSet(spec string) (*RangeSet, error) {
	spec = strings.TrimSpace(spec)
	if spec == "" {
		return nil, nil
	}

	rs := &RangeSet{spec: spec}
	for _, part := range strings.Split(spec, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		lo, hi, isRange := strings.Cut(part, "-")
		low, err := strconv.Atoi(strings.TrimSpace(lo))
		if err != nil {
			return nil, fmt.Errorf("invalid number %q in range %q", lo, spec)
		}
		high := low
		if isRange {
			high, err = strconv.Atoi(strings.TrimSpace(hi))
			if err != nil {
				return nil, fmt.Errorf("invalid number %q in range %q", hi, spec)
			}
		}
		if high < low {
			return nil, fmt.Errorf("range %q is inverted", part)
		}
		rs.ranges = append(rs.ranges, [2]int{low, high})
	}
	if len(rs.ranges) == 0 {
		return nil, nil
	}
	return rs, nil
}

// Contains reports whether v falls in the set. A nil RangeSet contains nothing;
// callers treat nil as "unset" before asking.
func (r *RangeSet) Contains(v int) bool {
	if r == nil {
		return false
	}
	for _, span := range r.ranges {
		if v >= span[0] && v <= span[1] {
			return true
		}
	}
	return false
}

func (r *RangeSet) String() string {
	if r == nil {
		return ""
	}
	return r.spec
}

// Matcher gates which differing responses are worth reporting. The similarity
// comparison decides what is a candidate; the matcher decides what the operator
// wanted to see. Filters are evaluated after matchers and win ties, which is the
// convention ffuf established.
type Matcher struct {
	MatchStatus  *RangeSet
	FilterStatus *RangeSet
	MatchSize    *RangeSet
	FilterSize   *RangeSet
	MatchWords   *RangeSet
	FilterWords  *RangeSet
	MatchLines   *RangeSet
	FilterLines  *RangeSet
	MatchRegex   *regexp.Regexp
	FilterRegex  *regexp.Regexp
}

// NewMatcher builds a Matcher from raw flag strings.
func NewMatcher(opts *Options) (*Matcher, error) {
	m := &Matcher{}

	specs := []struct {
		spec string
		dst  **RangeSet
		name string
	}{
		{opts.MatchStatus, &m.MatchStatus, "-mc"},
		{opts.FilterStatus, &m.FilterStatus, "-fc"},
		{opts.MatchSize, &m.MatchSize, "-ms"},
		{opts.FilterSize, &m.FilterSize, "-fs"},
		{opts.MatchWords, &m.MatchWords, "-mw"},
		{opts.FilterWords, &m.FilterWords, "-fw"},
		{opts.MatchLines, &m.MatchLines, "-ml"},
		{opts.FilterLines, &m.FilterLines, "-fl"},
	}
	for _, s := range specs {
		rs, err := ParseRangeSet(s.spec)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", s.name, err)
		}
		*s.dst = rs
	}

	if opts.MatchRegex != "" {
		re, err := regexp.Compile(opts.MatchRegex)
		if err != nil {
			return nil, fmt.Errorf("-mr: %w", err)
		}
		m.MatchRegex = re
	}
	if opts.FilterRegex != "" {
		re, err := regexp.Compile(opts.FilterRegex)
		if err != nil {
			return nil, fmt.Errorf("-fr: %w", err)
		}
		m.FilterRegex = re
	}

	return m, nil
}

// Active reports whether any match or filter condition is set.
func (m *Matcher) Active() bool {
	return m != nil && (m.MatchStatus != nil || m.FilterStatus != nil ||
		m.MatchSize != nil || m.FilterSize != nil ||
		m.MatchWords != nil || m.FilterWords != nil ||
		m.MatchLines != nil || m.FilterLines != nil ||
		m.MatchRegex != nil || m.FilterRegex != nil)
}

// Allows reports whether a result survives the configured conditions. Every set
// matcher must accept it, and no set filter may reject it.
func (m *Matcher) Allows(r *FuzzResult) bool {
	if m == nil || r == nil {
		return true
	}

	size := int(r.ContentLength)

	checks := []struct {
		match, filter *RangeSet
		value         int
	}{
		{m.MatchStatus, m.FilterStatus, r.Status},
		{m.MatchSize, m.FilterSize, size},
		{m.MatchWords, m.FilterWords, r.Words},
		{m.MatchLines, m.FilterLines, r.Lines},
	}
	for _, c := range checks {
		if c.match != nil && !c.match.Contains(c.value) {
			return false
		}
		if c.filter != nil && c.filter.Contains(c.value) {
			return false
		}
	}

	if m.MatchRegex != nil && !m.MatchRegex.MatchString(r.Body) {
		return false
	}
	if m.FilterRegex != nil && m.FilterRegex.MatchString(r.Body) {
		return false
	}

	return true
}
