package utils

import (
	"strings"
	"testing"
)

func TestParseRangeSet(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		spec    string
		wantNil bool
		wantErr bool
		in      []int // values expected to be contained
		out     []int // values expected to be absent
	}{
		{
			name:    "empty spec yields nil",
			spec:    "",
			wantNil: true,
		},
		{
			name: "single value",
			spec: "200",
			in:   []int{200},
			out:  []int{201, 199},
		},
		{
			name: "comma separated values",
			spec: "200,404",
			in:   []int{200, 404},
			out:  []int{201, 403},
		},
		{
			name: "range",
			spec: "300-399",
			in:   []int{300, 350, 399},
			out:  []int{299, 400},
		},
		{
			name: "whitespace tolerant mixed",
			spec: "200, 301-399 , 404",
			in:   []int{200, 301, 399, 404},
			out:  []int{300, 405, 201},
		},
		{
			name:    "inverted range is an error",
			spec:    "399-300",
			wantErr: true,
		},
		{
			name:    "garbage is an error",
			spec:    "abc",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			rs, err := ParseRangeSet(tt.spec)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("ParseRangeSet(%q) = %+v, want error", tt.spec, rs)
				}
				return
			}
			if err != nil {
				t.Fatalf("ParseRangeSet(%q) unexpected error: %v", tt.spec, err)
			}
			if tt.wantNil {
				if rs != nil {
					t.Fatalf("ParseRangeSet(%q) = %+v, want nil", tt.spec, rs)
				}
				return
			}
			for _, v := range tt.in {
				if !rs.Contains(v) {
					t.Errorf("ParseRangeSet(%q).Contains(%d) = false, want true", tt.spec, v)
				}
			}
			for _, v := range tt.out {
				if rs.Contains(v) {
					t.Errorf("ParseRangeSet(%q).Contains(%d) = true, want false", tt.spec, v)
				}
			}
		})
	}
}

func TestRangeSetNilContainsAndString(t *testing.T) {
	t.Parallel()

	var rs *RangeSet
	if rs.Contains(200) {
		t.Errorf("nil *RangeSet.Contains(200) = true, want false")
	}
	if got := rs.String(); got != "" {
		t.Errorf("nil *RangeSet.String() = %q, want empty", got)
	}
}

func TestMatcherAllowsNilCases(t *testing.T) {
	t.Parallel()

	m := &Matcher{}
	if !m.Allows(nil) {
		t.Errorf("Matcher.Allows(nil) = false, want true")
	}

	var nilMatcher *Matcher
	r := &FuzzResult{Status: 500, ContentLength: 999, Words: 1, Lines: 1}
	if !nilMatcher.Allows(r) {
		t.Errorf("nil *Matcher.Allows(result) = false, want true")
	}
}

func TestMatcherActive(t *testing.T) {
	t.Parallel()

	m := &Matcher{}
	if m.Active() {
		t.Errorf("empty Matcher.Active() = true, want false")
	}

	withStatus := &Matcher{}
	rs, err := ParseRangeSet("200")
	if err != nil {
		t.Fatalf("ParseRangeSet: %v", err)
	}
	withStatus.MatchStatus = rs
	if !withStatus.Active() {
		t.Errorf("Matcher with MatchStatus set: Active() = false, want true")
	}
}

func TestMatcherAllowsStatusMatchAndFilter(t *testing.T) {
	t.Parallel()

	optsMatchOnly := &Options{MatchStatus: "200,301-399"}
	mMatch, err := NewMatcher(optsMatchOnly)
	if err != nil {
		t.Fatalf("NewMatcher: %v", err)
	}
	inSet := &FuzzResult{Status: 200}
	outOfSet := &FuzzResult{Status: 404}
	if !mMatch.Allows(inSet) {
		t.Errorf("match-only: Allows(status=200) = false, want true")
	}
	if mMatch.Allows(outOfSet) {
		t.Errorf("match-only: Allows(status=404) = true, want false")
	}

	optsFilterOnly := &Options{FilterStatus: "200,301-399"}
	mFilter, err := NewMatcher(optsFilterOnly)
	if err != nil {
		t.Fatalf("NewMatcher: %v", err)
	}
	if mFilter.Allows(inSet) {
		t.Errorf("filter-only: Allows(status=200) = true, want false")
	}
	if !mFilter.Allows(outOfSet) {
		t.Errorf("filter-only: Allows(status=404) = false, want true")
	}
}

func TestMatcherFilterWinsOverMatch(t *testing.T) {
	t.Parallel()

	// When match and filter both name 200, the filter wins and the result
	// is rejected.
	opts := &Options{MatchStatus: "200", FilterStatus: "200"}
	m, err := NewMatcher(opts)
	if err != nil {
		t.Fatalf("NewMatcher: %v", err)
	}
	r := &FuzzResult{Status: 200}
	if m.Allows(r) {
		t.Errorf("Allows(status=200) with match=200,filter=200 = true, want false (filter wins)")
	}
}

func TestMatcherAllowsSizeWordsLines(t *testing.T) {
	t.Parallel()

	opts := &Options{
		MatchSize:  "100-200",
		MatchWords: "10-20",
		MatchLines: "1-5",
	}
	m, err := NewMatcher(opts)
	if err != nil {
		t.Fatalf("NewMatcher: %v", err)
	}

	ok := &FuzzResult{ContentLength: 150, Words: 15, Lines: 3}
	if !m.Allows(ok) {
		t.Errorf("Allows(in-range size/words/lines) = false, want true")
	}

	badSize := &FuzzResult{ContentLength: 999, Words: 15, Lines: 3}
	if m.Allows(badSize) {
		t.Errorf("Allows(out-of-range size) = true, want false")
	}

	badWords := &FuzzResult{ContentLength: 150, Words: 1, Lines: 3}
	if m.Allows(badWords) {
		t.Errorf("Allows(out-of-range words) = true, want false")
	}

	badLines := &FuzzResult{ContentLength: 150, Words: 15, Lines: 99}
	if m.Allows(badLines) {
		t.Errorf("Allows(out-of-range lines) = true, want false")
	}
}

func TestMatcherAllowsRegex(t *testing.T) {
	t.Parallel()

	optsMatch := &Options{MatchRegex: "welcome"}
	mMatch, err := NewMatcher(optsMatch)
	if err != nil {
		t.Fatalf("NewMatcher: %v", err)
	}
	if !mMatch.Allows(&FuzzResult{Body: "welcome home"}) {
		t.Errorf("MatchRegex: Allows(matching body) = false, want true")
	}
	if mMatch.Allows(&FuzzResult{Body: "goodbye"}) {
		t.Errorf("MatchRegex: Allows(non-matching body) = true, want false")
	}

	optsFilter := &Options{FilterRegex: "error"}
	mFilter, err := NewMatcher(optsFilter)
	if err != nil {
		t.Fatalf("NewMatcher: %v", err)
	}
	if mFilter.Allows(&FuzzResult{Body: "internal error occurred"}) {
		t.Errorf("FilterRegex: Allows(matching body) = true, want false")
	}
	if !mFilter.Allows(&FuzzResult{Body: "all good"}) {
		t.Errorf("FilterRegex: Allows(non-matching body) = false, want true")
	}
}

func TestNewMatcherInvalidRegexNamesFlag(t *testing.T) {
	t.Parallel()

	_, err := NewMatcher(&Options{MatchRegex: "("})
	if err == nil {
		t.Fatalf("NewMatcher with invalid -mr regex: want error, got nil")
	}
	if !strings.Contains(err.Error(), "-mr") {
		t.Errorf("NewMatcher invalid -mr error = %q, want it to name -mr", err.Error())
	}

	_, err = NewMatcher(&Options{FilterRegex: "("})
	if err == nil {
		t.Fatalf("NewMatcher with invalid -fr regex: want error, got nil")
	}
	if !strings.Contains(err.Error(), "-fr") {
		t.Errorf("NewMatcher invalid -fr error = %q, want it to name -fr", err.Error())
	}
}

func TestNewMatcherInvalidRangeNamesFlag(t *testing.T) {
	t.Parallel()

	_, err := NewMatcher(&Options{MatchStatus: "abc"})
	if err == nil {
		t.Fatalf("NewMatcher with invalid -mc range: want error, got nil")
	}
	if !strings.Contains(err.Error(), "-mc") {
		t.Errorf("NewMatcher invalid -mc error = %q, want it to name -mc", err.Error())
	}
}
