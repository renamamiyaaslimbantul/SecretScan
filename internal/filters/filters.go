package filters

import (
	"regexp"
	"strings"
)

type Filter struct{ excluded []*regexp.Regexp }

func New(patterns []string) *Filter { f, _ := Compile(patterns); return f }

func Compile(patterns []string) (*Filter, error) {
	f := &Filter{}
	for _, pattern := range patterns {
		r, err := regexp.Compile(pattern)
		if err != nil {
			return nil, err
		}
		f.excluded = append(f.excluded, r)
	}
	return f, nil
}

func (f *Filter) IsFalsePositive(value, line string) bool {
	lower := strings.ToLower(strings.TrimSpace(value))
	normalized := strings.NewReplacer("_", "-", " ", "-").Replace(lower)
	markers := []string{"your-", "example", "sample", "dummy", "fake", "test-", "placeholder", "changeme", "replace-me", "redacted", "xxxx"}
	for _, marker := range markers {
		if strings.Contains(normalized, marker) {
			return true
		}
	}
	if strings.HasPrefix(lower, "<") && strings.HasSuffix(lower, ">") {
		return true
	}
	if strings.Contains(strings.ToLower(line), "secretscan:allow") {
		return true
	}
	for _, r := range f.excluded {
		if r.MatchString(value) || r.MatchString(line) {
			return true
		}
	}
	return false
}
