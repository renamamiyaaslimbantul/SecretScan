package detectors

import (
	"fmt"
	"regexp"
	"sort"
	"strings"

	"github.com/renamamiyaaslimbantul/SecretScan/internal/config"
	"github.com/renamamiyaaslimbantul/SecretScan/internal/entropy"
	"github.com/renamamiyaaslimbantul/SecretScan/internal/filters"
	"github.com/renamamiyaaslimbantul/SecretScan/internal/model"
)

type rule struct {
	name       string
	re         *regexp.Regexp
	confidence int
	valueGroup int
	generic    bool
}
type Detector struct {
	rules   []rule
	filter  *filters.Filter
	minimum int
}

func New(cfg config.Config) (*Detector, error) {
	f, err := filters.Compile(cfg.ExcludedPatterns)
	if err != nil {
		return nil, err
	}
	specs := []struct {
		name, pattern     string
		confidence, group int
		generic           bool
	}{
		{"Private Key", `-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----`, 100, 0, false},
		{"GitHub Token", `\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{20,255}\b`, 98, 0, false},
		{"AWS Access Key", `\b(?:AKIA|ASIA)[A-Z0-9]{16}\b`, 98, 0, false},
		{"Google API Key", `\bAIza[0-9A-Za-z_-]{35}\b`, 98, 0, false},
		{"JWT", `\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b`, 94, 0, false},
		{"Database Connection String", `(?i)\b(?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?|redis|sqlserver):\/\/[^\s"']+`, 94, 0, false},
		{"API Key", `(?i)(?:api[_-]?key)\s*[:=]\s*["']?([A-Za-z0-9_\-+/=.]{12,})`, 78, 1, true},
		{"Password", `(?i)(?:password|passwd|pwd)\s*[:=]\s*["']?([^\s"']{8,})`, 76, 1, true},
		{"Access Token", `(?i)(?:access[_-]?token|auth[_-]?token|bearer[_-]?token)\s*[:=]\s*["']?([A-Za-z0-9_\-+/=.]{12,})`, 80, 1, true},
	}
	d := &Detector{filter: f, minimum: cfg.MinimumConfidence}
	for _, s := range specs {
		d.rules = append(d.rules, rule{s.name, regexp.MustCompile(s.pattern), s.confidence, s.group, s.generic})
	}
	for _, custom := range cfg.CustomRules {
		confidence := custom.Confidence
		if confidence == 0 {
			confidence = 85
		}
		r, compileErr := regexp.Compile(custom.Pattern)
		if compileErr != nil {
			return nil, fmt.Errorf("custom rule %q: %w", custom.Name, compileErr)
		}
		d.rules = append(d.rules, rule{custom.Name, r, confidence, 0, false})
	}
	return d, nil
}

func (d *Detector) ScanLine(file string, lineNumber int, line string) []model.Finding {
	var out []model.Finding
	seen := map[string]bool{}
	for _, r := range d.rules {
		indices := r.re.FindAllStringSubmatchIndex(line, -1)
		for _, idx := range indices {
			start, end := idx[0], idx[1]
			if r.valueGroup > 0 && len(idx) > r.valueGroup*2+1 && idx[r.valueGroup*2] >= 0 {
				start, end = idx[r.valueGroup*2], idx[r.valueGroup*2+1]
			}
			value := line[start:end]
			if d.filter.IsFalsePositive(value, line) {
				continue
			}
			confidence := r.confidence
			if r.generic {
				e := entropy.Shannon(value)
				if e >= 3.5 {
					confidence += 8
				} else if e < 2.5 {
					confidence -= 20
				}
			}
			if confidence > 100 {
				confidence = 100
			}
			key := fmt.Sprintf("%s:%d:%d", r.name, start, end)
			if confidence < d.minimum || seen[key] {
				continue
			}
			seen[key] = true
			out = append(out, model.Finding{File: file, Line: lineNumber, Type: r.name, Confidence: confidence, Snippet: redactLine(line, start, end)})
		}
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].Confidence > out[j].Confidence })
	return out
}

func redactLine(line string, start, end int) string {
	value := line[start:end]
	visible := 0
	if len(value) >= 8 {
		visible = 3
	}
	masked := strings.Repeat("*", max(8, len(value)-visible))
	if visible > 0 {
		masked = value[:visible] + masked
	}
	return line[:start] + masked + line[end:]
}
