package detectors

import (
	"strings"
	"testing"

	"github.com/renamamiyaaslimbantul/SecretScan/internal/config"
)

func TestDetectsSupportedSecretTypesAndRedacts(t *testing.T) {
	cases := []struct{ name, line string }{
		{"GitHub Token", `token = "gh` + `p_abcdefghijklmnopqrstuvwxyzABCDEFGH12"`},
		{"AWS Access Key", `aws_access_key_id = "AK` + `IAQ7W4E6R8T2Y9U3P5"`},
		{"Google API Key", `google_key = "AI` + `zaSyA1234567890abcdefghijklmnopqrstUV"`},
		{"JWT", `authorization = "ey` + `JhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.c2lnbmF0dXJlMTIzNDU2"`},
		{"Private Key", `-----BEGIN PRIVATE` + ` KEY-----`},
		{"Database Connection String", `DATABASE_URL="post` + `gres://admin:pA55w0rd9Zx@db.invalid/app"`},
		{"API Key", `api_key = "` + `z9Qp2Lm7Vx4Nc8Rt6Hs1Wd3K"`},
		{"Password", `password = "` + `B7!mQ2#vL9@xT4"`},
		{"Access Token", `access_token = "` + `Zx9Qv2Lm7Nc4Rt8Hs6Wd1Kp3"`},
	}
	d, err := New(config.Defaults())
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			findings := d.ScanLine("config.txt", 3, tc.line)
			if len(findings) == 0 {
				t.Fatalf("no finding for %s", tc.line)
			}
			if findings[0].Type != tc.name {
				t.Fatalf("type = %q", findings[0].Type)
			}
			if strings.Contains(findings[0].Snippet, secretPart(tc.line)) {
				t.Fatalf("secret leaked: %q", findings[0].Snippet)
			}
		})
	}
}

func TestFiltersExamplesAndAppliesThreshold(t *testing.T) {
	cfg := config.Defaults()
	cfg.MinimumConfidence = 95
	d, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	for _, line := range []string{`api_key="YOUR_API_KEY_HERE"`, `password="test-password"`, `access_token="example-token"`} {
		if got := d.ScanLine("x", 1, line); len(got) != 0 {
			t.Fatalf("false positive: %+v", got)
		}
	}
	if got := d.ScanLine("x", 1, `api_key="`+`z9Qp2Lm7Vx4Nc8Rt6Hs1Wd3K"`); len(got) != 0 {
		t.Fatalf("threshold ignored: %+v", got)
	}
}

func TestCustomRule(t *testing.T) {
	cfg := config.Defaults()
	cfg.CustomRules = []config.Rule{{Name: "Internal Token", Pattern: `INT_[A-Z0-9]{12}`, Confidence: 97}}
	d, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	got := d.ScanLine("x", 1, `token="INT_8F3K7P2M9Q4Z"`)
	if len(got) != 1 || got[0].Type != "Internal Token" {
		t.Fatalf("custom rule failed: %+v", got)
	}
}

func secretPart(line string) string {
	start := strings.Index(line, `"`)
	end := strings.LastIndex(line, `"`)
	if start >= 0 && end > start {
		return line[start+1 : end]
	}
	return line
}
