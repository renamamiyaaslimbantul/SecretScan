package reporter

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/renamamiyaaslimbantul/SecretScan/internal/model"
)

func TestTextFindingIsRedacted(t *testing.T) {
	result := model.Result{Version: "0.1.0", Target: ".", FilesScanned: 2, Findings: []model.Finding{{File: `src\config.js`, Line: 18, Type: "API Key", Confidence: 96, Snippet: `API_KEY = "sk-****************"`}}}
	var out bytes.Buffer
	if err := Text(&out, result, true); err != nil {
		t.Fatal(err)
	}
	text := out.String()
	for _, want := range []string{"SecretScan v0.1.0", "Scanning 2 files", "POSSIBLE SECRET", `src\config.js`, "1 potential secret found", "Scan failed"} {
		if !strings.Contains(text, want) {
			t.Errorf("missing %q in %q", want, text)
		}
	}
}

func TestTextClean(t *testing.T) {
	var out bytes.Buffer
	if err := Text(&out, model.Result{Version: "0.1.0", FilesScanned: 4, Passed: true}, false); err != nil {
		t.Fatal(err)
	}
	if got := out.String(); !strings.Contains(got, "[OK] No secrets detected") || !strings.Contains(got, "Scan passed") {
		t.Fatalf("unexpected output: %q", got)
	}
}

func TestJSONSchema(t *testing.T) {
	var out bytes.Buffer
	result := model.Result{Version: "0.1.0", Target: ".", Findings: []model.Finding{}, Passed: true}
	if err := JSON(&out, result); err != nil {
		t.Fatal(err)
	}
	var decoded map[string]any
	if err := json.Unmarshal(out.Bytes(), &decoded); err != nil {
		t.Fatal(err)
	}
	for _, key := range []string{"version", "target", "files_scanned", "findings", "passed"} {
		if _, ok := decoded[key]; !ok {
			t.Errorf("missing %s", key)
		}
	}
}
