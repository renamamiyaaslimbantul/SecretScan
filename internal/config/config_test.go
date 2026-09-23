package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestDefaults(t *testing.T) {
	cfg := Defaults()
	if cfg.MinimumConfidence != 70 || cfg.HookMinimumConfidence != 90 {
		t.Fatalf("unexpected thresholds: %+v", cfg)
	}
	if cfg.Output != "text" || len(cfg.Ignore) == 0 {
		t.Fatalf("unexpected defaults: %+v", cfg)
	}
	if !contains(cfg.Ignore, ".venv") || !contains(cfg.Ignore, "venv") {
		t.Fatalf("Python virtual environments missing from defaults: %+v", cfg.Ignore)
	}
}

func TestLoadMergesConfiguration(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, ".secretscan.yaml")
	data := []byte("minimum_confidence: 82\noutput: json\nignored:\n  - generated\nexcluded_patterns:\n  - safe-value\ncustom_rules:\n  - name: Internal Token\n    pattern: 'INT_[A-Z0-9]{12}'\n    confidence: 95\n")
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.MinimumConfidence != 82 || cfg.Output != "json" {
		t.Fatalf("bad merge: %+v", cfg)
	}
	if !contains(cfg.Ignore, "generated") || len(cfg.CustomRules) != 1 {
		t.Fatalf("bad lists: %+v", cfg)
	}
}

func TestLoadRejectsInvalidValues(t *testing.T) {
	for name, body := range map[string]string{
		"confidence": "minimum_confidence: 101\n",
		"output":     "output: xml\n",
		"regex":      "custom_rules:\n  - name: Broken\n    pattern: '[unterminated'\n",
	} {
		t.Run(name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), ".secretscan.yaml")
			if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
				t.Fatal(err)
			}
			if _, err := Load(path); err == nil {
				t.Fatal("expected validation error")
			}
		})
	}
}

func TestFindWalksUpward(t *testing.T) {
	root := t.TempDir()
	nested := filepath.Join(root, "a", "b")
	if err := os.MkdirAll(nested, 0o755); err != nil {
		t.Fatal(err)
	}
	want := filepath.Join(root, ".secretscan.yaml")
	if err := os.WriteFile(want, []byte("output: text\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	got, ok, err := Find(nested)
	if err != nil || !ok || got != want {
		t.Fatalf("Find() = %q, %v, %v", got, ok, err)
	}
}

func contains(items []string, want string) bool {
	for _, item := range items {
		if item == want {
			return true
		}
	}
	return false
}
