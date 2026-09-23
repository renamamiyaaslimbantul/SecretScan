package scanner

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/renamamiyaaslimbantul/SecretScan/internal/config"
	"github.com/renamamiyaaslimbantul/SecretScan/internal/detectors"
)

func TestScansFilesAndIgnoresDirectories(t *testing.T) {
	root := t.TempDir()
	mustWrite(t, filepath.Join(root, "src", "config.txt"), `api_key="`+`z9Qp2Lm7Vx4Nc8Rt6Hs1Wd3K"`)
	fakePassword := `V7!mQ2#vL9@` + `xT4`
	mustWrite(t, filepath.Join(root, "node_modules", "bad.txt"), `password="`+fakePassword+`"`)
	mustWrite(t, filepath.Join(root, ".venv", "Lib", "site-packages", "bad.py"), `password="`+fakePassword+`"`)
	d, _ := detectors.New(config.Defaults())
	s := New(config.Defaults(), d)
	result, err := s.Scan([]string{root})
	if err != nil {
		t.Fatal(err)
	}
	if result.FilesScanned != 1 || len(result.Findings) != 1 {
		t.Fatalf("unexpected result: %+v", result)
	}
}

func TestExplicitFileAndBinaryHandling(t *testing.T) {
	root := t.TempDir()
	clean := filepath.Join(root, "clean.txt")
	mustWrite(t, clean, "hello")
	binary := filepath.Join(root, "data.bin")
	if err := os.WriteFile(binary, []byte{'a', 0, 'b'}, 0o600); err != nil {
		t.Fatal(err)
	}
	d, _ := detectors.New(config.Defaults())
	s := New(config.Defaults(), d)
	result, err := s.Scan([]string{clean, binary})
	if err != nil {
		t.Fatal(err)
	}
	if result.FilesScanned != 1 {
		t.Fatalf("files scanned = %d", result.FilesScanned)
	}
}

func TestDoesNotFollowSymlink(t *testing.T) {
	root := t.TempDir()
	outside := t.TempDir()
	mustWrite(t, filepath.Join(outside, "secret.txt"), `api_key="`+`z9Qp2Lm7Vx4Nc8Rt6Hs1Wd3K"`)
	link := filepath.Join(root, "linked")
	if err := os.Symlink(outside, link); err != nil {
		t.Skipf("symlink unavailable: %v", err)
	}
	d, _ := detectors.New(config.Defaults())
	s := New(config.Defaults(), d)
	result, err := s.Scan([]string{root})
	if err != nil {
		t.Fatal(err)
	}
	if result.FilesScanned != 0 || len(result.Findings) != 0 {
		t.Fatalf("followed symlink: %+v", result)
	}
}

func TestScansMinifiedLineLargerThanOneMiB(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "bundle.js")
	content := strings.Repeat("a", 1024*1024) + `;api_key="` + `z9Qp2Lm7Vx4Nc8Rt6Hs1Wd3K"`
	mustWrite(t, path, content)

	d, _ := detectors.New(config.Defaults())
	s := New(config.Defaults(), d)
	result, err := s.Scan([]string{root})
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Findings) != 1 {
		t.Fatalf("findings = %d, want 1", len(result.Findings))
	}
}

func mustWrite(t *testing.T, path, data string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(data), 0o600); err != nil {
		t.Fatal(err)
	}
}
