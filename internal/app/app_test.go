package app

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestVersionAndHelp(t *testing.T) {
	for _, tc := range []struct {
		args []string
		want string
	}{{[]string{"--version"}, "SecretScan v"}, {[]string{"--help"}, "Usage:"}} {
		var out, errOut bytes.Buffer
		if code := Run(tc.args, &out, &errOut); code != 0 {
			t.Fatalf("code=%d stderr=%s", code, errOut.String())
		}
		if !strings.Contains(out.String(), tc.want) {
			t.Fatalf("output=%q", out.String())
		}
	}
}

func TestDefaultScanAndJSON(t *testing.T) {
	oldOS := currentOS
	currentOS = "windows"
	t.Cleanup(func() { currentOS = oldOS })
	dir := t.TempDir()
	path := filepath.Join(dir, "config.txt")
	if err := os.WriteFile(path, []byte(`api_key="`+"z9Qp2Lm7Vx4Nc8Rt6Hs1Wd3K"+`"`), 0o600); err != nil {
		t.Fatal(err)
	}
	var out, errOut bytes.Buffer
	code := Run([]string{dir, "--output", "json"}, &out, &errOut)
	if code != 1 || !strings.Contains(out.String(), `"passed": false`) {
		t.Fatalf("code=%d out=%s err=%s", code, out.String(), errOut.String())
	}
	if strings.Contains(out.String(), "z9Qp2Lm7Vx4Nc8Rt6Hs1Wd3K") {
		t.Fatal("raw secret leaked")
	}
}

func TestBadArgumentsUseExitTwo(t *testing.T) {
	var out, errOut bytes.Buffer
	if code := Run([]string{"--unknown"}, &out, &errOut); code != 2 || errOut.Len() == 0 {
		t.Fatalf("code=%d stderr=%q", code, errOut.String())
	}
}

func TestRejectsUnsupportedOperatingSystem(t *testing.T) {
	oldOS := currentOS
	currentOS = "linux"
	t.Cleanup(func() { currentOS = oldOS })
	var out, errOut bytes.Buffer
	if code := Run([]string{"."}, &out, &errOut); code != 2 || !strings.Contains(errOut.String(), "Windows only") {
		t.Fatalf("code=%d stderr=%q", code, errOut.String())
	}
}
