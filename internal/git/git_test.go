package git

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestStagedFilesHandlesSpacesAndDeletedFiles(t *testing.T) {
	repo := initRepo(t)
	write(t, filepath.Join(repo, "with space.txt"), "first")
	write(t, filepath.Join(repo, "delete.txt"), "gone")
	run(t, repo, "git", "add", ".")
	run(t, repo, "git", "commit", "-m", "initial")
	write(t, filepath.Join(repo, "with space.txt"), "second")
	if err := os.Remove(filepath.Join(repo, "delete.txt")); err != nil {
		t.Fatal(err)
	}
	run(t, repo, "git", "add", "-A")
	files, err := StagedFiles(repo)
	if err != nil {
		t.Fatal(err)
	}
	if len(files) != 1 || !strings.HasSuffix(files[0], "with space.txt") {
		t.Fatalf("files = %#v", files)
	}
}

func TestInstallHookIsIdempotentAndProtectsExistingHook(t *testing.T) {
	repo := initRepo(t)
	exe := filepath.Join(t.TempDir(), "secretscan.exe")
	write(t, exe, "binary")
	path, err := InstallHook(repo, exe)
	if err != nil {
		t.Fatal(err)
	}
	data, _ := os.ReadFile(path)
	if !strings.Contains(string(data), "scan-staged") {
		t.Fatalf("bad hook: %s", data)
	}
	if _, err := InstallHook(repo, exe); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("#!/bin/sh\necho custom\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	if _, err := InstallHook(repo, exe); err == nil {
		t.Fatal("expected overwrite refusal")
	}
}

func TestStagedContentReadsIndexNotWorkingTree(t *testing.T) {
	repo := initRepo(t)
	path := filepath.Join(repo, "config.txt")
	write(t, path, "staged-value")
	run(t, repo, "git", "add", "config.txt")
	write(t, path, "working-value")
	got, err := StagedContent(repo, path)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "staged-value" {
		t.Fatalf("content = %q", got)
	}
}

func initRepo(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	run(t, dir, "git", "init")
	run(t, dir, "git", "config", "user.email", "test@example.invalid")
	run(t, dir, "git", "config", "user.name", "SecretScan Test")
	return dir
}
func write(t *testing.T, path, data string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(data), 0o600); err != nil {
		t.Fatal(err)
	}
}
func run(t *testing.T, dir, name string, args ...string) {
	t.Helper()
	cmd := exec.Command(name, args...)
	cmd.Dir = dir
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("%s: %v: %s", name, err, out)
	}
}
