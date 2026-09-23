package git

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

const hookMarker = "# SecretScan managed hook"

func Root(dir string) (string, error) {
	cmd := exec.Command("git", "rev-parse", "--show-toplevel")
	cmd.Dir = dir
	out, err := cmd.Output()
	if err != nil {
		return "", errors.New("current directory is not a Git repository")
	}
	return filepath.Clean(strings.TrimSpace(string(out))), nil
}

func StagedFiles(dir string) ([]string, error) {
	root, err := Root(dir)
	if err != nil {
		return nil, err
	}
	cmd := exec.Command("git", "diff", "--cached", "--name-only", "--diff-filter=ACMR", "-z")
	cmd.Dir = root
	out, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("list staged files: %w", err)
	}
	parts := bytes.Split(out, []byte{0})
	files := make([]string, 0, len(parts))
	for _, part := range parts {
		if len(part) > 0 {
			files = append(files, filepath.Join(root, filepath.FromSlash(string(part))))
		}
	}
	return files, nil
}

func StagedContent(dir, absolutePath string) ([]byte, error) {
	root, err := Root(dir)
	if err != nil {
		return nil, err
	}
	rel, err := relativeRepositoryPath(root, absolutePath)
	if err != nil {
		return nil, errors.New("staged file is outside repository")
	}
	gitPath := filepath.ToSlash(rel)
	cmd := exec.Command("git", "show", ":"+gitPath)
	cmd.Dir = root
	out, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("read staged file %q: %w", gitPath, err)
	}
	return out, nil
}

func relativeRepositoryPath(root, path string) (string, error) {
	root, err := filepath.Abs(root)
	if err != nil {
		return "", err
	}
	path, err = filepath.Abs(path)
	if err != nil {
		return "", err
	}
	rel, err := filepath.Rel(root, path)
	if err == nil && rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return rel, nil
	}
	// Windows paths are case-insensitive. Git may normalize the drive or
	// directory casing differently from os.TempDir and filepath.Abs.
	if filepath.VolumeName(root) != "" && strings.EqualFold(filepath.VolumeName(root), filepath.VolumeName(path)) {
		rel, err = filepath.Rel(strings.ToLower(root), strings.ToLower(path))
		if err == nil && rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
			return rel, nil
		}
	}
	return "", errors.New("path is outside repository")
}

func InstallHook(dir, executable string) (string, error) {
	root, err := Root(dir)
	if err != nil {
		return "", err
	}
	gitDirCmd := exec.Command("git", "rev-parse", "--git-path", "hooks")
	gitDirCmd.Dir = root
	out, err := gitDirCmd.Output()
	if err != nil {
		return "", fmt.Errorf("locate Git hooks: %w", err)
	}
	hooks := strings.TrimSpace(string(out))
	if !filepath.IsAbs(hooks) {
		hooks = filepath.Join(root, hooks)
	}
	if err := os.MkdirAll(hooks, 0o755); err != nil {
		return "", fmt.Errorf("create hooks directory: %w", err)
	}
	hook := filepath.Join(hooks, "pre-commit")
	if existing, readErr := os.ReadFile(hook); readErr == nil && !strings.Contains(string(existing), hookMarker) {
		return "", errors.New("pre-commit hook already exists and is not managed by SecretScan")
	} else if readErr != nil && !os.IsNotExist(readErr) {
		return "", fmt.Errorf("read existing hook: %w", readErr)
	}
	abs, err := filepath.Abs(executable)
	if err != nil {
		return "", fmt.Errorf("resolve executable: %w", err)
	}
	escaped := strings.ReplaceAll(filepath.ToSlash(abs), `'`, `'\''`)
	content := fmt.Sprintf("#!/bin/sh\n%s\n'%s' scan-staged\n", hookMarker, escaped)
	if err := os.WriteFile(hook, []byte(content), 0o755); err != nil {
		return "", fmt.Errorf("write pre-commit hook: %w", err)
	}
	return hook, nil
}
