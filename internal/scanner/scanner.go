package scanner

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/renamamiyaaslimbantul/SecretScan/internal/config"
	"github.com/renamamiyaaslimbantul/SecretScan/internal/detectors"
	"github.com/renamamiyaaslimbantul/SecretScan/internal/model"
)

type Scanner struct {
	cfg      config.Config
	detector *detectors.Detector
	ignored  map[string]bool
}

func New(cfg config.Config, detector *detectors.Detector) *Scanner {
	ignored := make(map[string]bool, len(cfg.Ignore))
	for _, item := range cfg.Ignore {
		ignored[strings.ToLower(filepath.Clean(item))] = true
		ignored[strings.ToLower(filepath.Base(filepath.Clean(item)))] = true
	}
	return &Scanner{cfg: cfg, detector: detector, ignored: ignored}
}

func (s *Scanner) Scan(targets []string) (model.Result, error) {
	result := model.Result{Findings: []model.Finding{}, Passed: true}
	seen := map[string]bool{}
	for _, target := range targets {
		abs, err := filepath.Abs(target)
		if err != nil {
			return result, fmt.Errorf("resolve target: %w", err)
		}
		info, err := os.Lstat(abs)
		if err != nil {
			return result, fmt.Errorf("open target %q: %w", target, err)
		}
		if info.Mode()&os.ModeSymlink != 0 {
			continue
		}
		if !info.IsDir() {
			if !seen[abs] {
				if err := s.scanFile(abs, &result); err != nil {
					return result, err
				}
				seen[abs] = true
			}
			continue
		}
		err = filepath.WalkDir(abs, func(path string, entry os.DirEntry, walkErr error) error {
			if walkErr != nil {
				return walkErr
			}
			if path != abs && s.shouldIgnore(abs, path, entry.Name()) {
				if entry.IsDir() {
					return filepath.SkipDir
				}
				return nil
			}
			if entry.Type()&os.ModeSymlink != 0 {
				if entry.IsDir() {
					return filepath.SkipDir
				}
				return nil
			}
			if entry.IsDir() || seen[path] {
				return nil
			}
			seen[path] = true
			return s.scanFile(path, &result)
		})
		if err != nil {
			return result, fmt.Errorf("scan target %q: %w", target, err)
		}
	}
	sort.Slice(result.Findings, func(i, j int) bool {
		if result.Findings[i].File == result.Findings[j].File {
			return result.Findings[i].Line < result.Findings[j].Line
		}
		return result.Findings[i].File < result.Findings[j].File
	})
	result.Passed = len(result.Findings) == 0
	return result, nil
}

func (s *Scanner) shouldIgnore(root, path, name string) bool {
	if s.ignored[strings.ToLower(name)] {
		return true
	}
	rel, err := filepath.Rel(root, path)
	if err != nil {
		return false
	}
	return s.ignored[strings.ToLower(filepath.Clean(rel))]
}

func (s *Scanner) scanFile(path string, result *model.Result) error {
	info, err := os.Stat(path)
	if err != nil {
		return fmt.Errorf("inspect file %q: %w", path, err)
	}
	if !info.Mode().IsRegular() || info.Size() > s.cfg.MaxFileSize {
		return nil
	}
	f, err := os.Open(path)
	if err != nil {
		return fmt.Errorf("read file %q: %w", path, err)
	}
	defer f.Close()
	header := make([]byte, 8192)
	n, readErr := f.Read(header)
	if readErr != nil && readErr != io.EOF {
		return fmt.Errorf("read file %q: %w", path, readErr)
	}
	if bytes.IndexByte(header[:n], 0) >= 0 {
		return nil
	}
	if _, err := f.Seek(0, io.SeekStart); err != nil {
		return fmt.Errorf("read file %q: %w", path, err)
	}
	return s.scanReader(path, f, result)
}

func (s *Scanner) ScanContent(name string, data []byte) (model.Result, error) {
	result := model.Result{Findings: []model.Finding{}, Passed: true}
	if int64(len(data)) > s.cfg.MaxFileSize || bytes.IndexByte(data, 0) >= 0 {
		return result, nil
	}
	if err := s.scanReader(name, bytes.NewReader(data), &result); err != nil {
		return result, err
	}
	result.Passed = len(result.Findings) == 0
	return result, nil
}

func (s *Scanner) scanReader(name string, reader io.Reader, result *model.Result) error {
	result.FilesScanned++
	scan := bufio.NewScanner(reader)
	maxTokenSize := int(s.cfg.MaxFileSize) + 1
	if s.cfg.MaxFileSize >= int64(^uint(0)>>1) {
		maxTokenSize = int(^uint(0) >> 1)
	}
	scan.Buffer(make([]byte, 64*1024), maxTokenSize)
	line := 0
	for scan.Scan() {
		line++
		result.Findings = append(result.Findings, s.detector.ScanLine(name, line, scan.Text())...)
	}
	if err := scan.Err(); err != nil {
		return fmt.Errorf("scan file %q: %w", name, err)
	}
	return nil
}
