package config

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"gopkg.in/yaml.v3"
)

const FileName = ".secretscan.yaml"

type Rule struct {
	Name       string `yaml:"name"`
	Pattern    string `yaml:"pattern"`
	Confidence int    `yaml:"confidence"`
}

type Config struct {
	Ignore                []string `yaml:"ignored"`
	ExcludedPatterns      []string `yaml:"excluded_patterns"`
	CustomRules           []Rule   `yaml:"custom_rules"`
	MinimumConfidence     int      `yaml:"minimum_confidence"`
	HookMinimumConfidence int      `yaml:"hook_minimum_confidence"`
	Output                string   `yaml:"output"`
	MaxFileSize           int64    `yaml:"max_file_size"`
}

func Defaults() Config {
	return Config{
		Ignore:            []string{".git", "node_modules", ".venv", "venv", "bin", "obj", "vendor", "dist", "build"},
		MinimumConfidence: 70, HookMinimumConfidence: 90, Output: "text", MaxFileSize: 10 << 20,
	}
}

func Load(path string) (Config, error) {
	cfg := Defaults()
	data, err := os.ReadFile(path)
	if err != nil {
		return Config{}, fmt.Errorf("read configuration: %w", err)
	}
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return Config{}, fmt.Errorf("parse configuration: %w", err)
	}
	if err := cfg.Validate(); err != nil {
		return Config{}, err
	}
	return cfg, nil
}

func (c Config) Validate() error {
	if c.MinimumConfidence < 0 || c.MinimumConfidence > 100 {
		return errors.New("minimum_confidence must be between 0 and 100")
	}
	if c.HookMinimumConfidence < 0 || c.HookMinimumConfidence > 100 {
		return errors.New("hook_minimum_confidence must be between 0 and 100")
	}
	if c.Output != "text" && c.Output != "json" {
		return errors.New("output must be text or json")
	}
	if c.MaxFileSize <= 0 {
		return errors.New("max_file_size must be positive")
	}
	for i, rule := range c.CustomRules {
		if strings.TrimSpace(rule.Name) == "" || strings.TrimSpace(rule.Pattern) == "" {
			return fmt.Errorf("custom rule %d requires name and pattern", i+1)
		}
		if rule.Confidence == 0 {
			c.CustomRules[i].Confidence = 85
		}
		if rule.Confidence < 0 || rule.Confidence > 100 {
			return fmt.Errorf("custom rule %q confidence must be between 0 and 100", rule.Name)
		}
		if _, err := regexp.Compile(rule.Pattern); err != nil {
			return fmt.Errorf("custom rule %q has invalid pattern: %w", rule.Name, err)
		}
	}
	for _, pattern := range c.ExcludedPatterns {
		if _, err := regexp.Compile(pattern); err != nil {
			return fmt.Errorf("excluded pattern is invalid: %w", err)
		}
	}
	return nil
}

func Find(start string) (string, bool, error) {
	current, err := filepath.Abs(start)
	if err != nil {
		return "", false, err
	}
	if info, statErr := os.Stat(current); statErr == nil && !info.IsDir() {
		current = filepath.Dir(current)
	}
	for {
		candidate := filepath.Join(current, FileName)
		if _, err := os.Stat(candidate); err == nil {
			return candidate, true, nil
		} else if !os.IsNotExist(err) {
			return "", false, err
		}
		parent := filepath.Dir(current)
		if parent == current {
			return "", false, nil
		}
		current = parent
	}
}
