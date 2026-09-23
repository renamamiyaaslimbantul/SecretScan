package app

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/renamamiyaaslimbantul/SecretScan/internal/config"
	"github.com/renamamiyaaslimbantul/SecretScan/internal/detectors"
	gitutil "github.com/renamamiyaaslimbantul/SecretScan/internal/git"
	"github.com/renamamiyaaslimbantul/SecretScan/internal/model"
	"github.com/renamamiyaaslimbantul/SecretScan/internal/reporter"
	"github.com/renamamiyaaslimbantul/SecretScan/internal/scanner"
)

var Version = "0.1.0"

var currentOS = runtime.GOOS

type options struct{ command, target, output, configPath string }

func Run(args []string, stdout, stderr io.Writer) int {
	opts, err := parse(args)
	if err != nil {
		fmt.Fprintln(stderr, "SecretScan:", err)
		fmt.Fprintln(stderr, "Run 'secretscan --help' for usage.")
		return 2
	}
	if opts.command == "version" {
		fmt.Fprintf(stdout, "SecretScan v%s\n", Version)
		return 0
	}
	if opts.command == "help" {
		fmt.Fprint(stdout, usage)
		return 0
	}
	if currentOS != "windows" {
		fmt.Fprintln(stderr, "SecretScan v0.1.0 supports Windows only.")
		return 2
	}
	if opts.command == "install-hook" {
		exe, err := os.Executable()
		if err != nil {
			fmt.Fprintln(stderr, "SecretScan: cannot locate executable")
			return 2
		}
		path, err := gitutil.InstallHook(".", exe)
		if err != nil {
			fmt.Fprintln(stderr, "SecretScan:", err)
			return 2
		}
		fmt.Fprintln(stdout, "SecretScan pre-commit hook installed:", path)
		return 0
	}
	cfg, err := loadConfig(opts)
	if err != nil {
		fmt.Fprintln(stderr, "SecretScan:", err)
		return 2
	}
	if opts.output != "" {
		cfg.Output = opts.output
	}
	if opts.command == "scan-staged" {
		cfg.MinimumConfidence = cfg.HookMinimumConfidence
	}
	detector, err := detectors.New(cfg)
	if err != nil {
		fmt.Fprintln(stderr, "SecretScan: invalid detection configuration")
		return 2
	}
	s := scanner.New(cfg, detector)
	var result model.Result
	if opts.command == "scan-staged" {
		result, err = scanStaged(s)
	} else {
		result, err = s.Scan([]string{opts.target})
	}
	if err != nil {
		fmt.Fprintln(stderr, "SecretScan:", err)
		return 2
	}
	result.Version, result.Target = Version, opts.target
	if cfg.Output == "json" {
		err = reporter.JSON(stdout, result)
	} else {
		err = reporter.Text(stdout, result, true)
	}
	if err != nil {
		fmt.Fprintln(stderr, "SecretScan: write output failed")
		return 2
	}
	if !result.Passed {
		if opts.command == "scan-staged" {
			fmt.Fprintln(stdout, "\nCommit blocked.")
		}
		return 1
	}
	return 0
}

func scanStaged(s *scanner.Scanner) (model.Result, error) {
	files, err := gitutil.StagedFiles(".")
	if err != nil {
		return model.Result{}, err
	}
	result := model.Result{Findings: []model.Finding{}, Passed: true}
	for _, file := range files {
		data, err := gitutil.StagedContent(".", file)
		if err != nil {
			return result, err
		}
		part, err := s.ScanContent(file, data)
		if err != nil {
			return result, err
		}
		result.FilesScanned += part.FilesScanned
		result.Findings = append(result.Findings, part.Findings...)
	}
	result.Passed = len(result.Findings) == 0
	return result, nil
}

func loadConfig(opts options) (config.Config, error) {
	if opts.configPath != "" {
		return config.Load(opts.configPath)
	}
	start := opts.target
	if opts.command == "scan-staged" {
		start = "."
	}
	path, ok, err := config.Find(start)
	if err != nil {
		return config.Config{}, err
	}
	if !ok {
		return config.Defaults(), nil
	}
	return config.Load(path)
}

func parse(args []string) (options, error) {
	o := options{command: "scan", target: "."}
	if len(args) == 0 {
		return o, nil
	}
	positionals := []string{}
	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "--help", "-h":
			o.command = "help"
		case "--version", "-v":
			o.command = "version"
		case "--output":
			i++
			if i >= len(args) {
				return o, errors.New("--output requires text or json")
			}
			o.output = args[i]
			if o.output != "text" && o.output != "json" {
				return o, errors.New("--output must be text or json")
			}
		case "--config":
			i++
			if i >= len(args) {
				return o, errors.New("--config requires a path")
			}
			o.configPath = args[i]
		default:
			if strings.HasPrefix(args[i], "-") {
				return o, fmt.Errorf("unknown option %q", args[i])
			}
			positionals = append(positionals, args[i])
		}
	}
	if o.command == "help" || o.command == "version" {
		return o, nil
	}
	if len(positionals) > 0 {
		switch positionals[0] {
		case "scan":
			if len(positionals) > 1 {
				o.target = positionals[1]
			}
			if len(positionals) > 2 {
				return o, errors.New("too many scan targets")
			}
		case "install-hook":
			o.command = "install-hook"
		case "scan-staged":
			o.command = "scan-staged"
		default:
			o.target = positionals[0]
			if len(positionals) > 1 {
				return o, errors.New("too many scan targets")
			}
		}
	}
	if o.command == "scan-staged" {
		o.target = "staged files"
	}
	if o.configPath != "" {
		o.configPath = filepath.Clean(o.configPath)
	}
	return o, nil
}

const usage = `SecretScan - detect exposed credentials before they reach Git

Usage:
  secretscan [path] [--output text|json]
  secretscan scan [path] [--output text|json]
  secretscan install-hook
  secretscan --version
  secretscan --help

Options:
  --config <path>      Use a specific .secretscan.yaml file
  --output <format>    Write text or JSON output
`
