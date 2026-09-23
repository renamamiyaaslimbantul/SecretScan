package reporter

import (
	"fmt"
	"io"
	"path/filepath"

	"github.com/renamamiyaaslimbantul/SecretScan/internal/model"
)

func Text(w io.Writer, result model.Result, unicode bool) error {
	ok, bad, rule := "[OK]", "[X]", "----------------------------"
	if unicode {
		ok, bad, rule = "✓", "✗", "────────────────────────────"
	}
	if _, err := fmt.Fprintf(w, "SecretScan v%s\n\nScanning %d files...\n\n", result.Version, result.FilesScanned); err != nil {
		return err
	}
	if len(result.Findings) == 0 {
		_, err := fmt.Fprintf(w, "%s No secrets detected.\n\nScan passed.\n", ok)
		return err
	}
	for i, finding := range result.Findings {
		if _, err := fmt.Fprintf(w, "%s POSSIBLE SECRET\n\nFile: %s\nLine: %d\nType: %s\nConfidence: %d%%\n\n%s\n", bad, filepath.Clean(finding.File), finding.Line, finding.Type, finding.Confidence, finding.Snippet); err != nil {
			return err
		}
		if i < len(result.Findings)-1 {
			if _, err := fmt.Fprintln(w, "\n"+rule); err != nil {
				return err
			}
		}
	}
	noun := "secrets"
	if len(result.Findings) == 1 {
		noun = "secret"
	}
	_, err := fmt.Fprintf(w, "\n%s\n%d potential %s found.\n\nScan failed.\n", rule, len(result.Findings), noun)
	return err
}
