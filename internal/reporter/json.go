package reporter

import (
	"encoding/json"
	"io"

	"github.com/renamamiyaaslimbantul/SecretScan/internal/model"
)

func JSON(w io.Writer, result model.Result) error {
	encoder := json.NewEncoder(w)
	encoder.SetIndent("", "  ")
	return encoder.Encode(result)
}
