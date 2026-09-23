package model

type Finding struct {
	File       string `json:"file"`
	Line       int    `json:"line"`
	Type       string `json:"type"`
	Confidence int    `json:"confidence"`
	Snippet    string `json:"snippet"`
}

type Result struct {
	Version      string    `json:"version"`
	Target       string    `json:"target"`
	FilesScanned int       `json:"files_scanned"`
	Findings     []Finding `json:"findings"`
	Passed       bool      `json:"passed"`
	Error        string    `json:"error,omitempty"`
}
