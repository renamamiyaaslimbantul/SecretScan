# SecretScan

SecretScan is a Windows-first CLI that finds credentials accidentally left in source code before commit or push. It runs locally, makes no network requests, and redacts every reported match.

Current release: `v0.1.0` for Windows 10 and 11.

## What it detects

- GitHub tokens
- AWS access keys
- Google API keys
- JSON Web Tokens (JWTs)
- Private-key headers
- Database connection strings
- Generic API keys, passwords, and access tokens
- Project-specific regex rules

Detection combines provider-specific patterns, Shannon entropy, assignment context, confidence scoring, and filters for placeholders such as `YOUR_API_KEY_HERE`, `example-token`, `test-password`, and `<your-token>`.

Secret scanning is probabilistic. A clean result does not prove a repository contains no credentials. Rotate any credential that may have been exposed.

## Build on Windows

Requirements:

- Windows 10 or 11
- Go 1.23 or newer
- Git for Windows for hook support
- PowerShell

```powershell
git clone https://github.com/renamamiyaaslimbantul/SecretScan.git
Set-Location .\secretscan
go build -o secretscan.exe .\cmd\secretscan
.\secretscan.exe --version
```

The result is one executable. No service, account, API key, or runtime installation is required.

## Use

```powershell
# Scan current directory
.\secretscan.exe .

# Equivalent explicit command
.\secretscan.exe scan .\src

# Machine-readable output
.\secretscan.exe . --output json

# Help and version
.\secretscan.exe --help
.\secretscan.exe --version
```

Default ignored names:

```text
.git  node_modules  .venv  venv  bin  obj  vendor  dist  build
```

SecretScan accepts absolute and relative Windows paths. It does not follow symbolic links. Binary files and files over 10 MiB are skipped by default.

Exit codes:

- `0`: scan passed
- `1`: one or more findings met the confidence threshold
- `2`: invalid arguments, invalid configuration, or runtime failure

## Git pre-commit hook

Run this inside a Git repository using the executable you plan to keep:

```powershell
.\secretscan.exe install-hook
```

The generated Git for Windows hook calls that executable by absolute path. On commit it:

1. Reads staged paths from Git using null-delimited output.
2. Reads each file from the Git index, not the working tree.
3. Scans only added, copied, modified, or renamed staged files.
4. Blocks the commit when a finding meets `hook_minimum_confidence`.

SecretScan refuses to overwrite a pre-existing hook it does not manage. Moving or deleting `secretscan.exe` after installation breaks the hook; reinstall it from the new location.

## Configuration

Place `.secretscan.yaml` in the target directory or a parent directory. Use `--config` to select another file. See `.secretscan.yaml.example` for a complete example.

```yaml
ignored:
  - .git
  - node_modules
  - generated

excluded_patterns:
  - '^SAFE_[A-Z0-9_]+$'

minimum_confidence: 70
hook_minimum_confidence: 90
output: text
max_file_size: 10485760

custom_rules:
  - name: Internal Service Token
    pattern: 'INT_[A-Z0-9]{20}'
    confidence: 95
```

Configured `ignored` entries replace the default list, so include defaults you still need. Invalid regexes, output formats, limits, and confidence values stop the scan with exit code `2`.

Add `secretscan:allow` to a reviewed line to suppress it:

```text
api_key="known-safe-fixture-value" # secretscan:allow
```

## JSON output

`--output json` writes one object to stdout with this stable MVP shape:

```json
{
  "version": "0.1.0",
  "target": ".",
  "files_scanned": 142,
  "findings": [
    {
      "file": "src\\config.js",
      "line": 18,
      "type": "API Key",
      "confidence": 96,
      "snippet": "API_KEY = \"sk-****************\""
    }
  ],
  "passed": false
}
```

Diagnostics go to stderr so stdout stays parseable.

## Security behavior

- Scanned content never leaves the machine.
- SecretScan has no telemetry, cloud service, AI model, or external API integration.
- Findings retain redacted snippets only; raw matches are not stored in result structures.
- SecretScan does not write scan results to disk.
- Git is executed directly without PowerShell or shell command interpolation.
- File size and line length are bounded to limit memory use.
- Symlinks are skipped to avoid scanning outside the requested tree.
- Examples and tests contain synthetic, invalid credential-like strings only.

Avoid piping sensitive source into verbose wrappers or third-party log collectors. If a real credential is found, revoke or rotate it before removing it from Git history.

## Development

```powershell
go test ./...
go vet ./...
go build -o secretscan.exe .\cmd\secretscan
```

Test fixtures live in `tests\fixtures`. Do not add real credentials, even temporarily.

## License

MIT. See `LICENSE`.
