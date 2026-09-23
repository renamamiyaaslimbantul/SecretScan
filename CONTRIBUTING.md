# Contributing

Thanks for improving SecretScan.

## Development requirements

- Windows 10/11 for end-to-end behavior
- Go 1.23 or newer
- Git for Windows
- PowerShell

Run before opening a pull request:

```powershell
gofmt -w .\cmd .\internal
go test -race ./...
go vet ./...
go build -trimpath -o secretscan.exe .\cmd\secretscan
```

## Security rules

- Never add real credentials to source, fixtures, logs, screenshots, or commits.
- Use synthetic values and `.invalid` hostnames.
- Do not send scanned content to external services.
- Do not weaken redaction to make a test easier.
- Explain any detector false-positive or false-negative tradeoff in the pull request.

## Pull requests

Keep changes focused. Add or update tests for behavior changes. Include the command output from the verification steps above and describe Windows-specific behavior where relevant.
