[![CodeQL](https://github.com/ngmisl/vibe-condom/actions/workflows/github-code-scanning/codeql/badge.svg)](https://github.com/ngmisl/vibe-condom/actions/workflows/github-code-scanning/codeql) [![Go](https://github.com/ngmisl/vibe-condom/actions/workflows/go.yml/badge.svg)](https://github.com/ngmisl/vibe-condom/actions/workflows/go.yml) [![Security Scan](https://github.com/ngmisl/vibe-condom/actions/workflows/security-scan.yaml/badge.svg)](https://github.com/ngmisl/vibe-condom/actions/workflows/security-scan.yaml)

# Vibecondom

A Go-based security tool for detecting malicious prompt injections and hidden characters in text content intended for Large Language Models (LLMs).

![2025-04-16 12 51 12 embracethered com fdccd6384947](https://github.com/user-attachments/assets/97a15516-5825-4175-8f03-719d1b438e3a)

## Overview

Vibecondom scans text files for hidden characters, manipulative patterns, and potential LLM prompt injection payloads that could be used to circumvent AI safety measures. It's designed to be a defensive tool for AI system developers, content moderators, and security researchers.

## Features

- **Multiple Detection Methods**:
  - ASCII control characters
  - Zero-width characters
  - Bidirectional text control characters
  - Unicode tag characters (U+E0000 to U+E007F)
  - Potential Base64 encoded content (with heuristics to reduce false positives from path-like strings and by checking decoded content printability)
  - Mixed script detection (identifies text using multiple writing systems)

- **Flexible Usage**:
  - Local directory scanning
  - Remote git repository scanning
  - Configurable file extensions and scan options
  - Size limits to prevent resource exhaustion

- **Detailed Output**:
  - Contextual alerts with character positions
  - Decoding capabilities for suspicious content
  - Summary reporting

## Installation

Requirements:
- Go 1.24.2 or later

```bash
# Clone the repository
git clone https://github.com/yourusername/vibecondom.git
cd vibecondom

# Install dependencies
go mod tidy

# Build
go build
```

## Usage

Basic usage:

```bash
# Scan a local directory
./vibecondom -mode local -target /path/to/directory

# Scan a remote Git repository
./vibecondom -mode remote -target https://github.com/username/repo.git

# Decode potential Base64 and hidden Unicode tag characters. 
# Base64 detection uses heuristics to reduce false positives, such as checking if the decoded content is mostly printable ASCII and if the original string contains many path separators.
./vibecondom -mode local -target /path/to/directory -decode-base64

# Specify file extensions to scan (default: .txt,.md,.mdc,.windsurfrules)
./vibecondom -mode local -target /path/to/directory -exts ".txt,.md,.yaml"
```

### Command Line Options

| Flag | Description | Default |
|------|-------------|---------|
| `-mode` | Mode: 'local' (check directory) or 'remote' (clone Git repo) | `local` |
| `-target` | Directory path (local) or Git URL (remote) | Required |
| `-exts` | Comma-separated file extensions to check | `.txt,.md,.mdc,.windsurfrules,AGENT.md,AGENTS.md` |
| `-max-filesize` | Max file size in MB to scan | `50` |
| `-skip-check` | Comma-separated checks to disable | None |
| `-decode-base64` | Attempt to decode Base64 strings. Uses heuristics (ASCII printability of decoded data, path separator count in source) to reduce false positives. Also decodes hidden Unicode tag characters. | `false` |
| `-temp-base` | Base directory for temp clones (remote mode) | System temp dir |
| `-log-level` | Log level: debug, info, warn, error | `info` |

## Security Considerations

This tool is intended for defensive purposes only. Use responsibly and in accordance with applicable laws and regulations.

## GitHub Action

Vibecondom includes a GitHub Action workflow that automatically scans your repository for security issues on every push and pull request.

### Adding Vibecondom to Your Repository

1. **Create the workflow directory** in your repository if it doesn't exist:
   ```bash
   mkdir -p .github/workflows/
   ```

2. **Copy the workflow file** to your repository:
   ```bash
   # From the root of your repository
   curl -o .github/workflows/security-scan.yaml https://raw.githubusercontent.com/ngmisl/vibe-condom/main/.github/workflows/security-scan.yaml
   ```

3. **Customize the workflow** (optional):
   - By default, the workflow scans all text-based files
   - To customize file extensions, modify the `extensions` parameter in the workflow file
   - Adjust the schedule for periodic scans if needed

4. **Commit and push** the changes to your repository:
   ```bash
   git add .github/workflows/security-scan.yaml
   git commit -m "Add Vibecondom security scan"
   git push
   ```

### Features

- Scans all relevant files in the repository
- Runs on push to main/master branches and pull requests
- Weekly scheduled scans (runs every Sunday at 00:00 UTC)
- Uploads detailed scan results as artifacts
- Fails the build if any security issues are found
- Provides a security badge for your README:
  ```markdown
  [![Security Scan](https://github.com/your-username/your-repo/actions/workflows/security-scan.yaml/badge.svg)](https://github.com/your-username/your-repo/actions/workflows/security-scan.yaml)
  ```

### Default File Extensions

The scanner checks files with the following extensions by default:
- `.txt` - Text files
- `.md` - Markdown files
- `.mdc` - Markdown content files
- `.windsurfrules` - Windsurf rules files
- `AGENT.md` - AI agent configuration
- `AGENTS.md` - AI agents registry

To customize the file extensions, modify the `extensions` parameter in the workflow file:

```yaml
- name: Run Vibecondom Security Scan
  uses: ngmisl/vibe-condom@main
  with:
    extensions: ".txt,.md,.yaml,.yml"  # Customize file extensions here
```

## License

MIT

## Testing

Vibecondom includes a comprehensive test suite to ensure reliability and security. The tests cover:

- **Input Validation**: Verifies that only valid Git URLs are accepted
- **Security Checks**: Ensures command injection attempts are properly blocked
- **Error Handling**: Validates proper error handling for various edge cases
- **Command Execution**: Tests command execution with timeouts and error conditions

### Running Tests

To run the test suite:

```bash
# Run all tests
make test

# Or directly with go test
cd vibecondom
go test -v ./...

# Run tests with race detector
go test -race -v ./...

# Run tests with coverage report
go test -coverprofile=coverage.out ./... && go tool cover -html=coverage.out
```

### Test Coverage

The test suite includes:

1. **Unit Tests** for individual functions
2. **Integration Tests** for end-to-end functionality
3. **Security Tests** to validate input sanitization

### CI/CD Integration

Tests are automatically run on every push and pull request via GitHub Actions. The CI pipeline includes:

- Unit and integration tests
- Race condition detection
- Code coverage reporting
- Security scanning with CodeQL

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## Support

[Click Here](https://fourzerofour.fkey.id) to support <3
