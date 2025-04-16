[![CodeQL](https://github.com/ngmisl/vibe-condom/actions/workflows/github-code-scanning/codeql/badge.svg)](https://github.com/ngmisl/vibe-condom/actions/workflows/github-code-scanning/codeql) [![Go](https://github.com/ngmisl/vibe-condom/actions/workflows/go.yml/badge.svg)](https://github.com/ngmisl/vibe-condom/actions/workflows/go.yml)

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
  - Potential Base64 encoded content
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

# Decode potential Base64 and hidden Unicode tag characters
./vibecondom -mode local -target /path/to/directory -decode-base64

# Specify file extensions to scan (default: .txt,.md,.mdc,.windsurfrules)
./vibecondom -mode local -target /path/to/directory -exts ".txt,.md,.yaml"
```

### Command Line Options

| Flag | Description | Default |
|------|-------------|---------|
| `-mode` | Mode: 'local' (check directory) or 'remote' (clone Git repo) | `local` |
| `-target` | Directory path (local) or Git URL (remote) | Required |
| `-exts` | Comma-separated file extensions to check | `.txt,.md,.mdc,.windsurfrules` |
| `-max-filesize` | Max file size in MB to scan | `50` |
| `-skip-check` | Comma-separated checks to disable | None |
| `-decode-base64` | Attempt to decode Base64 strings and hidden Unicode | `false` |
| `-temp-base` | Base directory for temp clones (remote mode) | System temp dir |
| `-log-level` | Log level: debug, info, warn, error | `info` |

## Security Considerations

This tool is intended for defensive purposes only. Use responsibly and in accordance with applicable laws and regulations.

## License

MIT

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## Support

[Click Here](https://fourzerofour.fkey.id) to support <3
