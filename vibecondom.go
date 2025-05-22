package main

import (
	"bufio"
	"context"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"time"
	"unicode"

	"golang.org/x/text/unicode/rangetable"
)

const (
	megabyte = 1024 * 1024
)

// CheckType defines the type of checks available
type CheckType string

const (
	CheckASCIIControl CheckType = "ascii-control"
	CheckZeroWidth    CheckType = "zero-width"
	CheckBiDi         CheckType = "bidi"
	CheckBase64       CheckType = "base64"
	CheckMixedScript  CheckType = "mixed-script"
	CheckTagChars     CheckType = "tag-characters"
)

var AllChecks = []CheckType{
	CheckASCIIControl,
	CheckZeroWidth,
	CheckBiDi,
	CheckBase64,
	CheckMixedScript,
	CheckTagChars,
}

// --- Script Definitions for Mixed Script Detection ---
var latinRange = rangetable.Merge(unicode.Latin)
var cyrillicRange = rangetable.Merge(unicode.Cyrillic)
var greekRange = rangetable.Merge(unicode.Greek)

// Word boundary definition
var wordRegex = regexp.MustCompile(`[\pL\pN]+`)

// --- Regex for Base64 Heuristic ---
// Looks for potential Base64 strings (alphanumeric + / +, padding) - heuristic!
var potentialBase64Regex = regexp.MustCompile(`(?:[A-Za-z0-9+/]{4}){5,}(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?`)

type config struct {
	mode         string
	target       string
	extensions   []string
	tempDirBase  string
	maxFileSize  int64 // Max file size in bytes
	skipChecks   []CheckType
	decodeBase64 bool // Flag to attempt decoding base64
	logger       *slog.Logger
	gitPath      string // Path to git executable
	issuesFound  int    // Counter for total issues
	filesChecked int    // Counter for files checked
}

func main() {
	// --- Configuration via Flags ---
	cfg := &config{
		// Initialize logger early for potential setup errors
		logger: slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelInfo})),
	}
	var exts string
	var maxFileSizeMB int64
	var skipChecksRaw string
	var logLevel string

	// --- Set Default Extensions ---
	defaultExtensions := ".txt,.md,.mdc,.windsurfrules,AGENT.md,AGENTS.md"

	flag.StringVar(&cfg.mode, "mode", "local", "Mode: 'local' (check directory) or 'remote' (clone Git repo)")
	flag.StringVar(&cfg.target, "target", "", "Required: Directory path (local) or Git URL (remote)")
	// Use the defaultExtensions variable here
	flag.StringVar(&exts, "exts", defaultExtensions, fmt.Sprintf("Comma-separated file extensions to check (default: %s)", defaultExtensions)) // <<< UPDATED FLAG DEFINITION
	flag.Int64Var(&maxFileSizeMB, "max-filesize", 50, "Max file size in MB to scan (0 for unlimited)")
	flag.StringVar(&skipChecksRaw, "skip-check", "", fmt.Sprintf("Comma-separated checks to disable (options: %v)", AllChecks))
	flag.BoolVar(&cfg.decodeBase64, "decode-base64", false, "Attempt to decode potential Base64 strings and show hex dump (use with caution)")
	flag.StringVar(&cfg.tempDirBase, "temp-base", os.TempDir(), "Base directory for temp clones (remote mode)")
	flag.StringVar(&logLevel, "log-level", "info", "Log level: debug, info, warn, error")

	flag.Parse()

	// --- Setup Logger Level ---
	var level slog.Level
	switch strings.ToLower(logLevel) {
	case "debug":
		level = slog.LevelDebug
	case "info":
		level = slog.LevelInfo
	case "warn", "warning":
		level = slog.LevelWarn
	case "error":
		level = slog.LevelError
	default:
		cfg.logger.Warn("Invalid log level specified, defaulting to info", "level", logLevel)
		level = slog.LevelInfo
	}
	// Recreate logger with the chosen level
	cfg.logger = slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: level}))

	// --- Input Validation ---
	if cfg.target == "" {
		cfg.logger.Error("Missing required argument", "flag", "-target")
		os.Exit(1)
	}

	// Find git executable path early for remote mode
	var gitErr error
	if cfg.mode == "remote" {
		cfg.gitPath, gitErr = exec.LookPath("git")
		if gitErr != nil {
			cfg.logger.Error("Failed to find 'git' executable in PATH. 'git' is required for remote mode.", "error", gitErr)
			os.Exit(1)
		}
		cfg.logger.Debug("Found git executable", "path", cfg.gitPath)
	}

	// Parse extensions (use lower case for comparisons)
	cfg.extensions = strings.Split(exts, ",")
	validExts := []string{}
	for _, ext := range cfg.extensions {
		trimmed := strings.TrimSpace(ext)
		// Ensure it starts with '.' and isn't empty
		if trimmed != "" && strings.HasPrefix(trimmed, ".") {
			validExts = append(validExts, strings.ToLower(trimmed))
		} else if trimmed != "" {
			cfg.logger.Warn("Ignoring invalid extension format (must start with '.')", "extension", trimmed)
		}
	}
	if len(validExts) == 0 {
		cfg.logger.Error("No valid extensions provided or remaining after validation.", "input_exts", exts)
		os.Exit(1)
	}
	cfg.extensions = validExts
	cfg.logger.Info("Will check extensions", "extensions", cfg.extensions)

	// Parse skipped checks
	if skipChecksRaw != "" {
		skipped := strings.Split(skipChecksRaw, ",")
		for _, s := range skipped {
			trimmed := CheckType(strings.TrimSpace(s))
			isValidCheck := false
			for _, valid := range AllChecks {
				if trimmed == valid {
					// Avoid duplicates
					if !slices.Contains(cfg.skipChecks, trimmed) {
						cfg.skipChecks = append(cfg.skipChecks, trimmed)
					}
					isValidCheck = true
					break
				}
			}
			if !isValidCheck {
				cfg.logger.Warn("Ignoring invalid check name in -skip-check", "check", s)
			}
		}
		if len(cfg.skipChecks) > 0 {
			cfg.logger.Info("Skipping checks", "checks", cfg.skipChecks)
		}
	}

	if cfg.decodeBase64 {
		cfg.logger.Info("Base64 decoding enabled. Decoded content will be shown as hex dump.")
		if shouldSkipCheck(cfg, CheckBase64) {
			cfg.logger.Warn("Base64 decoding enabled, but Base64 check itself is skipped via -skip-check=base64. Decoding will not occur.")
		}
	}

	cfg.maxFileSize = maxFileSizeMB * megabyte // Convert MB to bytes

	// --- Execute ---
	startTime := time.Now()
	cfg.logger.Info("Scan starting", "time", startTime.Format(time.RFC3339))

	var err error
	switch cfg.mode {
	case "local":
		cfg.logger.Info("Starting local scan", "directory", cfg.target)
		err = checkLocalDirectory(cfg)
	case "remote":
		cfg.logger.Info("Starting remote scan", "repository", cfg.target)
		err = checkRemoteRepo(cfg)
	default:
		cfg.logger.Error("Invalid mode", "mode", cfg.mode)
		os.Exit(1)
	}

	duration := time.Since(startTime)
	cfg.logger.Info("Scan finished", "duration", duration.Round(time.Millisecond).String())

	if err != nil {
		// Log the specific error that caused the failure
		cfg.logger.Error("Operation failed", "error", err)
		// Exit with non-zero code to indicate failure
		os.Exit(1)
	}

	cfg.logger.Info("Scan summary", "files_checked", cfg.filesChecked, "potential_issues_found", cfg.issuesFound)
	if cfg.issuesFound > 0 {
		cfg.logger.Warn("Potential issues were found. Please review the alerts above carefully.")
		// os.Exit(2) // Optionally exit with a different code if issues found
	}
}

// Checks a local directory path using the shared config.
func checkLocalDirectory(cfg *config) error {
	cfg.logger.Debug("Walking directory", "path", cfg.target)
	return filepath.WalkDir(cfg.target, func(path string, d os.DirEntry, err error) error {
		// Handle initial error accessing the path/entry
		if err != nil {
			// Log permission errors distinctly
			if errors.Is(err, os.ErrPermission) {
				cfg.logger.Warn("Permission denied accessing path, skipping", "path", path, "error", err)
			} else {
				cfg.logger.Warn("Error accessing path, skipping", "path", path, "error", err)
			}
			// If the error is permission denied on the starting directory, stop early.
			if path == cfg.target && errors.Is(err, os.ErrPermission) {
				return fmt.Errorf("permission denied accessing start directory %s: %w", cfg.target, err)
			}
			// Skip this entry if it's inaccessible, but continue walking siblings/parent.
			// Returning nil here allows WalkDir to continue.
			return nil
		}

		// Skip directories, handle .git specifically
		if d.IsDir() {
			if d.Name() == ".git" {
				cfg.logger.Debug("Skipping .git directory", "path", path)
				return filepath.SkipDir // Stop walking this directory
			}
			return nil // Continue walking into subdirectory
		}

		// Check extension match (case-insensitive, uses pre-processed cfg.extensions)
		ext := strings.ToLower(filepath.Ext(d.Name()))
		if !slices.Contains(cfg.extensions, ext) {
			cfg.logger.Log(context.Background(), slog.LevelDebug-1, "Skipping file due to non-matching extension", "path", path, "extension", ext) // Verbose debug
			return nil                                                                                                                             // Skip files with non-matching extensions
		}

		// Get file info for size check
		info, err := d.Info()
		if err != nil {
			// This might happen for various reasons (e.g., broken symlink just after initial access)
			cfg.logger.Warn("Could not get file info, skipping", "path", path, "error", err)
			return nil
		}

		// Check file size limit
		if cfg.maxFileSize > 0 && info.Size() > cfg.maxFileSize {
			cfg.logger.Warn("File exceeds size limit, skipping",
				"path", path,
				"size_bytes", info.Size(),
				"limit_bytes", cfg.maxFileSize,
			)
			return nil
		}

		// Check the file content
		cfg.filesChecked++
		fileIssues, checkErr := checkFile(cfg, path)
		if checkErr != nil {
			// Log the error but continue scanning other files
			cfg.logger.Error("Error checking file content", "path", path, "error", checkErr)
			// Decide whether to stop the walk on a single file error
			// return checkErr // To stop entire walk
			return nil // To log error and continue walk
		}
		cfg.issuesFound += fileIssues
		return nil // Continue walking
	})
}

// validateGitURL checks if the URL is a valid Git URL
func validateGitURL(url string) error {
	// Basic check for common Git URL patterns
	// This is a basic validation - you might want to adjust based on your needs
	validPrefixes := []string{"https://", "http://", "git@", "git://", "ssh://"}
	
	// Check if URL starts with any valid prefix
	for _, prefix := range validPrefixes {
		if strings.HasPrefix(url, prefix) {
			return nil
		}
	}
	
	return fmt.Errorf("invalid Git URL format. Must start with one of: %v", validPrefixes)
}

// Clones a remote git repository and checks it using the shared config.
func checkRemoteRepo(cfg *config) error {
	// Validate the Git URL before proceeding
	if err := validateGitURL(cfg.target); err != nil {
		return fmt.Errorf("invalid repository URL: %w", err)
	}

	tempDir, err := os.MkdirTemp(cfg.tempDirBase, "repo-scan-*")
	if err != nil {
		return fmt.Errorf("failed to create temporary directory in %s: %w", cfg.tempDirBase, err)
	}
	cfg.logger.Info("Created temporary directory", "path", tempDir)

	// Defer cleanup, log start and outcome
	defer func() {
		cfg.logger.Info("Cleaning up temporary directory", "path", tempDir)
		if rmErr := os.RemoveAll(tempDir); rmErr != nil {
			cfg.logger.Warn("Failed to remove temporary directory", "path", tempDir, "error", rmErr)
		} else {
			cfg.logger.Debug("Successfully removed temporary directory", "path", tempDir)
		}
	}()

	cfg.logger.Info("Cloning repository...", "url", cfg.target, "destination", tempDir)

	// Create a context with timeout (5 minutes)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	// Execute git clone command safely with context
	cmd := exec.CommandContext(ctx, cfg.gitPath, "clone", "--depth", "1", "--quiet", cfg.target, tempDir)
	
	// Set a clean environment
	cmd.Env = []string{"PATH=" + os.Getenv("PATH")} // Only keep PATH for security
	
	// Set working directory to a safe location
	cmd.Dir = cfg.tempDirBase
	
	// Capture stderr for better error messages
	var stderr strings.Builder
	cmd.Stderr = &stderr

	err = cmd.Run()
	if err != nil {
		// Check if the context timed out
		if ctx.Err() == context.DeadlineExceeded {
			return fmt.Errorf("git clone timed out after 5 minutes")
		}
		
		// Attempt to remove partially cloned directory on failure
		_ = os.RemoveAll(tempDir) // Ignore error during cleanup on failure path
		
		// Sanitize the error message to prevent command injection in logs
		safeURL := cfg.target
		if len(safeURL) > 100 { // Truncate long URLs in error messages
			safeURL = safeURL[:100] + "..."
		}
		
		// Provide sanitized context in the error message
		return fmt.Errorf("git clone failed: %w. Git stderr: %s", err, strings.TrimSpace(stderr.String()))
	}

	cfg.logger.Info("Clone successful. Starting scan.", "path", tempDir)

	// Store original target and update cfg for local check
	originalTarget := cfg.target
	cfg.target = tempDir
	// Execute the local directory check on the cloned repo
	err = checkLocalDirectory(cfg)
	// Restore original target in config (good practice, though not strictly needed here)
	cfg.target = originalTarget
	// Return the result of the local check
	return err
}

// Checks if a specific check type should be skipped.
func shouldSkipCheck(cfg *config, check CheckType) bool {
	return slices.Contains(cfg.skipChecks, check)
}

// Performs the checks on a single file, reading line by line.
func checkFile(cfg *config, filePath string) (int, error) {
	file, err := os.Open(filePath)
	if err != nil {
		// Let the caller (checkLocalDirectory) handle logging based on error type
		return 0, fmt.Errorf("failed to open file: %w", err)
	}
	defer file.Close()

	cfg.logger.Debug("Checking file", "path", filePath)
	issueCount := 0
	// Use a bufio.Reader for potentially better performance with scanner
	reader := bufio.NewReader(file)
	scanner := bufio.NewScanner(reader)
	// Increase buffer size if needed, but start with default. Default is 64k.
	// const maxLineSize = 1 * 1024 * 1024 // Example: 1MB buffer
	// buf := make([]byte, maxLineSize)
	// scanner.Buffer(buf, maxLineSize)
	scanner.Split(bufio.ScanLines) // Process line by line

	lineNumber := 0
	for scanner.Scan() {
		lineNumber++
		line := scanner.Text()
		// Use runes for correct column calculation and character analysis
		lineRunes := []rune(line)

		// Collect all alerts for this line before logging once
		var lineAlertAttrs []slog.Attr

		// --- Perform character-level checks ---
		for col, r := range lineRunes {
			columnNumber := col + 1 // 1-based column number

			// 1. ASCII Control Characters (excluding tab, CR, LF)
			if !shouldSkipCheck(cfg, CheckASCIIControl) && r < 32 && r != '\t' && r != '\n' && r != '\r' {
				// msg := fmt.Sprintf("Invisible ASCII control character (Code: %d)", r)
				details := slog.Group("details", slog.Int("code", int(r)), slog.String("char_hex", fmt.Sprintf("0x%X", r)))
				lineAlertAttrs = append(lineAlertAttrs, slog.Any(fmt.Sprintf("col_%d_%s", columnNumber, CheckASCIIControl), details))
				issueCount++
			}

			// 2. Zero-Width Characters
			if !shouldSkipCheck(cfg, CheckZeroWidth) {
				var zwDetail, zwCode string
				switch r {
				case '\u200B':
					zwDetail = "Zero Width Space"
					zwCode = "U+200B"
				case '\u200C':
					zwDetail = "Zero Width Non-Joiner"
					zwCode = "U+200C"
				case '\u200D':
					zwDetail = "Zero Width Joiner"
					zwCode = "U+200D"
				case '\uFEFF':
					zwDetail = "Zero Width No-Break Space / BOM"
					zwCode = "U+FEFF"
				}
				if zwDetail != "" {
					// msg := fmt.Sprintf("%s (%s) detected", zwDetail, zwCode)
					details := slog.Group("details", slog.String("description", zwDetail), slog.String("code", zwCode))
					lineAlertAttrs = append(lineAlertAttrs, slog.Any(fmt.Sprintf("col_%d_%s", columnNumber, CheckZeroWidth), details))
					issueCount++
				}
			}

			// 3. Bidirectional Control Characters
			if !shouldSkipCheck(cfg, CheckBiDi) {
				if (r >= '\u202A' && r <= '\u202E') || (r >= '\u2066' && r <= '\u2069') {
					bidiCode := fmt.Sprintf("U+%04X", r)
					isRLO := r == '\u202E'
					// msg := fmt.Sprintf("Bidi Control Character (%s)%s", bidiCode, map[bool]string{true:" - RLO!", false:""}[isRLO])
					details := slog.Group("details", slog.String("code", bidiCode), slog.Bool("is_rlo", isRLO))
					lineAlertAttrs = append(lineAlertAttrs, slog.Any(fmt.Sprintf("col_%d_%s", columnNumber, CheckBiDi), details))
					issueCount++
				}
			}

			// 4. Tag Characters (U+E0000 to U+E007F)
			if !shouldSkipCheck(cfg, CheckTagChars) {
				// Use decimal values instead of rune literals for large Unicode code points
				if r >= 0xE0000 && r <= 0xE007F {
					tagCode := fmt.Sprintf("U+%04X", r)
					details := slog.Group("details",
						slog.String("code", tagCode),
						slog.String("description", "Language Tag Character"),
						slog.Int("decimal_value", int(r)))
					lineAlertAttrs = append(lineAlertAttrs, slog.Any(fmt.Sprintf("col_%d_%s", columnNumber, CheckTagChars), details))
					issueCount++
				}
			}
		} // End char checks

		// --- Perform line-level checks ---

		// 5. Base64 Heuristic Check
		if !shouldSkipCheck(cfg, CheckBase64) {
			matches := potentialBase64Regex.FindAllString(line, -1) // Find all non-overlapping matches
			if len(matches) > 0 {
				issueCount++ // Count once per line with any base64 match for summary
				// Use a distinct key for the line-level finding
				lineLevelBase64Key := fmt.Sprintf("line_%s", CheckBase64)
				base64Details := slog.Group("details",
					slog.Int("match_count", len(matches)),
					slog.String("first_match_snippet", truncateString(matches[0], 50)),
				)
				lineAlertAttrs = append(lineAlertAttrs, slog.Any(lineLevelBase64Key, base64Details))

				// Attempt decode if flag is set
				if cfg.decodeBase64 {
					// Add decoded results under the main finding
					var decodeAttrs []slog.Attr
					for i, match := range matches {
						// Enforce a maximum length on string to decode to prevent DoS on regex false positives
						const maxBase64Len = 10 * 1024 // Limit potential base64 strings to decode to 10KB
						if len(match) > maxBase64Len {
							decodeAttrs = append(decodeAttrs, slog.String(fmt.Sprintf("decode_attempt_%d", i+1), "Skipped decode: Input string too long"))
							continue
						}

						decodedBytes, err := base64.StdEncoding.DecodeString(match)
						var decodeVal any
						if err != nil {
							// Only log simple error message for common decode failures
							errMsg := "Decode failed"
							// Check for common padding error specifically
							var paddingErr base64.CorruptInputError
							if errors.As(err, &paddingErr) {
								errMsg += " (invalid padding/chars)"
							}
							// Don't log the full complex error object by default
							decodeVal = slog.StringValue(errMsg)
						} else {
							// Show as hex dump for safety
							hexDump := hex.Dump(decodedBytes)
							const maxDumpLen = 256 // Limit hex dump length in log
							if len(hexDump) > maxDumpLen {
								hexDump = hexDump[:maxDumpLen] + "\n... (truncated)"
							}
							// Use StringValue to embed the potentially multi-line dump correctly
							decodeVal = slog.StringValue("\n" + hexDump) // Add newline for readability
						}
						decodeAttrs = append(decodeAttrs, slog.Any(fmt.Sprintf("decode_attempt_%d", i+1), decodeVal))
					}
					// Convert []slog.Attr to []any for slog.Group
					decodeAttrsAny := make([]any, len(decodeAttrs))
					for i, attr := range decodeAttrs {
						decodeAttrsAny[i] = attr
					}
					// Add all decode attempts as a group under the main base64 finding
					lineAlertAttrs = append(lineAlertAttrs, slog.Group("decode_results", decodeAttrsAny...))
				}
			}
		}

		// 6. Mixed Script Detection
		if !shouldSkipCheck(cfg, CheckMixedScript) {
			words := wordRegex.FindAllString(line, -1)
			var mixedScriptWords []any // Using []any for slog group args
			for _, word := range words {
				scripts := identifyScripts(word)
				if len(scripts) > 1 { // Found > 1 script in the same word
					mixedScriptWords = append(mixedScriptWords, slog.Group(truncateString(word, 50), slog.Any("scripts", scripts)))
					// Don't break, collect all mixed words on the line
				}
			}
			if len(mixedScriptWords) > 0 {
				issueCount++ // Count once per line with any mixed script words
				lineAlertAttrs = append(lineAlertAttrs, slog.Group(fmt.Sprintf("line_%s", CheckMixedScript), mixedScriptWords...))
			}
		}

		// --- Log all findings for the current line ---
		if len(lineAlertAttrs) > 0 {
			// Consolidate attributes: context first, then specific findings
			logArgs := []any{
				slog.String("file", filePath),
				slog.Int("line", lineNumber),
				slog.String("line_content_snippet", truncateString(line, 120)), // Show snippet of the line
			}
			// Add the collected alert details
			for _, attr := range lineAlertAttrs {
				logArgs = append(logArgs, attr)
			}

			// Check if this line has tag characters and decode them if requested
			if cfg.decodeBase64 {
				// Attempt to decode the entire line's tag characters
				decoded := decodeTagChars(line)
				if decoded != "" {
					logArgs = append(logArgs, slog.String("decoded_tag_chars", decoded))
				}
			}

			// Log as a single WARNING event for this line
			cfg.logger.Warn("Potential Issue Detected", logArgs...)
		}

	} // End of line scanning loop

	// Check for scanner errors (like buffer too small)
	if err := scanner.Err(); err != nil {
		if errors.Is(err, bufio.ErrTooLong) {
			cfg.logger.Warn("Scan may be incomplete: A line exceeded the maximum buffer size. Consider increasing buffer if needed.",
				"path", filePath, "line_approx", lineNumber)
			// This isn't fatal, but worth noting. Continue processing other files.
		} else {
			// Return other I/O errors encountered during scan
			return issueCount, fmt.Errorf("error scanning file %s after line %d: %w", filePath, lineNumber, err)
		}
	}

	return issueCount, nil
}

// identifyScripts checks which scripts are present in a word.
func identifyScripts(word string) []string {
	scripts := make(map[string]bool)
	for _, r := range word {
		if unicode.Is(latinRange, r) {
			scripts["Latin"] = true
		}
		if unicode.Is(cyrillicRange, r) {
			scripts["Cyrillic"] = true
		}
		if unicode.Is(greekRange, r) {
			scripts["Greek"] = true
		}
		// Add more script checks if needed: Arabic, Hebrew, Han, etc.
	}
	// If the word contains only one script, don't flag it as mixed script. Only flag if multiple *scripts* are present.
	if len(scripts) <= 1 {
		return nil // Not considered mixed script
	}

	var result []string
	for script := range scripts {
		result = append(result, script)
	}
	slices.Sort(result) // Consistent order
	return result
}

// truncateString limits the length of a string for display, rune-aware.
func truncateString(s string, maxLen int) string {
	if maxLen <= 0 {
		return ""
	}
	runes := []rune(s)
	if len(runes) <= maxLen {
		return s
	}
	// Ensure we have space for "..."
	if maxLen < 3 {
		maxLen = 3
	}
	return string(runes[:maxLen-3]) + "..."
}

// decodeTagChars extracts and decodes any language tag characters in a string
func decodeTagChars(input string) string {
	var buf strings.Builder
	foundTags := false
	
	for _, r := range input {
		// Check if it's a tag character (U+E0000 to U+E007F)
		if r >= 0xE0000 && r <= 0xE007F {
			foundTags = true
			// Map tag character to regular ASCII
			// U+E0000 is a tag delimiter, U+E0001-U+E007F map to ASCII 0x01-0x7F
			if r == 0xE0000 {
				// Skip the tag delimiter
				continue
			} else {
				// Convert to normal ASCII by subtracting the appropriate offset
				// U+E0001 maps to ASCII 0x01 (SOH)
				normalChar := r - 0xE0000
				// Only include printable characters
				if normalChar >= 0x20 && normalChar <= 0x7E {
					buf.WriteRune(normalChar)
				} else {
					// For non-printable characters, show a representation
					buf.WriteString(fmt.Sprintf("[0x%02X]", normalChar))
				}
			}
		}
	}
	
	if !foundTags {
		return ""
	}
	
	return buf.String()
}
