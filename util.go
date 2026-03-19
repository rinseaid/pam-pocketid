package main

import (
	"io"
	"strings"
	"unicode/utf8"
)

// maxLogOutput caps how much command output is included in log messages
// to prevent multi-megabyte log lines that break log aggregators.
const maxLogOutput = 4096

// limitedWriter wraps a writer and silently discards bytes beyond the limit.
type limitedWriter struct {
	w io.Writer
	n int64
}

func (lw *limitedWriter) Write(p []byte) (int, error) {
	total := len(p) // preserve original length before truncation
	if lw.n <= 0 {
		return total, nil // discard
	}
	if int64(len(p)) > lw.n {
		p = p[:lw.n]
	}
	n, err := lw.w.Write(p)
	lw.n -= int64(n)
	return total, err // report full write to avoid short-write errors from cmd
}

// truncateOutput trims whitespace and caps output for log messages.
func truncateOutput(s string) string {
	s = strings.TrimSpace(s)
	if len(s) > maxLogOutput {
		// Find a valid UTF-8 boundary to avoid splitting multi-byte characters.
		truncLen := maxLogOutput
		for truncLen > 0 && !utf8.RuneStart(s[truncLen]) {
			truncLen--
		}
		return s[:truncLen] + "...(truncated)"
	}
	return s
}
