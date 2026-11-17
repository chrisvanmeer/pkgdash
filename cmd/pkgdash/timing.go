package main

import (
	"fmt"
	"os"
	"strings"
	"sync"
	"time"
)

// Optional load diagnostics. Enable with PKGDASH_DEBUG_TIMING=1. Output is
// buffered and printed after the TUI exits, so it cannot corrupt the alternate
// screen. Set PKGDASH_TIMING_FILE to also stream lines to a file while running.
var (
	timingEnabled bool
	timingFile    string
	timingStart   time.Time
	timingMu      sync.Mutex
	timingLines   []string
)

func initTiming() {
	timingEnabled = os.Getenv("PKGDASH_DEBUG_TIMING") == "1"
	timingFile = os.Getenv("PKGDASH_TIMING_FILE")
	timingStart = time.Now()
}

func timingLog(format string, args ...any) {
	if !timingEnabled {
		return
	}
	line := fmt.Sprintf("[%7.3fs] %s", time.Since(timingStart).Seconds(), fmt.Sprintf(format, args...))
	timingMu.Lock()
	defer timingMu.Unlock()
	if timingFile != "" {
		if f, err := os.OpenFile(timingFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644); err == nil {
			_, _ = fmt.Fprintln(f, line)
			_ = f.Close()
		}
		return
	}
	timingLines = append(timingLines, line)
}

// timingMeasure returns a function that logs the elapsed time when called.
// Intended for `defer timingMeasure("label")()`.
func timingMeasure(format string, args ...any) func() {
	if !timingEnabled {
		return func() {}
	}
	label := fmt.Sprintf(format, args...)
	start := time.Now()
	return func() {
		line := fmt.Sprintf("[%7.3fs] %-58s %9.2f ms", time.Since(timingStart).Seconds(), label, float64(time.Since(start).Microseconds())/1000)
		timingMu.Lock()
		defer timingMu.Unlock()
		if timingFile != "" {
			if f, err := os.OpenFile(timingFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644); err == nil {
				_, _ = fmt.Fprintln(f, line)
				_ = f.Close()
			}
			return
		}
		timingLines = append(timingLines, line)
	}
}

func flushTiming() {
	if !timingEnabled {
		return
	}
	timingMu.Lock()
	defer timingMu.Unlock()
	if timingFile != "" {
		return // already streamed to file
	}
	if len(timingLines) == 0 {
		return
	}
	var b strings.Builder
	b.WriteString("\n--- pkgdash load timing (PKGDASH_DEBUG_TIMING=1) ---\n")
	for _, line := range timingLines {
		b.WriteString(line)
		b.WriteByte('\n')
	}
	_, _ = os.Stdout.WriteString(b.String())
}
