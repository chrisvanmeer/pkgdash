package main

import (
	"strings"
	"testing"
	"time"
)

func TestTimingHelpers(t *testing.T) {
	oldEnabled, oldFile, oldStart := timingEnabled, timingFile, timingStart
	oldLines := timingLines
	defer func() {
		timingEnabled, timingFile, timingStart = oldEnabled, oldFile, oldStart
		timingLines = oldLines
	}()

	timingEnabled = true
	timingFile = ""
	timingStart = time.Now()
	timingLines = nil

	timingLog("event one")
	done := timingMeasure("measured event")
	time.Sleep(time.Millisecond)
	done()

	if len(timingLines) != 2 {
		t.Fatalf("got %d timing lines, want 2: %v", len(timingLines), timingLines)
	}
	if !strings.Contains(timingLines[0], "event one") {
		t.Fatalf("first line missing log: %q", timingLines[0])
	}
	if !strings.Contains(timingLines[1], "measured event") || !strings.Contains(timingLines[1], "ms") {
		t.Fatalf("second line missing measurement: %q", timingLines[1])
	}
}

func TestTimingDisabledIsNoop(t *testing.T) {
	oldEnabled, oldLines := timingEnabled, timingLines
	defer func() {
		timingEnabled, timingLines = oldEnabled, oldLines
	}()

	timingEnabled = false
	timingLines = nil
	timingLog("should not appear")
	timingMeasure("should not appear")()
	if len(timingLines) != 0 {
		t.Fatalf("timing logged while disabled: %v", timingLines)
	}
}
