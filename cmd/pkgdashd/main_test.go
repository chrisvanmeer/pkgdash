package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestComputeDiffsRecordsRemovalsForMissingHost(t *testing.T) {
	prev := map[string]map[string]string{"gone": {"bash": "5.2", "curl": "8.0"}}
	curr := map[string]map[string]string{}
	diffs := ComputeDiffs(prev, curr)
	if len(diffs) != 2 {
		t.Fatalf("got %d events, want 2: %+v", len(diffs), diffs)
	}
	for _, d := range diffs {
		if d.Action != "REMOVED" || d.Hostname != "gone" || d.NewVersion != "" {
			t.Fatalf("unexpected event: %+v", d)
		}
	}
}

func TestHistoryManagerReturnsNewestEventsOnly(t *testing.T) {
	hm := NewHistoryManager(t.TempDir())
	now := time.Now()
	events := make([]ChangeEvent, 0, 5)
	for i := 0; i < 5; i++ {
		events = append(events, ChangeEvent{
			Timestamp: now.Add(time.Duration(i) * time.Minute),
			Hostname:  "host",
			Package:   "pkg",
			Action:    "ADDED",
		})
	}
	hm.RecordChanges(events)

	got := hm.GetHistory("host", "", 2)
	if len(got) != 2 {
		t.Fatalf("got %d events, want 2", len(got))
	}
	if !got[0].Timestamp.Equal(events[4].Timestamp) || !got[1].Timestamp.Equal(events[3].Timestamp) {
		t.Fatalf("expected newest two events, got %+v", got)
	}
}

func TestHistoryManagerPreFilterCaseInsensitive(t *testing.T) {
	hm := NewHistoryManager(t.TempDir())
	now := time.Now()
	events := []ChangeEvent{
		{Timestamp: now.Add(1 * time.Minute), Hostname: "Web-01", Package: "Nginx", Action: "ADDED"},
		{Timestamp: now.Add(2 * time.Minute), Hostname: "db-02", Package: "Postgres", Action: "ADDED"},
		{Timestamp: now.Add(3 * time.Minute), Hostname: "WEB-01", Package: "Curl", Action: "MODIFIED"},
	}
	hm.RecordChanges(events)

	// The raw-line pre-filter uses ASCII case folding; the final EqualFold
	// check must still produce the same result as an unfiltered scan.
	got := hm.GetHistory("web-01", "", 10)
	if len(got) != 2 {
		t.Fatalf("got %d events for host filter, want 2: %+v", len(got), got)
	}

	got = hm.GetHistory("", "nginx", 10)
	if len(got) != 1 || got[0].Hostname != "Web-01" {
		t.Fatalf("got %+v for package filter, want the Nginx event", got)
	}

	// Non-ASCII queries bypass the pre-filter and must still work.
	hm.RecordChanges([]ChangeEvent{{Timestamp: now.Add(4 * time.Minute), Hostname: "héllo", Package: "pkg", Action: "ADDED"}})
	got = hm.GetHistory("HÉLLO", "", 10)
	if len(got) != 1 || got[0].Hostname != "héllo" {
		t.Fatalf("got %+v for non-ASCII filter, want the héllo event", got)
	}
}

func TestSystemdEnvValueEscaping(t *testing.T) {
	value := `pa$ss"word\with` + "`tick`"
	got := systemdEnvValue(value)
	want := `"pa\$ss\"word\\with\` + "`tick\\`" + `"`
	if got != want {
		t.Fatalf("systemdEnvValue(%q) = %q, want %q", value, got, want)
	}
}

func TestAcceptsGzip(t *testing.T) {
	for header, want := range map[string]bool{
		"gzip":                true,
		"br, gzip;q=0.8":      true,
		"gzip;q=0":            false,
		"deflate":             false,
		"GZIP, deflate;q=0.5": true,
	} {
		if got := acceptsGzip(header); got != want {
			t.Fatalf("acceptsGzip(%q) = %v, want %v", header, got, want)
		}
	}
}

func TestOSVCacheRoundTrip(t *testing.T) {
	activeDataPath = t.TempDir()
	osvCacheMu.Lock()
	osvCache = map[pkgKey]osvCacheEntry{
		{Name: "@scope/pkg@1", Version: "1.0", Ecosystem: "npm"}: {
			Vulnerabilities: []Vulnerability{{ID: "GHSA-1"}},
			FetchedAt:       time.Now(),
		},
	}
	osvCacheMu.Unlock()

	saveOSVCacheToDisk()
	data, err := os.ReadFile(filepath.Join(activeDataPath, "osv_cache.json"))
	if err != nil {
		t.Fatal(err)
	}
	var records []osvCacheRecord
	if err := json.Unmarshal(data, &records); err != nil {
		t.Fatal(err)
	}
	if len(records) != 1 || !strings.Contains(string(data), "@scope/pkg@1") {
		t.Fatalf("unexpected cache file: %s", data)
	}

	osvCacheMu.Lock()
	osvCache = map[pkgKey]osvCacheEntry{}
	osvCacheMu.Unlock()
	loadOSVCacheFromDisk()
	osvCacheMu.RLock()
	_, ok := osvCache[pkgKey{Name: "@scope/pkg@1", Version: "1.0", Ecosystem: "npm"}]
	osvCacheMu.RUnlock()
	if !ok {
		t.Fatal("cache entry with @ in name was not restored")
	}
}
