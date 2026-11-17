package main

import (
	"fmt"
	"strings"
	"testing"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
)

func newTestModel() model {
	m := model{
		width:         120,
		height:        40,
		ready:         true,
		visibleLines:  26,
		syncIssues:    make(map[string]string),
		updateChan:    make(chan dataMsg, 1),
		historyEvents: nil,
	}
	m.applyWindowSize(m.width, m.height)
	return m
}

func TestUpdateIgnoresStaleHistoryResponses(t *testing.T) {
	m := newTestModel()
	m.historyRequestID = 2
	m.historyLoading = true

	stale := historyDataMsg{
		requestID: 1,
		events:    []ChangeEvent{{Package: "stale-package"}},
	}
	updated, _ := m.Update(stale)
	m = updated.(model)
	if len(m.historyEvents) != 0 || !m.historyLoading {
		t.Fatalf("stale response was applied: events=%v loading=%v", m.historyEvents, m.historyLoading)
	}

	fresh := historyDataMsg{
		requestID: 2,
		events:    []ChangeEvent{{Package: "fresh-package"}},
	}
	updated, _ = m.Update(fresh)
	m = updated.(model)
	if len(m.historyEvents) != 1 || m.historyEvents[0].Package != "fresh-package" {
		t.Fatalf("fresh response was not applied: %v", m.historyEvents)
	}
	if m.historyLoading {
		t.Fatal("history still marked as loading after a matching response")
	}
}

func TestRequestHistoryTagsAndTracksRequest(t *testing.T) {
	m := newTestModel()
	cmd := m.requestHistory("host-a", "libssl")
	if cmd == nil {
		t.Fatal("requestHistory returned no command")
	}
	if m.historyRequestID != 1 || !m.historyLoading {
		t.Fatalf("request state = id %d, loading %v", m.historyRequestID, m.historyLoading)
	}
	msg := cmd().(historyDataMsg)
	if msg.requestID != 1 || msg.queryHost != "host-a" || msg.queryPkg != "libssl" {
		t.Fatalf("unexpected history command message: %+v", msg)
	}
}

func TestUpdateTracksPerDaemonFailures(t *testing.T) {
	m := newTestModel()
	var result tea.Model = m

	for _, msg := range []dataMsg{
		{server: "alpha", err: "connection refused"},
		{server: "beta", items: []FlatItem{{Hostname: "ok-host"}}},
	} {
		result, _ = result.Update(msg)
	}
	m = result.(model)
	if len(m.syncIssues) != 1 || m.syncIssues["alpha"] != "connection refused" {
		t.Fatalf("unexpected sync issues: %v", m.syncIssues)
	}
	if !strings.Contains(m.syncError, "alpha") || !strings.Contains(m.syncError, "connection refused") {
		t.Fatalf("unexpected sync error: %q", m.syncError)
	}

	result, _ = result.Update(dataMsg{server: "alpha"})
	m = result.(model)
	if len(m.syncIssues) != 0 || m.syncError != "" {
		t.Fatalf("recovered daemon was not cleared: %v / %q", m.syncIssues, m.syncError)
	}
}

func TestDataMsgDoneKeepsSyncError(t *testing.T) {
	m := newTestModel()
	var result tea.Model = m
	result, _ = result.Update(dataMsg{server: "alpha", err: "timeout"})
	result, _ = result.Update(dataMsg{isDone: true})
	m = result.(model)
	if !m.loaded {
		t.Fatal("done message did not mark model as loaded")
	}
	if !strings.Contains(m.syncError, "timeout") {
		t.Fatalf("done message dropped the sync error: %q", m.syncError)
	}
	if out := m.View(); !strings.Contains(out, "PARTIAL SYNC") {
		t.Fatal("header does not show degraded sync status")
	}
}

func TestApplyWindowSizeWhileModalOpen(t *testing.T) {
	m := newTestModel()
	m.showHistoryView = true
	m.historyEvents = make([]ChangeEvent, 30)
	for i := range m.historyEvents {
		m.historyEvents[i] = ChangeEvent{Package: fmt.Sprintf("pkg-%02d", i)}
	}
	m.historyCursor = 29
	m.applyWindowSize(120, 40)
	m.updateHistoryViewport()
	if m.visibleLines != 26 || m.historyOffset != 4 {
		t.Fatalf("large window: visible=%d offset=%d", m.visibleLines, m.historyOffset)
	}

	m.applyWindowSize(100, 20)
	m.updateHistoryViewport()
	if m.visibleLines != 6 || m.diffVisibleLines != 3 {
		t.Fatalf("resize did not refresh viewports: visible=%d diff=%d", m.visibleLines, m.diffVisibleLines)
	}
	if m.historyOffset != 24 {
		t.Fatalf("cursor scrolled out of view after resize: offset=%d", m.historyOffset)
	}
	if out := m.View(); !strings.Contains(out, "pkg-29") {
		t.Fatal("selected history row is not visible after resize")
	}
}

func TestFleetHistoryRendersFullViewport(t *testing.T) {
	m := newTestModel()
	m.showHistoryView = true
	m.visibleLines = 3
	for i := 0; i < 6; i++ {
		m.historyEvents = append(m.historyEvents, ChangeEvent{
			Timestamp: time.Date(2026, 1, i+1, 12, 0, 0, 0, time.UTC),
			Hostname:  "host-a",
			Action:    "ADDED",
			Package:   fmt.Sprintf("unique-pkg-%d", i),
		})
	}

	out := m.View()
	for _, want := range []string{"unique-pkg-0", "unique-pkg-1", "unique-pkg-2"} {
		if !strings.Contains(out, want) {
			t.Fatalf("missing %s in fleet history view", want)
		}
	}
	if strings.Contains(out, "unique-pkg-3") {
		t.Fatal("fleet history rendered more rows than fit in the viewport")
	}
}

func TestHistoryLoadingIsVisible(t *testing.T) {
	m := newTestModel()
	m.showHistoryView = true
	m.historyLoading = true
	if out := m.View(); !strings.Contains(out, "LOADING") {
		t.Fatal("loading state is not shown while history is fetched")
	}
}

func TestGetFleetInsightsSumsVulnerabilities(t *testing.T) {
	m := newTestModel()
	m.hasOSV = true
	m.filtered = []FlatItem{
		{Hostname: "a", PkgName: "libssl", Vulnerabilities: []Vulnerability{{ID: "CVE-1"}, {ID: "CVE-2"}}},
		{Hostname: "b", PkgName: "libssl", Vulnerabilities: []Vulnerability{{ID: "CVE-3"}, {ID: "CVE-4"}}},
	}
	out := m.getFleetInsights()
	if !strings.Contains(out, "4 Vulnerability/CVE(s)") {
		t.Fatalf("expected summed vulnerability count, got %q", out)
	}
	if !strings.Contains(out, "2 host(s)") {
		t.Fatalf("expected host count, got %q", out)
	}
}

func TestGetFleetInsightsCacheInvalidation(t *testing.T) {
	m := newTestModel()
	m.filtered = []FlatItem{
		{Hostname: "a", PkgName: "nginx", Version: "1.0"},
		{Hostname: "b", PkgName: "nginx", Version: "1.1"},
	}
	m.filterGen++

	first := m.getFleetInsights()
	if !strings.Contains(first, "2 host(s)") {
		t.Fatalf("unexpected initial insights: %q", first)
	}

	// Same package + same generation must return the cached value.
	m.insightsText = "SENTINEL"
	if got := m.getFleetInsights(); got != "SENTINEL" {
		t.Fatalf("cache not reused: %q", got)
	}

	// Changing the selected package must recompute.
	m.insightsText = ""
	m.filtered[0].PkgName = "other"
	if got := m.getFleetInsights(); !strings.Contains(got, "'other'") {
		t.Fatalf("package change not reflected: %q", got)
	}

	// New data (generation bump) must also recompute even for same package.
	m.insightsText = "SENTINEL2"
	m.filterGen++
	if got := m.getFleetInsights(); got == "SENTINEL2" {
		t.Fatal("generation bump did not invalidate cache")
	}
}

func TestCycleIndexWrapsInBothDirections(t *testing.T) {
	for _, tc := range []struct {
		current   int
		backwards bool
		want      int
	}{
		{current: 0, backwards: false, want: 1},
		{current: 1, backwards: false, want: 0},
		{current: 0, backwards: true, want: 1},
		{current: 1, backwards: true, want: 0},
	} {
		if got := cycleIndex(tc.current, 2, tc.backwards); got != tc.want {
			t.Errorf("cycleIndex(%d, 2, %v) = %d, want %d", tc.current, tc.backwards, got, tc.want)
		}
	}
}

func TestModalsFitNarrowTerminal(t *testing.T) {
	m := newTestModel()
	m.applyWindowSize(60, 25)

	events := []ChangeEvent{{
		Timestamp:  time.Now(),
		Hostname:   "a-very-long-hostname.example.com",
		Action:     "MODIFIED",
		Package:    "a-very-long-package-name",
		OldVersion: "1.0",
		NewVersion: "2.0",
	}}

	for name, setup := range map[string]func(*model){
		"help": func(m *model) { m.showHelpModal = true },
		"osv": func(m *model) {
			m.showOSVModal = true
			m.selectedOSVPkg = "a-very-long-package-name"
			m.selectedOSVVulns = []Vulnerability{{ID: "CVE-2026-123456", Summary: strings.Repeat("long summary ", 10)}}
		},
		"history": func(m *model) { m.showHistoryView = true; m.historyEvents = events },
		"package history": func(m *model) {
			m.showPackageHistoryModal = true
			m.packageHistoryEvents = events
		},
		"host": func(m *model) {
			m.showHostModal = true
			m.selectedHost = FlatItem{Hostname: "a-very-long-hostname.example.com", Vulnerabilities: []Vulnerability{{ID: "CVE-1"}}}
		},
		"about": func(m *model) { m.showAboutModal = true },
	} {
		t.Run(name, func(t *testing.T) {
			local := m
			setup(&local)
			for _, line := range strings.Split(local.View(), "\n") {
				if w := lipgloss.Width(line); w > local.width {
					t.Fatalf("modal line is %d columns wide in a %d-column terminal: %q", w, local.width, line)
				}
			}
		})
	}
}
