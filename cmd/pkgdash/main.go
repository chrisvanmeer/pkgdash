package main

import (
	"compress/gzip"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"runtime/debug"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/charmbracelet/bubbles/textinput"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"github.com/charmbracelet/x/ansi"

	"pkgdash-project/internal/pkgdash"
)

// ============================================================================
// CONFIGURATION & PLACEHOLDERS (Edit default filter placeholders here)
// ============================================================================
const (
	PlaceholderHost = "Filter hostname..."
	PlaceholderOS   = "Filter OS..."
	PlaceholderPkg  = "Filter package..."
	PlaceholderVer  = "Filter version..."
)

// Domain types live in the shared package so the TUI and web UI cannot drift.
type (
	Vulnerability = pkgdash.Vulnerability
	PackageInfo   = pkgdash.PackageInfo
	HostPayload   = pkgdash.HostPayload
	FlatItem      = pkgdash.FlatItem
	DiffRow       = pkgdash.DiffRow
	ChangeEvent   = pkgdash.ChangeEvent
)

type SortColumn int

const (
	SortHostname SortColumn = iota
	SortOS
	SortPackage
	SortVersion
)

// --- CYBERPUNK / TOKYO NIGHT PALETTE ---
var (
	cPurple   = lipgloss.Color("#7D56F4")
	cCyan     = lipgloss.Color("#04D9D9")
	cPink     = lipgloss.Color("#FF79C6")
	cGreen    = lipgloss.Color("#50FA7B")
	cYellow   = lipgloss.Color("#F1FA8C")
	cRed      = lipgloss.Color("#FF5555")
	cHeaderBg = lipgloss.Color("#313244")
	cMuted    = lipgloss.Color("#6C7086")
	cText     = lipgloss.Color("#CDD6F4")
	cBorder   = lipgloss.Color("#45475A")

	// --- STYLES ---
	baseStyle = lipgloss.NewStyle().Padding(0, 1)

	panelStyle = lipgloss.NewStyle().
			Border(lipgloss.RoundedBorder()).
			BorderForeground(cBorder).
			Padding(0, 1)

	headerPanelStyle = panelStyle.BorderForeground(cPurple)
	tableFrameStyle  = panelStyle

	titleBadge = lipgloss.NewStyle().
			Foreground(lipgloss.Color("#11111B")).
			Background(cPurple).
			Padding(0, 1).
			Bold(true)

	secBadge = lipgloss.NewStyle().
			Foreground(lipgloss.Color("#11111B")).
			Background(cCyan).
			Padding(0, 1).
			Bold(true)

	osvBadgeStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color("#11111B")).
			Background(cRed).
			Padding(0, 1).
			Bold(true)

	syncBadge = lipgloss.NewStyle().
			Foreground(lipgloss.Color("#11111B")).
			Background(cYellow).
			Padding(0, 1).
			Bold(true)

	readyBadge = lipgloss.NewStyle().
			Foreground(lipgloss.Color("#11111B")).
			Background(cGreen).
			Padding(0, 1).
			Bold(true)

	syncErrBadge = lipgloss.NewStyle().
			Foreground(lipgloss.Color("#11111B")).
			Background(cPink).
			Padding(0, 1).
			Bold(true)

	actionAddedBadge = lipgloss.NewStyle().
				Foreground(lipgloss.Color("#11111B")).
				Background(cGreen).
				Padding(0, 1).
				Bold(true)

	actionModifiedBadge = lipgloss.NewStyle().
				Foreground(lipgloss.Color("#11111B")).
				Background(cCyan).
				Padding(0, 1).
				Bold(true)

	actionRemovedBadge = lipgloss.NewStyle().
				Foreground(lipgloss.Color("#11111B")).
				Background(cRed).
				Padding(0, 1).
				Bold(true)

	// Severity badges for CVSS
	sevCriticalStyle = lipgloss.NewStyle().Foreground(lipgloss.Color("#FFFFFF")).Background(cRed).Bold(true).Padding(0, 1)
	sevHighStyle     = lipgloss.NewStyle().Foreground(lipgloss.Color("#11111B")).Background(lipgloss.Color("#FFB86C")).Bold(true).Padding(0, 1)
	sevMediumStyle   = lipgloss.NewStyle().Foreground(lipgloss.Color("#11111B")).Background(cYellow).Bold(true).Padding(0, 1)
	sevLowStyle      = lipgloss.NewStyle().Foreground(lipgloss.Color("#11111B")).Background(cGreen).Bold(true).Padding(0, 1)
	sevUnknownStyle  = lipgloss.NewStyle().Foreground(cText).Background(cMuted).Padding(0, 1)

	metaStyle = lipgloss.NewStyle().
			Foreground(cMuted).
			Italic(true)

	flashStyle = lipgloss.NewStyle().
			Foreground(cGreen).
			Bold(true)

	filterBoxBlurred = lipgloss.NewStyle().
				Border(lipgloss.NormalBorder()).
				BorderForeground(cBorder).
				Padding(0, 1).
				Align(lipgloss.Left)

	filterBoxFocused = filterBoxBlurred.BorderForeground(cPink)

	labelFocused = lipgloss.NewStyle().
			Foreground(cPink).
			Bold(true)

	labelBlurred = lipgloss.NewStyle().
			Foreground(cMuted)

	regexBadgeActive = lipgloss.NewStyle().
				Foreground(lipgloss.Color("#11111B")).
				Background(cPink).
				Bold(true)

	regexBadgeInactive = lipgloss.NewStyle().
				Foreground(cMuted)

	tableHeaderStyle = lipgloss.NewStyle().
				Foreground(cText).
				Background(cHeaderBg).
				Bold(true)

	rowStyleNormal = lipgloss.NewStyle().Foreground(cText)
	vulnRowStyle   = lipgloss.NewStyle().Foreground(cRed)

	selectedStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color("#11111B")).
			Background(cPink).
			Bold(true)

	selectedVulnStyle = lipgloss.NewStyle().
				Foreground(lipgloss.Color("#11111B")).
				Background(cRed).
				Bold(true)

	selectedDiffStyle = selectedStyle

	insightBoxStyle = lipgloss.NewStyle().
			Foreground(cCyan).
			Italic(true)

	footerBoxStyle = lipgloss.NewStyle().
			Border(lipgloss.RoundedBorder()).
			BorderForeground(cBorder).
			Foreground(cMuted).
			Padding(0, 1)

	modalStyle = lipgloss.NewStyle().
			Border(lipgloss.DoubleBorder()).
			BorderForeground(cPurple).
			Padding(1, 3).
			Align(lipgloss.Center)
)

func formatOSLabel(name, version string) string {
	return pkgdash.OSLabel(name, version)
}

func renderSevBadge(sev float64) string {
	if sev <= 0 {
		return sevUnknownStyle.Render("CVSS N/A")
	}
	scoreStr := fmt.Sprintf("CVSS %.1f", sev)
	switch {
	case sev >= 9.0:
		return sevCriticalStyle.Render(scoreStr)
	case sev >= 7.0:
		return sevHighStyle.Render(scoreStr)
	case sev >= 4.0:
		return sevMediumStyle.Render(scoreStr)
	default:
		return sevLowStyle.Render(scoreStr)
	}
}

type dataMsg struct {
	server    string
	items     []FlatItem
	timestamp time.Time
	isDone    bool
	hasOSV    bool
	err       string
}

type historyDataMsg struct {
	requestID uint64
	events    []ChangeEvent
	queryHost string
	queryPkg  string
}

type model struct {
	servers []string
	psk     string
	minSev  float64

	hostInput    textinput.Model
	osInput      textinput.Model
	pkgInput     textinput.Model
	verInput     textinput.Model
	focusedInput int

	allItems      []FlatItem
	filtered      []FlatItem
	filterGen     uint64 // bumped whenever filtered is replaced or extended
	insightsPkg   string
	insightsGen   uint64
	insightsText  string
	lastUpdated   time.Time
	width         int
	height        int
	ready         bool
	loaded        bool
	sortCol       SortColumn
	sortDesc      bool
	offset        int
	cursor        int
	visibleLines  int
	showOnlyVulns bool

	showHelpModal  bool
	showAboutModal bool
	showHostModal  bool
	selectedHost   FlatItem
	hostModalTab   int // 0: Overview, 1: History

	// OSV Vulnerability Scrollable Detail Modal
	showOSVModal     bool
	selectedOSVPkg   string
	selectedOSVVer   string
	selectedOSVVulns []Vulnerability
	osvModalCursor   int
	osvModalOffset   int

	// Per-Package Chronological Timeline Modal
	showPackageHistoryModal bool
	packageHistoryEvents    []ChangeEvent
	packageHistoryCursor    int
	packageHistoryOffset    int
	selectedPkgHost         string
	selectedPkgName         string

	// Fleet History (Time Travel)
	showHistoryView  bool
	historyLoading   bool
	historyRequestID uint64
	historyEvents    []ChangeEvent
	historyCursor    int
	historyOffset    int

	// Host History Events
	hostHistoryEvents []ChangeEvent
	hostHistoryCursor int
	hostHistoryOffset int

	// Diff Selection Modal
	showDiffSelectModal bool
	diffHostAInput      textinput.Model
	diffHostBInput      textinput.Model
	diffSelectFocused   int // 0: Host A, 1: Host B
	diffSelectError     string

	// Diff View Modal
	showDiffViewModal bool
	diffFilterInput   textinput.Model
	selectedHostA     string
	selectedHostB     string
	diffAllItems      []DiffRow
	diffFiltered      []DiffRow
	diffCursor        int
	diffOffset        int
	diffVisibleLines  int
	diffOnlyDiffs     bool

	flashMsg   string
	syncIssues map[string]string
	syncError  string
	updateChan chan dataMsg
	hasTLS     bool
	hasPSK     bool
	hasOSV     bool
}

var (
	apiClient         *http.Client
	historyHTTPClient *http.Client
)

// Loading a large inventory allocates hundreds of MB in a short burst. With
// the default GOGC=100 that triggers repeated stop-the-world collections (the
// 20-55 ms stalls in decode and Update). Raise the threshold for the load and
// restore it once the data is sorted and visible.
var originalGCPercent int

func main() {
	initTiming()
	defer flushTiming()
	originalGCPercent = debug.SetGCPercent(400)

	flagMinSev := flag.Float64("min-severity", -1, "Minimum CVSS severity threshold to display vulnerabilities")
	flagCAFile := flag.String("ca-file", "", "PEM file containing the CA that signed the daemon certificate")
	flagCertFile := flag.String("cert-file", "", "Client certificate for mutual TLS")
	flagKeyFile := flag.String("key-file", "", "Client key for mutual TLS")
	flagServerName := flag.String("tls-server-name", "", "Override the TLS server name (SNI and verification)")
	flagInsecure := flag.Bool("insecure-tls", false, "Disable TLS certificate verification (unsafe, use only for testing)")
	flag.Parse()

	cfg := pkgdash.LoadClientConfig()
	servers, psk, minSev := cfg.Servers, cfg.PSK, cfg.MinSeverity
	if *flagMinSev >= 0 {
		minSev = *flagMinSev
	}

	if len(servers) == 0 {
		log.Fatal("No servers found. Set PKGDASH_SERVERS or configure ~/.local/pkgdash.config")
	}

	tlsOpts := cfg.TLS
	if *flagCAFile != "" {
		tlsOpts.CAFile = *flagCAFile
	}
	if *flagCertFile != "" {
		tlsOpts.CertFile = *flagCertFile
	}
	if *flagKeyFile != "" {
		tlsOpts.KeyFile = *flagKeyFile
	}
	if *flagServerName != "" {
		tlsOpts.ServerName = *flagServerName
	}
	if *flagInsecure {
		tlsOpts.Insecure = true
	}
	tlsCfg, err := pkgdash.NewTLSConfig(tlsOpts)
	if err != nil {
		log.Fatalf("Invalid TLS configuration: %v", err)
	}
	apiClient = pkgdash.NewHTTPClient(15*time.Second, tlsCfg)
	historyHTTPClient = pkgdash.NewHTTPClient(5*time.Second, tlsCfg)

	hi := textinput.New()
	hi.Placeholder = PlaceholderHost
	hi.Prompt = ""
	hi.Focus()

	oi := textinput.New()
	oi.Placeholder = PlaceholderOS
	oi.Prompt = ""

	pi := textinput.New()
	pi.Placeholder = PlaceholderPkg
	pi.Prompt = ""

	vi := textinput.New()
	vi.Placeholder = PlaceholderVer
	vi.Prompt = ""

	diffA := textinput.New()
	diffA.Placeholder = "Type hostname or pattern for Host A..."
	diffA.Prompt = ""

	diffB := textinput.New()
	diffB.Placeholder = "Type hostname or pattern for Host B..."
	diffB.Prompt = ""

	diffF := textinput.New()
	diffF.Placeholder = "Filter compared packages..."
	diffF.Prompt = ""

	// Batches of items are sent per daemon while streaming. A generous buffer
	// lets producers keep decoding while the TUI event loop renders; a full
	// channel must not stall network decoding (that cost 2.2s for 185k rows).
	updateChan := make(chan dataMsg, 256)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	hasTLS := !tlsOpts.Insecure
	for _, s := range servers {
		if strings.HasPrefix(strings.ToLower(s), "http://") {
			hasTLS = false
		}
	}

	m := model{
		servers:         servers,
		psk:             psk,
		minSev:          minSev,
		hostInput:       hi,
		osInput:         oi,
		pkgInput:        pi,
		verInput:        vi,
		diffHostAInput:  diffA,
		diffHostBInput:  diffB,
		diffFilterInput: diffF,
		focusedInput:    0,
		sortCol:         SortHostname,
		sortDesc:        false,
		offset:          0,
		cursor:          0,
		showHelpModal:   false,
		showAboutModal:  false,
		showHostModal:   false,
		loaded:          false,
		syncIssues:      make(map[string]string),
		updateChan:      updateChan,
		hasTLS:          hasTLS,
		hasPSK:          psk != "",
		diffOnlyDiffs:   false,
		showOnlyVulns:   false,
	}

	go fetchAllDataAsync(ctx, servers, psk, minSev, updateChan)

	p := tea.NewProgram(m, tea.WithAltScreen())
	if _, err := p.Run(); err != nil {
		fmt.Printf("Error running TUI: %v\n", err)
	}
	cancel()
}

func fetchAllDataAsync(ctx context.Context, servers []string, psk string, minSev float64, updateChan chan dataMsg) {
	defer timingMeasure("fetchAllDataAsync: TOTAL")()
	var wg sync.WaitGroup
	send := func(msg dataMsg) bool {
		if !timingEnabled {
			select {
			case <-ctx.Done():
				return false
			case updateChan <- msg:
				return true
			}
		}
		start := time.Now()
		select {
		case <-ctx.Done():
			return false
		case updateChan <- msg:
			blocked := time.Since(start)
			if blocked > 5*time.Millisecond {
				timingLog("send BLOCKED %s (server=%s hosts=%d done=%v)", blocked, msg.server, len(msg.items), msg.isDone)
			}
			return true
		}
	}

	for _, s := range servers {
		wg.Add(1)
		go func(server string) {
			defer wg.Done()
			defer timingMeasure("server %s: TOTAL", server)()
			// Report failures through the UI instead of logging to stderr,
			// which would corrupt Bubble Tea's alternate screen.
			fail := func(format string, args ...any) {
				send(dataMsg{server: server, err: fmt.Sprintf(format, args...)})
			}

			url, err := pkgdash.Endpoint(server, psk, "/packages")
			if err != nil {
				fail("%v", err)
				return
			}

			req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
			if err != nil {
				fail("%v", err)
				return
			}
			req.Header.Set("Accept-Encoding", "gzip")
			if psk != "" {
				req.Header.Set("X-PSK", psk)
			}

			httpDone := timingMeasure("server %s: http.Do -> response headers", server)
			resp, err := apiClient.Do(req)
			httpDone()
			if err != nil {
				if ctx.Err() == nil {
					fail("%v", err)
				}
				return
			}
			defer func() { _ = resp.Body.Close() }()
			if resp.StatusCode != http.StatusOK {
				fail("HTTP %s", resp.Status)
				return
			}

			timingLog("server %s: HTTP %s, encoding=%q, content-length=%q", server, resp.Status, resp.Header.Get("Content-Encoding"), resp.Header.Get("Content-Length"))

			osvHeaderActive := strings.EqualFold(resp.Header.Get("X-OSV-Enabled"), "true")

			var reader io.Reader = resp.Body
			if resp.Header.Get("Content-Encoding") == "gzip" {
				gz, err := gzip.NewReader(resp.Body)
				if err == nil {
					defer func() { _ = gz.Close() }()
					reader = gz
				}
			}

			var serverMaxTime time.Time
			if lastMod := resp.Header.Get("Last-Modified"); lastMod != "" {
				if parsedTime, err := time.Parse(http.TimeFormat, lastMod); err == nil {
					serverMaxTime = parsedTime
				}
			}

			decoder := json.NewDecoder(reader)
			decodeDone := timingMeasure("server %s: decode+flatten ALL hosts", server)
			token, err := decoder.Token()
			if err != nil {
				fail("invalid response: %v", err)
				return
			}
			if delim, ok := token.(json.Delim); !ok || delim != '[' {
				fail("unexpected response payload")
				return
			}

			hostCount, itemCount := 0, 0
			const batchSize = 4000
			var batch []FlatItem
			batchHasOSV := false
			flushBatch := func() bool {
				if len(batch) == 0 {
					return true
				}
				if !send(dataMsg{
					server:    server,
					items:     batch,
					timestamp: serverMaxTime,
					hasOSV:    batchHasOSV,
				}) {
					return false
				}
				batch = nil
				batchHasOSV = false
				return true
			}

			for decoder.More() {
				hostStart := time.Now()
				var host HostPayload
				if err := decoder.Decode(&host); err != nil {
					fail("invalid host record: %v", err)
					return
				}
				if d := time.Since(hostStart); d > 20*time.Millisecond {
					timingLog("server %s: SLOW host %s decode %s (%d pkgs)", server, host.Hostname, d, len(host.Packages))
				}
				hostCount++
				itemCount += len(host.Packages)

				isOSV := osvHeaderActive || host.OSVEnabled
				batchHasOSV = batchHasOSV || isOSV
				for _, pkg := range host.Packages {
					var filteredVulns []Vulnerability
					for _, v := range pkg.Vulnerabilities {
						if minSev <= 0 || v.Severity >= minSev {
							filteredVulns = append(filteredVulns, v)
						}
					}
					batch = append(batch, FlatItem{
						Hostname:        host.Hostname,
						IPAddress:       host.IPAddress,
						OSName:          host.OSName,
						OSVersion:       host.OSVersion,
						HostFunction:    host.HostFunction,
						PkgName:         pkg.Name,
						Version:         pkg.Version,
						Arch:            pkg.Arch,
						Vulnerabilities: filteredVulns,
						OSVEnabled:      isOSV,
					})
				}

				if len(batch) >= batchSize && !flushBatch() {
					return
				}
			}
			if !flushBatch() {
				return
			}
			decodeDone()
			timingLog("server %s: decoded %d hosts / %d packages", server, hostCount, itemCount)
			// An empty but successful response clears any previous issue.
			send(dataMsg{server: server})
		}(s)
	}

	go func() {
		wg.Wait()
		timingLog("all servers finished -> sending isDone")
		send(dataMsg{isDone: true})
	}()
}

func fetchHistoryCmd(servers []string, psk string, hostname, pkgName string, requestID uint64) tea.Cmd {
	return func() tea.Msg {
		var allEvents []ChangeEvent

		for _, s := range servers {
			url, err := pkgdash.HistoryURL(s, psk, hostname, pkgName)
			if err != nil {
				continue
			}

			req, err := http.NewRequest(http.MethodGet, url, nil)
			if err != nil {
				continue
			}
			if psk != "" {
				req.Header.Set("X-PSK", psk)
			}

			resp, err := historyHTTPClient.Do(req)
			if err != nil {
				continue
			}
			if resp.StatusCode != http.StatusOK {
				_ = resp.Body.Close()
				continue
			}

			var evts []ChangeEvent
			if err := json.NewDecoder(resp.Body).Decode(&evts); err == nil {
				allEvents = append(allEvents, evts...)
			}
			_ = resp.Body.Close()
		}

		// Multi-server histories must be globally chronological, not grouped by server.
		sort.Slice(allEvents, func(i, j int) bool {
			return allEvents[i].Timestamp.Before(allEvents[j].Timestamp)
		})
		return historyDataMsg{
			requestID: requestID,
			events:    allEvents,
			queryHost: hostname,
			queryPkg:  pkgName,
		}
	}
}

func waitForUpdate(sub chan dataMsg) tea.Cmd {
	return func() tea.Msg { return <-sub }
}

// requestHistory starts a new history lookup and tags it so late responses
// from a previous request cannot overwrite the visible panel.
func (m *model) requestHistory(hostname, pkgName string) tea.Cmd {
	m.historyRequestID++
	m.historyLoading = true
	if m.syncIssues == nil {
		m.syncIssues = make(map[string]string)
	}
	return fetchHistoryCmd(m.servers, m.psk, hostname, pkgName, m.historyRequestID)
}

// updateSyncError folds the per-server failures into one header message.
func (m *model) updateSyncError() {
	if len(m.syncIssues) == 0 {
		m.syncError = ""
		return
	}
	names := make([]string, 0, len(m.syncIssues))
	for server := range m.syncIssues {
		names = append(names, server)
	}
	sort.Strings(names)
	parts := make([]string, 0, len(names))
	for _, name := range names {
		parts = append(parts, fmt.Sprintf("%s: %s", name, m.syncIssues[name]))
	}
	m.syncError = strings.Join(parts, " | ")
}

// applyWindowSize keeps every viewport in sync, including while a modal is
// open. Previously resizing only refreshed the main table.
func (m *model) applyWindowSize(w, h int) {
	m.width, m.height, m.ready = w, h, true

	m.visibleLines = h - 14
	if m.visibleLines < 1 {
		m.visibleLines = 1
	}
	m.diffVisibleLines = h - 18
	if m.diffVisibleLines < 3 {
		m.diffVisibleLines = 3
	}

	m.updateViewport()
	m.updateHistoryViewport()
	m.updateHostHistoryViewport()
	m.updatePackageHistoryViewport()
	m.updateDiffViewport()
	m.updateOSVModalViewport()
}

// cycleIndex moves through a small fixed set of tabs/inputs in either
// direction without ever wrapping to a negative index.
func cycleIndex(current, count int, backwards bool) int {
	if count <= 0 {
		return 0
	}
	if backwards {
		return (current - 1 + count) % count
	}
	return (current + 1) % count
}

// fitModalWidth caps a preferred modal width to the available terminal width
// instead of forcing a hard minimum that overflows small terminals.
func (m *model) fitModalWidth(preferred, overhead int) int {
	available := m.width - overhead
	if available < 1 {
		available = 1
	}
	if preferred > available {
		return available
	}
	return preferred
}

func (m *model) switchFocus(target int) {
	m.focusedInput = (target + 4) % 4

	m.hostInput.Blur()
	m.osInput.Blur()
	m.pkgInput.Blur()
	m.verInput.Blur()

	switch m.focusedInput {
	case 0:
		m.hostInput.Focus()
	case 1:
		m.osInput.Focus()
	case 2:
		m.pkgInput.Focus()
	case 3:
		m.verInput.Focus()
	}
}

func (m *model) sortData() {
	defer timingMeasure("TUI: sortData (%d items)", len(m.allItems))()
	fields := []pkgdash.SortField{pkgdash.SortHost, pkgdash.SortOS, pkgdash.SortPkg, pkgdash.SortVer}
	pkgdash.SortItems(m.allItems, fields[m.sortCol], m.sortDesc)
	m.filterItems()
}

func (m *model) updateViewport() {
	if len(m.filtered) == 0 {
		m.cursor = 0
		m.offset = 0
		return
	}

	if m.cursor < 0 {
		m.cursor = 0
	} else if m.cursor >= len(m.filtered) {
		m.cursor = len(m.filtered) - 1
	}

	if m.cursor < m.offset {
		m.offset = m.cursor
	} else if m.cursor >= m.offset+m.visibleLines {
		m.offset = m.cursor - m.visibleLines + 1
	}
}

func (m *model) updateHistoryViewport() {
	if len(m.historyEvents) == 0 {
		m.historyCursor = 0
		m.historyOffset = 0
		return
	}

	if m.historyCursor < 0 {
		m.historyCursor = 0
	} else if m.historyCursor >= len(m.historyEvents) {
		m.historyCursor = len(m.historyEvents) - 1
	}

	if m.historyCursor < m.historyOffset {
		m.historyOffset = m.historyCursor
	} else if m.historyCursor >= m.historyOffset+m.visibleLines {
		m.historyOffset = m.historyCursor - m.visibleLines + 1
	}
}

func (m *model) updateHostHistoryViewport() {
	if len(m.hostHistoryEvents) == 0 {
		m.hostHistoryCursor = 0
		m.hostHistoryOffset = 0
		return
	}

	if m.hostHistoryCursor < 0 {
		m.hostHistoryCursor = 0
	} else if m.hostHistoryCursor >= len(m.hostHistoryEvents) {
		m.hostHistoryCursor = len(m.hostHistoryEvents) - 1
	}

	if m.hostHistoryCursor < m.hostHistoryOffset {
		m.hostHistoryOffset = m.hostHistoryCursor
	} else if m.hostHistoryCursor >= m.hostHistoryOffset+6 {
		m.hostHistoryOffset = m.hostHistoryCursor - 6 + 1
	}
}

func (m *model) updatePackageHistoryViewport() {
	if len(m.packageHistoryEvents) == 0 {
		m.packageHistoryCursor = 0
		m.packageHistoryOffset = 0
		return
	}

	if m.packageHistoryCursor < 0 {
		m.packageHistoryCursor = 0
	} else if m.packageHistoryCursor >= len(m.packageHistoryEvents) {
		m.packageHistoryCursor = len(m.packageHistoryEvents) - 1
	}

	if m.packageHistoryCursor < m.packageHistoryOffset {
		m.packageHistoryOffset = m.packageHistoryCursor
	} else if m.packageHistoryCursor >= m.packageHistoryOffset+8 {
		m.packageHistoryOffset = m.packageHistoryCursor - 8 + 1
	}
}

func (m *model) updateOSVModalViewport() {
	if len(m.selectedOSVVulns) == 0 {
		m.osvModalCursor = 0
		m.osvModalOffset = 0
		return
	}

	if m.osvModalCursor < 0 {
		m.osvModalCursor = 0
	} else if m.osvModalCursor >= len(m.selectedOSVVulns) {
		m.osvModalCursor = len(m.selectedOSVVulns) - 1
	}

	visibleItems := 3
	if m.osvModalCursor < m.osvModalOffset {
		m.osvModalOffset = m.osvModalCursor
	} else if m.osvModalCursor >= m.osvModalOffset+visibleItems {
		m.osvModalOffset = m.osvModalCursor - visibleItems + 1
	}
}

func (m *model) getUniqueHosts() []string {
	hostMap := make(map[string]bool)
	for _, item := range m.allItems {
		if strings.TrimSpace(item.Hostname) != "" {
			hostMap[item.Hostname] = true
		}
	}
	var hosts []string
	for h := range hostMap {
		hosts = append(hosts, h)
	}
	sort.Strings(hosts)
	return hosts
}

func (m *model) getMatchedHosts(query, exclude string) []string {
	all := m.getUniqueHosts()
	var matches []string
	qLower := strings.ToLower(strings.TrimSpace(query))

	for _, h := range all {
		if exclude != "" && strings.EqualFold(h, exclude) {
			continue
		}
		if qLower == "" || strings.Contains(strings.ToLower(h), qLower) {
			matches = append(matches, h)
		}
		if len(matches) >= 4 {
			break
		}
	}
	return matches
}

func (m *model) resolveHost(query string) string {
	query = strings.TrimSpace(query)
	if query == "" {
		return ""
	}
	hosts := m.getUniqueHosts()
	for _, h := range hosts {
		if strings.EqualFold(h, query) {
			return h
		}
	}
	for _, h := range hosts {
		if strings.Contains(strings.ToLower(h), strings.ToLower(query)) {
			return h
		}
	}
	return ""
}

func saveCSV(items []FlatItem) string {
	cwd, err := os.Getwd()
	if err != nil {
		return fmt.Sprintf("Error getting directory: %v", err)
	}

	path := filepath.Join(cwd, "pkgdash_output.csv")
	file, err := os.Create(path)
	if err != nil {
		return fmt.Sprintf("Error creating file: %v", err)
	}
	defer func() { _ = file.Close() }()

	if err := pkgdash.WriteCSV(file, items); err != nil {
		return fmt.Sprintf("Error writing CSV: %v", err)
	}

	return fmt.Sprintf("✓ Exported %d records to %s", len(items), filepath.Base(path))
}

func saveInventory(items []FlatItem) string {
	if len(items) == 0 {
		return "No search results to export to inventory"
	}

	cwd, err := os.Getwd()
	if err != nil {
		return fmt.Sprintf("Error getting directory: %v", err)
	}

	path := filepath.Join(cwd, "temp_inventory.ini")
	file, err := os.Create(path)
	if err != nil {
		return fmt.Sprintf("Error creating inventory file: %v", err)
	}
	defer func() { _ = file.Close() }()

	count, err := pkgdash.WriteINI(file, items)
	if err != nil {
		return fmt.Sprintf("Error writing inventory file: %v", err)
	}
	if count == 0 {
		return "No valid hosts found in search results"
	}

	return fmt.Sprintf("✓ Exported %d host(s) to %s", count, filepath.Base(path))
}

func buildDiffData(hostA, hostB string, allItems []FlatItem) []DiffRow {
	return pkgdash.BuildDiffData(hostA, hostB, allItems)
}

func (m *model) filterDiffItems() {
	q := strings.TrimSpace(m.diffFilterInput.Value())
	matcher := createFieldMatcher(q)

	var filtered []DiffRow
	for _, item := range m.diffAllItems {
		if m.diffOnlyDiffs && !item.IsDiff {
			continue
		}
		if q == "" || matcher(item.PkgName) || matcher(item.VersionA) || matcher(item.VersionB) {
			filtered = append(filtered, item)
		}
	}
	m.diffFiltered = filtered
}

func (m *model) updateDiffViewport() {
	if len(m.diffFiltered) == 0 {
		m.diffCursor = 0
		m.diffOffset = 0
		return
	}

	if m.diffCursor < 0 {
		m.diffCursor = 0
	} else if m.diffCursor >= len(m.diffFiltered) {
		m.diffCursor = len(m.diffFiltered) - 1
	}

	if m.diffCursor < m.diffOffset {
		m.diffOffset = m.diffCursor
	} else if m.diffCursor >= m.diffOffset+m.diffVisibleLines {
		m.diffOffset = m.diffCursor - m.diffVisibleLines + 1
	}
}

func (m model) Init() tea.Cmd {
	return tea.Batch(textinput.Blink, waitForUpdate(m.updateChan))
}

func (m model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	var cmd tea.Cmd

	switch msg := msg.(type) {
	case dataMsg:
		defer timingMeasure("TUI: Update dataMsg (server=%s hosts=%d done=%v)", msg.server, len(msg.items), msg.isDone)()
		if msg.hasOSV {
			m.hasOSV = true
		}
		if msg.server != "" {
			if m.syncIssues == nil {
				m.syncIssues = make(map[string]string)
			}
			if msg.err != "" {
				m.syncIssues[msg.server] = msg.err
			} else {
				delete(m.syncIssues, msg.server)
			}
			m.updateSyncError()
		}
		if msg.isDone {
			m.loaded = true
			m.updateSyncError()
			m.sortData()
			m.updateViewport()
			var gcStats debug.GCStats
			debug.ReadGCStats(&gcStats)
			timingLog("after load: %d GCs, total GC pause %s",
				gcStats.NumGC, gcStats.PauseTotal.Truncate(time.Millisecond))
			debug.SetGCPercent(originalGCPercent)
			return m, nil
		}

		// The first chunk tells us roughly how many batches to expect. Growing
		// allItems with Go's default doubling caused 8-16 MB memcpy stalls on
		// large inventories; pre-size once from the first chunk instead.
		if m.allItems == nil && len(msg.items) > 0 {
			m.allItems = make([]FlatItem, 0, len(msg.items)*64)
		}
		appendDone := timingMeasure("TUI:   append chunk (n=%d cap=%d)", len(msg.items), cap(m.allItems))
		m.allItems = append(m.allItems, msg.items...)
		appendDone()
		m.filterGen++
		if msg.timestamp.After(m.lastUpdated) {
			m.lastUpdated = msg.timestamp
		}

		// Filter only the newly arrived chunk. Before this, every chunk
		// re-filtered the entire inventory, which became O(N²) for large
		// inventories with an active search query.
		if m.hostInput.Value() == "" && m.osInput.Value() == "" &&
			m.pkgInput.Value() == "" && m.verInput.Value() == "" && !m.showOnlyVulns {
			m.filtered = m.allItems
		} else {
			m.filtered = pkgdash.FilterAppend(
				m.filtered,
				msg.items,
				m.hostInput.Value(),
				m.osInput.Value(),
				m.pkgInput.Value(),
				m.verInput.Value(),
				m.showOnlyVulns,
			)
		}
		m.updateViewport()

		return m, waitForUpdate(m.updateChan)

	case historyDataMsg:
		if msg.requestID != m.historyRequestID {
			return m, nil
		}
		m.historyLoading = false
		if msg.queryPkg != "" {
			m.packageHistoryEvents = msg.events
			m.selectedPkgHost = msg.queryHost
			m.selectedPkgName = msg.queryPkg
			m.packageHistoryCursor = 0
			m.packageHistoryOffset = 0
			m.showPackageHistoryModal = true
		} else if msg.queryHost != "" {
			m.hostHistoryEvents = msg.events
			m.hostHistoryCursor = 0
			m.hostHistoryOffset = 0
		} else {
			m.historyEvents = msg.events
			m.historyCursor = 0
			m.historyOffset = 0
		}
		return m, nil
	}

	// 0. Keyboard Shortcuts Help Modal
	if m.showHelpModal {
		switch msg := msg.(type) {
		case tea.KeyMsg:
			switch msg.String() {
			case "esc", "enter", "ctrl+c", "f1", "q":
				m.showHelpModal = false
				return m, nil
			}
		case tea.WindowSizeMsg:
			m.applyWindowSize(msg.Width, msg.Height)
		}
		return m, nil
	}

	// 1. OSV Vulnerability Detail Modal
	if m.showOSVModal {
		switch msg := msg.(type) {
		case tea.KeyMsg:
			switch msg.String() {
			case "esc", "enter", "ctrl+c", "ctrl+a", "q":
				m.showOSVModal = false
				return m, nil

			case "up", "ctrl+k", "k":
				m.osvModalCursor--
				m.updateOSVModalViewport()
				return m, nil

			case "down", "ctrl+j", "j":
				m.osvModalCursor++
				m.updateOSVModalViewport()
				return m, nil

			case "pgup":
				m.osvModalCursor -= 3
				m.updateOSVModalViewport()
				return m, nil

			case "pgdown":
				m.osvModalCursor += 3
				m.updateOSVModalViewport()
				return m, nil
			}
		case tea.WindowSizeMsg:
			m.applyWindowSize(msg.Width, msg.Height)
		}
		return m, nil
	}

	// 2. Per-Package Chronological History Modal
	if m.showPackageHistoryModal {
		switch msg := msg.(type) {
		case tea.KeyMsg:
			switch msg.String() {
			case "esc", "enter", "ctrl+c":
				m.showPackageHistoryModal = false
				return m, nil

			case "up", "ctrl+k":
				m.packageHistoryCursor--
				m.updatePackageHistoryViewport()
				return m, nil

			case "down", "ctrl+j":
				m.packageHistoryCursor++
				m.updatePackageHistoryViewport()
				return m, nil
			}
		case tea.WindowSizeMsg:
			m.applyWindowSize(msg.Width, msg.Height)
		}
		return m, nil
	}

	// 3. Fleet History (Time Travel) View (Ctrl+Y)
	if m.showHistoryView {
		switch msg := msg.(type) {
		case tea.KeyMsg:
			switch msg.String() {
			case "esc", "ctrl+y":
				m.showHistoryView = false
				return m, nil

			case "enter":
				if len(m.historyEvents) > 0 && m.historyCursor < len(m.historyEvents) {
					evt := m.historyEvents[m.historyCursor]
					return m, m.requestHistory(evt.Hostname, evt.Package)
				}
				return m, nil

			case "up", "ctrl+k":
				m.historyCursor--
				m.updateHistoryViewport()
				return m, nil

			case "down", "ctrl+j":
				m.historyCursor++
				m.updateHistoryViewport()
				return m, nil

			case "pgup":
				m.historyCursor -= m.visibleLines
				m.updateHistoryViewport()
				return m, nil

			case "pgdown":
				m.historyCursor += m.visibleLines
				m.updateHistoryViewport()
				return m, nil
			}

		case tea.WindowSizeMsg:
			m.applyWindowSize(msg.Width, msg.Height)
		}
		return m, nil
	}

	// 4. About or Host Detail Modals
	if m.showAboutModal || m.showHostModal {
		switch msg := msg.(type) {
		case tea.KeyMsg:
			switch msg.String() {
			case "esc", "ctrl+c":
				m.showAboutModal = false
				m.showHostModal = false
				return m, nil

			case "ctrl+a":
				if m.showHostModal && len(m.selectedHost.Vulnerabilities) > 0 {
					m.selectedOSVPkg = m.selectedHost.PkgName
					m.selectedOSVVer = m.selectedHost.Version
					m.selectedOSVVulns = m.selectedHost.Vulnerabilities
					m.osvModalCursor = 0
					m.osvModalOffset = 0
					m.showOSVModal = true
				}
				return m, nil

			case "enter":
				if m.showAboutModal {
					m.showAboutModal = false
				} else if m.showHostModal && m.hostModalTab == 1 {
					if len(m.hostHistoryEvents) > 0 && m.hostHistoryCursor < len(m.hostHistoryEvents) {
						evt := m.hostHistoryEvents[m.hostHistoryCursor]
						return m, m.requestHistory(evt.Hostname, evt.Package)
					}
				} else {
					m.showHostModal = false
				}
				return m, nil

			case "tab", "shift+tab":
				if m.showHostModal {
					m.hostModalTab = cycleIndex(m.hostModalTab, 2, msg.String() == "shift+tab")
					if m.hostModalTab == 1 && len(m.hostHistoryEvents) == 0 {
						return m, m.requestHistory(m.selectedHost.Hostname, "")
					}
				}
				return m, nil

			case "up", "ctrl+k":
				if m.showHostModal && m.hostModalTab == 1 {
					m.hostHistoryCursor--
					m.updateHostHistoryViewport()
				}
				return m, nil

			case "down", "ctrl+j":
				if m.showHostModal && m.hostModalTab == 1 {
					m.hostHistoryCursor++
					m.updateHostHistoryViewport()
				}
				return m, nil
			}
		case tea.WindowSizeMsg:
			m.applyWindowSize(msg.Width, msg.Height)
		}
		return m, nil
	}

	// 5. Diff Selection Modal
	if m.showDiffSelectModal {
		switch msg := msg.(type) {
		case tea.KeyMsg:
			switch msg.String() {
			case "esc", "ctrl+c":
				m.showDiffSelectModal = false
				return m, nil

			case "tab", "shift+tab":
				m.diffSelectFocused = cycleIndex(m.diffSelectFocused, 2, msg.String() == "shift+tab")
				if m.diffSelectFocused == 0 {
					m.diffHostAInput.Focus()
					m.diffHostBInput.Blur()
				} else {
					m.diffHostAInput.Blur()
					m.diffHostBInput.Focus()
				}
				return m, nil

			case "enter":
				hostA := m.resolveHost(m.diffHostAInput.Value())
				hostB := m.resolveHost(m.diffHostBInput.Value())

				if hostA == "" {
					matchesA := m.getMatchedHosts(m.diffHostAInput.Value(), "")
					if len(matchesA) > 0 {
						hostA = matchesA[0]
					}
				}
				if hostB == "" {
					matchesB := m.getMatchedHosts(m.diffHostBInput.Value(), hostA)
					if len(matchesB) > 0 {
						hostB = matchesB[0]
					}
				}

				if hostA == "" {
					m.diffSelectError = fmt.Sprintf("Host A '%s' not found in fleet", m.diffHostAInput.Value())
					return m, nil
				}
				if hostB == "" {
					m.diffSelectError = fmt.Sprintf("Host B '%s' not found in fleet", m.diffHostBInput.Value())
					return m, nil
				}
				if strings.EqualFold(hostA, hostB) {
					m.diffSelectError = "Host A and Host B must be different servers!"
					return m, nil
				}

				m.selectedHostA = hostA
				m.selectedHostB = hostB
				m.diffAllItems = buildDiffData(hostA, hostB, m.allItems)
				m.diffFilterInput.SetValue("")
				m.diffFilterInput.Focus()
				m.diffOnlyDiffs = false
				m.filterDiffItems()
				m.diffCursor = 0
				m.diffOffset = 0

				m.showDiffSelectModal = false
				m.showDiffViewModal = true
				return m, nil
			}

		case tea.WindowSizeMsg:
			m.applyWindowSize(msg.Width, msg.Height)
		}

		if m.diffSelectFocused == 0 {
			m.diffHostAInput, cmd = m.diffHostAInput.Update(msg)
		} else {
			m.diffHostBInput, cmd = m.diffHostBInput.Update(msg)
		}
		return m, cmd
	}

	// 6. Diff View Modal
	if m.showDiffViewModal {
		switch msg := msg.(type) {
		case tea.KeyMsg:
			switch msg.String() {
			case "esc", "ctrl+c":
				m.showDiffViewModal = false
				return m, nil

			case "ctrl+t", "ctrl+d":
				m.diffOnlyDiffs = !m.diffOnlyDiffs
				m.filterDiffItems()
				m.diffCursor = 0
				m.diffOffset = 0
				m.updateDiffViewport()
				return m, nil

			case "up", "ctrl+k":
				m.diffCursor--
				m.updateDiffViewport()
				return m, nil

			case "down", "ctrl+j":
				m.diffCursor++
				m.updateDiffViewport()
				return m, nil

			case "pgup":
				m.diffCursor -= m.diffVisibleLines
				m.updateDiffViewport()
				return m, nil

			case "pgdown":
				m.diffCursor += m.diffVisibleLines
				m.updateDiffViewport()
				return m, nil
			}

		case tea.WindowSizeMsg:
			m.applyWindowSize(msg.Width, msg.Height)
		}

		prevQuery := m.diffFilterInput.Value()
		m.diffFilterInput, cmd = m.diffFilterInput.Update(msg)
		if m.diffFilterInput.Value() != prevQuery {
			m.filterDiffItems()
			m.diffCursor = 0
			m.updateDiffViewport()
		}

		return m, cmd
	}

	// 7. Main View Keyboard Navigation
	switch msg := msg.(type) {
	case tea.KeyMsg:
		if msg.String() != "ctrl+s" && msg.String() != "ctrl+e" && msg.String() != "ctrl+a" && msg.String() != "ctrl+u" {
			m.flashMsg = ""
		}

		switch msg.String() {
		case "f1":
			m.showHelpModal = true
			return m, nil

		case "esc":
			return m, tea.Quit
		case "ctrl+u":
			if !m.hasOSV {
				m.flashMsg = "OSV integration disabled on daemon"
				return m, nil
			}
			m.showOnlyVulns = !m.showOnlyVulns
			m.filterItems()
			m.cursor = 0
			m.updateViewport()
			if m.showOnlyVulns {
				m.flashMsg = "Filter active: vulnerable packages only"
			} else {
				m.flashMsg = "Showing all packages"
			}
			return m, nil

		case "ctrl+a":
			if len(m.filtered) > 0 && m.cursor < len(m.filtered) {
				item := m.filtered[m.cursor]
				if len(item.Vulnerabilities) > 0 {
					m.selectedOSVPkg = item.PkgName
					m.selectedOSVVer = item.Version
					m.selectedOSVVulns = item.Vulnerabilities
					m.osvModalCursor = 0
					m.osvModalOffset = 0
					m.showOSVModal = true
				} else if !item.OSVEnabled && !m.hasOSV {
					m.flashMsg = "OSV integration disabled on daemon"
				} else {
					m.flashMsg = "No vulnerabilities detected for this package"
				}
			}
			return m, nil

		case "enter":
			if len(m.filtered) > 0 && m.cursor < len(m.filtered) {
				m.selectedHost = m.filtered[m.cursor]
				m.showHostModal = true
				m.hostModalTab = 0
				m.hostHistoryEvents = nil
			}
			return m, nil
		case "ctrl+c":
			m.showAboutModal = true
			return m, nil
		case "ctrl+y":
			m.showHistoryView = true
			return m, m.requestHistory("", "")
		case "ctrl+s":
			m.flashMsg = saveCSV(m.filtered)
			return m, nil
		case "ctrl+e":
			m.flashMsg = saveInventory(m.filtered)
			return m, nil
		case "ctrl+d":
			if len(m.allItems) == 0 {
				m.flashMsg = "No host data available to compare"
				return m, nil
			}
			m.showDiffSelectModal = true
			m.diffSelectError = ""
			m.diffSelectFocused = 0

			if len(m.filtered) > 0 && m.cursor < len(m.filtered) {
				m.diffHostAInput.SetValue(m.filtered[m.cursor].Hostname)
				m.diffHostBInput.SetValue("")
				m.diffSelectFocused = 1
				m.diffHostAInput.Blur()
				m.diffHostBInput.Focus()
			} else {
				m.diffHostAInput.SetValue("")
				m.diffHostBInput.SetValue("")
				m.diffHostAInput.Focus()
				m.diffHostBInput.Blur()
			}
			return m, nil

		case "tab":
			m.switchFocus(m.focusedInput + 1)
			return m, nil
		case "shift+tab":
			m.switchFocus(m.focusedInput - 1)
			return m, nil

		case "up", "ctrl+k":
			m.cursor--
			m.updateViewport()
			return m, nil

		case "down", "ctrl+j":
			m.cursor++
			m.updateViewport()
			return m, nil

		case "pgup":
			m.cursor -= m.visibleLines
			m.updateViewport()
			return m, nil

		case "pgdown":
			m.cursor += m.visibleLines
			m.updateViewport()
			return m, nil

		case "ctrl+o":
			if m.sortCol == SortOS {
				m.sortDesc = !m.sortDesc
			} else {
				m.sortCol = SortOS
				m.sortDesc = false
			}
			m.sortData()
			m.cursor = 0
			m.updateViewport()
			return m, nil

		case "ctrl+h":
			if m.sortCol == SortHostname {
				m.sortDesc = !m.sortDesc
			} else {
				m.sortCol = SortHostname
				m.sortDesc = false
			}
			m.sortData()
			m.cursor = 0
			m.updateViewport()
			return m, nil

		case "ctrl+p":
			if m.sortCol == SortPackage {
				m.sortDesc = !m.sortDesc
			} else {
				m.sortCol = SortPackage
				m.sortDesc = false
			}
			m.sortData()
			m.cursor = 0
			m.updateViewport()
			return m, nil

		case "ctrl+v":
			if m.sortCol == SortVersion {
				m.sortDesc = !m.sortDesc
			} else {
				m.sortCol = SortVersion
				m.sortDesc = false
			}
			m.sortData()
			m.cursor = 0
			m.updateViewport()
			return m, nil
		}

	case tea.WindowSizeMsg:
		m.applyWindowSize(msg.Width, msg.Height)
	}

	var hPrev, oPrev, pPrev, vPrev string
	hPrev = m.hostInput.Value()
	oPrev = m.osInput.Value()
	pPrev = m.pkgInput.Value()
	vPrev = m.verInput.Value()

	switch m.focusedInput {
	case 0:
		m.hostInput, cmd = m.hostInput.Update(msg)
	case 1:
		m.osInput, cmd = m.osInput.Update(msg)
	case 2:
		m.pkgInput, cmd = m.pkgInput.Update(msg)
	case 3:
		m.verInput, cmd = m.verInput.Update(msg)
	}

	if m.hostInput.Value() != hPrev || m.osInput.Value() != oPrev || m.pkgInput.Value() != pPrev || m.verInput.Value() != vPrev {
		m.filterItems()
		m.cursor = 0
		m.updateViewport()
	}

	return m, cmd
}

func (m *model) filterItems() {
	defer timingMeasure("TUI: filterItems (%d items)", len(m.allItems))()
	m.filtered = pkgdash.Filter(
		m.allItems,
		m.hostInput.Value(),
		m.osInput.Value(),
		m.pkgInput.Value(),
		m.verInput.Value(),
		m.showOnlyVulns,
	)
	m.filterGen++
}

func createFieldMatcher(query string) func(string) bool {
	return pkgdash.NewMatcher(query)
}

func isLikelyRegex(query string) bool {
	return pkgdash.IsLikelyRegex(query)
}

func (m *model) getFleetInsights() string {
	if len(m.filtered) == 0 || m.cursor >= len(m.filtered) {
		return ""
	}

	selectedPkg := m.filtered[m.cursor].PkgName
	// This runs on every render. Scanning all rows with EqualFold was the
	// dominant cost during streaming load (and on every keystroke). Cache the
	// result until the filtered data or the selected package changes.
	if m.insightsPkg == selectedPkg && m.insightsGen == m.filterGen {
		return m.insightsText
	}

	hostMap := make(map[string]bool)
	versionMap := make(map[string]bool)
	vulnCount := 0

	for _, item := range m.filtered {
		if strings.EqualFold(item.PkgName, selectedPkg) {
			hostMap[item.Hostname] = true
			versionMap[item.Version] = true
			vulnCount += len(item.Vulnerabilities)
		}
	}

	isFiltered := len(m.filtered) < len(m.allItems)
	filterTag := ""
	if isFiltered {
		filterTag = " (filtered search results)"
	}

	vulnText := ""
	if m.hasOSV && vulnCount > 0 {
		vulnText = fmt.Sprintf(" ⚠️ %d Vulnerability/CVE(s) flagged across those hosts", vulnCount)
	}

	m.insightsPkg = selectedPkg
	m.insightsGen = m.filterGen
	m.insightsText = fmt.Sprintf("📊 Fleet Insights%s: '%s' is present on %d host(s) across %d unique version(s)%s",
		filterTag, selectedPkg, len(hostMap), len(versionMap), vulnText)
	return m.insightsText
}

func renderActionBadge(action string) string {
	switch strings.ToUpper(action) {
	case "ADDED":
		return actionAddedBadge.Render(" + ADDED ")
	case "MODIFIED":
		return actionModifiedBadge.Render(" ~ MODIFIED ")
	case "REMOVED":
		return actionRemovedBadge.Render(" - REMOVED ")
	default:
		return actionModifiedBadge.Render(" " + action + " ")
	}
}

// truncate limits text to a visual column width. Emojis and ANSI styling must
// not make a cell wider than its allocated columns, otherwise joined panels
// drift out of alignment.
func truncate(str string, maxLen int) string {
	if maxLen <= 0 {
		return ""
	}
	tail := "..."
	if maxLen < len(tail) {
		tail = strings.Repeat(".", maxLen)
	}
	return ansi.Truncate(str, maxLen, tail)
}

// modalHelpText keeps a long keyboard hint from widening a dialog beyond the
// terminal. All modals are rendered inside a border plus three columns of
// padding, so this leaves a comfortable margin.
func (m *model) modalHelpText(text string) string {
	width := m.width - 14
	if width < 1 {
		width = 1
	}
	return lipgloss.NewStyle().Foreground(cMuted).Render(truncate(text, width))
}

// distributeWidths splits a total width over relative weights, keeping a minimum
// width per column and handing out rounding leftovers so the sum stays exactly
// equal to total. This keeps the filter cards aligned with the other panels.
func distributeWidths(total int, weights []float64, minWidth int) []int {
	widths := make([]int, len(weights))
	if len(weights) == 0 {
		return widths
	}

	evenSplit := func() []int {
		base := total / len(weights)
		for i := range widths {
			widths[i] = base
		}
		for i := 0; i < total%len(weights); i++ {
			widths[i]++
		}
		return widths
	}

	sum := 0.0
	for _, w := range weights {
		sum += w
	}
	if total < minWidth*len(weights) || sum <= 0 {
		return evenSplit()
	}

	remaining := total - minWidth*len(weights)
	assigned := 0
	for i, w := range weights {
		extra := int(float64(remaining) * w / sum)
		widths[i] = minWidth + extra
		assigned += extra
	}
	for i := 0; assigned < remaining; i = (i + 1) % len(widths) {
		widths[i]++
		assigned++
	}
	return widths
}

func (m model) View() (view string) {
	viewStart := time.Now()
	defer func() {
		if d := time.Since(viewStart); d > 20*time.Millisecond {
			timingLog("TUI: SLOW View %s (%d visible rows)", d, m.visibleLines)
		}
	}()
	if !m.ready {
		return "Initializing Dashboard..."
	}

	// 0. Keyboard Shortcuts Help Modal
	if m.showHelpModal {
		modalWidth := m.fitModalWidth(74, 12)

		titleBar := titleBadge.Render(" ⌨️ KEYBOARD SHORTCUTS ")

		keyDescWidths := distributeWidths(modalWidth-4, []float64{0.32, 0.68}, 6)
		colKeyW, colDescW := keyDescWidths[0], keyDescWidths[1]

		hdrKey := tableHeaderStyle.Width(colKeyW).MaxWidth(colKeyW).Render(" SHORTCUT")
		hdrDesc := tableHeaderStyle.Width(colDescW).MaxWidth(colDescW).Render(" ACTION / DESCRIPTION")
		tableHdr := lipgloss.JoinHorizontal(lipgloss.Left, hdrKey, hdrDesc)

		type shortcutItem struct {
			key   string
			desc  string
			isCat bool
		}

		shortcuts := []shortcutItem{
			{key: "NAVIGATION & SORTING", isCat: true},
			{key: "Tab / Shift+Tab", desc: "Switch search input field"},
			{key: "▲ / ▼  (Ctrl+K/J)", desc: "Navigate table rows"},
			{key: "PgUp / PgDown", desc: "Scroll full page"},
			{key: "Ctrl+H / P / O / V", desc: "Sort by Host / Package / OS / Version"},

			{key: "VIEWS & MODALS", isCat: true},
			{key: "Enter", desc: "Open Host overview & change history"},
			{key: "Ctrl+A", desc: "Open OSV Security Advisory"},
			{key: "Ctrl+Y", desc: "Open Fleet Audit Log (Timeline)"},
			{key: "Ctrl+D", desc: "Compare host packages (Diff tool)"},
			{key: "Ctrl+C", desc: "About Pkgdash Control Center"},

			{key: "FILTERS & EXPORT", isCat: true},
			{key: "Ctrl+U", desc: "Toggle Vulnerable-only filter"},
			{key: "Ctrl+S", desc: "Export search results to CSV"},
			{key: "Ctrl+E", desc: "Export host list to Ansible INI"},
			{key: "F1", desc: "Show this shortcuts menu"},
			{key: "Esc", desc: "Close modal / Quit application"},
		}

		var lines []string
		lines = append(lines, tableHdr)

		for _, s := range shortcuts {
			if s.isCat {
				catStr := lipgloss.NewStyle().Foreground(cPink).Bold(true).Render(" ❯ " + s.key)
				lines = append(lines, catStr)
			} else {
				kStr := lipgloss.NewStyle().Foreground(cCyan).Bold(true).Width(colKeyW).MaxWidth(colKeyW).Render(" " + s.key)
				dStr := rowStyleNormal.Width(colDescW).MaxWidth(colDescW).Render(s.desc)
				lines = append(lines, lipgloss.JoinHorizontal(lipgloss.Left, kStr, dStr))
			}
		}

		body := strings.Join(lines, "\n")
		frame := panelStyle.BorderForeground(cPurple).Width(modalWidth + 2).Render(body)
		helpText := m.modalHelpText("[Press Esc / Enter / F1 to close]")

		content := lipgloss.JoinVertical(lipgloss.Center,
			titleBar,
			"",
			frame,
			"",
			helpText,
		)

		dialog := modalStyle.Render(content)
		return lipgloss.Place(m.width, m.height, lipgloss.Center, lipgloss.Center, dialog)
	}

	// 1. OSV Vulnerability Detail Modal (Strictly Bounded Width)
	if m.showOSVModal {
		modalContentWidth := m.fitModalWidth(80, 24)

		titleBar := titleBadge.Render(fmt.Sprintf(" 🛡 OSV ADVISORY: %s (%s) ", m.selectedOSVPkg, m.selectedOSVVer))

		start := m.osvModalOffset
		end := m.osvModalOffset + 3
		if end > len(m.selectedOSVVulns) {
			end = len(m.selectedOSVVulns)
		}

		viewport := m.selectedOSVVulns[start:end]

		var detailLines []string
		detailLines = append(detailLines, labelFocused.Render(fmt.Sprintf("Showing %d-%d of %d vulnerability record(s):", start+1, end, len(m.selectedOSVVulns))))
		detailLines = append(detailLines, "")

		for i, v := range viewport {
			absIdx := start + i
			isSelected := absIdx == m.osvModalCursor

			cveStr := v.ID
			if len(v.CVE) > 0 {
				cveStr += " (" + strings.Join(v.CVE, ", ") + ")"
			}

			lblStyle := labelFocused
			valStyle := rowStyleNormal
			if isSelected {
				lblStyle = selectedStyle
				valStyle = selectedStyle
			}

			prefix := "  "
			if isSelected {
				prefix = "❯ "
			}

			cleanURL := strings.Replace(v.URL, "https://osv.dev/vulnerabilities/", "https://osv.dev/vulnerability/", 1)
			sevBadgeStr := renderSevBadge(v.Severity)

			detailLines = append(detailLines, lipgloss.JoinHorizontal(lipgloss.Left, lblStyle.Render(prefix+"ID/CVE:  "), lipgloss.NewStyle().Foreground(cRed).Bold(true).Render(cveStr), "  ", sevBadgeStr))
			if v.Summary != "" {
				detailLines = append(detailLines, lipgloss.JoinHorizontal(lipgloss.Left, lblStyle.Render("  Summary: "), valStyle.Render(truncate(v.Summary, modalContentWidth-12))))
			}
			if v.Details != "" {
				detailLines = append(detailLines, lipgloss.JoinHorizontal(lipgloss.Left, lblStyle.Render("  Details: "), valStyle.Render(truncate(v.Details, modalContentWidth-12))))
			}
			if cleanURL != "" {
				detailLines = append(detailLines, lipgloss.JoinHorizontal(lipgloss.Left, lblStyle.Render("  Link:    "), lipgloss.NewStyle().Foreground(cCyan).Underline(true).Render(truncate(cleanURL, modalContentWidth-12))))
			}
			detailLines = append(detailLines, "")
		}

		body := lipgloss.JoinVertical(lipgloss.Left, detailLines...)
		frame := panelStyle.BorderForeground(cRed).Width(modalContentWidth).Render(body)

		helpText := m.modalHelpText("[▲/▼ / PgUp/PgDown] Scroll Advisories  |  [Esc / Enter] Close Pop-up")

		content := lipgloss.JoinVertical(lipgloss.Center,
			titleBar,
			"",
			frame,
			"",
			helpText,
		)

		dialog := modalStyle.Render(content)
		return lipgloss.Place(m.width, m.height, lipgloss.Center, lipgloss.Center, dialog)
	}

	// 2. Per-Package Chronological Timeline Modal
	if m.showPackageHistoryModal {
		innerWidth := m.fitModalWidth(94, 14)

		titleBar := titleBadge.Render(fmt.Sprintf(" 📦 PACKAGE TIMELINE: %s on %s ", m.selectedPkgName, m.selectedPkgHost))

		colTimeW, colActionW := 18, 13
		if innerWidth < 45 {
			colTimeW, colActionW = 10, 9
		}
		colVerW := innerWidth - colTimeW - colActionW
		if colVerW < 4 {
			colVerW = 4
		}

		hdrTime := tableHeaderStyle.Width(colTimeW).MaxWidth(colTimeW).Render(" TIMESTAMP")
		hdrAction := tableHeaderStyle.Width(colActionW).MaxWidth(colActionW).Render(" ACTION")
		hdrVer := tableHeaderStyle.Width(colVerW).MaxWidth(colVerW).Render(" VERSION CHANGE")

		tableHdr := lipgloss.JoinHorizontal(lipgloss.Left, hdrTime, hdrAction, hdrVer)

		start := m.packageHistoryOffset
		end := m.packageHistoryOffset + 8
		if end > len(m.packageHistoryEvents) {
			end = len(m.packageHistoryEvents)
		}

		var rowStrs []string
		if len(m.packageHistoryEvents) == 0 {
			rowStrs = append(rowStrs, lipgloss.NewStyle().Foreground(cMuted).Italic(true).Render(" No changes recorded for this package."))
		} else {
			viewport := m.packageHistoryEvents[start:end]
			for i, evt := range viewport {
				absIndex := start + i
				isSelected := absIndex == m.packageHistoryCursor

				timeStr := " " + evt.Timestamp.Local().Format("2006-01-02 15:04:05")
				badgeStr := renderActionBadge(evt.Action)

				var verDetail string
				switch evt.Action {
				case "MODIFIED":
					verDetail = fmt.Sprintf(" %s -> %s", evt.OldVersion, evt.NewVersion)
				case "ADDED":
					verDetail = " " + evt.NewVersion
				default:
					verDetail = " " + evt.OldVersion
				}

				if isSelected {
					cTime := selectedStyle.Width(colTimeW).MaxWidth(colTimeW).Render(truncate(timeStr, colTimeW))
					cBadge := badgeStr
					cVer := selectedStyle.Width(colVerW).MaxWidth(colVerW).Render(truncate(verDetail, colVerW))

					rowStrs = append(rowStrs, lipgloss.JoinHorizontal(lipgloss.Left, cTime, cBadge, cVer))
				} else {
					cTime := rowStyleNormal.Width(colTimeW).MaxWidth(colTimeW).Render(truncate(timeStr, colTimeW))
					cBadge := badgeStr
					cVer := lipgloss.NewStyle().Foreground(cMuted).Width(colVerW).MaxWidth(colVerW).Render(truncate(verDetail, colVerW))

					rowStrs = append(rowStrs, lipgloss.JoinHorizontal(lipgloss.Left, cTime, cBadge, cVer))
				}
			}
		}

		for i := len(rowStrs); i < 8; i++ {
			rowStrs = append(rowStrs, "")
		}

		historyBody := lipgloss.JoinVertical(lipgloss.Left, tableHdr, strings.Join(rowStrs, "\n"))
		frame := panelStyle.BorderForeground(cPurple).Width(innerWidth + 4).Render(historyBody)

		helpText := m.modalHelpText("[▲/▼] Scroll  |  [Esc / Enter] Back to Previous View")

		content := lipgloss.JoinVertical(lipgloss.Center,
			titleBar,
			"",
			frame,
			"",
			helpText,
		)

		dialog := modalStyle.Render(content)
		return lipgloss.Place(m.width, m.height, lipgloss.Center, lipgloss.Center, dialog)
	}

	// 3. About Modal
	if m.showAboutModal {
		modalContent := lipgloss.JoinVertical(lipgloss.Center,
			titleBadge.Render(" PKGDASH CONTROL CENTER "),
			"",
			"Designed & Developed by Chris van Meer",
			"High-Performance Infrastructure Monitor",
			"",
			fmt.Sprintf("© %d • All rights reserved", time.Now().Year()),
			"",
			lipgloss.NewStyle().Foreground(cMuted).Render("[Press Esc / Enter / Ctrl+C to close]"),
		)
		dialog := modalStyle.Render(modalContent)
		return lipgloss.Place(m.width, m.height, lipgloss.Center, lipgloss.Center, dialog)
	}

	// 4. Fleet History View (Ctrl+Y)
	if m.showHistoryView {
		innerWidth := m.fitModalWidth(110, 14)

		titleBar := titleBadge.Render(" 📜 FLEET AUDIT LOG / TIME TRAVEL ")
		if m.historyLoading {
			titleBar += " " + syncBadge.Render(" ⏳ LOADING ")
		}

		historyCols := distributeWidths(innerWidth, []float64{0.18, 0.27, 0.14, 0.24, 0.17}, 5)
		colTimeW, colHostW, colActionW, colPkgW, colVerW := historyCols[0], historyCols[1], historyCols[2], historyCols[3], historyCols[4]

		hdrTime := tableHeaderStyle.Width(colTimeW).MaxWidth(colTimeW).Render(" TIMESTAMP")
		hdrHost := tableHeaderStyle.Width(colHostW).MaxWidth(colHostW).Render(" HOSTNAME")
		hdrAction := tableHeaderStyle.Width(colActionW).MaxWidth(colActionW).Render(" ACTION")
		hdrPkg := tableHeaderStyle.Width(colPkgW).MaxWidth(colPkgW).Render(" PACKAGE")
		hdrVer := tableHeaderStyle.Width(colVerW).MaxWidth(colVerW).Render(" VERSION DETAILS")

		tableHdr := lipgloss.JoinHorizontal(lipgloss.Left, hdrTime, hdrHost, hdrAction, hdrPkg, hdrVer)

		start := m.historyOffset
		end := start + m.visibleLines
		if end > len(m.historyEvents) {
			end = len(m.historyEvents)
		}

		var rowStrs []string
		if len(m.historyEvents) == 0 {
			emptyText := " No package change history recorded yet."
			if m.historyLoading {
				emptyText = " Loading history from daemons..."
			}
			rowStrs = append(rowStrs, lipgloss.NewStyle().Foreground(cMuted).Italic(true).Render(emptyText))
		} else {
			viewport := m.historyEvents[start:end]
			for i, evt := range viewport {
				absIndex := start + i
				isSelected := absIndex == m.historyCursor

				timeStr := " " + evt.Timestamp.Local().Format("2006-01-02 15:04")
				hostStr := " " + evt.Hostname
				badgeStr := renderActionBadge(evt.Action)
				pkgStr := " " + evt.Package

				var verDetail string
				switch evt.Action {
				case "MODIFIED":
					verDetail = fmt.Sprintf(" %s -> %s", evt.OldVersion, evt.NewVersion)
				case "ADDED":
					verDetail = " " + evt.NewVersion
				default:
					verDetail = " " + evt.OldVersion
				}

				if isSelected {
					cTime := selectedStyle.Width(colTimeW).MaxWidth(colTimeW).Render(truncate(timeStr, colTimeW))
					cHost := selectedStyle.Width(colHostW).MaxWidth(colHostW).Render(truncate(hostStr, colHostW))
					cBadge := badgeStr
					cPkg := selectedStyle.Width(colPkgW).MaxWidth(colPkgW).Render(truncate(pkgStr, colPkgW))
					cVer := selectedStyle.Width(colVerW).MaxWidth(colVerW).Render(truncate(verDetail, colVerW))

					rowStrs = append(rowStrs, lipgloss.JoinHorizontal(lipgloss.Left, cTime, cHost, cBadge, cPkg, cVer))
				} else {
					cTime := rowStyleNormal.Width(colTimeW).MaxWidth(colTimeW).Render(truncate(timeStr, colTimeW))
					cHost := lipgloss.NewStyle().Foreground(cCyan).Width(colHostW).MaxWidth(colHostW).Render(truncate(hostStr, colHostW))
					cBadge := badgeStr
					cPkg := lipgloss.NewStyle().Foreground(cText).Bold(true).Width(colPkgW).MaxWidth(colPkgW).Render(truncate(pkgStr, colPkgW))
					cVer := lipgloss.NewStyle().Foreground(cMuted).Width(colVerW).MaxWidth(colVerW).Render(truncate(verDetail, colVerW))

					rowStrs = append(rowStrs, lipgloss.JoinHorizontal(lipgloss.Left, cTime, cHost, cBadge, cPkg, cVer))
				}
			}
		}

		for i := len(rowStrs); i < m.visibleLines-1; i++ {
			rowStrs = append(rowStrs, "")
		}

		historyBody := lipgloss.JoinVertical(lipgloss.Left, tableHdr, strings.Join(rowStrs, "\n"))
		frame := panelStyle.BorderForeground(cPurple).Width(innerWidth + 4).Render(historyBody)

		helpText := m.modalHelpText("[▲/▼] Scroll  |  [Enter] Inspect Full Package Timeline  |  [Esc / Ctrl+Y] Close History View")

		content := lipgloss.JoinVertical(lipgloss.Center,
			titleBar,
			"",
			frame,
			"",
			helpText,
		)

		dialog := modalStyle.Render(content)
		return lipgloss.Place(m.width, m.height, lipgloss.Center, lipgloss.Center, dialog)
	}

	// 5. Host Detail Modal
	if m.showHostModal {
		osStr := strings.TrimSpace(m.selectedHost.OSName + " " + m.selectedHost.OSVersion)
		if osStr == "" {
			osStr = "Unknown"
		}
		fnStr := m.selectedHost.HostFunction
		if fnStr == "" {
			fnStr = "-"
		}
		ipStr := m.selectedHost.IPAddress
		if ipStr == "" {
			ipStr = "Unknown"
		}

		tabOverviewStyle := labelBlurred
		tabHistoryStyle := labelBlurred
		if m.hostModalTab == 0 {
			tabOverviewStyle = labelFocused
		} else {
			tabHistoryStyle = labelFocused
		}

		tabs := lipgloss.JoinHorizontal(lipgloss.Left,
			tabOverviewStyle.Render("[1] Host Overview"),
			"   |   ",
			tabHistoryStyle.Render("[2] Change History"),
		)

		hostTitle := fmt.Sprintf(" HOST: %s ", m.selectedHost.Hostname)

		modalInnerWidth := m.fitModalWidth(74, 20)

		lblStyle := labelFocused.Width(16)

		var bodyContent string
		if m.hostModalTab == 0 {
			vulnSummary := "None detected"
			if m.minSev > 0 {
				vulnSummary = fmt.Sprintf("None detected >= %.1f", m.minSev)
			}

			if len(m.selectedHost.Vulnerabilities) > 0 {
				var ids []string
				for _, v := range m.selectedHost.Vulnerabilities {
					if len(v.CVE) > 0 {
						ids = append(ids, v.CVE[0])
					} else {
						ids = append(ids, v.ID)
					}
				}
				if len(ids) > 2 {
					vulnSummary = fmt.Sprintf("⚠️ %d flagged (%s, +%d more)", len(m.selectedHost.Vulnerabilities), strings.Join(ids[:2], ", "), len(ids)-2)
				} else {
					vulnSummary = fmt.Sprintf("⚠️ %d flagged (%s)", len(m.selectedHost.Vulnerabilities), strings.Join(ids, ", "))
				}
			}

			overviewLines := []string{
				lipgloss.JoinHorizontal(lipgloss.Left, lblStyle.Render("Hostname:"), rowStyleNormal.Render(m.selectedHost.Hostname)),
				lipgloss.JoinHorizontal(lipgloss.Left, lblStyle.Render("IP Address:"), rowStyleNormal.Render(ipStr)),
				lipgloss.JoinHorizontal(lipgloss.Left, lblStyle.Render("OS:"), rowStyleNormal.Render(osStr)),
				lipgloss.JoinHorizontal(lipgloss.Left, lblStyle.Render("Host Function:"), rowStyleNormal.Render(fnStr)),
				lipgloss.JoinHorizontal(lipgloss.Left, lblStyle.Render("Package:"), rowStyleNormal.Render(m.selectedHost.PkgName+" "+m.selectedHost.Version)),
			}

			if m.selectedHost.OSVEnabled || m.hasOSV {
				overviewLines = append(overviewLines, lipgloss.JoinHorizontal(lipgloss.Left, lblStyle.Render("Security/CVE:"), lipgloss.NewStyle().Foreground(cRed).Bold(true).Render(vulnSummary)))
			}

			bodyContent = strings.Join(overviewLines, "\n")
		} else {
			if len(m.hostHistoryEvents) == 0 {
				bodyContent = lipgloss.NewStyle().Foreground(cMuted).Italic(true).Render("No package changes recorded for this host.")
			} else {
				start := m.hostHistoryOffset
				end := m.hostHistoryOffset + 6
				if end > len(m.hostHistoryEvents) {
					end = len(m.hostHistoryEvents)
				}

				col1W := 14 // Date
				col3W := 26 // Package Name
				col4W := 32 // Version Details

				var rows []string
				viewport := m.hostHistoryEvents[start:end]
				for i, evt := range viewport {
					absIdx := start + i
					timeStr := " " + evt.Timestamp.Local().Format("01-02 15:04")
					badgeStr := renderActionBadge(evt.Action)
					pkgStr := " " + evt.Package

					var verDetail string
					switch evt.Action {
					case "MODIFIED":
						verDetail = fmt.Sprintf(" %s -> %s", evt.OldVersion, evt.NewVersion)
					case "ADDED":
						verDetail = " " + evt.NewVersion
					default:
						verDetail = " " + evt.OldVersion
					}

					cTime := rowStyleNormal.Width(col1W).MaxWidth(col1W).Render(truncate(timeStr, col1W))
					cBadge := badgeStr
					cPkg := lipgloss.NewStyle().Foreground(cText).Bold(true).Width(col3W).MaxWidth(col3W).Render(truncate(pkgStr, col3W))
					cVer := lipgloss.NewStyle().Foreground(cMuted).Width(col4W).MaxWidth(col4W).Render(truncate(verDetail, col4W))

					line := lipgloss.JoinHorizontal(lipgloss.Left, cTime, cBadge, cPkg, cVer)

					if absIdx == m.hostHistoryCursor {
						line = selectedStyle.Render(line)
					}
					rows = append(rows, line)
				}
				bodyContent = strings.Join(rows, "\n")
			}
		}

		helpBar := "[Tab] Switch Tab  |  [Enter] Inspect Full Timeline  |  [Esc] Close"
		if len(m.selectedHost.Vulnerabilities) > 0 {
			helpBar = "[Ctrl+A] View OSV Advisory  |  " + helpBar
		}
		helpBar = truncate(helpBar, modalInnerWidth)

		modalContent := lipgloss.JoinVertical(lipgloss.Left,
			lipgloss.NewStyle().Width(modalInnerWidth).Align(lipgloss.Center).Render(titleBadge.Render(hostTitle)),
			"",
			lipgloss.NewStyle().Width(modalInnerWidth).Align(lipgloss.Center).Render(tabs),
			"",
			bodyContent,
			"",
			lipgloss.NewStyle().Width(modalInnerWidth).Align(lipgloss.Center).Render(lipgloss.NewStyle().Foreground(cMuted).Render(helpBar)),
		)

		hostModalFrameStyle := lipgloss.NewStyle().
			Border(lipgloss.DoubleBorder()).
			BorderForeground(cPurple).
			Padding(1, 3).
			Align(lipgloss.Left)

		dialog := hostModalFrameStyle.Render(modalContent)
		return lipgloss.Place(m.width, m.height, lipgloss.Center, lipgloss.Center, dialog)
	}

	// 6. Diff Selection Modal with Styled Typeahead
	if m.showDiffSelectModal {
		titleBar := titleBadge.Render(" ⚔️ COMPARE HOST PACKAGES (DIFF) ")

		errText := ""
		if m.diffSelectError != "" {
			errText = lipgloss.NewStyle().Foreground(cPink).Bold(true).Render("⚠️ " + m.diffSelectError)
		}

		labelAStyle := labelBlurred
		labelBStyle := labelBlurred
		if m.diffSelectFocused == 0 {
			labelAStyle = labelFocused
		} else {
			labelBStyle = labelFocused
		}

		formatSuggestions := func(matches []string) string {
			if len(matches) == 0 {
				return lipgloss.NewStyle().Foreground(cMuted).Italic(true).Render("   💡 Suggestions: (no hosts found)")
			}
			var pills []string
			for _, h := range matches {
				pills = append(pills, lipgloss.NewStyle().Foreground(cCyan).Bold(true).Render(h))
			}
			return lipgloss.NewStyle().Foreground(cMuted).Render("   💡 Suggestions: ") + strings.Join(pills, lipgloss.NewStyle().Foreground(cMuted).Render("   •   "))
		}

		matchesA := m.getMatchedHosts(m.diffHostAInput.Value(), "")
		matchesB := m.getMatchedHosts(m.diffHostBInput.Value(), m.resolveHost(m.diffHostAInput.Value()))

		form := lipgloss.JoinVertical(lipgloss.Left,
			lipgloss.JoinHorizontal(lipgloss.Left, labelAStyle.Render("Host A (Base):    "), m.diffHostAInput.View()),
			formatSuggestions(matchesA),
			"",
			lipgloss.JoinHorizontal(lipgloss.Left, labelBStyle.Render("Host B (Target): "), m.diffHostBInput.View()),
			formatSuggestions(matchesB),
		)

		helpText := m.modalHelpText("[Tab] Switch Field  |  [Enter] Compare Top Match  |  [Esc] Cancel")

		content := lipgloss.JoinVertical(lipgloss.Center,
			titleBar,
			"",
			form,
			"",
			errText,
			"",
			helpText,
		)

		dialog := modalStyle.Render(content)
		return lipgloss.Place(m.width, m.height, lipgloss.Center, lipgloss.Center, dialog)
	}

	// 7. Diff View Modal
	if m.showDiffViewModal {
		modalOuterW := m.fitModalWidth(110, 10)

		panelOuterW := (modalOuterW - 9) / 2
		if panelOuterW < 5 {
			panelOuterW = 5
		}
		panelInnerW := panelOuterW - 4

		pkgColW := int(float64(panelInnerW) * 0.58)
		verColW := panelInnerW - pkgColW

		titleBar := titleBadge.Render(fmt.Sprintf(" ⚔️ DIFF: %s vs %s ", m.selectedHostA, m.selectedHostB))

		filterWidth := modalOuterW - 20
		if filterWidth < 4 {
			filterWidth = 4
		}
		m.diffFilterInput.Width = filterWidth
		searchLine := lipgloss.JoinHorizontal(lipgloss.Left,
			labelFocused.Render("❯ Filter: "),
			m.diffFilterInput.View(),
		)

		hdrA := tableHeaderStyle.Width(panelInnerW).MaxWidth(panelInnerW).Align(lipgloss.Center).Render(truncate("🖥️ Host A: "+m.selectedHostA, panelInnerW))
		hdrB := tableHeaderStyle.Width(panelInnerW).MaxWidth(panelInnerW).Align(lipgloss.Center).Render(truncate("🖥️ Host B: "+m.selectedHostB, panelInnerW))

		colHdrA := lipgloss.JoinHorizontal(lipgloss.Left,
			tableHeaderStyle.Width(pkgColW).MaxWidth(pkgColW).Render(" PACKAGE"),
			tableHeaderStyle.Width(verColW).MaxWidth(verColW).Render(" VERSION"),
		)
		colHdrB := lipgloss.JoinHorizontal(lipgloss.Left,
			tableHeaderStyle.Width(pkgColW).MaxWidth(pkgColW).Render(" PACKAGE"),
			tableHeaderStyle.Width(verColW).MaxWidth(verColW).Render(" VERSION"),
		)

		panelHdrA := lipgloss.JoinVertical(lipgloss.Left, hdrA, colHdrA)
		panelHdrB := lipgloss.JoinVertical(lipgloss.Left, hdrB, colHdrB)

		start := m.diffOffset
		end := m.diffOffset + m.diffVisibleLines
		if end > len(m.diffFiltered) {
			end = len(m.diffFiltered)
		}

		viewport := m.diffFiltered[start:end]

		var rowsA []string
		var rowsB []string

		styleSamePkg := lipgloss.NewStyle().Foreground(cText)
		styleSameVer := lipgloss.NewStyle().Foreground(cMuted)
		styleDiffA := lipgloss.NewStyle().Foreground(cCyan).Bold(true)
		styleDiffB := lipgloss.NewStyle().Foreground(cPink).Bold(true)
		styleMissing := lipgloss.NewStyle().Foreground(cMuted).Italic(true)

		for i, item := range viewport {
			absIdx := start + i
			isSelected := absIdx == m.diffCursor

			stPkgA, stVerA := styleSamePkg, styleSameVer
			stPkgB, stVerB := styleSamePkg, styleSameVer

			if item.IsDiff {
				if item.VersionA == "-" {
					stVerA = styleMissing
				} else {
					stVerA = styleDiffA
				}

				if item.VersionB == "-" {
					stVerB = styleMissing
				} else {
					stVerB = styleDiffB
				}
			}

			if isSelected {
				stPkgA = selectedDiffStyle
				stVerA = selectedDiffStyle
				stPkgB = selectedDiffStyle
				stVerB = selectedDiffStyle
			}

			rPkgA := truncate(" "+item.PkgName, pkgColW)
			rVerA := truncate(" "+item.VersionA, verColW)
			rPkgB := truncate(" "+item.PkgName, pkgColW)
			rVerB := truncate(" "+item.VersionB, verColW)

			cellPkgA := stPkgA.Width(pkgColW).MaxWidth(pkgColW).Render(rPkgA)
			cellVerA := stVerA.Width(verColW).MaxWidth(verColW).Render(rVerA)
			cellPkgB := stPkgB.Width(pkgColW).MaxWidth(pkgColW).Render(rPkgB)
			cellVerB := stVerB.Width(verColW).MaxWidth(verColW).Render(rVerB)

			rowsA = append(rowsA, lipgloss.JoinHorizontal(lipgloss.Left, cellPkgA, cellVerA))
			rowsB = append(rowsB, lipgloss.JoinHorizontal(lipgloss.Left, cellPkgB, cellVerB))
		}

		for i := len(viewport); i < m.diffVisibleLines; i++ {
			rowsA = append(rowsA, strings.Repeat(" ", panelInnerW))
			rowsB = append(rowsB, strings.Repeat(" ", panelInnerW))
		}

		bodyA := strings.Join(rowsA, "\n")
		bodyB := strings.Join(rowsB, "\n")

		boxA := panelStyle.BorderForeground(cCyan).Width(panelOuterW).Render(lipgloss.JoinVertical(lipgloss.Left, panelHdrA, bodyA))
		boxB := panelStyle.BorderForeground(cPink).Width(panelOuterW).Render(lipgloss.JoinVertical(lipgloss.Left, panelHdrB, bodyB))

		panels := lipgloss.JoinHorizontal(lipgloss.Top, boxA, " ", boxB)

		diffCount := 0
		for _, item := range m.diffAllItems {
			if item.IsDiff {
				diffCount++
			}
		}

		modeTag := "All Packages"
		if m.diffOnlyDiffs {
			modeTag = "Only Diffs [Active]"
		}

		statsText := fmt.Sprintf("📊 Comparison: %d differences out of %d total packages  |  Mode: %s", diffCount, len(m.diffAllItems), modeTag)
		stats := insightBoxStyle.Render(truncate(statsText, modalOuterW-8))

		help := m.modalHelpText("[Ctrl+T] Toggle Diffs Only  |  [Filter] Search  |  [▲/▼] Scroll  |  [Esc] Close")

		content := lipgloss.JoinVertical(lipgloss.Center,
			titleBar,
			"",
			searchLine,
			"",
			panels,
			"",
			stats,
			help,
		)

		dialog := modalStyle.Render(content)
		return lipgloss.Place(m.width, m.height, lipgloss.Center, lipgloss.Center, dialog)
	}

	// 8. Main Dashboard View
	availWidth := m.width - 2
	if availWidth < 60 {
		return "Terminal window too small..."
	}

	innerWidth := availWidth - 4

	// --- HEADER PANEL ---
	tBadge := titleBadge.Render(" 📦 PKGDASH ")

	secStatus := " HTTP "
	switch {
	case m.hasTLS && m.hasPSK:
		secStatus = " 🔒 SECURE "
	case m.hasTLS:
		secStatus = " 🔒 TLS "
	case m.hasPSK:
		secStatus = " 🔑 PSK "
	}
	sBadge := secBadge.Render(secStatus)

	var osvBadgeStr string
	if m.hasOSV {
		if m.minSev > 0 {
			osvBadgeStr = osvBadgeStyle.Render(fmt.Sprintf("🛡 OSV (≥%.1f)", m.minSev))
		} else {
			osvBadgeStr = osvBadgeStyle.Render("🛡 OSV")
		}
	}

	var stBadge string
	switch {
	case !m.loaded:
		stBadge = syncBadge.Render(" ⚡ STREAMING ")
	case m.syncError != "":
		stBadge = syncErrBadge.Render(" ⚠ PARTIAL SYNC ")
	default:
		stBadge = readyBadge.Render(" ✓ SYNCED ")
	}

	timeStr := "Never"
	if !m.lastUpdated.IsZero() {
		timeStr = m.lastUpdated.Local().Format("15:04:05")
	}
	mText := metaStyle.Render(fmt.Sprintf("Updated: %s", timeStr))

	leftBadgesList := []string{tBadge, sBadge}
	if osvBadgeStr != "" {
		leftBadgesList = append(leftBadgesList, osvBadgeStr)
	}
	leftBadgesList = append(leftBadgesList, stBadge)

	leftBadges := strings.Join(leftBadgesList, " ")
	rightMeta := mText
	statusMsg, statusStyle := m.flashMsg, flashStyle
	if statusMsg == "" && m.syncError != "" {
		statusMsg, statusStyle = m.syncError, lipgloss.NewStyle().Foreground(cPink)
	}
	if statusMsg != "" {
		rightMeta = statusStyle.Render(statusMsg) + " " + mText
	}

	leftWidth := lipgloss.Width(leftBadges)
	maxRightW := innerWidth - leftWidth - 1
	if maxRightW > 0 {
		rightMeta = truncate(rightMeta, maxRightW)
	} else {
		rightMeta = ""
	}

	rightWidth := lipgloss.Width(rightMeta)
	gap := innerWidth - leftWidth - rightWidth
	if gap < 0 {
		gap = 0
	}

	headerContent := lipgloss.JoinHorizontal(lipgloss.Top, leftBadges, strings.Repeat(" ", gap), rightMeta)
	headerCard := headerPanelStyle.Render(headerContent)

	// --- SEARCH FILTER CARDS ---
	cardWidths := distributeWidths(availWidth, []float64{0.24, 0.22, 0.34, 0.20}, 15)
	cw1, cw2, cw3, cw4 := cardWidths[0], cardWidths[1], cardWidths[2], cardWidths[3]

	renderFilterCard := func(title string, input textinput.Model, isFocused bool, query string, cardTotalWidth int) string {
		var lStyle, bStyle lipgloss.Style
		promptChar := "  "

		if isFocused {
			lStyle = labelFocused
			bStyle = filterBoxFocused
			promptChar = "❯ "
		} else {
			lStyle = labelBlurred
			bStyle = filterBoxBlurred
		}

		// lipgloss.Width includes the style's horizontal padding; the border is
		// added on top. Keep every content line inside the remaining space so
		// cards never wrap and the whole filter row stays exactly availWidth.
		boxWidth := cardTotalWidth - 2
		if boxWidth < 1 {
			boxWidth = 1
		}
		contentWidth := boxWidth - 2
		if contentWidth < 1 {
			contentWidth = 1
		}

		input.Width = contentWidth - lipgloss.Width(promptChar)
		if input.Width < 1 {
			input.Width = 1
		}

		// On very narrow cards, drop the mode badge so the label stays readable.
		modeWidth := 0
		var modeIndicator string
		if contentWidth >= 13 {
			modeWidth = 6 // " [TXT]" / " [REG]"
			if isLikelyRegex(query) {
				modeIndicator = regexBadgeActive.Render("[REG]")
			} else {
				modeIndicator = regexBadgeInactive.Render("[TXT]")
			}
		}

		titleWidth := contentWidth - modeWidth
		if titleWidth < 1 {
			titleWidth = 1
		}
		safeTitle := truncate(title, titleWidth)
		headerLine := lStyle.Render(safeTitle)
		if modeWidth > 0 {
			headerLine = lipgloss.JoinHorizontal(lipgloss.Left, headerLine, " ", modeIndicator)
		}
		inputLine := lipgloss.JoinHorizontal(lipgloss.Left, lStyle.Render(promptChar), input.View())

		cardContent := lipgloss.JoinVertical(lipgloss.Left, headerLine, inputLine)

		return bStyle.Width(boxWidth).Render(cardContent)
	}

	cardHost := renderFilterCard("HOST", m.hostInput, m.focusedInput == 0, m.hostInput.Value(), cw1)
	cardOS := renderFilterCard("OS", m.osInput, m.focusedInput == 1, m.osInput.Value(), cw2)
	cardPkg := renderFilterCard("PACKAGE", m.pkgInput, m.focusedInput == 2, m.pkgInput.Value(), cw3)
	cardVer := renderFilterCard("VERSION", m.verInput, m.focusedInput == 3, m.verInput.Value(), cw4)

	filterPanel := lipgloss.JoinHorizontal(lipgloss.Left, cardHost, cardOS, cardPkg, cardVer)

	// --- MAIN TABLE ---
	tw1 := int(float64(innerWidth) * 0.23)
	tw2 := int(float64(innerWidth) * 0.21)
	tw3 := int(float64(innerWidth) * 0.31)
	tw4 := innerWidth - tw1 - tw2 - tw3

	hHostText := " HOSTNAME"
	hOSText := " OS / VERSION"
	hPkgText := " PACKAGE NAME"
	hVerText := " VERSION"

	indicator := " ▲"
	if m.sortDesc {
		indicator = " ▼"
	}

	switch m.sortCol {
	case SortHostname:
		hHostText += indicator
	case SortOS:
		hOSText += indicator
	case SortPackage:
		hPkgText += indicator
	case SortVersion:
		hVerText += indicator
	}

	hHost := tableHeaderStyle.Width(tw1).MaxWidth(tw1).Render(truncate(hHostText, tw1))
	hOS := tableHeaderStyle.Width(tw2).MaxWidth(tw2).Render(truncate(hOSText, tw2))
	hPkg := tableHeaderStyle.Width(tw3).MaxWidth(tw3).Render(truncate(hPkgText, tw3))
	hVer := tableHeaderStyle.Width(tw4).MaxWidth(tw4).Render(truncate(hVerText, tw4))

	tableHeader := lipgloss.JoinHorizontal(lipgloss.Left, hHost, hOS, hPkg, hVer)

	var rowStrs []string
	start := m.offset
	end := m.offset + m.visibleLines
	if end > len(m.filtered) {
		end = len(m.filtered)
	}

	viewport := m.filtered[start:end]

	for i, item := range viewport {
		absIndex := start + i
		isSelected := absIndex == m.cursor
		hasVuln := m.hasOSV && len(item.Vulnerabilities) > 0

		rHostRaw := "  " + item.Hostname
		if isSelected {
			rHostRaw = "❯ " + item.Hostname
		}

		rOSRaw := " " + formatOSLabel(item.OSName, item.OSVersion)
		rPkgRaw := " " + item.PkgName
		rVerRaw := " " + item.Version
		if hasVuln {
			rVerRaw += " ⚠️"
		}

		rowStyle := rowStyleNormal
		if hasVuln {
			rowStyle = vulnRowStyle
		}
		if isSelected {
			if hasVuln {
				rowStyle = selectedVulnStyle
			} else {
				rowStyle = selectedStyle
			}
		}

		rHost := rowStyle.Width(tw1).MaxWidth(tw1).Render(truncate(rHostRaw, tw1))
		rOS := rowStyle.Width(tw2).MaxWidth(tw2).Render(truncate(rOSRaw, tw2))
		rPkg := rowStyle.Width(tw3).MaxWidth(tw3).Render(truncate(rPkgRaw, tw3))
		rVer := rowStyle.Width(tw4).MaxWidth(tw4).Render(truncate(rVerRaw, tw4))

		rowStrs = append(rowStrs, lipgloss.JoinHorizontal(lipgloss.Left, rHost, rOS, rPkg, rVer))
	}

	for i := len(viewport); i < m.visibleLines; i++ {
		rowStrs = append(rowStrs, "")
	}

	tableBody := strings.Join(rowStrs, "\n")

	insightsRaw := truncate(m.getFleetInsights(), innerWidth)
	insightsText := insightBoxStyle.Render(insightsRaw)

	tableContent := lipgloss.JoinVertical(lipgloss.Left, tableHeader, tableBody, insightsText)
	tableFrame := tableFrameStyle.Render(tableContent)

	// --- FOOTER PANEL ---
	displayStart := 0
	if len(m.filtered) > 0 {
		displayStart = start + 1
	}

	keyHelp := "[F1] Shortcuts"
	if m.showOnlyVulns {
		keyHelp += "  |  [Ctrl+U] Vulns [ACTIVE]"
	}
	counterText := fmt.Sprintf("Records: %d-%d / %d (Total: %d)", displayStart, end, len(m.filtered), len(m.allItems))

	leftW := lipgloss.Width(keyHelp)
	rightW := lipgloss.Width(counterText)

	gapFooter := innerWidth - leftW - rightW
	if gapFooter < 0 {
		gapFooter = 0
		counterText = truncate(counterText, innerWidth-leftW)
	}

	footerContent := lipgloss.JoinHorizontal(lipgloss.Top, keyHelp, strings.Repeat(" ", gapFooter), counterText)
	footerBox := footerBoxStyle.Width(innerWidth + 2).Render(footerContent)

	ui := lipgloss.JoinVertical(lipgloss.Left,
		headerCard,
		filterPanel,
		tableFrame,
		footerBox,
	)

	return baseStyle.Render(ui)
}
