package main

import (
	"bufio"
	"compress/gzip"
	"crypto/tls"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/charmbracelet/bubbles/textinput"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
)

// ============================================================================
// CONFIGURATION & PLACEHOLDERS (Edit default filter placeholders here)
// ============================================================================
const (
	PlaceholderHost = "Filter hostname..."
	PlaceholderPkg  = "Filter package..."
	PlaceholderVer  = "Filter version..."
)

type Vulnerability struct {
	ID      string   `json:"id"`
	CVE     []string `json:"cve,omitempty"`
	Summary string   `json:"summary,omitempty"`
	Details string   `json:"details,omitempty"`
	URL     string   `json:"url,omitempty"`
}

type PackageInfo struct {
	Name            string          `json:"name"`
	Version         string          `json:"version"`
	Arch            string          `json:"arch"`
	Vulnerabilities []Vulnerability `json:"vulnerabilities,omitempty"`
}

type HostPayload struct {
	Hostname     string        `json:"hostname"`
	IPAddress    string        `json:"ip_address,omitempty"`
	OSName       string        `json:"os_name,omitempty"`
	OSVersion    string        `json:"os_version,omitempty"`
	HostFunction string        `json:"host_function,omitempty"`
	Packages     []PackageInfo `json:"packages"`
	OSVEnabled   bool          `json:"osv_enabled"`
}

type FlatItem struct {
	Hostname        string
	IPAddress       string
	OSName          string
	OSVersion       string
	HostFunction    string
	PkgName         string
	Version         string
	Arch            string
	Vulnerabilities []Vulnerability
	OSVEnabled      bool
}

type DiffRow struct {
	PkgName  string
	VersionA string
	VersionB string
	IsDiff   bool
}

type ChangeEvent struct {
	Timestamp  time.Time `json:"timestamp"`
	Hostname   string    `json:"hostname"`
	Package    string    `json:"package"`
	OldVersion string    `json:"old_version,omitempty"`
	NewVersion string    `json:"new_version,omitempty"`
	Action     string    `json:"action"` // "ADDED", "REMOVED", "MODIFIED"
}

type SortColumn int

const (
	SortHostname SortColumn = iota
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

type dataMsg struct {
	items     []FlatItem
	timestamp time.Time
	isDone    bool
	hasOSV    bool
}

type historyDataMsg struct {
	events    []ChangeEvent
	queryHost string
	queryPkg  string
}

type model struct {
	servers []string
	psk     string

	hostInput    textinput.Model
	pkgInput     textinput.Model
	verInput     textinput.Model
	focusedInput int

	allItems      []FlatItem
	filtered      []FlatItem
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
	showHistoryView bool
	historyEvents   []ChangeEvent
	historyCursor   int
	historyOffset   int

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
	updateChan chan dataMsg
	hasTLS     bool
	hasPSK     bool
	hasOSV     bool
}

func main() {
	servers, psk := getConfig()
	if len(servers) == 0 {
		log.Fatal("No servers found. Set PKGDASH_SERVERS or configure ~/.local/pkgdash.config")
	}

	hi := textinput.New()
	hi.Placeholder = PlaceholderHost
	hi.Prompt = ""
	hi.Focus()

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

	updateChan := make(chan dataMsg)

	hasTLS := false
	for _, s := range servers {
		if strings.HasPrefix(s, "https://") {
			hasTLS = true
			break
		}
	}

	m := model{
		servers:         servers,
		psk:             psk,
		hostInput:       hi,
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
		showAboutModal:  false,
		showHostModal:   false,
		loaded:          false,
		updateChan:      updateChan,
		hasTLS:          hasTLS,
		hasPSK:          psk != "",
		diffOnlyDiffs:   false,
		showOnlyVulns:   false,
	}

	go fetchAllDataAsync(servers, psk, updateChan)

	p := tea.NewProgram(m, tea.WithAltScreen())
	if _, err := p.Run(); err != nil {
		fmt.Printf("Error running TUI: %v\n", err)
	}
}

func getConfig() ([]string, string) {
	var servers []string
	psk := os.Getenv("PKGDASH_PSK")

	if envServers := os.Getenv("PKGDASH_SERVERS"); envServers != "" {
		servers = strings.Split(envServers, ",")
	}

	home, err := os.UserHomeDir()
	if err == nil {
		cfgPath := filepath.Join(home, ".local", "pkgdash.config")
		if file, err := os.Open(cfgPath); err == nil {
			defer func() { _ = file.Close() }()
			scanner := bufio.NewScanner(file)
			for scanner.Scan() {
				line := strings.TrimSpace(scanner.Text())
				if line == "" || strings.HasPrefix(line, "#") {
					continue
				}

				if strings.HasPrefix(strings.ToLower(line), "psk=") {
					if psk == "" {
						psk = line[4:]
					}
				} else if len(servers) == 0 {
					servers = append(servers, line)
				}
			}
			_ = scanner.Err()
		}
	}
	return servers, psk
}

func fetchAllDataAsync(servers []string, psk string, updateChan chan dataMsg) {
	var wg sync.WaitGroup

	customTransport := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	client := http.Client{
		Timeout:   15 * time.Second,
		Transport: customTransport,
	}

	for _, s := range servers {
		wg.Add(1)
		go func(server string) {
			defer wg.Done()
			url := server

			if !strings.HasPrefix(url, "http://") && !strings.HasPrefix(url, "https://") {
				url = "http://" + url
			}

			cleanURL := strings.TrimPrefix(strings.TrimPrefix(url, "http://"), "https://")
			if !strings.Contains(cleanURL, ":") {
				url += ":9876"
			}
			url += "/packages"

			req, err := http.NewRequest("GET", url, nil)
			if err != nil {
				return
			}
			req.Header.Set("Accept-Encoding", "gzip")
			if psk != "" {
				req.Header.Set("X-PSK", psk)
			}

			resp, err := client.Do(req)
			if err != nil || resp.StatusCode == http.StatusUnauthorized {
				return
			}
			defer func() { _ = resp.Body.Close() }()

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
			token, err := decoder.Token()
			if err != nil {
				return
			}
			if delim, ok := token.(json.Delim); !ok || delim != '[' {
				return
			}

			for decoder.More() {
				var host HostPayload
				if err := decoder.Decode(&host); err != nil {
					break
				}

				isOSV := osvHeaderActive || host.OSVEnabled

				var localItems []FlatItem
				for _, pkg := range host.Packages {
					localItems = append(localItems, FlatItem{
						Hostname:        host.Hostname,
						IPAddress:       host.IPAddress,
						OSName:          host.OSName,
						OSVersion:       host.OSVersion,
						HostFunction:    host.HostFunction,
						PkgName:         pkg.Name,
						Version:         pkg.Version,
						Arch:            pkg.Arch,
						Vulnerabilities: pkg.Vulnerabilities,
						OSVEnabled:      isOSV,
					})
				}

				updateChan <- dataMsg{
					items:     localItems,
					timestamp: serverMaxTime,
					isDone:    false,
					hasOSV:    isOSV,
				}
			}
		}(s)
	}

	go func() {
		wg.Wait()
		updateChan <- dataMsg{isDone: true}
	}()
}

func fetchHistoryCmd(servers []string, psk string, hostname, pkgName string) tea.Cmd {
	return func() tea.Msg {
		var allEvents []ChangeEvent
		customTransport := &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		}
		client := http.Client{
			Timeout:   5 * time.Second,
			Transport: customTransport,
		}

		for _, s := range servers {
			url := s
			if !strings.HasPrefix(url, "http://") && !strings.HasPrefix(url, "https://") {
				url = "http://" + url
			}

			cleanURL := strings.TrimPrefix(strings.TrimPrefix(url, "http://"), "https://")
			if !strings.Contains(cleanURL, ":") {
				url += ":9876"
			}
			url += "/history"

			var params []string
			if hostname != "" {
				params = append(params, "host="+hostname)
			}
			if pkgName != "" {
				params = append(params, "pkg="+pkgName)
			}
			if len(params) > 0 {
				url += "?" + strings.Join(params, "&")
			}

			req, err := http.NewRequest("GET", url, nil)
			if err != nil {
				continue
			}
			if psk != "" {
				req.Header.Set("X-PSK", psk)
			}

			resp, err := client.Do(req)
			if err != nil || resp.StatusCode != http.StatusOK {
				continue
			}

			var evts []ChangeEvent
			if err := json.NewDecoder(resp.Body).Decode(&evts); err == nil {
				allEvents = append(allEvents, evts...)
			}
			_ = resp.Body.Close()
		}

		return historyDataMsg{
			events:    allEvents,
			queryHost: hostname,
			queryPkg:  pkgName,
		}
	}
}

func waitForUpdate(sub chan dataMsg) tea.Cmd {
	return func() tea.Msg { return <-sub }
}

func (m *model) switchFocus(target int) {
	m.focusedInput = (target + 3) % 3

	m.hostInput.Blur()
	m.pkgInput.Blur()
	m.verInput.Blur()

	switch m.focusedInput {
	case 0:
		m.hostInput.Focus()
	case 1:
		m.pkgInput.Focus()
	case 2:
		m.verInput.Focus()
	}
}

func (m *model) sortData() {
	sort.Slice(m.allItems, func(i, j int) bool {
		a, b := m.allItems[i], m.allItems[j]

		ah, bh := strings.ToLower(a.Hostname), strings.ToLower(b.Hostname)
		ap, bp := strings.ToLower(a.PkgName), strings.ToLower(b.PkgName)
		av, bv := a.Version, b.Version

		var primaryLess, primaryEqual bool

		switch m.sortCol {
		case SortHostname:
			primaryLess = ah < bh
			primaryEqual = ah == bh
		case SortPackage:
			primaryLess = ap < bp
			primaryEqual = ap == bp
		case SortVersion:
			primaryLess = av < bv
			primaryEqual = av == bv
		}

		if primaryEqual {
			if ah != bh {
				return ah < bh
			}
			if ap != bp {
				return ap < bp
			}
			return av < bv
		}

		if m.sortDesc {
			return !primaryLess
		}
		return primaryLess
	})

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

	writer := csv.NewWriter(file)
	defer writer.Flush()

	if err := writer.Write([]string{"Hostname", "Package", "Version", "Architecture", "CVE_Count"}); err != nil {
		return fmt.Sprintf("Error writing CSV header: %v", err)
	}

	for _, item := range items {
		cveCount := fmt.Sprintf("%d", len(item.Vulnerabilities))
		if err := writer.Write([]string{item.Hostname, item.PkgName, item.Version, item.Arch, cveCount}); err != nil {
			return fmt.Sprintf("Error writing CSV row: %v", err)
		}
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

	hostMap := make(map[string]bool)
	for _, item := range items {
		if strings.TrimSpace(item.Hostname) != "" {
			hostMap[item.Hostname] = true
		}
	}

	if len(hostMap) == 0 {
		return "No valid hosts found in search results"
	}

	var hosts []string
	for h := range hostMap {
		hosts = append(hosts, h)
	}
	sort.Strings(hosts)

	path := filepath.Join(cwd, "temp_inventory.ini")
	file, err := os.Create(path)
	if err != nil {
		return fmt.Sprintf("Error creating inventory file: %v", err)
	}
	defer func() { _ = file.Close() }()

	var sb strings.Builder
	sb.WriteString("[all]\n")
	for _, h := range hosts {
		sb.WriteString(h)
		sb.WriteString("\n")
	}

	if _, err := file.WriteString(sb.String()); err != nil {
		return fmt.Sprintf("Error writing inventory file: %v", err)
	}

	return fmt.Sprintf("✓ Exported %d host(s) to %s", len(hosts), filepath.Base(path))
}

func buildDiffData(hostA, hostB string, allItems []FlatItem) []DiffRow {
	pkgsA := make(map[string]string)
	pkgsB := make(map[string]string)
	allPkgNamesMap := make(map[string]bool)

	for _, item := range allItems {
		if strings.EqualFold(item.Hostname, hostA) {
			pkgsA[item.PkgName] = item.Version
			allPkgNamesMap[item.PkgName] = true
		}
		if strings.EqualFold(item.Hostname, hostB) {
			pkgsB[item.PkgName] = item.Version
			allPkgNamesMap[item.PkgName] = true
		}
	}

	var pkgNames []string
	for name := range allPkgNamesMap {
		pkgNames = append(pkgNames, name)
	}
	sort.Strings(pkgNames)

	var rows []DiffRow
	for _, name := range pkgNames {
		verA, hasA := pkgsA[name]
		if !hasA {
			verA = "-"
		}
		verB, hasB := pkgsB[name]
		if !hasB {
			verB = "-"
		}

		isDiff := (verA != verB)

		rows = append(rows, DiffRow{
			PkgName:  name,
			VersionA: verA,
			VersionB: verB,
			IsDiff:   isDiff,
		})
	}

	return rows
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
		if msg.hasOSV {
			m.hasOSV = true
		}
		if msg.isDone {
			m.loaded = true
			m.sortData()
			m.updateViewport()
			return m, nil
		}

		m.allItems = append(m.allItems, msg.items...)
		if msg.timestamp.After(m.lastUpdated) {
			m.lastUpdated = msg.timestamp
		}

		m.filterItems()
		m.updateViewport()

		return m, waitForUpdate(m.updateChan)

	case historyDataMsg:
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

	// 1. OSV Vulnerability Detail Modal
	if m.showOSVModal {
		switch msg := msg.(type) {
		case tea.KeyMsg:
			switch msg.String() {
			case "esc", "enter", "ctrl+c", "ctrl+o", "q":
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
			m.width = msg.Width
			m.height = msg.Height
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
			m.width = msg.Width
			m.height = msg.Height
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
					return m, fetchHistoryCmd(m.servers, m.psk, evt.Hostname, evt.Package)
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
			m.width = msg.Width
			m.height = msg.Height
			m.updateHistoryViewport()
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

			case "ctrl+o":
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
						return m, fetchHistoryCmd(m.servers, m.psk, evt.Hostname, evt.Package)
					}
				} else {
					m.showHostModal = false
				}
				return m, nil

			case "tab", "shift+tab":
				if m.showHostModal {
					m.hostModalTab = (m.hostModalTab + 1) % 2
					if m.hostModalTab == 1 && len(m.hostHistoryEvents) == 0 {
						return m, fetchHistoryCmd(m.servers, m.psk, m.selectedHost.Hostname, "")
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
			m.width = msg.Width
			m.height = msg.Height
		}
		return m, nil
	}

	// 5. Diff Host Selection Modal
	if m.showDiffSelectModal {
		switch msg := msg.(type) {
		case tea.KeyMsg:
			switch msg.String() {
			case "esc", "ctrl+c":
				m.showDiffSelectModal = false
				return m, nil

			case "tab", "shift+tab":
				m.diffSelectFocused = (m.diffSelectFocused + 1) % 2
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
			m.width = msg.Width
			m.height = msg.Height
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
			m.width = msg.Width
			m.height = msg.Height
			m.diffVisibleLines = m.height - 18
			if m.diffVisibleLines < 3 {
				m.diffVisibleLines = 3
			}
			m.updateDiffViewport()
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
		if msg.String() != "ctrl+s" && msg.String() != "ctrl+e" && msg.String() != "ctrl+o" && msg.String() != "ctrl+u" {
			m.flashMsg = ""
		}

		switch msg.String() {
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

		case "ctrl+o":
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
			return m, fetchHistoryCmd(m.servers, m.psk, "", "")
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
		m.width = msg.Width
		m.height = msg.Height
		m.ready = true

		reservedLines := 14
		m.visibleLines = m.height - reservedLines
		if m.visibleLines < 1 {
			m.visibleLines = 1
		}
		m.updateViewport()

		m.diffVisibleLines = m.height - 18
		if m.diffVisibleLines < 3 {
			m.diffVisibleLines = 3
		}
	}

	var hPrev, pPrev, vPrev string
	hPrev = m.hostInput.Value()
	pPrev = m.pkgInput.Value()
	vPrev = m.verInput.Value()

	switch m.focusedInput {
	case 0:
		m.hostInput, cmd = m.hostInput.Update(msg)
	case 1:
		m.pkgInput, cmd = m.pkgInput.Update(msg)
	case 2:
		m.verInput, cmd = m.verInput.Update(msg)
	}

	if m.hostInput.Value() != hPrev || m.pkgInput.Value() != pPrev || m.verInput.Value() != vPrev {
		m.filterItems()
		m.cursor = 0
		m.updateViewport()
	}

	return m, cmd
}

func (m *model) filterItems() {
	hQuery := strings.TrimSpace(m.hostInput.Value())
	pQuery := strings.TrimSpace(m.pkgInput.Value())
	vQuery := strings.TrimSpace(m.verInput.Value())

	if hQuery == "" && pQuery == "" && vQuery == "" && !m.showOnlyVulns {
		m.filtered = m.allItems
		return
	}

	hMatch := createFieldMatcher(hQuery)
	pMatch := createFieldMatcher(pQuery)
	vMatch := createFieldMatcher(vQuery)

	var filtered []FlatItem
	for _, item := range m.allItems {
		if m.showOnlyVulns && len(item.Vulnerabilities) == 0 {
			continue
		}
		if hMatch(item.Hostname) && pMatch(item.PkgName) && vMatch(item.Version) {
			filtered = append(filtered, item)
		}
	}

	m.filtered = filtered
}

func createFieldMatcher(query string) func(string) bool {
	if query == "" {
		return func(s string) bool { return true }
	}

	if isLikelyRegex(query) {
		re, err := regexp.Compile("(?i)" + query)
		if err == nil {
			return func(s string) bool { return re.MatchString(s) }
		}
	}

	terms := strings.Fields(strings.ToLower(query))
	return func(s string) bool {
		sLower := strings.ToLower(s)
		for _, term := range terms {
			if !strings.Contains(sLower, term) {
				return false
			}
		}
		return true
	}
}

func isLikelyRegex(query string) bool {
	metaChars := []string{"^", "$", "*", "+", "?", "[", "]", "(", ")", "{", "}", "|", "\\"}
	for _, char := range metaChars {
		if strings.Contains(query, char) {
			return true
		}
	}
	return false
}

func (m *model) getFleetInsights() string {
	if len(m.filtered) == 0 || m.cursor >= len(m.filtered) {
		return ""
	}

	selectedPkg := m.filtered[m.cursor].PkgName
	hostMap := make(map[string]bool)
	versionMap := make(map[string]bool)
	vulnCount := 0

	for _, item := range m.filtered {
		if strings.EqualFold(item.PkgName, selectedPkg) {
			hostMap[item.Hostname] = true
			versionMap[item.Version] = true
			if len(item.Vulnerabilities) > vulnCount {
				vulnCount = len(item.Vulnerabilities)
			}
		}
	}

	isFiltered := len(m.filtered) < len(m.allItems)
	filterTag := ""
	if isFiltered {
		filterTag = " (filtered search results)"
	}

	vulnText := ""
	if m.hasOSV && vulnCount > 0 {
		vulnText = fmt.Sprintf(" ⚠️ %d Vulnerability/CVE(s) flagged", vulnCount)
	}

	return fmt.Sprintf("📊 Fleet Insights%s: '%s' is present on %d host(s) across %d unique version(s)%s",
		filterTag, selectedPkg, len(hostMap), len(versionMap), vulnText)
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

func truncate(str string, maxLen int) string {
	if maxLen <= 0 {
		return ""
	}
	runes := []rune(str)
	if len(runes) > maxLen {
		if maxLen > 3 {
			return string(runes[:maxLen-3]) + "..."
		}
		return string(runes[:maxLen])
	}
	return str
}

func (m model) View() string {
	if !m.ready {
		return "Initializing Dashboard..."
	}

	// 1. OSV Vulnerability Detail Modal (Strictly Bounded Width)
	if m.showOSVModal {
		modalContentWidth := m.width - 24
		if modalContentWidth > 80 {
			modalContentWidth = 80
		}
		if modalContentWidth < 50 {
			modalContentWidth = 50
		}

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

			detailLines = append(detailLines, lipgloss.JoinHorizontal(lipgloss.Left, lblStyle.Render(prefix+"ID/CVE:  "), lipgloss.NewStyle().Foreground(cRed).Bold(true).Render(cveStr)))
			if v.Summary != "" {
				detailLines = append(detailLines, lipgloss.JoinHorizontal(lipgloss.Left, lblStyle.Render("  Summary: "), valStyle.Render(truncate(v.Summary, modalContentWidth-12))))
			}
			if cleanURL != "" {
				detailLines = append(detailLines, lipgloss.JoinHorizontal(lipgloss.Left, lblStyle.Render("  Link:    "), lipgloss.NewStyle().Foreground(cCyan).Underline(true).Render(truncate(cleanURL, modalContentWidth-12))))
			}
			detailLines = append(detailLines, "")
		}

		body := lipgloss.JoinVertical(lipgloss.Left, detailLines...)
		frame := panelStyle.BorderForeground(cRed).Width(modalContentWidth).Render(body)

		helpText := lipgloss.NewStyle().Foreground(cMuted).Render("[▲/▼ / PgUp/PgDown] Scroll Advisories  |  [Esc / Enter] Close Pop-up")

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
		innerWidth := m.width - 12
		if innerWidth < 70 {
			innerWidth = 70
		}

		titleBar := titleBadge.Render(fmt.Sprintf(" 📦 PACKAGE TIMELINE: %s on %s ", m.selectedPkgName, m.selectedPkgHost))

		colTimeW := 18
		colActionW := 13
		colVerW := innerWidth - colTimeW - colActionW

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

		helpText := lipgloss.NewStyle().Foreground(cMuted).Render("[▲/▼] Scroll  |  [Esc / Enter] Back to Previous View")

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
		innerWidth := m.width - 10
		if innerWidth < 90 {
			innerWidth = 90
		}

		titleBar := titleBadge.Render(" 📜 FLEET AUDIT LOG / TIME TRAVEL ")

		colTimeW := 18
		colHostW := int(float64(innerWidth) * 0.28)
		colActionW := 13
		colPkgW := int(float64(innerWidth) * 0.25)
		colVerW := innerWidth - colTimeW - colHostW - colActionW - colPkgW

		if colVerW < 10 {
			colVerW = 10
		}

		hdrTime := tableHeaderStyle.Width(colTimeW).MaxWidth(colTimeW).Render(" TIMESTAMP")
		hdrHost := tableHeaderStyle.Width(colHostW).MaxWidth(colHostW).Render(" HOSTNAME")
		hdrAction := tableHeaderStyle.Width(colActionW).MaxWidth(colActionW).Render(" ACTION")
		hdrPkg := tableHeaderStyle.Width(colPkgW).MaxWidth(colPkgW).Render(" PACKAGE")
		hdrVer := tableHeaderStyle.Width(colVerW).MaxWidth(colVerW).Render(" VERSION DETAILS")

		tableHdr := lipgloss.JoinHorizontal(lipgloss.Left, hdrTime, hdrHost, hdrAction, hdrPkg, hdrVer)

		start := m.historyOffset
		end := m.historyOffset + m.visibleLines - 1
		if end > len(m.historyEvents) {
			end = len(m.historyEvents)
		}

		var rowStrs []string
		if len(m.historyEvents) == 0 {
			rowStrs = append(rowStrs, lipgloss.NewStyle().Foreground(cMuted).Italic(true).Render(" No package change history recorded yet."))
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

		helpText := lipgloss.NewStyle().Foreground(cMuted).Render("[▲/▼] Scroll  |  [Enter] Inspect Full Package Timeline  |  [Esc / Ctrl+Y] Close History View")

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

		modalInnerWidth := m.width - 20
		if modalInnerWidth < 74 {
			modalInnerWidth = 74
		}

		lblStyle := labelFocused.Width(16)

		var bodyContent string
		if m.hostModalTab == 0 {
			vulnSummary := "None detected"
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
			helpBar = "[Ctrl+O] View OSV Advisory  |  " + helpBar
		}

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
			lipgloss.JoinHorizontal(lipgloss.Left, labelAStyle.Render("Host A (Base):   "), m.diffHostAInput.View()),
			formatSuggestions(matchesA),
			"",
			lipgloss.JoinHorizontal(lipgloss.Left, labelBStyle.Render("Host B (Target): "), m.diffHostBInput.View()),
			formatSuggestions(matchesB),
		)

		helpText := lipgloss.NewStyle().Foreground(cMuted).Render("[Tab] Switch Field  |  [Enter] Compare Top Match  |  [Esc] Cancel")

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
		modalOuterW := m.width - 10
		if modalOuterW < 70 {
			modalOuterW = 70
		}

		panelOuterW := (modalOuterW - 9) / 2
		panelInnerW := panelOuterW - 4
		if panelInnerW < 20 {
			panelInnerW = 20
			panelOuterW = panelInnerW + 4
		}

		pkgColW := int(float64(panelInnerW) * 0.58)
		verColW := panelInnerW - pkgColW

		titleBar := titleBadge.Render(fmt.Sprintf(" ⚔️ DIFF: %s vs %s ", m.selectedHostA, m.selectedHostB))

		m.diffFilterInput.Width = modalOuterW - 20
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

		help := lipgloss.NewStyle().Foreground(cMuted).Render("[Ctrl+T] Toggle Diffs Only  |  [Filter] Search  |  [▲/▼] Scroll  |  [Esc] Close")

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
	if m.hasTLS || m.hasPSK {
		secStatus = " 🔒 SECURE "
	}
	sBadge := secBadge.Render(secStatus)

	var osvBadgeStr string
	if m.hasOSV {
		osvBadgeStr = osvBadgeStyle.Render("🛡 OSV")
	}

	var stBadge string
	if !m.loaded {
		stBadge = syncBadge.Render(" ⚡ STREAMING ")
	} else {
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
	if m.flashMsg != "" {
		rightMeta = flashStyle.Render(m.flashMsg) + " " + mText
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
	cw1 := int(float64(availWidth)*0.28) + 2
	cw2 := int(float64(availWidth)*0.40) + 1
	cw3 := availWidth - cw1 - cw2

	m.hostInput.Width = cw1 - 5
	m.pkgInput.Width = cw2 - 5
	m.verInput.Width = cw3 - 5

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

		safeInnerW := cardTotalWidth - 2
		if safeInnerW < 1 {
			safeInnerW = 1
		}

		safeTitleLen := safeInnerW - 6
		if safeTitleLen < 1 {
			safeTitleLen = 1
		}
		safeTitle := truncate(title, safeTitleLen)

		var modeIndicator string
		if isLikelyRegex(query) {
			modeIndicator = regexBadgeActive.Render("[REG]")
		} else {
			modeIndicator = regexBadgeInactive.Render("[TXT]")
		}

		headerLine := lipgloss.JoinHorizontal(lipgloss.Left, lStyle.Render(safeTitle), " ", modeIndicator)
		inputLine := lipgloss.JoinHorizontal(lipgloss.Left, lStyle.Render(promptChar), input.View())

		cardContent := lipgloss.JoinVertical(lipgloss.Left, headerLine, inputLine)

		return bStyle.Width(safeInnerW).Render(cardContent)
	}

	cardHost := renderFilterCard("HOST", m.hostInput, m.focusedInput == 0, m.hostInput.Value(), cw1)
	cardPkg := renderFilterCard("PACKAGE", m.pkgInput, m.focusedInput == 1, m.pkgInput.Value(), cw2)
	cardVer := renderFilterCard("VERSION", m.verInput, m.focusedInput == 2, m.verInput.Value(), cw3)

	filterPanel := lipgloss.JoinHorizontal(lipgloss.Left, cardHost, cardPkg, cardVer)

	// --- MAIN TABLE ---
	tw1 := int(float64(innerWidth) * 0.28)
	tw2 := int(float64(innerWidth) * 0.42)
	tw3 := innerWidth - tw1 - tw2

	hHostText := " HOSTNAME"
	hPkgText := " PACKAGE NAME"
	hVerText := " VERSION"

	indicator := " ▲"
	if m.sortDesc {
		indicator = " ▼"
	}

	switch m.sortCol {
	case SortHostname:
		hHostText += indicator
	case SortPackage:
		hPkgText += indicator
	case SortVersion:
		hVerText += indicator
	}

	hHost := tableHeaderStyle.Width(tw1).MaxWidth(tw1).Render(truncate(hHostText, tw1))
	hPkg := tableHeaderStyle.Width(tw2).MaxWidth(tw2).Render(truncate(hPkgText, tw2))
	hVer := tableHeaderStyle.Width(tw3).MaxWidth(tw3).Render(truncate(hVerText, tw3))

	tableHeader := lipgloss.JoinHorizontal(lipgloss.Left, hHost, hPkg, hVer)

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

		rPkgRaw := " " + item.PkgName
		rVerRaw := " " + item.Version
		if hasVuln {
			rVerRaw += " ⚠️"
		}

		var rHost, rPkg, rVer string
		if isSelected {
			if hasVuln {
				rHost = selectedVulnStyle.Width(tw1).MaxWidth(tw1).Render(truncate(rHostRaw, tw1))
				rPkg = selectedVulnStyle.Width(tw2).MaxWidth(tw2).Render(truncate(rPkgRaw, tw2))
				rVer = selectedVulnStyle.Width(tw3).MaxWidth(tw3).Render(truncate(rVerRaw, tw3))
			} else {
				rHost = selectedStyle.Width(tw1).MaxWidth(tw1).Render(truncate(rHostRaw, tw1))
				rPkg = selectedStyle.Width(tw2).MaxWidth(tw2).Render(truncate(rPkgRaw, tw2))
				rVer = selectedStyle.Width(tw3).MaxWidth(tw3).Render(truncate(rVerRaw, tw3))
			}
		} else {
			if hasVuln {
				rHost = vulnRowStyle.Width(tw1).MaxWidth(tw1).Render(truncate(rHostRaw, tw1))
				rPkg = vulnRowStyle.Width(tw2).MaxWidth(tw2).Render(truncate(rPkgRaw, tw2))
				rVer = vulnRowStyle.Width(tw3).MaxWidth(tw3).Render(truncate(rVerRaw, tw3))
			} else {
				rHost = rowStyleNormal.Width(tw1).MaxWidth(tw1).Render(truncate(rHostRaw, tw1))
				rPkg = rowStyleNormal.Width(tw2).MaxWidth(tw2).Render(truncate(rPkgRaw, tw2))
				rVer = rowStyleNormal.Width(tw3).MaxWidth(tw3).Render(truncate(rVerRaw, tw3))
			}
		}

		rowStrs = append(rowStrs, lipgloss.JoinHorizontal(lipgloss.Left, rHost, rPkg, rVer))
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

	keyHelp := "[Enter] Info  |  [Ctrl+Y] History  |  [Ctrl+D] Diff  |  [Ctrl+S] CSV  |  [Tab] Switch"
	if m.hasOSV {
		vulnTag := "[Ctrl+U] Vulns Only"
		if m.showOnlyVulns {
			vulnTag = "[Ctrl+U] Vulns Only [ACTIVE]"
		}
		keyHelp = vulnTag + "  |  [Ctrl+O] OSV Advisory  |  " + keyHelp
	}
	counterText := fmt.Sprintf("Records: %d-%d / %d (Total: %d)", displayStart, end, len(m.filtered), len(m.allItems))

	footerText := fmt.Sprintf("%s   •   %s", keyHelp, counterText)
	footerContent := truncate(footerText, innerWidth)

	footerBox := footerBoxStyle.Width(innerWidth + 2).Render(footerContent)

	ui := lipgloss.JoinVertical(lipgloss.Left,
		headerCard,
		filterPanel,
		tableFrame,
		footerBox,
	)

	return baseStyle.Render(ui)
}
