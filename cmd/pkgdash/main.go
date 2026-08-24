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

type PackageInfo struct {
	Name    string `json:"name"`
	Version string `json:"version"`
	Arch    string `json:"arch"`
}

type HostPayload struct {
	Hostname     string        `json:"hostname"`
	IPAddress    string        `json:"ip_address,omitempty"`
	OSName       string        `json:"os_name,omitempty"`
	OSVersion    string        `json:"os_version,omitempty"`
	HostFunction string        `json:"host_function,omitempty"`
	Packages     []PackageInfo `json:"packages"`
}

type FlatItem struct {
	Hostname     string
	IPAddress    string
	OSName       string
	OSVersion    string
	HostFunction string
	PkgName      string
	Version      string
	Arch         string
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

	metaStyle = lipgloss.NewStyle().
			Foreground(cMuted).
			Italic(true)

	flashStyle = lipgloss.NewStyle().
			Foreground(cGreen).
			Bold(true)

	filterBoxBlurred = lipgloss.NewStyle().
				Border(lipgloss.NormalBorder()).
				BorderForeground(cBorder).
				Padding(0, 1)

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

	selectedStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color("#11111B")).
			Background(cPink).
			Bold(true)

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
			Padding(1, 4).
			Align(lipgloss.Center)
)

type dataMsg struct {
	items     []FlatItem
	timestamp time.Time
	isDone    bool
}

type model struct {
	hostInput    textinput.Model
	pkgInput     textinput.Model
	verInput     textinput.Model
	focusedInput int

	allItems     []FlatItem
	filtered     []FlatItem
	lastUpdated  time.Time
	width        int
	height       int
	ready        bool
	loaded       bool
	sortCol      SortColumn
	sortDesc     bool
	offset       int
	cursor       int
	visibleLines int

	showAboutModal bool
	showHostModal  bool
	selectedHost   FlatItem

	flashMsg   string
	updateChan chan dataMsg
	hasTLS     bool
	hasPSK     bool
}

func main() {
	servers, psk := getConfig()
	if len(servers) == 0 {
		log.Fatal("No servers found. Set PKGDASH_SERVERS or configure ~/.local/pkgdash.config")
	}

	hi := textinput.New()
	hi.Placeholder = PlaceholderHost
	hi.Focus()

	pi := textinput.New()
	pi.Placeholder = PlaceholderPkg

	vi := textinput.New()
	vi.Placeholder = PlaceholderVer

	updateChan := make(chan dataMsg)

	hasTLS := false
	for _, s := range servers {
		if strings.HasPrefix(s, "https://") {
			hasTLS = true
			break
		}
	}

	m := model{
		hostInput:      hi,
		pkgInput:       pi,
		verInput:       vi,
		focusedInput:   0,
		sortCol:        SortHostname,
		sortDesc:       false,
		offset:         0,
		cursor:         0,
		showAboutModal: false,
		showHostModal:  false,
		loaded:         false,
		updateChan:     updateChan,
		hasTLS:         hasTLS,
		hasPSK:         psk != "",
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

				var localItems []FlatItem
				for _, pkg := range host.Packages {
					localItems = append(localItems, FlatItem{
						Hostname:     host.Hostname,
						IPAddress:    host.IPAddress,
						OSName:       host.OSName,
						OSVersion:    host.OSVersion,
						HostFunction: host.HostFunction,
						PkgName:      pkg.Name,
						Version:      pkg.Version,
						Arch:         pkg.Arch,
					})
				}

				updateChan <- dataMsg{
					items:     localItems,
					timestamp: serverMaxTime,
					isDone:    false,
				}
			}
		}(s)
	}

	go func() {
		wg.Wait()
		updateChan <- dataMsg{isDone: true}
	}()
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

	if err := writer.Write([]string{"Hostname", "Package", "Version", "Architecture"}); err != nil {
		return fmt.Sprintf("Error writing CSV header: %v", err)
	}

	for _, item := range items {
		if err := writer.Write([]string{item.Hostname, item.PkgName, item.Version, item.Arch}); err != nil {
			return fmt.Sprintf("Error writing CSV row: %v", err)
		}
	}

	return fmt.Sprintf("✓ Exported %d records to %s", len(items), filepath.Base(path))
}

func (m model) Init() tea.Cmd {
	return tea.Batch(textinput.Blink, waitForUpdate(m.updateChan))
}

func (m model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	var cmd tea.Cmd

	switch msg := msg.(type) {
	case dataMsg:
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
	}

	if m.showAboutModal || m.showHostModal {
		switch msg := msg.(type) {
		case tea.KeyMsg:
			switch msg.Type {
			case tea.KeyEsc, tea.KeyEnter, tea.KeyCtrlC:
				m.showAboutModal = false
				m.showHostModal = false
			}
		case tea.WindowSizeMsg:
			m.width = msg.Width
			m.height = msg.Height
		}
		return m, nil
	}

	switch msg := msg.(type) {
	case tea.KeyMsg:
		if msg.Type != tea.KeyCtrlS {
			m.flashMsg = ""
		}

		switch msg.Type {
		case tea.KeyEsc:
			return m, tea.Quit
		case tea.KeyEnter:
			if len(m.filtered) > 0 && m.cursor < len(m.filtered) {
				m.selectedHost = m.filtered[m.cursor]
				m.showHostModal = true
			}
			return m, nil
		case tea.KeyCtrlC:
			m.showAboutModal = true
			return m, nil
		case tea.KeyCtrlS:
			m.flashMsg = saveCSV(m.filtered)
			return m, nil

		case tea.KeyTab:
			m.switchFocus(m.focusedInput + 1)
			return m, nil
		case tea.KeyShiftTab:
			m.switchFocus(m.focusedInput - 1)
			return m, nil

		case tea.KeyUp, tea.KeyCtrlK:
			m.cursor--
			m.updateViewport()
			return m, nil

		case tea.KeyDown, tea.KeyCtrlJ:
			m.cursor++
			m.updateViewport()
			return m, nil

		case tea.KeyPgUp:
			m.cursor -= m.visibleLines
			m.updateViewport()
			return m, nil

		case tea.KeyPgDown:
			m.cursor += m.visibleLines
			m.updateViewport()
			return m, nil

		case tea.KeyCtrlH:
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

		case tea.KeyCtrlP:
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

		case tea.KeyCtrlV:
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

	if hQuery == "" && pQuery == "" && vQuery == "" {
		m.filtered = m.allItems
		return
	}

	hMatch := createFieldMatcher(hQuery)
	pMatch := createFieldMatcher(pQuery)
	vMatch := createFieldMatcher(vQuery)

	var filtered []FlatItem
	for _, item := range m.allItems {
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

	for _, item := range m.filtered {
		if strings.EqualFold(item.PkgName, selectedPkg) {
			hostMap[item.Hostname] = true
			versionMap[item.Version] = true
		}
	}

	isFiltered := len(m.filtered) < len(m.allItems)
	filterTag := ""
	if isFiltered {
		filterTag = " (filtered search results)"
	}

	return fmt.Sprintf("📊 Fleet Insights%s: '%s' is present on %d host(s) across %d unique version(s)",
		filterTag, selectedPkg, len(hostMap), len(versionMap))
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

	if m.showHostModal {
		osStr := strings.TrimSpace(m.selectedHost.OSName + " " + m.selectedHost.OSVersion)
		if osStr == "" {
			osStr = "Onbekend"
		}
		fnStr := m.selectedHost.HostFunction
		if fnStr == "" {
			fnStr = "-"
		}
		ipStr := m.selectedHost.IPAddress
		if ipStr == "" {
			ipStr = "Onbekend"
		}

		hostTitle := fmt.Sprintf(" HOST INFORMATION: %s ", m.selectedHost.Hostname)

		details := lipgloss.JoinVertical(lipgloss.Left,
			lipgloss.JoinHorizontal(lipgloss.Left, labelFocused.Render("Hostname:      "), rowStyleNormal.Render(m.selectedHost.Hostname)),
			lipgloss.JoinHorizontal(lipgloss.Left, labelFocused.Render("IP Address:    "), rowStyleNormal.Render(ipStr)),
			lipgloss.JoinHorizontal(lipgloss.Left, labelFocused.Render("OS:            "), rowStyleNormal.Render(osStr)),
			lipgloss.JoinHorizontal(lipgloss.Left, labelFocused.Render("Host Function: "), rowStyleNormal.Render(fnStr)),
		)

		modalContent := lipgloss.JoinVertical(lipgloss.Center,
			titleBadge.Render(hostTitle),
			"",
			details,
			"",
			lipgloss.NewStyle().Foreground(cMuted).Render("[Press Esc or Enter to close]"),
		)
		dialog := modalStyle.Render(modalContent)
		return lipgloss.Place(m.width, m.height, lipgloss.Center, lipgloss.Center, dialog)
	}

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

	leftBadges := lipgloss.JoinHorizontal(lipgloss.Center, tBadge, " ", sBadge, " ", stBadge)
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
	cw1 := int(float64(availWidth) * 0.28)
	cw2 := int(float64(availWidth) * 0.40)
	cw3 := availWidth - cw1 - cw2 - 3

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

		safeInnerW := cardTotalWidth - 4
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

		return bStyle.Render(cardContent)
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

		rHostRaw := "  " + item.Hostname
		if isSelected {
			rHostRaw = "❯ " + item.Hostname
		}

		rPkgRaw := " " + item.PkgName
		rVerRaw := " " + item.Version

		var rHost, rPkg, rVer string
		if isSelected {
			rHost = selectedStyle.Width(tw1).MaxWidth(tw1).Render(truncate(rHostRaw, tw1))
			rPkg = selectedStyle.Width(tw2).MaxWidth(tw2).Render(truncate(rPkgRaw, tw2))
			rVer = selectedStyle.Width(tw3).MaxWidth(tw3).Render(truncate(rVerRaw, tw3))
		} else {
			rHost = rowStyleNormal.Width(tw1).MaxWidth(tw1).Render(truncate(rHostRaw, tw1))
			rPkg = rowStyleNormal.Width(tw2).MaxWidth(tw2).Render(truncate(rPkgRaw, tw2))
			rVer = rowStyleNormal.Width(tw3).MaxWidth(tw3).Render(truncate(rVerRaw, tw3))
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

	keyHelp := "[Enter] Host Info  |  [Tab] Switch Filter  |  [Ctrl+H/P/V] Sort  |  [Ctrl+S] Export CSV"
	counterText := fmt.Sprintf("Records: %d-%d / %d (Total: %d)", displayStart, end, len(m.filtered), len(m.allItems))

	footerText := fmt.Sprintf("%s  •  %s", keyHelp, counterText)
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
