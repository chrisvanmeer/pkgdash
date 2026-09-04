package main

import (
	"bufio"
	"compress/gzip"
	"crypto/tls"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"html/template"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
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

var (
	globalItems   []FlatItem
	lastUpdated   time.Time
	dataMutex     sync.RWMutex
	serversConfig []string
	pskConfig     string
	webPort       string = ":8080"
	hasOSVGlobal  bool
)

func main() {
	serversConfig, pskConfig = getConfig()
	if len(serversConfig) == 0 {
		log.Fatal("No servers found. Set PKGDASH_SERVERS or configure ~/.local/pkgdash.config")
	}

	// Start background data synchronization loop (polls backend every 15 seconds)
	go func() {
		for {
			fetchAllData(serversConfig, pskConfig)
			time.Sleep(15 * time.Second)
		}
	}()

	// Brief initial pause to populate cache
	time.Sleep(500 * time.Millisecond)

	http.HandleFunc("/", handleIndex)
	http.HandleFunc("/table", handleTable)
	http.HandleFunc("/modal/host", handleHostModal)
	http.HandleFunc("/modal/host/history", handleHostHistoryModal)
	http.HandleFunc("/modal/package/history", handlePackageHistoryModal)
	http.HandleFunc("/modal/timeline", handleTimelineModal)
	http.HandleFunc("/modal/diff", handleDiffModal)
	http.HandleFunc("/modal/osv", handleOSVModal)
	http.HandleFunc("/diff/results", handleDiffResults)
	http.HandleFunc("/export/csv", handleExportCSV)
	http.HandleFunc("/export/ini", handleExportINI)

	fmt.Printf("🚀 Starting pkgdash-web on http://localhost%s\n", webPort)
	log.Fatal(http.ListenAndServe(webPort, nil))
}

func getConfig() ([]string, string) {
	var servers []string
	psk := os.Getenv("PKGDASH_PSK")

	if envServers := os.Getenv("PKGDASH_SERVERS"); envServers != "" {
		servers = strings.Split(envServers, ",")
	}
	if envPort := os.Getenv("PKGDASH_WEB_PORT"); envPort != "" {
		if !strings.HasPrefix(envPort, ":") {
			webPort = ":" + envPort
		} else {
			webPort = envPort
		}
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
				} else if strings.HasPrefix(strings.ToLower(line), "web_port=") {
					portVal := line[9:]
					if !strings.HasPrefix(portVal, ":") {
						webPort = ":" + portVal
					} else {
						webPort = portVal
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

func fetchAllData(servers []string, psk string) {
	var wg sync.WaitGroup
	var allItems []FlatItem
	var latestTime time.Time
	var itemsMutex sync.Mutex
	osvDetected := false

	customTransport := &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}
	client := http.Client{Timeout: 15 * time.Second, Transport: customTransport}

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
			if err != nil || resp.StatusCode != 200 {
				return
			}
			defer func() { _ = resp.Body.Close() }()

			osvHeaderActive := strings.EqualFold(resp.Header.Get("X-OSV-Enabled"), "true")
			if osvHeaderActive {
				itemsMutex.Lock()
				osvDetected = true
				itemsMutex.Unlock()
			}

			var reader io.Reader = resp.Body
			if resp.Header.Get("Content-Encoding") == "gzip" {
				if gz, err := gzip.NewReader(resp.Body); err == nil {
					defer func() { _ = gz.Close() }()
					reader = gz
				}
			}

			if lastMod := resp.Header.Get("Last-Modified"); lastMod != "" {
				if parsedTime, err := time.Parse(http.TimeFormat, lastMod); err == nil {
					itemsMutex.Lock()
					if parsedTime.After(latestTime) {
						latestTime = parsedTime
					}
					itemsMutex.Unlock()
				}
			}

			var payload []HostPayload
			if err := json.NewDecoder(reader).Decode(&payload); err == nil {
				var localItems []FlatItem
				for _, host := range payload {
					isOSV := osvHeaderActive || host.OSVEnabled
					if isOSV {
						itemsMutex.Lock()
						osvDetected = true
						itemsMutex.Unlock()
					}

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
				}
				itemsMutex.Lock()
				allItems = append(allItems, localItems...)
				itemsMutex.Unlock()
			}
		}(s)
	}

	wg.Wait()
	if len(allItems) > 0 {
		dataMutex.Lock()
		globalItems = allItems
		hasOSVGlobal = osvDetected
		if !latestTime.IsZero() {
			lastUpdated = latestTime
		} else {
			lastUpdated = time.Now()
		}
		dataMutex.Unlock()
	}
}

func fetchHistoryFromDaemons(hostname, pkgName string) []ChangeEvent {
	var allEvents []ChangeEvent
	customTransport := &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}
	client := http.Client{Timeout: 5 * time.Second, Transport: customTransport}

	dataMutex.RLock()
	servers, psk := serversConfig, pskConfig
	dataMutex.RUnlock()

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
		if err != nil || resp.StatusCode != 200 {
			continue
		}

		var evts []ChangeEvent
		if err := json.NewDecoder(resp.Body).Decode(&evts); err == nil {
			allEvents = append(allEvents, evts...)
		}
		_ = resp.Body.Close()
	}

	sort.Slice(allEvents, func(i, j int) bool {
		return allEvents[i].Timestamp.After(allEvents[j].Timestamp)
	})

	return allEvents
}

// --- HTTP Handlers ---

func handleIndex(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}

	isSecure := r.TLS != nil || strings.EqualFold(r.Header.Get("X-Forwarded-Proto"), "https")
	secStatus := "🔓 HTTP"
	if isSecure {
		secStatus = "🔒 SECURE"
	}

	dataMutex.RLock()
	hasOSV := hasOSVGlobal
	dataMutex.RUnlock()

	_ = tmpl.ExecuteTemplate(w, "index", map[string]interface{}{
		"LastUpdated": lastUpdated.Local().Format("15:04:05"),
		"SecStatus":   secStatus,
		"HasOSV":      hasOSV,
	})
}

func filterAndSort(r *http.Request) ([]FlatItem, int, int, int) {
	dataMutex.RLock()
	defer dataMutex.RUnlock()

	hostQuery := strings.TrimSpace(r.URL.Query().Get("host"))
	pkgQuery := strings.TrimSpace(r.URL.Query().Get("pkg"))
	verQuery := strings.TrimSpace(r.URL.Query().Get("ver"))
	vulnOnly := r.URL.Query().Get("vulnOnly") == "true"

	hMatch := createFieldMatcher(hostQuery)
	pMatch := createFieldMatcher(pkgQuery)
	vMatch := createFieldMatcher(verQuery)

	var filtered []FlatItem
	hostMap := make(map[string]bool)
	verMap := make(map[string]bool)
	vulnCount := 0

	for _, item := range globalItems {
		if vulnOnly && len(item.Vulnerabilities) == 0 {
			continue
		}
		if hMatch(item.Hostname) && pMatch(item.PkgName) && vMatch(item.Version) {
			filtered = append(filtered, item)
			hostMap[item.Hostname] = true
			verMap[item.Version] = true
			if len(item.Vulnerabilities) > vulnCount {
				vulnCount = len(item.Vulnerabilities)
			}
		}
	}

	sortCol := r.URL.Query().Get("sort")
	sortDesc := r.URL.Query().Get("desc") == "true"

	sort.Slice(filtered, func(i, j int) bool {
		a, b := filtered[i], filtered[j]
		ah, bh := strings.ToLower(a.Hostname), strings.ToLower(b.Hostname)
		ap, bp := strings.ToLower(a.PkgName), strings.ToLower(b.PkgName)
		av, bv := a.Version, b.Version

		var primaryLess, primaryEqual bool
		switch sortCol {
		case "pkg":
			primaryLess, primaryEqual = ap < bp, ap == bp
		case "ver":
			primaryLess, primaryEqual = av < bv, av == bv
		default:
			primaryLess, primaryEqual = ah < bh, ah == bh
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
		if sortDesc {
			return !primaryLess
		}
		return primaryLess
	})

	return filtered, len(hostMap), len(verMap), vulnCount
}

func handleTable(w http.ResponseWriter, r *http.Request) {
	filtered, hCount, vCount, vulnCount := filterAndSort(r)

	pageStr := r.URL.Query().Get("page")
	page := 1
	if p, err := strconv.Atoi(pageStr); err == nil && p > 0 {
		page = p
	}

	pageSize := 1000

	start := (page - 1) * pageSize
	end := start + pageSize

	if start >= len(filtered) && len(filtered) > 0 {
		return
	}
	if end > len(filtered) {
		end = len(filtered)
	}

	var displayItems []FlatItem
	if len(filtered) > 0 {
		displayItems = filtered[start:end]
	}

	hasNext := end < len(filtered)

	stats := ""
	dataMutex.RLock()
	hasOSV := hasOSVGlobal
	dataMutex.RUnlock()

	if r.URL.Query().Get("pkg") != "" && len(filtered) > 0 {
		vulnText := ""
		if hasOSV && vulnCount > 0 {
			vulnText = fmt.Sprintf(" ⚠️ %d Vulnerability/CVE(s) flagged", vulnCount)
		}
		stats = fmt.Sprintf("📊 Fleet Insights: '%s' is present on %d host(s) across %d unique version(s)%s", r.URL.Query().Get("pkg"), hCount, vCount, vulnText)
	}

	sortCol := r.URL.Query().Get("sort")
	if sortCol == "" {
		sortCol = "host"
	}
	sortDesc := r.URL.Query().Get("desc") == "true"

	dataMutex.RLock()
	totalCount := len(globalItems)
	dataMutex.RUnlock()

	data := map[string]interface{}{
		"Items":          displayItems,
		"HasNext":        hasNext,
		"NextPage":       page + 1,
		"Stats":          stats,
		"TotalCount":     totalCount,
		"FilteredCount":  len(filtered),
		"DisplayedCount": end,
		"SortCol":        sortCol,
		"SortDesc":       sortDesc,
		"HasOSV":         hasOSV,
	}

	if page > 1 {
		_ = tmpl.ExecuteTemplate(w, "table_rows", data)
	} else {
		_ = tmpl.ExecuteTemplate(w, "table", data)
	}
}

func handleHostModal(w http.ResponseWriter, r *http.Request) {
	hostname := r.URL.Query().Get("h")
	pkgName := r.URL.Query().Get("p")
	var host FlatItem
	dataMutex.RLock()
	hasOSV := hasOSVGlobal
	for _, item := range globalItems {
		if item.Hostname == hostname && (pkgName == "" || item.PkgName == pkgName) {
			host = item
			break
		}
	}
	dataMutex.RUnlock()

	vulnSummary := "None detected"
	if len(host.Vulnerabilities) > 0 {
		var ids []string
		for _, v := range host.Vulnerabilities {
			if len(v.CVE) > 0 {
				ids = append(ids, v.CVE[0])
			} else {
				ids = append(ids, v.ID)
			}
		}
		if len(ids) > 2 {
			vulnSummary = fmt.Sprintf("⚠️ %d flagged (%s, +%d more)", len(host.Vulnerabilities), strings.Join(ids[:2], ", "), len(ids)-2)
		} else {
			vulnSummary = fmt.Sprintf("⚠️ %d flagged (%s)", len(host.Vulnerabilities), strings.Join(ids, ", "))
		}
	}

	_ = tmpl.ExecuteTemplate(w, "modal_host", map[string]interface{}{
		"Host":        host,
		"HasOSV":      hasOSV || host.OSVEnabled,
		"VulnSummary": vulnSummary,
	})
}

func handleHostHistoryModal(w http.ResponseWriter, r *http.Request) {
	hostname := r.URL.Query().Get("h")
	events := fetchHistoryFromDaemons(hostname, "")
	_ = tmpl.ExecuteTemplate(w, "modal_host_history", map[string]interface{}{
		"Hostname": hostname,
		"Events":   events,
	})
}

func handlePackageHistoryModal(w http.ResponseWriter, r *http.Request) {
	hostname := r.URL.Query().Get("h")
	pkgName := r.URL.Query().Get("p")

	events := fetchHistoryFromDaemons(hostname, pkgName)
	_ = tmpl.ExecuteTemplate(w, "modal_package_history", map[string]interface{}{
		"Hostname": hostname,
		"Package":  pkgName,
		"Events":   events,
	})
}

func handleTimelineModal(w http.ResponseWriter, r *http.Request) {
	events := fetchHistoryFromDaemons("", "")
	_ = tmpl.ExecuteTemplate(w, "modal_timeline", events)
}

func handleOSVModal(w http.ResponseWriter, r *http.Request) {
	hostname := r.URL.Query().Get("h")
	pkgName := r.URL.Query().Get("p")

	var selectedItem FlatItem
	dataMutex.RLock()
	for _, item := range globalItems {
		if item.Hostname == hostname && item.PkgName == pkgName {
			selectedItem = item
			break
		}
	}
	dataMutex.RUnlock()

	_ = tmpl.ExecuteTemplate(w, "modal_osv", map[string]interface{}{
		"Hostname":        hostname,
		"Package":         pkgName,
		"Version":         selectedItem.Version,
		"Vulnerabilities": selectedItem.Vulnerabilities,
	})
}

func handleDiffModal(w http.ResponseWriter, r *http.Request) {
	dataMutex.RLock()
	hostMap := make(map[string]bool)
	for _, item := range globalItems {
		hostMap[item.Hostname] = true
	}
	dataMutex.RUnlock()

	var hosts []string
	for h := range hostMap {
		hosts = append(hosts, h)
	}
	sort.Strings(hosts)

	_ = tmpl.ExecuteTemplate(w, "modal_diff", map[string]interface{}{"Hosts": hosts})
}

func handleDiffResults(w http.ResponseWriter, r *http.Request) {
	hostA := r.URL.Query().Get("hostA")
	hostB := r.URL.Query().Get("hostB")
	filter := strings.ToLower(strings.TrimSpace(r.URL.Query().Get("filter")))
	diffOnly := r.URL.Query().Get("diffOnly") == "on"

	if hostA == "" || hostB == "" || hostA == hostB {
		_, _ = w.Write([]byte(`<div class="text-pink text-center mt-3" style="text-align:center; margin-top:1rem;">Please select two different hosts.</div>`))
		return
	}

	pkgsA, pkgsB := make(map[string]string), make(map[string]string)
	allPkgs := make(map[string]bool)

	dataMutex.RLock()
	for _, item := range globalItems {
		if strings.EqualFold(item.Hostname, hostA) {
			pkgsA[item.PkgName] = item.Version
			allPkgs[item.PkgName] = true
		}
		if strings.EqualFold(item.Hostname, hostB) {
			pkgsB[item.PkgName] = item.Version
			allPkgs[item.PkgName] = true
		}
	}
	dataMutex.RUnlock()

	var pNames []string
	for p := range allPkgs {
		pNames = append(pNames, p)
	}
	sort.Strings(pNames)

	var rows []DiffRow
	diffCount := 0
	for _, name := range pNames {
		vA, hasA := pkgsA[name]
		if !hasA {
			vA = "-"
		}
		vB, hasB := pkgsB[name]
		if !hasB {
			vB = "-"
		}
		isDiff := vA != vB
		if isDiff {
			diffCount++
		}

		if diffOnly && !isDiff {
			continue
		}
		if filter != "" && !strings.Contains(strings.ToLower(name), filter) && !strings.Contains(strings.ToLower(vA), filter) && !strings.Contains(strings.ToLower(vB), filter) {
			continue
		}

		rows = append(rows, DiffRow{PkgName: name, VersionA: vA, VersionB: vB, IsDiff: isDiff})
	}

	stats := fmt.Sprintf("📊 Comparison: %d differences out of %d total packages", diffCount, len(allPkgs))

	_ = tmpl.ExecuteTemplate(w, "diff_table", map[string]interface{}{
		"HostA": hostA, "HostB": hostB, "Rows": rows, "Stats": stats,
	})
}

func handleExportCSV(w http.ResponseWriter, r *http.Request) {
	filtered, _, _, _ := filterAndSort(r)
	w.Header().Set("Content-Type", "text/csv")
	w.Header().Set("Content-Disposition", "attachment;filename=pkgdash_export.csv")
	writer := csv.NewWriter(w)
	_ = writer.Write([]string{"Hostname", "Package", "Version", "Architecture", "CVE_Count"})
	for _, i := range filtered {
		cveCount := strconv.Itoa(len(i.Vulnerabilities))
		_ = writer.Write([]string{i.Hostname, i.PkgName, i.Version, i.Arch, cveCount})
	}
	writer.Flush()
}

func handleExportINI(w http.ResponseWriter, r *http.Request) {
	filtered, _, _, _ := filterAndSort(r)
	hostMap := make(map[string]bool)
	for _, item := range filtered {
		if item.Hostname != "" {
			hostMap[item.Hostname] = true
		}
	}
	var hosts []string
	for h := range hostMap {
		hosts = append(hosts, h)
	}
	sort.Strings(hosts)

	w.Header().Set("Content-Type", "text/plain")
	w.Header().Set("Content-Disposition", "attachment;filename=inventory.ini")
	_, _ = w.Write([]byte("[all]\n"))
	for _, h := range hosts {
		_, _ = w.Write([]byte(h))
		_, _ = w.Write([]byte("\n"))
	}
}

func createFieldMatcher(query string) func(string) bool {
	if query == "" {
		return func(s string) bool { return true }
	}
	if isLikelyRegex(query) {
		if re, err := regexp.Compile("(?i)" + query); err == nil {
			return func(s string) bool { return re.MatchString(s) }
		}
	}
	terms := strings.Fields(strings.ToLower(query))
	return func(s string) bool {
		sLower := strings.ToLower(s)
		for _, t := range terms {
			if !strings.Contains(sLower, t) {
				return false
			}
		}
		return true
	}
}

func isLikelyRegex(query string) bool {
	for _, char := range []string{"^", "$", "*", "+", "?", "[", "]", "(", ")", "{", "}", "|", "\\"} {
		if strings.Contains(query, char) {
			return true
		}
	}
	return false
}

// --- HTML TEMPLATES ---
var tmpl = template.Must(template.New("").Funcs(template.FuncMap{
	"isRegex": func(q string) string {
		if isLikelyRegex(q) {
			return "[REG]"
		}
		return "[TXT]"
	},
	"formatTime": func(t time.Time) string {
		return t.Local().Format("2006-01-02 15:04:05")
	},
	"cleanURL": func(rawURL string) string {
		return strings.Replace(rawURL, "https://osv.dev/vulnerabilities/", "https://osv.dev/vulnerability/", 1)
	},
	"joinCVE": func(cves []string) string {
		if len(cves) == 0 {
			return ""
		}
		return " (" + strings.Join(cves, ", ") + ")"
	},
}).Parse(`
{{define "index"}}
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Pkgdash Web</title>
    <!-- Embedded SVG Favicon -->
    <link rel="icon" href="data:image/svg+xml,<svg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 100 100'><text y='.9em' font-size='90'>📦</text></svg>">
    <script src="https://unpkg.com/htmx.org@1.9.10"></script>
    <style>
        :root {
            --bg: #1e1e2e; --surface: #313244; --border: #45475A;
            --text: #CDD6F4; --muted: #6C7086; --purple: #7D56F4;
            --cyan: #04D9D9; --pink: #FF79C6; --green: #50FA7B;
            --yellow: #F1FA8C; --red: #FF5555; --dark-text: #11111B;
        }

        /* Unified Flex Layout */
        body {
            background: var(--bg);
            color: var(--text);
            font-family: 'Fira Code', Consolas, monospace;
            margin: 0;
            padding: 1rem;
            line-height: 1.4;
            font-size: 14px;
            height: 100vh;
            display: flex;
            flex-direction: column;
            box-sizing: border-box;
            gap: 1rem;
        }

        .panel { border: 2px solid var(--border); border-radius: 8px; padding: 0.5rem; }
        .header-panel { border-color: var(--purple); display: flex; justify-content: space-between; align-items: center; flex-shrink: 0; }
        .badge { padding: 0.1rem 0.5rem; font-weight: bold; color: var(--dark-text); display: inline-block; margin-right: 0.5rem; }
        .bg-purple { background: var(--purple); } 
        .bg-cyan { background: var(--cyan); } 
        .bg-green { background: var(--green); } 
        .bg-yellow { background: var(--yellow); } 
        .bg-red { background: var(--red); color: white; }

        .flex { display: flex; gap: 1rem; flex-shrink: 0; }
        .filter-card { flex: 1; border: 1px solid var(--border); border-radius: 4px; padding: 0.5rem; transition: border 0.2s; }
        .filter-card:focus-within { border-color: var(--pink); }
        .filter-card:focus-within .f-label { color: var(--pink); font-weight: bold; }
        .f-label { color: var(--muted); margin-bottom: 0.3rem; display: flex; justify-content: space-between; }
        .f-input-wrapper { display: flex; color: var(--muted); }
        .filter-card:focus-within .f-input-wrapper { color: var(--pink); }
        input[type="text"] { background: transparent; border: none; color: var(--text); font-family: inherit; width: 100%; outline: none; margin-left: 0.5rem; }

        #filter-form { margin: 0; }

        /* Main table container */
        #table-container { flex: 1; overflow-y: auto; overflow-x: hidden; padding: 0; position: relative; }

        table { width: 100%; border-collapse: collapse; table-layout: fixed; }

        /* Sticky table headers */
        th {
            background: var(--surface);
            color: var(--text);
            padding: 0.5rem;
            text-align: left;
            cursor: pointer;
            user-select: none;
            position: sticky;
            top: 0;
            z-index: 10;
            box-shadow: 0 2px 2px rgba(0,0,0,0.1);
        }

        td { padding: 0.3rem 0.5rem; white-space: nowrap; overflow: hidden; text-overflow: ellipsis; }
        tr:hover td { background: var(--pink); color: var(--dark-text); cursor: pointer; }
        tr.vuln-row td { color: var(--red); }
        tr.vuln-row:hover td { background: var(--red); color: white; }

        .insights { color: var(--cyan); font-style: italic; padding: 0.5rem; border-top: 1px solid var(--border); position: sticky; bottom: 0; background: var(--bg); z-index: 10;}
        .footer { border: 2px solid var(--border); border-radius: 8px; padding: 0.5rem; color: var(--muted); display: flex; justify-content: space-between; flex-shrink: 0; }

        .btn-link { color: var(--muted); text-decoration: none; cursor: pointer; padding: 0 0.5rem; }
        .btn-link:hover { color: var(--pink); }
        .btn-link.active { color: var(--red); font-weight: bold; }

        /* Modals - Bounded width */
        dialog { background: var(--bg); color: var(--text); border: 3px double var(--purple); border-radius: 8px; padding: 1.5rem; width: 100%; box-shadow: 0 10px 30px rgba(0,0,0,0.5); }
        dialog#diffModal, dialog#timelineModal, dialog#hostModal, dialog#osvModal, dialog#packageHistoryModal { max-width: 1000px; }
        dialog#aboutModal { max-width: 600px; }
        dialog::backdrop { background: rgba(0,0,0,0.7); }
        .modal-header { font-weight: bold; margin-bottom: 1rem; text-align: center; }
        .text-pink { color: var(--pink); } .text-cyan { color: var(--cyan); } .text-red { color: var(--red); font-weight: bold; }
        select { background: var(--surface); color: var(--text); border: 1px solid var(--border); padding: 0.3rem; font-family: inherit; width: 100%; margin-bottom: 1rem; outline: none; }
        button { background: var(--surface); color: var(--text); border: 1px solid var(--border); padding: 0.4rem 1rem; cursor: pointer; font-family: inherit; }
        button:hover { background: var(--pink); color: var(--dark-text); }

        .tab-btn { background: transparent; border: 1px solid var(--border); color: var(--muted); padding: 0.4rem 1rem; margin-right: 0.5rem; cursor: pointer; }
        .tab-btn.active { border-color: var(--pink); color: var(--pink); font-weight: bold; background: var(--surface); }

        /* Diff Table specific */
        .diff-table { font-size: 13px; }
        .diff-table th { background: var(--bg); border-bottom: 2px solid var(--border); box-shadow: none; }
        .diff-table td { border-bottom: 1px solid #313244; }
        .diff-table tr.is-diff td.diff-col { font-weight: bold; }
        .diff-table tr.is-diff td.diff-col-a { color: var(--cyan); }
        .diff-table tr.is-diff td.diff-col-b { color: var(--pink); }

        /* Audit History & Vulnerability Tables */
        .history-table { width: 100%; font-size: 13px; border-collapse: collapse; table-layout: fixed; }
        .history-table th { background: var(--surface); padding: 0.5rem; text-align: left; border-bottom: 2px solid var(--border); }
        .history-table td { padding: 0.4rem 0.5rem; border-bottom: 1px solid var(--surface); white-space: nowrap; overflow: hidden; text-overflow: ellipsis; }
        .history-table tbody tr:hover td { background: var(--pink); color: var(--dark-text); cursor: pointer; }

        .osv-item { border-bottom: 1px solid var(--border); padding: 0.75rem 0; }
        .osv-item:last-child { border-bottom: none; }
        .osv-link { color: var(--cyan); text-decoration: underline; }
        .osv-link:hover { color: var(--pink); }
    </style>
</head>
<body>

    <!-- Header Panel -->
    <div class="panel header-panel">
        <div>
            <span class="badge bg-purple"> 📦 PKGDASH-WEB </span>
            <span class="badge bg-cyan"> {{.SecStatus}} </span>
            {{if .HasOSV}}<span class="badge bg-red">🛡 OSV</span>{{end}}
            <span class="badge bg-green"> ✓ SYNCED </span>
        </div>
        <div class="text-muted" style="font-style: italic;">
            Updated: <span id="last-updated">{{.LastUpdated}}</span>
        </div>
    </div>

    <!-- Filter Form -->
    <form id="filter-form" class="flex">
        <input type="hidden" name="sort" id="sort-col" value="host">
        <input type="hidden" name="desc" id="sort-desc" value="false">
        <input type="hidden" name="vulnOnly" id="vulnOnlyHidden" value="false">

        <div class="filter-card">
            <div class="f-label"><span>HOST</span> <span class="indicator">[TXT]</span></div>
            <div class="f-input-wrapper">❯ <input type="text" name="host" placeholder="Filter hostname..." autofocus hx-get="/table" hx-target="#table-container" hx-include="#filter-form" hx-trigger="keyup changed delay:250ms"></div>
        </div>
        <div class="filter-card">
            <div class="f-label"><span>PACKAGE</span> <span class="indicator">[TXT]</span></div>
            <div class="f-input-wrapper">❯ <input type="text" name="pkg" placeholder="Filter package..." hx-get="/table" hx-target="#table-container" hx-include="#filter-form" hx-trigger="keyup changed delay:250ms"></div>
        </div>
        <div class="filter-card">
            <div class="f-label"><span>VERSION</span> <span class="indicator">[TXT]</span></div>
            <div class="f-input-wrapper">❯ <input type="text" name="ver" placeholder="Filter version..." hx-get="/table" hx-target="#table-container" hx-include="#filter-form" hx-trigger="keyup changed delay:250ms"></div>
        </div>
    </form>

    <!-- Main Table Container -->
    <div class="panel" id="table-container" hx-get="/table" hx-trigger="load">
        <!-- Loaded via HTMX -->
    </div>

    <!-- Footer -->
    <div class="footer">
        <div>
            <a class="btn-link" onclick="document.getElementById('aboutModal').showModal()">[About]</a> |
            <a class="btn-link" hx-get="/modal/timeline" hx-target="#timeline-dialog-content" onclick="document.getElementById('timelineModal').showModal()">[Ctrl+Y] Timeline</a> |
            <a class="btn-link" hx-get="/modal/diff" hx-target="#diff-dialog-content" onclick="document.getElementById('diffModal').showModal()">[Ctrl+D] Diff</a> |
            <a class="btn-link" href="#" onclick="exportFile('/export/ini')">[Ctrl+E] Export INI</a> |
            <a class="btn-link" href="#" onclick="exportFile('/export/csv')">[Ctrl+S] Export CSV</a>
            {{if .HasOSV}}
            | <a class="btn-link" href="#" id="vuln-toggle-btn" onclick="toggleVulns()">[Ctrl+U] Vulns Only</a>
            {{end}}
        </div>
        <div id="record-count">Records: 0 / 0</div>
    </div>

    <!-- Modals -->
    <dialog id="aboutModal">
        <div class="modal-header"><span class="badge bg-purple"> PKGDASH CONTROL CENTER </span></div>
        <div style="text-align: center; margin-bottom: 2rem;">
            Designed & Developed by Chris van Meer<br>
            High-Performance Fleet Package Inventory (Web Edition)<br>
            <span class="text-muted">© 2026 • All rights reserved</span>
        </div>
        <div style="text-align: center;"><button type="button" onclick="this.closest('dialog').close()">[Close]</button></div>
    </dialog>

    <dialog id="hostModal">
        <div id="host-dialog-content"></div>
        <div style="text-align: center; margin-top: 1rem;"><button type="button" onclick="this.closest('dialog').close()">[Close]</button></div>
    </dialog>

    <dialog id="osvModal">
        <div id="osv-dialog-content"></div>
        <div style="text-align: center; margin-top: 1rem;"><button type="button" onclick="this.closest('dialog').close()">[Close]</button></div>
    </dialog>

    <dialog id="packageHistoryModal">
        <div id="pkg-history-dialog-content"></div>
        <div style="text-align: center; margin-top: 1rem;"><button type="button" onclick="this.closest('dialog').close()">[Close]</button></div>
    </dialog>

    <dialog id="diffModal">
        <div id="diff-dialog-content"></div>
    </dialog>

    <dialog id="timelineModal">
        <div id="timeline-dialog-content"></div>
        <div style="text-align: center; margin-top: 1rem;"><button type="button" onclick="this.closest('dialog').close()">[Close]</button></div>
    </dialog>

    <script>
        function exportFile(endpoint) {
            const formData = new FormData(document.getElementById('filter-form'));
            const params = new URLSearchParams(formData).toString();
            window.location.href = endpoint + '?' + params;
        }

        function toggleVulns() {
            const hidden = document.getElementById('vulnOnlyHidden');
            const btn = document.getElementById('vuln-toggle-btn');
            if (hidden.value === "true") {
                hidden.value = "false";
                btn.innerHTML = "[Ctrl+U] Vulns Only";
                btn.classList.remove('active');
            } else {
                hidden.value = "true";
                btn.innerHTML = "[Ctrl+U] Vulns Only [ACTIVE]";
                btn.classList.add('active');
            }
            htmx.ajax('GET', '/table', {target: '#table-container', source: '#filter-form'});
        }

        // Global Keyboard Shortcuts (Ctrl+Y, Ctrl+D, Ctrl+S, Ctrl+E, Ctrl+U)
        document.addEventListener('keydown', function(e) {
            if (e.ctrlKey || e.metaKey) {
                const key = e.key.toLowerCase();
                if (key === 'y') {
                    e.preventDefault();
                    htmx.ajax('GET', '/modal/timeline', {target: '#timeline-dialog-content'});
                    document.getElementById('timelineModal').showModal();
                } else if (key === 'd') {
                    e.preventDefault();
                    htmx.ajax('GET', '/modal/diff', {target: '#diff-dialog-content'});
                    document.getElementById('diffModal').showModal();
                } else if (key === 's') {
                    e.preventDefault();
                    exportFile('/export/csv');
                } else if (key === 'e') {
                    e.preventDefault();
                    exportFile('/export/ini');
                } else if (key === 'u') {
                    e.preventDefault();
                    if (document.getElementById('vulnOnlyHidden')) {
                        toggleVulns();
                    }
                }
            }
        });

        // Handle Table Sorting
        document.body.addEventListener('click', function(evt) {
            if (evt.target.matches('th[data-sort]')) {
                const sortInput = document.getElementById('sort-col');
                const descInput = document.getElementById('sort-desc');
                const col = evt.target.getAttribute('data-sort');

                if (sortInput.value === col) {
                    descInput.value = descInput.value === "true" ? "false" : "true";
                } else {
                    sortInput.value = col;
                    descInput.value = "false";
                }
                htmx.ajax('GET', '/table', {target: '#table-container', source: '#filter-form'});
            }
        });

        // Regex indicator updater
        document.querySelectorAll('input[type="text"]').forEach(input => {
            input.addEventListener('input', (e) => {
                const isReg = /[\\^\$\*\+\?\[\]\(\)\{\}\|]/.test(e.target.value);
                e.target.closest('.filter-card').querySelector('.indicator').innerText = isReg ? '[REG]' : '[TXT]';
                e.target.closest('.filter-card').querySelector('.indicator').style.color = isReg ? 'var(--pink)' : 'var(--muted)';
            });
        });

        // Modal Close on click outside (Fixed buggy boundingrect check)
        document.querySelectorAll('dialog').forEach(dialog => {
            dialog.addEventListener('click', (e) => {
                // native behavior: backdrop is part of dialog, content is children
                if (e.target === dialog) {
                    dialog.close();
                }
            });
        });
    </script>
</body>
</html>
{{end}}

{{define "table"}}
    <table>
        <thead>
            <tr>
                <th style="width:28%" data-sort="host"> HOSTNAME {{if eq .SortCol "host"}}{{if .SortDesc}}▼{{else}}▲{{end}}{{end}}</th>
                <th style="width:42%" data-sort="pkg"> PACKAGE NAME {{if eq .SortCol "pkg"}}{{if .SortDesc}}▼{{else}}▲{{end}}{{end}}</th>
                <th style="width:30%" data-sort="ver"> VERSION {{if eq .SortCol "ver"}}{{if .SortDesc}}▼{{else}}▲{{end}}{{end}}</th>
            </tr>
        </thead>
        <tbody>
            {{template "table_rows" .}}
        </tbody>
    </table>
    {{if .Stats}}
    <div class="insights">{{.Stats}}</div>
    {{end}}
{{end}}

{{define "table_rows"}}
    {{$hasOSV := .HasOSV}}
    {{range .Items}}
    {{$hasVuln := and $hasOSV .Vulnerabilities}}
    <tr {{if $hasVuln}}class="vuln-row"{{end}} hx-get="/modal/host?h={{.Hostname}}&p={{.PkgName}}" hx-target="#host-dialog-content" onclick="document.getElementById('hostModal').showModal()">
        <td>  {{.Hostname}}</td>
        <td>{{.PkgName}}</td>
        <td>{{.Version}}{{if $hasVuln}} ⚠️{{end}}</td>
    </tr>
    {{end}}

    {{if .HasNext}}
    <tr id="loader-{{.NextPage}}" hx-get="/table?page={{.NextPage}}" hx-include="#filter-form" hx-trigger="revealed" hx-swap="outerHTML">
        <td colspan="3" style="text-align:center; padding: 1rem; color: var(--muted); font-style: italic;">Loading more records...</td>
    </tr>
    {{end}}

    <script>
        {{if lt .DisplayedCount .FilteredCount}}
            document.getElementById('record-count').innerText = "Records: {{.DisplayedCount}} (shown) of {{.FilteredCount}} / {{.TotalCount}} (Total)";
        {{else}}
            document.getElementById('record-count').innerText = "Records: {{.FilteredCount}} / {{.TotalCount}}";
        {{end}}
    </script>
{{end}}

{{define "modal_host"}}
    <div class="modal-header"><span class="badge bg-purple" style="text-transform: uppercase;"> HOST INFORMATION: {{.Host.Hostname}} </span></div>
    
    <div style="margin-bottom: 1.5rem; text-align: center;">
        <button type="button" class="tab-btn active" onclick="document.getElementById('tab-overview').style.display='block'; document.getElementById('tab-history').style.display='none'; this.classList.add('active'); this.nextElementSibling.classList.remove('active');">Overview</button>
        <button type="button" class="tab-btn" hx-get="/modal/host/history?h={{.Host.Hostname}}" hx-target="#tab-history" onclick="document.getElementById('tab-overview').style.display='none'; document.getElementById('tab-history').style.display='block'; this.classList.add('active'); this.previousElementSibling.classList.remove('active');">Change History</button>
    </div>

    <div id="tab-overview" style="margin-left: 2rem; line-height: 2;">
        <div><span class="text-pink" style="font-weight:bold; display:inline-block; width: 140px;">Hostname:</span> {{.Host.Hostname}}</div>
        <div><span class="text-pink" style="font-weight:bold; display:inline-block; width: 140px;">IP Address:</span> {{if .Host.IPAddress}}{{.Host.IPAddress}}{{else}}Unknown{{end}}</div>
        <div><span class="text-pink" style="font-weight:bold; display:inline-block; width: 140px;">OS:</span> {{if .Host.OSName}}{{.Host.OSName}} {{.Host.OSVersion}}{{else}}Unknown{{end}}</div>
        <div><span class="text-pink" style="font-weight:bold; display:inline-block; width: 140px;">Host Function:</span> {{if .Host.HostFunction}}{{.Host.HostFunction}}{{else}}-{{end}}</div>
        <div>
            <span class="text-pink" style="font-weight:bold; display:inline-block; width: 140px;">Package:</span> {{.Host.PkgName}} {{.Host.Version}}
            <button type="button" style="margin-left: 1rem; padding: 0.2rem 0.6rem; font-size: 12px;" hx-get="/modal/package/history?h={{.Host.Hostname}}&p={{.Host.PkgName}}" hx-target="#pkg-history-dialog-content" onclick="document.getElementById('packageHistoryModal').showModal();">[View Package Timeline]</button>
        </div>
        {{if .HasOSV}}
        <div>
            <span class="text-pink" style="font-weight:bold; display:inline-block; width: 140px;">Security/CVE:</span> 
            <span class="text-red">{{.VulnSummary}}</span>
            {{if .Host.Vulnerabilities}}
            <button type="button" style="margin-left: 1rem; padding: 0.2rem 0.6rem; font-size: 12px;" hx-get="/modal/osv?h={{.Host.Hostname}}&p={{.Host.PkgName}}" hx-target="#osv-dialog-content" onclick="document.getElementById('osvModal').showModal();">[View OSV Advisory]</button>
            {{end}}
        </div>
        {{end}}
    </div>

    <div id="tab-history" style="display:none; max-height: 400px; overflow-y: auto;">
        <!-- Loaded via HTMX -->
    </div>
{{end}}

{{define "modal_osv"}}
    <div class="modal-header"><span class="badge bg-red"> 🛡 OSV ADVISORY: {{.Package}} ({{.Version}}) </span></div>
    <div class="text-muted" style="text-align: center; margin-bottom: 1rem;">Host: {{.Hostname}}</div>

    <div style="max-height: 450px; overflow-y: auto; padding-right: 0.5rem;">
        {{range .Vulnerabilities}}
        <div class="osv-item">
            <div><span class="text-pink" style="font-weight:bold;">ID/CVE:</span> <span class="text-red">{{.ID}}{{joinCVE .CVE}}</span></div>
            {{if .Summary}}
            <div style="margin-top:0.3rem;"><span class="text-pink" style="font-weight:bold;">Summary:</span> {{.Summary}}</div>
            {{end}}
            {{if .URL}}
            <div style="margin-top:0.3rem;"><span class="text-pink" style="font-weight:bold;">Link:</span> <a href="{{cleanURL .URL}}" target="_blank" rel="noopener noreferrer" class="osv-link">{{cleanURL .URL}}</a></div>
            {{end}}
        </div>
        {{else}}
        <div style="text-align:center; padding: 2rem; color:var(--muted); font-style:italic;">No vulnerabilities registered for this package version.</div>
        {{end}}
    </div>
{{end}}

{{define "modal_host_history"}}
    {{if .Events}}
    <table class="history-table">
        <thead>
            <tr>
                <th style="width:180px;">TIMESTAMP</th>
                <th style="width:130px;">ACTION</th>
                <th style="width:280px;">PACKAGE NAME</th>
                <th>VERSION DETAILS</th>
            </tr>
        </thead>
        <tbody>
            {{range .Events}}
            <tr hx-get="/modal/package/history?h={{$.Hostname}}&p={{.Package}}" hx-target="#pkg-history-dialog-content" onclick="document.getElementById('packageHistoryModal').showModal()">
                <td style="color:var(--muted);">{{formatTime .Timestamp}}</td>
                <td>
                    {{if eq .Action "ADDED"}}<span class="badge bg-green">+ ADDED</span>
                    {{else if eq .Action "MODIFIED"}}<span class="badge bg-cyan">~ MODIFIED</span>
                    {{else if eq .Action "REMOVED"}}<span class="badge bg-red">- REMOVED</span>
                    {{else}}<span class="badge bg-cyan">{{.Action}}</span>
                    {{end}}
                </td>
                <td style="font-weight:bold; color:var(--text);">{{.Package}}</td>
                <td style="color:var(--muted); font-family: monospace;">
                    {{if eq .Action "ADDED"}}{{.NewVersion}}
                    {{else if eq .Action "MODIFIED"}}{{.OldVersion}} &rarr; <span style="color:var(--green); font-weight:bold;">{{.NewVersion}}</span>
                    {{else if eq .Action "REMOVED"}}{{.OldVersion}}
                    {{end}}
                </td>
            </tr>
            {{end}}
        </tbody>
    </table>
    {{else}}
    <div style="text-align:center; padding: 2rem; color:var(--muted); font-style:italic;">No package change history recorded for this host.</div>
    {{end}}
{{end}}

{{define "modal_timeline"}}
    <div class="modal-header"><span class="badge bg-purple"> 📜 FLEET AUDIT LOG / TIME TRAVEL </span></div>
    
    <div style="max-height: 500px; overflow-y: auto;">
        {{if .}}
        <table class="history-table">
            <thead style="position:sticky; top:0; z-index:5;">
                <tr>
                    <th style="width:180px;">TIMESTAMP</th>
                    <th style="width:260px;">HOSTNAME</th>
                    <th style="width:130px;">ACTION</th>
                    <th style="width:260px;">PACKAGE NAME</th>
                    <th>VERSION DETAILS</th>
                </tr>
            </thead>
            <tbody>
                {{range .}}
                <tr hx-get="/modal/package/history?h={{.Hostname}}&p={{.Package}}" hx-target="#pkg-history-dialog-content" onclick="document.getElementById('packageHistoryModal').showModal()">
                    <td style="color:var(--muted);">{{formatTime .Timestamp}}</td>
                    <td class="text-cyan" style="font-weight:bold;">{{.Hostname}}</td>
                    <td>
                        {{if eq .Action "ADDED"}}<span class="badge bg-green">+ ADDED</span>
                        {{else if eq .Action "MODIFIED"}}<span class="badge bg-cyan">~ MODIFIED</span>
                        {{else if eq .Action "REMOVED"}}<span class="badge bg-red">- REMOVED</span>
                        {{else}}<span class="badge bg-cyan">{{.Action}}</span>
                        {{end}}
                    </td>
                    <td style="font-weight:bold; color:var(--text);">{{.Package}}</td>
                    <td style="color:var(--muted); font-family: monospace;">
                        {{if eq .Action "ADDED"}}{{.NewVersion}}
                        {{else if eq .Action "MODIFIED"}}{{.OldVersion}} &rarr; <span style="color:var(--green); font-weight:bold;">{{.NewVersion}}</span>
                        {{else if eq .Action "REMOVED"}}{{.OldVersion}}
                        {{end}}
                    </td>
                </tr>
                {{end}}
            </tbody>
        </table>
        {{else}}
        <div style="text-align:center; padding: 2rem; color:var(--muted); font-style:italic;">No package change events recorded yet across the fleet.</div>
        {{end}}
    </div>
{{end}}

{{define "modal_package_history"}}
    <div class="modal-header">
        <span class="badge bg-purple"> 📦 PACKAGE TIMELINE: {{.Package}} on {{.Hostname}} </span>
    </div>

    <div style="max-height: 400px; overflow-y: auto;">
        <table class="history-table">
            <thead>
                <tr>
                    <th style="width:200px;">TIMESTAMP</th>
                    <th style="width:140px;">ACTION</th>
                    <th>VERSION CHANGE DETAILS</th>
                </tr>
            </thead>
            <tbody>
                {{range .Events}}
                <tr>
                    <td style="color:var(--muted);">{{formatTime .Timestamp}}</td>
                    <td>
                        {{if eq .Action "ADDED"}}<span class="badge bg-green">+ ADDED</span>
                        {{else if eq .Action "MODIFIED"}}<span class="badge bg-cyan">~ MODIFIED</span>
                        {{else if eq .Action "REMOVED"}}<span class="badge bg-red">- REMOVED</span>
                        {{else}}<span class="badge bg-cyan">{{.Action}}</span>
                        {{end}}
                    </td>
                    <td style="font-family: monospace;">
                        {{if eq .Action "ADDED"}}{{.NewVersion}}
                        {{else if eq .Action "MODIFIED"}}{{.OldVersion}} &rarr; <span style="color:var(--green); font-weight:bold;">{{.NewVersion}}</span>
                        {{else if eq .Action "REMOVED"}}{{.OldVersion}}
                        {{end}}
                    </td>
                </tr>
                {{end}}
            </tbody>
        </table>
    </div>
{{end}}

{{define "modal_diff"}}
    <div class="modal-header"><span class="badge bg-purple"> ⚔️ COMPARE HOST PACKAGES (DIFF) </span></div>

    <form id="diff-form" hx-get="/diff/results" hx-target="#diff-results" hx-trigger="change from:select, keyup changed delay:200ms from:input[type='text'], change from:input[type='checkbox']">
        <div class="flex" style="margin-bottom: 1rem;">
            <div style="flex:1;">
                <label class="text-pink" style="font-weight:bold; display:block; margin-bottom: 0.5rem;">Host A (Base):</label>
                <select name="hostA">
                    <option value="">-- Select Host A --</option>
                    {{range .Hosts}}<option value="{{.}}">{{.}}</option>{{end}}
                </select>
            </div>
            <div style="flex:1;">
                <label class="text-pink" style="font-weight:bold; display:block; margin-bottom: 0.5rem;">Host B (Target):</label>
                <select name="hostB">
                    <option value="">-- Select Host B --</option>
                    {{range .Hosts}}<option value="{{.}}">{{.}}</option>{{end}}
                </select>
            </div>
        </div>

        <div class="panel" style="border-color: var(--cyan); display: flex; flex-wrap: nowrap; align-items: center; gap: 1rem; padding: 0.5rem 1rem;">
            <span class="text-pink" style="font-weight:bold; white-space:nowrap;">❯ Filter:</span>
            <input type="text" name="filter" placeholder="Filter compared packages..." style="flex: 1; min-width: 0; margin: 0; background: transparent; border: none; color: var(--text); outline: none;">
            <label style="display:flex; align-items:center; gap:0.5rem; cursor:pointer; white-space: nowrap; margin: 0;">
                <input type="checkbox" name="diffOnly" style="margin:0;">
                <span class="text-muted">Show differences only</span>
            </label>
        </div>
    </form>

    <div id="diff-results" style="margin-top: 1rem; max-height: 400px; overflow-y: auto;">
        <!-- Diff table loads here -->
    </div>
    <div style="text-align: center; margin-top: 1rem;"><button type="button" onclick="this.closest('dialog').close()">[Close]</button></div>
{{end}}

{{define "diff_table"}}
    <table class="diff-table">
        <thead style="position: sticky; top: 0;">
            <tr>
                <th style="width: 40%; text-align:center;"> PACKAGE</th>
                <th style="width: 30%; text-align:center; border-color: var(--cyan);"><span class="text-cyan">🖥️ Host A: {{.HostA}}</span></th>
                <th style="width: 30%; text-align:center; border-color: var(--pink);"><span class="text-pink">🖥️ Host B: {{.HostB}}</span></th>
            </tr>
        </thead>
        <tbody>
            {{range .Rows}}
            <tr {{if .IsDiff}}class="is-diff"{{end}}>
                <td> {{.PkgName}}</td>
                <td style="text-align:center;" class="diff-col diff-col-a">{{.VersionA}}</td>
                <td style="text-align:center;" class="diff-col diff-col-b">{{.VersionB}}</td>
            </tr>
            {{end}}
        </tbody>
    </table>
    <div class="insights" style="text-align:center; border:none; position: sticky; bottom: 0;">{{.Stats}}</div>
{{end}}
`))
