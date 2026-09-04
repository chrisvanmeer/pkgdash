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

type DiffRow struct {
	PkgName  string
	VersionA string
	VersionB string
	IsDiff   bool
}

var (
	globalItems   []FlatItem
	lastUpdated   time.Time
	dataMutex     sync.RWMutex
	serversConfig []string
	pskConfig     string
	webPort       string = ":8080"
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
	http.HandleFunc("/modal/diff", handleDiffModal)
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
		}
	}
	return servers, psk
}

func fetchAllData(servers []string, psk string) {
	var wg sync.WaitGroup
	var allItems []FlatItem
	var latestTime time.Time
	var itemsMutex sync.Mutex

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
					for _, pkg := range host.Packages {
						localItems = append(localItems, FlatItem{
							Hostname: host.Hostname, IPAddress: host.IPAddress,
							OSName: host.OSName, OSVersion: host.OSVersion,
							HostFunction: host.HostFunction, PkgName: pkg.Name,
							Version: pkg.Version, Arch: pkg.Arch,
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
		if !latestTime.IsZero() {
			lastUpdated = latestTime
		} else {
			lastUpdated = time.Now()
		}
		dataMutex.Unlock()
	}
}

// --- HTTP Handlers ---

func handleIndex(w http.ResponseWriter, r *http.Request) {
	isSecure := r.TLS != nil || strings.EqualFold(r.Header.Get("X-Forwarded-Proto"), "https")
	secStatus := "🔓 HTTP"
	if isSecure {
		secStatus = "🔒 SECURE"
	}

	_ = tmpl.ExecuteTemplate(w, "index", map[string]interface{}{
		"LastUpdated": lastUpdated.Local().Format("15:04:05"),
		"SecStatus":   secStatus,
	})
}

// filterAndSort filters and sorts all matching records in memory.
func filterAndSort(r *http.Request) ([]FlatItem, int, int) {
	dataMutex.RLock()
	defer dataMutex.RUnlock()

	hostQuery := strings.TrimSpace(r.URL.Query().Get("host"))
	pkgQuery := strings.TrimSpace(r.URL.Query().Get("pkg"))
	verQuery := strings.TrimSpace(r.URL.Query().Get("ver"))

	hMatch := createFieldMatcher(hostQuery)
	pMatch := createFieldMatcher(pkgQuery)
	vMatch := createFieldMatcher(verQuery)

	var filtered []FlatItem
	hostMap := make(map[string]bool)
	verMap := make(map[string]bool)

	for _, item := range globalItems {
		if hMatch(item.Hostname) && pMatch(item.PkgName) && vMatch(item.Version) {
			filtered = append(filtered, item)
			hostMap[item.Hostname] = true
			verMap[item.Version] = true
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

	return filtered, len(hostMap), len(verMap)
}

func handleTable(w http.ResponseWriter, r *http.Request) {
	filtered, hCount, vCount := filterAndSort(r)

	pageStr := r.URL.Query().Get("page")
	page := 1
	if p, err := strconv.Atoi(pageStr); err == nil && p > 0 {
		page = p
	}

	pageSize := 1000 // Batch size for HTMX infinite scrolling

	start := (page - 1) * pageSize
	end := start + pageSize

	if start >= len(filtered) && len(filtered) > 0 {
		return // Reached end of record set
	}
	if end > len(filtered) {
		end = len(filtered)
	}

	if page > 1 {
		log.Printf("Serving Infinite Scroll: Page %d (Rows %d to %d)\n", page, start, end)
	}

	var displayItems []FlatItem
	if len(filtered) > 0 {
		displayItems = filtered[start:end]
	}

	hasNext := end < len(filtered)

	stats := ""
	if r.URL.Query().Get("pkg") != "" && len(filtered) > 0 {
		stats = fmt.Sprintf("📊 Fleet Insights (filtered search results): '%s' is present on %d host(s) across %d unique version(s)", r.URL.Query().Get("pkg"), hCount, vCount)
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
	}

	if page > 1 {
		_ = tmpl.ExecuteTemplate(w, "table_rows", data)
	} else {
		_ = tmpl.ExecuteTemplate(w, "table", data)
	}
}

func handleHostModal(w http.ResponseWriter, r *http.Request) {
	hostname := r.URL.Query().Get("h")
	var host FlatItem
	dataMutex.RLock()
	for _, item := range globalItems {
		if item.Hostname == hostname {
			host = item
			break
		}
	}
	dataMutex.RUnlock()
	_ = tmpl.ExecuteTemplate(w, "modal_host", host)
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

	if hostA == "" || hostB == "" {
		_, _ = w.Write([]byte(`<div class="text-pink text-center mt-3" style="text-align:center; margin-top:1rem;">Please select Host A and Host B to compare.</div>`))
		return
	}
	if hostA == hostB {
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
	filtered, _, _ := filterAndSort(r) // Bypasses pagination to export all matches
	w.Header().Set("Content-Type", "text/csv")
	w.Header().Set("Content-Disposition", "attachment;filename=pkgdash_export.csv")
	writer := csv.NewWriter(w)
	_ = writer.Write([]string{"Hostname", "Package", "Version", "Architecture"})
	for _, i := range filtered {
		_ = writer.Write([]string{i.Hostname, i.PkgName, i.Version, i.Arch})
	}
	writer.Flush()
}

func handleExportINI(w http.ResponseWriter, r *http.Request) {
	filtered, _, _ := filterAndSort(r) // Bypasses pagination to export all matches
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
		_, _ = w.Write([]byte(h + "\n"))
	}
}

// --- Regex Matcher ---
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
		} else {
			return "[TXT]"
		}
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
            --yellow: #F1FA8C; --dark-text: #11111B;
        }

        /* Unified Flex Layout to guarantee 1rem spacing gaps between boxes */
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
        .bg-purple { background: var(--purple); } .bg-cyan { background: var(--cyan); } .bg-green { background: var(--green); } .bg-yellow { background: var(--yellow); }

        .flex { display: flex; gap: 1rem; flex-shrink: 0; }
        .filter-card { flex: 1; border: 1px solid var(--border); border-radius: 4px; padding: 0.5rem; transition: border 0.2s; }
        .filter-card:focus-within { border-color: var(--pink); }
        .filter-card:focus-within .f-label { color: var(--pink); font-weight: bold; }
        .f-label { color: var(--muted); margin-bottom: 0.3rem; display: flex; justify-content: space-between; }
        .f-input-wrapper { display: flex; color: var(--muted); }
        .filter-card:focus-within .f-input-wrapper { color: var(--pink); }
        input[type="text"] { background: transparent; border: none; color: var(--text); font-family: inherit; width: 100%; outline: none; margin-left: 0.5rem; }

        #filter-form { margin: 0; }

        /* Main table container fills remaining viewport space */
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

        td { padding: 0.2rem 0.5rem; white-space: nowrap; overflow: hidden; text-overflow: ellipsis; }
        tr:hover td { background: var(--pink); color: var(--dark-text); cursor: pointer; }

        .insights { color: var(--cyan); font-style: italic; padding: 0.5rem; border-top: 1px solid var(--border); position: sticky; bottom: 0; background: var(--bg); z-index: 10;}
        .footer { border: 2px solid var(--border); border-radius: 8px; padding: 0.5rem; color: var(--muted); display: flex; justify-content: space-between; flex-shrink: 0; }

        .btn-link { color: var(--muted); text-decoration: none; cursor: pointer; padding: 0 0.5rem; }
        .btn-link:hover { color: var(--pink); }

        /* Modals */
        dialog { background: var(--bg); color: var(--text); border: 3px double var(--purple); border-radius: 8px; padding: 1.5rem; width: 100%; box-shadow: 0 10px 30px rgba(0,0,0,0.5); }
        dialog#diffModal { max-width: 1100px; }
        dialog#aboutModal, dialog#hostModal { max-width: 800px; }
        dialog::backdrop { background: rgba(0,0,0,0.7); }
        .modal-header { font-weight: bold; margin-bottom: 1rem; text-align: center; }
        .text-pink { color: var(--pink); } .text-cyan { color: var(--cyan); }
        select { background: var(--surface); color: var(--text); border: 1px solid var(--border); padding: 0.3rem; font-family: inherit; width: 100%; margin-bottom: 1rem; outline: none; }
		button { background: var(--surface); color: var(--text); border: 1px solid var(--border); padding: 0.4rem 1rem; cursor: pointer; font-family: inherit; }
		button:hover { background: var(--pink); color: var(--dark-text); }

		/* Diff Table specific */
        .diff-table { font-size: 13px; }
		.diff-table th { background: var(--bg); border-bottom: 2px solid var(--border); box-shadow: none; }
		.diff-table td { border-bottom: 1px solid #313244; }
		.diff-table tr.is-diff td.diff-col { font-weight: bold; }
		.diff-table tr.is-diff td.diff-col-a { color: var(--cyan); }
		.diff-table tr.is-diff td.diff-col-b { color: var(--pink); }
    </style>
</head>
<body>

		<!-- Header Panel -->
    <div class="panel header-panel">
        <div>
            <span class="badge bg-purple"> 📦 PKGDASH-WEB </span>
            <span class="badge bg-cyan"> {{.SecStatus}} </span>
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

        <div class="filter-card">
            <div class="f-label"><span>HOST</span> <span class="indicator">[TXT]</span></div>
            <div class="f-input-wrapper">❯ <input type="text" name="host" placeholder="Filter hostname..." autofocus hx-get="/table" hx-target="#table-container" hx-trigger="keyup changed delay:250ms"></div>
        </div>
        <div class="filter-card">
            <div class="f-label"><span>PACKAGE</span> <span class="indicator">[TXT]</span></div>
            <div class="f-input-wrapper">❯ <input type="text" name="pkg" placeholder="Filter package..." hx-get="/table" hx-target="#table-container" hx-trigger="keyup changed delay:250ms"></div>
        </div>
        <div class="filter-card">
            <div class="f-label"><span>VERSION</span> <span class="indicator">[TXT]</span></div>
            <div class="f-input-wrapper">❯ <input type="text" name="ver" placeholder="Filter version..." hx-get="/table" hx-target="#table-container" hx-trigger="keyup changed delay:250ms"></div>
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
            <a class="btn-link" hx-get="/modal/diff" hx-target="#diff-dialog-content" onclick="document.getElementById('diffModal').showModal()">[Ctrl+D] Diff</a> |
            <a class="btn-link" href="#" onclick="exportFile('/export/ini')">[Ctrl+E] Export INI</a> |
            <a class="btn-link" href="#" onclick="exportFile('/export/csv')">[Ctrl+S] Export CSV</a>
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
        <div style="text-align: center;"><button onclick="this.closest('dialog').close()">[Close]</button></div>
    </dialog>

    <dialog id="hostModal">
        <div id="host-dialog-content"></div>
        <div style="text-align: center; margin-top: 1rem;"><button onclick="this.closest('dialog').close()">[Close]</button></div>
    </dialog>

    <dialog id="diffModal">
        <div id="diff-dialog-content"></div>
    </dialog>

    <script>
        function exportFile(endpoint) {
            const formData = new FormData(document.getElementById('filter-form'));
            const params = new URLSearchParams(formData).toString();
            window.location.href = endpoint + '?' + params;
        }

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

		// Modal Close on click outside
		document.querySelectorAll('dialog').forEach(dialog => {
			dialog.addEventListener('click', (e) => {
				const rect = dialog.getBoundingClientRect();
				if(e.clientY < rect.top || e.clientY > rect.bottom || e.clientX < rect.left || e.clientX > rect.right) {
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
    {{range .Items}}
    <tr hx-get="/modal/host?h={{.Hostname}}" hx-target="#host-dialog-content" onclick="document.getElementById('hostModal').showModal()">
        <td>  {{.Hostname}}</td>
        <td>{{.PkgName}}</td>
        <td>{{.Version}}</td>
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
    <div class="modal-header"><span class="badge bg-purple" style="text-transform: uppercase;"> HOST INFORMATION: {{.Hostname}} </span></div>
    <div style="margin-left: 2rem; line-height: 1.8;">
        <div><span class="text-pink" style="font-weight:bold; display:inline-block; width: 120px;">Hostname:</span> {{.Hostname}}</div>
        <div><span class="text-pink" style="font-weight:bold; display:inline-block; width: 120px;">IP Address:</span> {{if .IPAddress}}{{.IPAddress}}{{else}}Unknown{{end}}</div>
        <div><span class="text-pink" style="font-weight:bold; display:inline-block; width: 120px;">OS:</span> {{if .OSName}}{{.OSName}} {{.OSVersion}}{{else}}Unknown{{end}}</div>
        <div><span class="text-pink" style="font-weight:bold; display:inline-block; width: 120px;">Host Function:</span> {{if .HostFunction}}{{.HostFunction}}{{else}}-{{end}}</div>
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
    <div style="text-align: center; margin-top: 1rem;"><button onclick="this.closest('dialog').close()">[Close]</button></div>
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
