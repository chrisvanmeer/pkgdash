package main

import (
	"bytes"
	"compress/gzip"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"flag"
	"fmt"
	"io"
	"log"
	"math/big"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"
)

const (
	defaultPort        = ":9876"
	defaultDataPath    = "/tmp/pkgdash"
	defaultOSVEnable   = false
	defaultOSVURL      = "https://api.osv.dev"
	defaultOSVProxy    = ""
	defaultOSVCacheTTL = 12 * time.Hour
	serviceName        = "pkgdashd"
	installDir         = "/usr/local/bin"
	osvHTTPTimeout     = 30 * time.Second
	osvBatchSize       = 100
	syncInterval       = 30 * time.Second
)

var (
	activeDataPath string
	activePSK      string
	historyMgr     *HistoryManager
	previousState  = make(map[string]map[string]string)

	// OSV Configuration
	activeOSVEnabled  bool
	activeOSVURL      string
	activeOSVProxy    string
	activeOSVCacheTTL time.Duration
	osvHTTPClient     *http.Client

	// OSV Cache
	osvCacheMu sync.RWMutex
	osvCache   = make(map[string]osvCacheEntry)
	isScanning bool
)

type pkgKey struct {
	Name      string
	Version   string
	Ecosystem string
}

type osvCacheEntry struct {
	Vulnerabilities []Vulnerability `json:"vulnerabilities"`
	FetchedAt       time.Time       `json:"fetched_at"`
}

var (
	cacheMu        sync.RWMutex
	cachedRawJSON  []byte
	cachedGzip     []byte
	cachedModTime  time.Time
	lastCacheCheck time.Time
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

type osvQuery struct {
	Package osvPackage `json:"package"`
	Version string     `json:"version"`
}

type osvPackage struct {
	Name      string `json:"name"`
	Ecosystem string `json:"ecosystem,omitempty"`
}

type osvBatchRequest struct {
	Queries []osvQuery `json:"queries"`
}

type osvBatchResponse struct {
	Results []osvResult `json:"results"`
}

type osvResult struct {
	Vulns []osvVuln `json:"vulns"`
}

type osvVuln struct {
	ID         string         `json:"id"`
	Summary    string         `json:"summary"`
	Details    string         `json:"details"`
	Aliases    []string       `json:"aliases"`
	References []osvReference `json:"references"`
}

type osvReference struct {
	Type string `json:"type"`
	URL  string `json:"url"`
}

func main() {
	installFlag := flag.Bool("install", false, "Install binary to /usr/local/bin and enable systemd service")
	uninstallFlag := flag.Bool("uninstall", false, "Stop, disable, and remove the systemd service and binary")
	portFlag := flag.String("port", defaultPort, "Port to listen on")
	dataPathFlag := flag.String("data-path", defaultDataPath, "Path to the directory containing JSON files")
	pskFlag := flag.String("psk", "", "Pre-shared key for authentication (optional)")
	tlsFlag := flag.Bool("tls", false, "Enable TLS encryption (auto-generates certificates)")

	osvEnableFlag := flag.Bool("enable-osv", defaultOSVEnable, "Enable OSV.dev vulnerability checking")
	osvURLFlag := flag.String("osv-url", defaultOSVURL, "OSV API URL (or internal mirror)")
	osvProxyFlag := flag.String("osv-proxy", defaultOSVProxy, "Proxy URL for OSV requests")
	osvCacheTTLFlag := flag.Duration("osv-cache-ttl", defaultOSVCacheTTL, "OSV cache TTL duration (e.g. 6h, 12h, 24h)")

	flag.Parse()

	activeDataPath = *dataPathFlag
	activePSK = *pskFlag
	activeOSVEnabled = *osvEnableFlag
	activeOSVURL = strings.TrimRight(*osvURLFlag, "/")
	activeOSVProxy = *osvProxyFlag
	activeOSVCacheTTL = *osvCacheTTLFlag

	if *installFlag && *uninstallFlag {
		log.Fatal("Cannot use --install and --uninstall at the same time")
	}

	if *installFlag {
		if err := installSystemdService(*portFlag, *dataPathFlag, *pskFlag, *tlsFlag, activeOSVEnabled, activeOSVURL, activeOSVProxy, activeOSVCacheTTL); err != nil {
			log.Fatalf("Failed to install systemd service: %v", err)
		}
		fmt.Printf("Systemd service installed successfully.\nListening on %s | Reading from %s\n", *portFlag, *dataPathFlag)
		return
	}

	if *uninstallFlag {
		if err := uninstallSystemdService(); err != nil {
			log.Fatalf("Failed to uninstall systemd service: %v", err)
		}
		fmt.Println("Systemd service uninstalled successfully.")
		return
	}

	if activeOSVEnabled {
		initOSVHTTPClient()
		loadOSVCacheFromDisk()
		log.Printf("OSV vulnerability integration ENABLED (API: %s | Cache TTL: %s)", activeOSVURL, activeOSVCacheTTL)
	}

	historyMgr = NewHistoryManager(activeDataPath)

	refreshCache(false)

	go startBackgroundSync(syncInterval)

	http.HandleFunc("/packages", handlePackages)
	http.HandleFunc("/history", handleHistory)
	log.Printf("Starting pkgdashd listener on port %s, serving data from %s...", *portFlag, activeDataPath)

	if *tlsFlag {
		certPath := filepath.Join(activeDataPath, "cert.pem")
		keyPath := filepath.Join(activeDataPath, "key.pem")
		if err := ensureTLSCerts(certPath, keyPath); err != nil {
			log.Fatalf("Failed to generate TLS certificates: %v", err)
		}
		if err := http.ListenAndServeTLS(*portFlag, certPath, keyPath, nil); err != nil {
			log.Fatalf("Server error (TLS): %v", err)
		}
	} else {
		if err := http.ListenAndServe(*portFlag, nil); err != nil {
			log.Fatalf("Server error: %v", err)
		}
	}
}

func determineEcosystem(osName, osVersion string) string {
	name := strings.ToLower(osName)

	if strings.Contains(name, "ubuntu") {
		re := regexp.MustCompile(`\d+\.\d+`)
		if match := re.FindString(osVersion); match != "" {
			return "Ubuntu:" + match
		}
		return "Ubuntu"
	}

	if strings.Contains(name, "debian") {
		parts := strings.Split(osVersion, ".")
		if len(parts) > 0 && parts[0] != "" {
			return "Debian:" + parts[0]
		}
		return "Debian"
	}

	if strings.Contains(name, "alpine") {
		re := regexp.MustCompile(`\d+\.\d+`)
		if match := re.FindString(osVersion); match != "" {
			return "Alpine:v" + match
		}
		return "Alpine"
	}

	return ""
}

func initOSVHTTPClient() {
	transport := &http.Transport{}
	if activeOSVProxy != "" {
		proxyURL, err := url.Parse(activeOSVProxy)
		if err == nil {
			transport.Proxy = http.ProxyURL(proxyURL)
		} else {
			log.Printf("Warning: Invalid OSV proxy URL %q: %v. Falling back to environment proxy.", activeOSVProxy, err)
			transport.Proxy = http.ProxyFromEnvironment
		}
	} else {
		transport.Proxy = http.ProxyFromEnvironment
	}

	osvHTTPClient = &http.Client{
		Transport: transport,
		Timeout:   osvHTTPTimeout,
	}
}

func loadOSVCacheFromDisk() {
	cacheFile := filepath.Join(activeDataPath, "osv_cache.json")
	data, err := os.ReadFile(cacheFile)
	if err != nil {
		return
	}

	osvCacheMu.Lock()
	defer osvCacheMu.Unlock()
	_ = json.Unmarshal(data, &osvCache)
	log.Printf("Loaded %d cached OSV package entries from disk", len(osvCache))
}

func saveOSVCacheToDisk() {
	osvCacheMu.RLock()
	defer osvCacheMu.RUnlock()

	data, err := json.Marshal(osvCache)
	if err != nil {
		return
	}

	cacheFile := filepath.Join(activeDataPath, "osv_cache.json")
	_ = os.WriteFile(cacheFile, data, 0640)
}

func startBackgroundSync(interval time.Duration) {
	time.Sleep(2 * time.Second)
	if activeOSVEnabled {
		refreshCache(true)
	}

	ticker := time.NewTicker(interval)
	for range ticker.C {
		refreshCache(activeOSVEnabled)
	}
}

func refreshCache(fetchOSV bool) {
	files, err := filepath.Glob(filepath.Join(activeDataPath, "*.json"))
	if err != nil {
		return
	}

	var newestTime time.Time
	var allHosts []HostPayload
	currentState := make(map[string]map[string]string)

	for _, file := range files {
		if strings.HasSuffix(file, "history.json") || strings.HasSuffix(file, "history.jsonl") || strings.HasSuffix(file, "osv_cache.json") {
			continue
		}
		if info, err := os.Stat(file); err == nil && info.ModTime().After(newestTime) {
			newestTime = info.ModTime()
		}
		data, err := os.ReadFile(file)
		if err != nil {
			continue
		}
		var hosts []HostPayload
		if err := json.Unmarshal(data, &hosts); err == nil {
			for i := range hosts {
				hosts[i].OSVEnabled = activeOSVEnabled
				if currentState[hosts[i].Hostname] == nil {
					currentState[hosts[i].Hostname] = make(map[string]string)
				}
				for _, pkg := range hosts[i].Packages {
					currentState[hosts[i].Hostname][pkg.Name] = pkg.Version
				}
			}
			allHosts = append(allHosts, hosts...)
		}
	}

	if historyMgr != nil {
		diffs := ComputeDiffs(previousState, currentState)
		if len(diffs) > 0 {
			historyMgr.RecordChanges(diffs)
		}
	}
	previousState = currentState

	if activeOSVEnabled && len(allHosts) > 0 {
		if fetchOSV && !isScanning {
			go func(h []HostPayload) {
				isScanning = true
				defer func() { isScanning = false }()
				enrichWithOSV(h)
				saveOSVCacheToDisk()
				updatePayloadCache(h, newestTime)
			}(allHosts)
		} else {
			attachCachedOSV(allHosts)
		}
	}

	updatePayloadCache(allHosts, newestTime)
}

func updatePayloadCache(allHosts []HostPayload, newestTime time.Time) {
	rawJSON, err := json.Marshal(allHosts)
	if err != nil {
		return
	}

	var gzBuf bytes.Buffer
	gzWriter := gzip.NewWriter(&gzBuf)
	if _, err := gzWriter.Write(rawJSON); err != nil {
		return
	}
	if err := gzWriter.Close(); err != nil {
		return
	}

	cacheMu.Lock()
	cachedRawJSON = rawJSON
	cachedGzip = gzBuf.Bytes()
	cachedModTime = newestTime
	lastCacheCheck = time.Now()
	cacheMu.Unlock()
}

func attachCachedOSV(hosts []HostPayload) {
	osvCacheMu.RLock()
	defer osvCacheMu.RUnlock()

	for i := range hosts {
		eco := determineEcosystem(hosts[i].OSName, hosts[i].OSVersion)
		for j := range hosts[i].Packages {
			p := &hosts[i].Packages[j]
			key := p.Name + "@" + p.Version + "@" + eco
			if entry, ok := osvCache[key]; ok && len(entry.Vulnerabilities) > 0 {
				p.Vulnerabilities = entry.Vulnerabilities
			}
		}
	}
}

func enrichWithOSV(hosts []HostPayload) {
	uniquePkgs := make(map[pkgKey]bool)
	for _, h := range hosts {
		eco := determineEcosystem(h.OSName, h.OSVersion)
		for _, p := range h.Packages {
			if p.Name != "" && p.Version != "" {
				uniquePkgs[pkgKey{Name: p.Name, Version: p.Version, Ecosystem: eco}] = true
			}
		}
	}

	var toFetch []pkgKey
	osvCacheMu.RLock()
	for pk := range uniquePkgs {
		key := pk.Name + "@" + pk.Version + "@" + pk.Ecosystem
		entry, exists := osvCache[key]
		if !exists || time.Since(entry.FetchedAt) > activeOSVCacheTTL {
			toFetch = append(toFetch, pk)
		}
	}
	osvCacheMu.RUnlock()

	if len(toFetch) > 0 {
		log.Printf("Querying OSV.dev API for %d packages (Cache TTL: %s)...", len(toFetch), activeOSVCacheTTL)
		fetchOSVBatch(toFetch)
	}

	attachCachedOSV(hosts)
}

func fetchOSVBatch(pkgs []pkgKey) {
	vulnCount := 0
	for i := 0; i < len(pkgs); i += osvBatchSize {
		end := i + osvBatchSize
		if end > len(pkgs) {
			end = len(pkgs)
		}
		chunk := pkgs[i:end]

		reqBody := osvBatchRequest{Queries: make([]osvQuery, len(chunk))}
		for idx, p := range chunk {
			reqBody.Queries[idx] = osvQuery{
				Package: osvPackage{
					Name:      p.Name,
					Ecosystem: p.Ecosystem,
				},
				Version: p.Version,
			}
		}

		bodyBytes, err := json.Marshal(reqBody)
		if err != nil {
			continue
		}

		endpoint := fmt.Sprintf("%s/v1/querybatch", activeOSVURL)
		resp, err := osvHTTPClient.Post(endpoint, "application/json", bytes.NewBuffer(bodyBytes))
		if err != nil {
			log.Printf("OSV query failed: %v", err)
			continue
		}

		if resp.StatusCode != http.StatusOK {
			resp.Body.Close()
			log.Printf("OSV query returned status %d", resp.StatusCode)
			continue
		}

		var batchResp osvBatchResponse
		err = json.NewDecoder(resp.Body).Decode(&batchResp)
		resp.Body.Close()
		if err != nil {
			log.Printf("OSV response decoding failed: %v", err)
			continue
		}

		osvCacheMu.Lock()
		now := time.Now()
		for idx, res := range batchResp.Results {
			if idx >= len(chunk) {
				break
			}
			p := chunk[idx]
			key := p.Name + "@" + p.Version + "@" + p.Ecosystem

			var vulns []Vulnerability
			for _, v := range res.Vulns {
				var cves []string
				for _, alias := range v.Aliases {
					if strings.HasPrefix(alias, "CVE-") {
						cves = append(cves, alias)
					}
				}

				vulnURL := fmt.Sprintf("https://osv.dev/vulnerability/%s", v.ID)
				for _, ref := range v.References {
					if (ref.Type == "ADVISORY" || ref.Type == "WEB") && strings.HasPrefix(ref.URL, "http") {
						vulnURL = ref.URL
						break
					}
				}

				vulns = append(vulns, Vulnerability{
					ID:      v.ID,
					CVE:     cves,
					Summary: v.Summary,
					Details: v.Details,
					URL:     vulnURL,
				})
			}

			if len(vulns) > 0 {
				vulnCount += len(vulns)
			}

			osvCache[key] = osvCacheEntry{
				Vulnerabilities: vulns,
				FetchedAt:       now,
			}
		}
		osvCacheMu.Unlock()
	}
	log.Printf("OSV scan complete: found %d vulnerabilities across scanned packages", vulnCount)
}

func handlePackages(w http.ResponseWriter, r *http.Request) {
	if activePSK != "" {
		if r.Header.Get("X-PSK") != activePSK {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}
	}

	cacheMu.RLock()
	rawJSON := cachedRawJSON
	gzData := cachedGzip
	modTime := cachedModTime
	cacheMu.RUnlock()

	if rawJSON == nil {
		http.Error(w, "Data background sync in progress", http.StatusServiceUnavailable)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("X-OSV-Enabled", fmt.Sprintf("%t", activeOSVEnabled))
	if !modTime.IsZero() {
		w.Header().Set("Last-Modified", modTime.UTC().Format(http.TimeFormat))
	}

	if strings.Contains(r.Header.Get("Accept-Encoding"), "gzip") {
		w.Header().Set("Content-Encoding", "gzip")
		_, _ = w.Write(gzData)
		return
	}

	_, _ = w.Write(rawJSON)
}

func handleHistory(w http.ResponseWriter, r *http.Request) {
	if activePSK != "" {
		if r.Header.Get("X-PSK") != activePSK {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}
	}

	hostname := r.URL.Query().Get("host")
	pkgName := r.URL.Query().Get("pkg")
	events := historyMgr.GetHistory(hostname, pkgName, 100)

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(events)
}

func ensureTLSCerts(certPath, keyPath string) error {
	if _, err := os.Stat(certPath); err == nil {
		if _, err := os.Stat(keyPath); err == nil {
			return nil
		}
	}
	if err := os.MkdirAll(activeDataPath, 0755); err != nil {
		return err
	}
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return err
	}
	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{Organization: []string{"pkgdash Auto-TLS"}},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(3650 * 24 * time.Hour),
		KeyUsage:     x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	derBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
	if err != nil {
		return err
	}

	certOut, err := os.Create(certPath)
	if err != nil {
		return err
	}
	_ = pem.Encode(certOut, &pem.Block{Type: "CERTIFICATE", Bytes: derBytes})
	_ = certOut.Close()

	keyOut, err := os.Create(keyPath)
	if err != nil {
		return err
	}
	privBytes, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		_ = keyOut.Close()
		return err
	}
	_ = pem.Encode(keyOut, &pem.Block{Type: "PRIVATE KEY", Bytes: privBytes})
	_ = keyOut.Close()

	return nil
}

func copyFile(src, dst string) error {
	s, err := os.Open(src)
	if err != nil {
		return err
	}
	defer func() { _ = s.Close() }()

	destFile, err := os.Create(dst)
	if err != nil {
		return err
	}
	defer func() { _ = destFile.Close() }()

	_, err = io.Copy(destFile, s)
	return err
}

func installSystemdService(port, dataPath, psk string, tlsEnabled, osvEnabled bool, osvURL, osvProxy string, osvCacheTTL time.Duration) error {
	exePath, err := os.Executable()
	if err != nil {
		return err
	}
	exePath, _ = filepath.Abs(exePath)
	targetPath := filepath.Join(installDir, serviceName)

	if exePath != targetPath {
		if err := os.MkdirAll(installDir, 0755); err != nil {
			return err
		}
		if err := copyFile(exePath, targetPath); err != nil {
			return err
		}
		if err := os.Chmod(targetPath, 0755); err != nil {
			return err
		}
	}

	execCmd := fmt.Sprintf("%s --port=%q --data-path=%q", targetPath, port, dataPath)
	if psk != "" {
		execCmd += fmt.Sprintf(" --psk=%q", psk)
	}
	if tlsEnabled {
		execCmd += " --tls"
	}
	if osvEnabled {
		execCmd += " --enable-osv"
		if osvURL != "" && osvURL != defaultOSVURL {
			execCmd += fmt.Sprintf(" --osv-url=%q", osvURL)
		}
		if osvProxy != "" {
			execCmd += fmt.Sprintf(" --osv-proxy=%q", osvProxy)
		}
		if osvCacheTTL != defaultOSVCacheTTL {
			execCmd += fmt.Sprintf(" --osv-cache-ttl=%q", osvCacheTTL.String())
		}
	}

	unitContent := fmt.Sprintf(`[Unit]
Description=pkgdash package listener daemon
After=network.target

[Service]
Type=simple
ExecStart=%s
Restart=always
User=root

[Install]
WantedBy=multi-user.target
`, execCmd)

	unitPath := fmt.Sprintf("/etc/systemd/system/%s.service", serviceName)
	if err := os.WriteFile(unitPath, []byte(unitContent), 0644); err != nil {
		return err
	}

	if err := exec.Command("systemctl", "daemon-reload").Run(); err != nil {
		return fmt.Errorf("daemon-reload failed: %w", err)
	}
	if err := exec.Command("systemctl", "enable", "--now", serviceName).Run(); err != nil {
		return fmt.Errorf("enable service failed: %w", err)
	}
	if err := exec.Command("systemctl", "restart", serviceName).Run(); err != nil {
		return fmt.Errorf("restart service failed: %w", err)
	}

	return nil
}

func uninstallSystemdService() error {
	_ = exec.Command("systemctl", "stop", serviceName).Run()
	_ = exec.Command("systemctl", "disable", serviceName).Run()
	_ = os.Remove(fmt.Sprintf("/etc/systemd/system/%s.service", serviceName))
	_ = exec.Command("systemctl", "daemon-reload").Run()
	_ = os.Remove(filepath.Join(installDir, serviceName))
	return nil
}
