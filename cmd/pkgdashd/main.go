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
	"strings"
	"sync"
	"time"
)

const (
	defaultPort      = ":9876"
	defaultDataPath  = "/tmp/pkgdash"
	defaultOSVEnable = false
	defaultOSVURL    = "https://api.osv.dev"
	defaultOSVProxy  = ""
	serviceName      = "pkgdashd"
	installDir       = "/usr/local/bin"
	osvCacheTTL      = 12 * time.Hour
	osvHTTPTimeout   = 15 * time.Second
	osvBatchSize     = 500
)

var (
	activeDataPath string
	activePSK      string
	historyMgr     *HistoryManager
	previousState  = make(map[string]map[string]string)

	// OSV Configuration
	activeOSVEnabled bool
	activeOSVURL     string
	activeOSVProxy   string
	osvHTTPClient    *http.Client

	// OSV Cache
	osvCacheMu sync.RWMutex
	osvCache   = make(map[string]osvCacheEntry)
)

type pkgKey struct {
	Name    string
	Version string
}

type osvCacheEntry struct {
	vulnerabilities []Vulnerability
	fetchedAt       time.Time
}

// Cache structures for package payloads
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

// OSV Request/Response structs
type osvQuery struct {
	Package osvPackage `json:"package"`
	Version string     `json:"version"`
}

type osvPackage struct {
	Name string `json:"name"`
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

	// OSV Flags
	osvEnableFlag := flag.Bool("enable-osv", defaultOSVEnable, "Enable OSV.dev vulnerability checking")
	osvURLFlag := flag.String("osv-url", defaultOSVURL, "OSV API URL (or internal mirror)")
	osvProxyFlag := flag.String("osv-proxy", defaultOSVProxy, "Proxy URL for OSV requests (e.g., http://proxy.internal:8080)")

	flag.Parse()

	activeDataPath = *dataPathFlag
	activePSK = *pskFlag
	activeOSVEnabled = *osvEnableFlag
	activeOSVURL = strings.TrimRight(*osvURLFlag, "/")
	activeOSVProxy = *osvProxyFlag

	if activeOSVEnabled {
		initOSVHTTPClient()
		log.Printf("OSV vulnerability integration ENABLED (API: %s)", activeOSVURL)
	}

	if *installFlag && *uninstallFlag {
		log.Fatal("Cannot use --install and --uninstall at the same time")
	}

	if *installFlag {
		if err := installSystemdService(*portFlag, *dataPathFlag, *pskFlag, *tlsFlag, activeOSVEnabled, activeOSVURL, activeOSVProxy); err != nil {
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

	// Initialize History Manager
	historyMgr = NewHistoryManager(activeDataPath)

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

func loadDataWithCache() ([]byte, []byte, time.Time, error) {
	cacheMu.RLock()
	if time.Since(lastCacheCheck) < 2*time.Second && cachedRawJSON != nil {
		raw, gz, t := cachedRawJSON, cachedGzip, cachedModTime
		cacheMu.RUnlock()
		return raw, gz, t, nil
	}
	cacheMu.RUnlock()

	cacheMu.Lock()
	defer cacheMu.Unlock()

	files, err := filepath.Glob(filepath.Join(activeDataPath, "*.json"))
	if err != nil {
		return nil, nil, time.Time{}, err
	}

	var newestTime time.Time
	var allHosts []HostPayload
	currentState := make(map[string]map[string]string)

	for _, file := range files {
		if strings.HasSuffix(file, "history.json") || strings.HasSuffix(file, "history.jsonl") {
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

	// Calculate diffs and log changes
	if historyMgr != nil {
		diffs := ComputeDiffs(previousState, currentState)
		if len(diffs) > 0 {
			historyMgr.RecordChanges(diffs)
		}
	}
	previousState = currentState

	// Fetch OSV vulnerabilities if enabled
	if activeOSVEnabled && len(allHosts) > 0 {
		enrichWithOSV(allHosts)
	}

	rawJSON, err := json.Marshal(allHosts)
	if err != nil {
		return nil, nil, time.Time{}, err
	}

	var gzBuf bytes.Buffer
	gzWriter := gzip.NewWriter(&gzBuf)
	if _, err := gzWriter.Write(rawJSON); err != nil {
		return nil, nil, time.Time{}, err
	}
	if err := gzWriter.Close(); err != nil {
		return nil, nil, time.Time{}, err
	}

	cachedRawJSON = rawJSON
	cachedGzip = gzBuf.Bytes()
	cachedModTime = newestTime
	lastCacheCheck = time.Now()

	return cachedRawJSON, cachedGzip, cachedModTime, nil
}

func enrichWithOSV(hosts []HostPayload) {
	uniquePkgs := make(map[pkgKey]bool)
	for _, h := range hosts {
		for _, p := range h.Packages {
			if p.Name != "" && p.Version != "" {
				uniquePkgs[pkgKey{Name: p.Name, Version: p.Version}] = true
			}
		}
	}

	// Filter packages that need OSV lookup
	var toFetch []pkgKey
	osvCacheMu.RLock()
	for pk := range uniquePkgs {
		key := pk.Name + "@" + pk.Version
		entry, exists := osvCache[key]
		if !exists || time.Since(entry.fetchedAt) > osvCacheTTL {
			toFetch = append(toFetch, pk)
		}
	}
	osvCacheMu.RUnlock()

	// Batch query OSV API
	if len(toFetch) > 0 {
		fetchOSVBatch(toFetch)
	}

	// Attach results to hosts
	osvCacheMu.RLock()
	defer osvCacheMu.RUnlock()

	for i := range hosts {
		for j := range hosts[i].Packages {
			p := &hosts[i].Packages[j]
			key := p.Name + "@" + p.Version
			if entry, ok := osvCache[key]; ok && len(entry.vulnerabilities) > 0 {
				p.Vulnerabilities = entry.vulnerabilities
			}
		}
	}
}

func fetchOSVBatch(pkgs []pkgKey) {
	for i := 0; i < len(pkgs); i += osvBatchSize {
		end := i + osvBatchSize
		if end > len(pkgs) {
			end = len(pkgs)
		}
		chunk := pkgs[i:end]

		reqBody := osvBatchRequest{Queries: make([]osvQuery, len(chunk))}
		for idx, p := range chunk {
			reqBody.Queries[idx] = osvQuery{
				Package: osvPackage{Name: p.Name},
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
			key := p.Name + "@" + p.Version

			var vulns []Vulnerability
			for _, v := range res.Vulns {
				var cves []string
				for _, alias := range v.Aliases {
					if strings.HasPrefix(alias, "CVE-") {
						cves = append(cves, alias)
					}
				}

				vulnURL := fmt.Sprintf("https://osv.dev/vulnerabilities/%s", v.ID)
				for _, ref := range v.References {
					if ref.URL != "" {
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

			osvCache[key] = osvCacheEntry{
				vulnerabilities: vulns,
				fetchedAt:       now,
			}
		}
		osvCacheMu.Unlock()
	}
}

func handlePackages(w http.ResponseWriter, r *http.Request) {
	if activePSK != "" {
		if r.Header.Get("X-PSK") != activePSK {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}
	}

	rawJSON, gzData, modTime, err := loadDataWithCache()
	if err != nil {
		http.Error(w, fmt.Sprintf("Failed to load package data: %v", err), http.StatusInternalServerError)
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

	// Dynamic trigger to ensure fresh scan state before returning history
	_, _, _, _ = loadDataWithCache()

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
	sourceFile, err := os.Open(src)
	if err != nil {
		return err
	}
	defer func() { _ = sourceFile.Close() }()

	destFile, err := os.Create(dst)
	if err != nil {
		return err
	}
	defer func() { _ = destFile.Close() }()

	_, err = io.Copy(destFile, sourceFile)
	return err
}

func installSystemdService(port, dataPath, psk string, tlsEnabled, osvEnabled bool, osvURL, osvProxy string) error {
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
