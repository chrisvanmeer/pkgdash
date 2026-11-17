package main

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/subtle"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"math"
	"math/big"
	"mime"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"syscall"
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
	envFilePath        = "/etc/default/pkgdashd"
	installDir         = "/usr/local/bin"
	osvHTTPTimeout     = 30 * time.Second
	osvBatchSize       = 100
	syncInterval       = 30 * time.Second
)

var (
	activeDataPath string
	activePSK      string
	activeTLSHosts []string
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
	osvCache   = make(map[pkgKey]osvCacheEntry)

	// Payload/scan coordination. All fields are guarded by scanMu.
	scanMu          sync.Mutex
	scanActive      bool
	scanSequence    uint64
	payloadSequence uint64

	// Vulnerability Details Hydration Cache
	vulnDetailsCacheMu sync.RWMutex
	vulnDetailsCache   = make(map[string]osvDetailEntry)
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

// osvCacheRecord is the on-disk representation. Go maps with struct keys cannot
// be marshalled directly, so the cache is stored as a list of records.
type osvCacheRecord struct {
	Key   pkgKey        `json:"key"`
	Entry osvCacheEntry `json:"entry"`
}

type osvDetailEntry struct {
	Vuln      osvVuln
	FetchedAt time.Time
}

const (
	maxVulnDetailsCache = 2000
	vulnDetailsTTL      = 7 * 24 * time.Hour
)

var (
	cacheMu       sync.RWMutex
	cachedRawJSON []byte
	cachedGzip    []byte
	cachedModTime time.Time
)

// Vulnerability represents a vulnerability item. All fields are explicitly serialized in JSON.
type Vulnerability struct {
	ID       string  `json:"id"`
	Details  string  `json:"details"`
	URL      string  `json:"url"`
	Severity float64 `json:"severity"`
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

type osvSeverity struct {
	Type  string `json:"type"`
	Score string `json:"score"`
}

type osvAffected struct {
	Package  osvPackage    `json:"package"`
	Severity []osvSeverity `json:"severity,omitempty"`
}

type osvVuln struct {
	ID               string                 `json:"id"`
	Summary          string                 `json:"summary"`
	Details          string                 `json:"details"`
	Aliases          []string               `json:"aliases"`
	References       []osvReference         `json:"references"`
	Severity         []osvSeverity          `json:"severity,omitempty"`
	Affected         []osvAffected          `json:"affected,omitempty"`
	DatabaseSpecific map[string]interface{} `json:"database_specific,omitempty"`
}

type osvReference struct {
	Type string `json:"type"`
	URL  string `json:"url"`
}

func getEnvOrDefault(key, defaultValue string) string {
	if val := os.Getenv(key); val != "" {
		return val
	}
	return defaultValue
}

func getEnvBoolOrDefault(key string, defaultValue bool) bool {
	if val := os.Getenv(key); val != "" {
		return strings.ToLower(val) == "true" || val == "1"
	}
	return defaultValue
}

func getEnvDurationOrDefault(key string, defaultValue time.Duration) time.Duration {
	if val := os.Getenv(key); val != "" {
		if d, err := time.ParseDuration(val); err == nil && d > 0 {
			return d
		}
		log.Printf("Ignoring invalid %s=%q, using %s", key, val, defaultValue)
	}
	return defaultValue
}

// calculateCVSSv3BaseScore calculates the numeric base score from a CVSS 3.0/3.1 vector string.
func calculateCVSSv3BaseScore(vector string) float64 {
	parts := strings.Split(vector, "/")
	metrics := make(map[string]string)
	for _, part := range parts {
		kv := strings.Split(part, ":")
		if len(kv) == 2 {
			metrics[kv[0]] = kv[1]
		}
	}

	avMap := map[string]float64{"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2}
	acMap := map[string]float64{"L": 0.77, "H": 0.44}
	uiMap := map[string]float64{"N": 0.85, "R": 0.62}
	ciaMap := map[string]float64{"H": 0.56, "L": 0.22, "N": 0.0}

	scope := metrics["S"]
	prMap := map[string]float64{"N": 0.85, "L": 0.62, "H": 0.27}
	if scope == "C" {
		prMap["L"] = 0.68
		prMap["H"] = 0.50
	}

	av, ok1 := avMap[metrics["AV"]]
	ac, ok2 := acMap[metrics["AC"]]
	pr, ok3 := prMap[metrics["PR"]]
	ui, ok4 := uiMap[metrics["UI"]]
	c, ok5 := ciaMap[metrics["C"]]
	i, ok6 := ciaMap[metrics["I"]]
	a, ok7 := ciaMap[metrics["A"]]

	if !ok1 || !ok2 || !ok3 || !ok4 || !ok5 || !ok6 || !ok7 {
		return 0.0
	}

	iss := 1.0 - ((1.0 - c) * (1.0 - i) * (1.0 - a))
	if iss <= 0 {
		return 0.0
	}

	var impact float64
	switch scope {
	case "U":
		impact = 6.42 * iss
	case "C":
		impact = 7.52*(iss-0.029) - 3.25*math.Pow(iss-0.02, 15)
	default:
		return 0.0
	}

	exploitability := 8.22 * av * ac * pr * ui

	var baseScore float64
	if impact <= 0 {
		baseScore = 0.0
	} else {
		switch scope {
		case "U":
			baseScore = math.Min(impact+exploitability, 10.0)
		case "C":
			baseScore = math.Min(1.08*(impact+exploitability), 10.0)
		default:
			baseScore = 0.0
		}
	}

	return math.Ceil(baseScore*10.0) / 10.0
}

// calculateCVSSv4BaseScore provides an estimate for CVSS v4.0 vectors.
func calculateCVSSv4BaseScore(vector string) float64 {
	parts := strings.Split(vector, "/")
	metrics := make(map[string]string)
	for _, part := range parts {
		kv := strings.Split(part, ":")
		if len(kv) == 2 {
			metrics[kv[0]] = kv[1]
		}
	}

	vc := metrics["VC"]
	vi := metrics["VI"]
	va := metrics["VA"]

	if vc == "H" && vi == "H" && va == "H" {
		return 9.3
	} else if vc == "H" || vi == "H" || va == "H" {
		return 7.5
	} else if vc == "L" || vi == "L" || va == "L" {
		return 5.3
	}
	return 6.0
}

// parseCVSSScore converts a numeric string, textual rating, or CVSS vector into a float64 score.
func parseCVSSScore(scoreStr string) float64 {
	scoreStr = strings.TrimSpace(scoreStr)
	if scoreStr == "" {
		return 0.0
	}

	if val, err := strconv.ParseFloat(scoreStr, 64); err == nil {
		if math.IsNaN(val) || math.IsInf(val, 0) || val < 0 || val > 10 {
			return 0
		}
		return val
	}

	switch strings.ToLower(scoreStr) {
	case "critical":
		return 9.5
	case "high":
		return 7.5
	case "medium", "moderate":
		return 5.5
	case "low":
		return 2.5
	case "negligible", "untriaged", "informational":
		return 0.1
	}

	if idx := strings.Index(scoreStr, "CVSS:3."); idx != -1 {
		return calculateCVSSv3BaseScore(scoreStr[idx:])
	}

	if idx := strings.Index(scoreStr, "CVSS:4.0/"); idx != -1 {
		return calculateCVSSv4BaseScore(scoreStr[idx:])
	}

	return 0.0
}

// extractHighestCVSSScore checks explicit CVSS vectors first.
// Textual vendor ratings (like type "Ubuntu" with score "medium") are only used as fallback if no CVSS vector exists.
func extractHighestCVSSScore(v osvVuln) float64 {
	var maxScore float64

	isCVSS := func(sev osvSeverity) bool {
		t := strings.ToUpper(sev.Type)
		s := strings.TrimSpace(sev.Score)
		return strings.HasPrefix(t, "CVSS") || strings.HasPrefix(s, "CVSS:")
	}

	// 1. First pass: look ONLY for explicit CVSS vectors/scores
	for _, sev := range v.Severity {
		if isCVSS(sev) {
			if score := parseCVSSScore(sev.Score); score > maxScore {
				maxScore = score
			}
		}
	}

	for _, aff := range v.Affected {
		for _, sev := range aff.Severity {
			if isCVSS(sev) {
				if score := parseCVSSScore(sev.Score); score > maxScore {
					maxScore = score
				}
			}
		}
	}

	// 2. Second pass: fallback to textual ratings (type "Ubuntu", etc.) if no CVSS vector was found
	if maxScore == 0.0 {
		for _, sev := range v.Severity {
			if !isCVSS(sev) {
				if score := parseCVSSScore(sev.Score); score > maxScore {
					maxScore = score
				}
			}
		}
		for _, aff := range v.Affected {
			for _, sev := range aff.Severity {
				if !isCVSS(sev) {
					if score := parseCVSSScore(sev.Score); score > maxScore {
						maxScore = score
					}
				}
			}
		}
	}

	// 3. Third pass: fallback to database_specific ratings if still no score found
	if maxScore == 0.0 && v.DatabaseSpecific != nil {
		if prio, ok := v.DatabaseSpecific["ubuntu_priority"].(string); ok {
			maxScore = parseCVSSScore(prio)
		} else if sevStr, ok := v.DatabaseSpecific["severity"].(string); ok {
			maxScore = parseCVSSScore(sevStr)
		} else if sevNum, ok := v.DatabaseSpecific["severity"].(float64); ok {
			if !math.IsNaN(sevNum) && !math.IsInf(sevNum, 0) && sevNum >= 0 && sevNum <= 10 {
				maxScore = sevNum
			}
		}
	}

	if math.IsNaN(maxScore) || math.IsInf(maxScore, 0) {
		return 0
	}
	return maxScore
}

// fetchOSVVulnerabilityDetails retrieves full vulnerability payload by ID with rate-limit retry support.
func fetchOSVVulnerabilityDetails(vulnID string) (osvVuln, error) {
	vulnDetailsCacheMu.RLock()
	if entry, exists := vulnDetailsCache[vulnID]; exists && time.Since(entry.FetchedAt) < vulnDetailsTTL {
		vulnDetailsCacheMu.RUnlock()
		return entry.Vuln, nil
	}
	vulnDetailsCacheMu.RUnlock()

	endpoint := fmt.Sprintf("%s/v1/vulns/%s", activeOSVURL, url.PathEscape(vulnID))
	maxRetries := 3
	var lastErr error

	for attempt := 0; attempt < maxRetries; attempt++ {
		if attempt > 0 {
			time.Sleep(time.Duration(attempt*150) * time.Millisecond)
		}

		resp, err := osvHTTPClient.Get(endpoint)
		if err != nil {
			lastErr = err
			continue
		}

		if resp.StatusCode == http.StatusTooManyRequests {
			_ = resp.Body.Close()
			time.Sleep(time.Duration((attempt+1)*300) * time.Millisecond)
			lastErr = fmt.Errorf("rate limited (429)")
			continue
		}

		if resp.StatusCode != http.StatusOK {
			_ = resp.Body.Close()
			lastErr = fmt.Errorf("HTTP status %d", resp.StatusCode)
			continue
		}

		var v osvVuln
		err = json.NewDecoder(resp.Body).Decode(&v)
		_ = resp.Body.Close()
		if err != nil {
			lastErr = err
			continue
		}

		vulnDetailsCacheMu.Lock()
		if len(vulnDetailsCache) >= maxVulnDetailsCache {
			// Remove the oldest entries to keep memory bounded.
			var oldestID string
			var oldestTime time.Time
			for id, cached := range vulnDetailsCache {
				if oldestID == "" || cached.FetchedAt.Before(oldestTime) {
					oldestID, oldestTime = id, cached.FetchedAt
				}
			}
			delete(vulnDetailsCache, oldestID)
		}
		vulnDetailsCache[vulnID] = osvDetailEntry{Vuln: v, FetchedAt: time.Now()}
		vulnDetailsCacheMu.Unlock()

		return v, nil
	}

	return osvVuln{}, lastErr
}

// hydrateVulnerabilities fetches complete vulnerability details concurrently with rate limiting.
func hydrateVulnerabilities(vulnIDs []string) {
	uniqueIDs := make([]string, 0, len(vulnIDs))
	seen := make(map[string]bool)

	vulnDetailsCacheMu.RLock()
	for _, id := range vulnIDs {
		if !seen[id] {
			seen[id] = true
			entry, exists := vulnDetailsCache[id]
			if !exists || time.Since(entry.FetchedAt) >= vulnDetailsTTL {
				uniqueIDs = append(uniqueIDs, id)
			}
		}
	}
	vulnDetailsCacheMu.RUnlock()

	if len(uniqueIDs) == 0 {
		return
	}

	log.Printf("Hydrating CVSS scores for %d unique vulnerabilities in background...", len(uniqueIDs))

	jobs := make(chan string, len(uniqueIDs))
	for _, id := range uniqueIDs {
		jobs <- id
	}
	close(jobs)

	var wg sync.WaitGroup
	workers := 5
	if len(uniqueIDs) < workers {
		workers = len(uniqueIDs)
	}

	var successCount int64
	var mu sync.Mutex

	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for id := range jobs {
				time.Sleep(15 * time.Millisecond) // Throttle to prevent rate limits
				_, err := fetchOSVVulnerabilityDetails(id)
				if err == nil {
					mu.Lock()
					successCount++
					mu.Unlock()
				}
			}
		}()
	}

	wg.Wait()
	log.Printf("Background hydration complete: successfully fetched %d/%d vulnerability details", successCount, len(uniqueIDs))
}

func main() {
	installFlag := flag.Bool("install", false, "Install binary to /usr/local/bin and enable systemd service")
	uninstallFlag := flag.Bool("uninstall", false, "Stop, disable, and remove the systemd service and binary")

	portFlag := flag.String("port", getEnvOrDefault("PKGDASH_PORT", defaultPort), "Port to listen on")
	dataPathFlag := flag.String("data-path", getEnvOrDefault("PKGDASH_DATA_PATH", defaultDataPath), "Path to directory containing JSON files")
	pskFlag := flag.String("psk", getEnvOrDefault("PKGDASH_PSK", ""), "Pre-shared key for authentication")
	tlsFlag := flag.Bool("tls", getEnvBoolOrDefault("PKGDASH_TLS", false), "Enable TLS encryption")
	tlsHostsFlag := flag.String("tls-hosts", getEnvOrDefault("PKGDASH_TLS_HOSTS", ""), "Comma-separated DNS names/IPs to include in generated TLS certificate (SANs)")
	serviceUserFlag := flag.String("service-user", getEnvOrDefault("PKGDASH_SERVICE_USER", ""), "User account used by the installed systemd service (empty means root)")

	osvEnableFlag := flag.Bool("enable-osv", getEnvBoolOrDefault("PKGDASH_ENABLE_OSV", defaultOSVEnable), "Enable OSV.dev vulnerability checking")
	osvURLFlag := flag.String("osv-url", getEnvOrDefault("PKGDASH_OSV_URL", defaultOSVURL), "OSV API URL")
	osvProxyFlag := flag.String("osv-proxy", getEnvOrDefault("PKGDASH_OSV_PROXY", defaultOSVProxy), "Proxy URL for OSV requests")
	osvCacheTTLFlag := flag.Duration("osv-cache-ttl", getEnvDurationOrDefault("PKGDASH_OSV_CACHE_TTL", defaultOSVCacheTTL), "OSV cache TTL duration")

	flag.Parse()

	activeDataPath = *dataPathFlag
	activePSK = strings.TrimSpace(*pskFlag)
	for _, host := range strings.Split(*tlsHostsFlag, ",") {
		if host = strings.TrimSpace(host); host != "" {
			activeTLSHosts = append(activeTLSHosts, host)
		}
	}
	if hostname, err := os.Hostname(); err == nil && hostname != "" {
		activeTLSHosts = append(activeTLSHosts, hostname)
	}
	activeTLSHosts = append(activeTLSHosts, "localhost", "127.0.0.1", "::1")
	activeOSVEnabled = *osvEnableFlag
	activeOSVURL = strings.TrimRight(*osvURLFlag, "/")
	activeOSVProxy = *osvProxyFlag
	activeOSVCacheTTL = *osvCacheTTLFlag

	if *installFlag && *uninstallFlag {
		log.Fatal("Cannot use --install and --uninstall at the same time")
	}

	if *installFlag {
		if err := installSystemdService(*portFlag, *dataPathFlag, *pskFlag, *tlsFlag, *tlsHostsFlag, *serviceUserFlag, activeOSVEnabled, activeOSVURL, activeOSVProxy, activeOSVCacheTTL); err != nil {
			log.Fatalf("Failed to install systemd service: %v", err)
		}
		fmt.Printf("Systemd service installed successfully.\nConfiguration written to %s (0600)\nListening on %s | Reading from %s\n", envFilePath, *portFlag, *dataPathFlag)
		return
	}

	if *uninstallFlag {
		if err := uninstallSystemdService(); err != nil {
			log.Fatalf("Failed to uninstall systemd service: %v", err)
		}
		fmt.Println("Systemd service uninstalled successfully.")
		return
	}

	if activePSK != "" && !*tlsFlag {
		log.Fatal("Refusing to start: --psk requires --tls (a PSK sent over plaintext HTTP can be intercepted)")
	}

	if activeOSVEnabled {
		initOSVHTTPClient()
		loadOSVCacheFromDisk()
		log.Printf("OSV vulnerability integration ENABLED (API: %s | Cache TTL: %s)", activeOSVURL, activeOSVCacheTTL)
	}

	historyMgr = NewHistoryManager(activeDataPath)

	refreshCache(false)

	go startBackgroundSync(syncInterval)

	mux := http.NewServeMux()
	mux.HandleFunc("/packages", handlePackages)
	mux.HandleFunc("/history", handleHistory)
	server := &http.Server{
		Addr:              *portFlag,
		Handler:           mux,
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      60 * time.Second,
		IdleTimeout:       120 * time.Second,
	}
	log.Printf("Starting pkgdashd listener on port %s, serving data from %s...", *portFlag, activeDataPath)

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	go func() {
		<-ctx.Done()
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if err := server.Shutdown(shutdownCtx); err != nil {
			log.Printf("Graceful shutdown failed: %v", err)
		}
	}()

	var err error
	if *tlsFlag {
		certPath := filepath.Join(activeDataPath, "cert.pem")
		keyPath := filepath.Join(activeDataPath, "key.pem")
		if err = ensureTLSCerts(certPath, keyPath); err != nil {
			log.Fatalf("Failed to generate TLS certificates: %v", err)
		}
		err = server.ListenAndServeTLS(certPath, keyPath)
	} else {
		err = server.ListenAndServe()
	}
	if err != nil && !errors.Is(err, http.ErrServerClosed) {
		log.Fatalf("Server error: %v", err)
	}
}

var osVersionRegex = regexp.MustCompile(`\d+\.\d+`)

func determineEcosystem(osName, osVersion string) string {
	name := strings.ToLower(osName)

	if strings.Contains(name, "ubuntu") {
		if match := osVersionRegex.FindString(osVersion); match != "" {
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
		if match := osVersionRegex.FindString(osVersion); match != "" {
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

	var records []osvCacheRecord
	if err := json.Unmarshal(data, &records); err != nil {
		log.Printf("Ignoring unreadable OSV cache: %v", err)
		return
	}
	loaded := make(map[pkgKey]osvCacheEntry, len(records))
	for _, record := range records {
		if record.Key.Name == "" {
			continue
		}
		loaded[record.Key] = record.Entry
	}

	osvCacheMu.Lock()
	osvCache = loaded
	osvCacheMu.Unlock()
	log.Printf("Loaded %d cached OSV package entries from disk", len(loaded))
}

func saveOSVCacheToDisk() {
	osvCacheMu.RLock()
	records := make([]osvCacheRecord, 0, len(osvCache))
	for key, entry := range osvCache {
		records = append(records, osvCacheRecord{Key: key, Entry: entry})
	}
	osvCacheMu.RUnlock()

	data, err := json.Marshal(records)
	if err != nil {
		log.Printf("Failed to encode OSV cache: %v", err)
		return
	}

	if err := os.MkdirAll(activeDataPath, 0750); err != nil {
		log.Printf("Failed to create data directory: %v", err)
		return
	}
	cacheFile := filepath.Join(activeDataPath, "osv_cache.json")
	tmpFile, err := os.CreateTemp(activeDataPath, ".osv_cache-*.tmp")
	if err != nil {
		log.Printf("Failed to create temporary OSV cache file: %v", err)
		return
	}
	tmpName := tmpFile.Name()
	defer func() { _ = os.Remove(tmpName) }()
	if _, err := tmpFile.Write(data); err != nil {
		_ = tmpFile.Close()
		log.Printf("Failed to write OSV cache: %v", err)
		return
	}
	if err := tmpFile.Close(); err != nil {
		log.Printf("Failed to close OSV cache file: %v", err)
		return
	}
	if err := os.Chmod(tmpName, 0640); err != nil {
		log.Printf("Failed to set OSV cache permissions: %v", err)
		return
	}
	if err := os.Rename(tmpName, cacheFile); err != nil {
		log.Printf("Failed to replace OSV cache file: %v", err)
	}
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
	if err := os.MkdirAll(activeDataPath, 0750); err != nil {
		log.Printf("Cannot access data directory %s: %v", activeDataPath, err)
		return
	}
	files, err := filepath.Glob(filepath.Join(activeDataPath, "*.json"))
	if err != nil {
		log.Printf("Cannot list data files: %v", err)
		return
	}

	var newestTime time.Time
	var allHosts []HostPayload
	currentState := make(map[string]map[string]string)
	readFailed := false

	for _, file := range files {
		if strings.HasSuffix(file, "history.json") || strings.HasSuffix(file, "history.jsonl") || strings.HasSuffix(file, "osv_cache.json") {
			continue
		}

		info, err := os.Stat(file)
		if err != nil {
			log.Printf("Cannot stat %s: %v", file, err)
			readFailed = true
			continue
		}
		if info.Size() == 0 {
			continue
		}
		if info.ModTime().After(newestTime) {
			newestTime = info.ModTime()
		}

		data, err := os.ReadFile(file)
		if err != nil {
			log.Printf("Cannot read %s (skipping this sync cycle): %v", file, err)
			readFailed = true
			continue
		}

		var hosts []HostPayload
		if err := json.Unmarshal(data, &hosts); err != nil {
			log.Printf("Cannot parse %s (skipping this sync cycle): %v", file, err)
			readFailed = true
			continue
		}
		if len(hosts) == 0 {
			continue
		}
		for i := range hosts {
			hosts[i].OSVEnabled = activeOSVEnabled
			if currentState[hosts[i].Hostname] == nil {
				currentState[hosts[i].Hostname] = make(map[string]string)
			}
			for _, pkg := range hosts[i].Packages {
				currentState[hosts[i].Hostname][packageStateKey(pkg.Name, pkg.Arch)] = pkg.Version
			}
		}
		allHosts = append(allHosts, hosts...)
	}

	// A transient read failure would otherwise look like package removals.
	if readFailed {
		log.Printf("Skipping history and payload update: one or more data files could not be read")
		return
	}

	scanMu.Lock()
	if historyMgr != nil && len(previousState) > 0 {
		diffs := ComputeDiffs(previousState, currentState)
		if len(diffs) > 0 {
			historyMgr.RecordChanges(diffs)
		}
	}
	previousState = currentState
	payloadSequence++
	currentPayloadSeq := payloadSequence
	scanning := scanActive
	if activeOSVEnabled && len(allHosts) > 0 && fetchOSV && !scanning {
		scanActive = true
		scanSequence++
		scanSeq := scanSequence
		scanMu.Unlock()
		go func(hosts []HostPayload, modTime time.Time) {
			defer func() {
				scanMu.Lock()
				scanActive = false
				scanMu.Unlock()
			}()
			enrichWithOSV(hosts, modTime, scanSeq, currentPayloadSeq)
		}(allHosts, newestTime)
		return
	}
	scanMu.Unlock()

	if activeOSVEnabled && len(allHosts) > 0 {
		attachCachedOSV(allHosts)
	}
	updatePayloadCache(allHosts, newestTime)
}

// publishOSVPayload only applies results from the active OSV scan. If files
// changed or a newer scan started while this one ran, the stale result is
// discarded instead of overwriting fresh data.
func publishOSVPayload(hosts []HostPayload, newestTime time.Time, scanSeq, payloadSeq uint64) {
	scanMu.Lock()
	currentScan, currentPayload := scanSequence, payloadSequence
	scanMu.Unlock()
	if currentScan != scanSeq || currentPayload != payloadSeq {
		log.Printf("Discarding stale OSV result (scan %d/%d, current %d/%d)", scanSeq, payloadSeq, currentScan, currentPayload)
		return
	}
	updatePayloadCache(hosts, newestTime)
}

func updatePayloadCache(allHosts []HostPayload, newestTime time.Time) {
	if allHosts == nil {
		allHosts = []HostPayload{}
	}
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
	cacheMu.Unlock()
}

func attachCachedOSV(hosts []HostPayload) {
	osvCacheMu.RLock()
	defer osvCacheMu.RUnlock()

	for i := range hosts {
		eco := determineEcosystem(hosts[i].OSName, hosts[i].OSVersion)
		for j := range hosts[i].Packages {
			p := &hosts[i].Packages[j]
			key := pkgKey{Name: p.Name, Version: p.Version, Ecosystem: eco}
			entry, ok := osvCache[key]
			if !ok || time.Since(entry.FetchedAt) > activeOSVCacheTTL {
				continue
			}
			if len(entry.Vulnerabilities) > 0 {
				p.Vulnerabilities = entry.Vulnerabilities
			}
		}
	}
}

func enrichWithOSV(hosts []HostPayload, newestTime time.Time, scanSeq, payloadSeq uint64) {
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
		entry, exists := osvCache[pk]
		if !exists || time.Since(entry.FetchedAt) > activeOSVCacheTTL {
			toFetch = append(toFetch, pk)
		}
	}
	osvCacheMu.RUnlock()

	if len(toFetch) > 0 {
		log.Printf("Querying OSV.dev API for %d packages (Cache TTL: %s)...", len(toFetch), activeOSVCacheTTL)
		fetchOSVBatch(toFetch, hosts, newestTime, scanSeq, payloadSeq)
	} else {
		attachCachedOSV(hosts)
		publishOSVPayload(hosts, newestTime, scanSeq, payloadSeq)
	}
}

func fetchOSVBatch(pkgs []pkgKey, hosts []HostPayload, newestTime time.Time, scanSeq, payloadSeq uint64) {
	vulnCount := 0
	var idsToHydrate []string
	now := time.Now()
	// Results are collected without holding the cache lock during network I/O.
	updates := make(map[pkgKey]osvCacheEntry, len(pkgs))

	for i := 0; i < len(pkgs); i += osvBatchSize {
		end := min(i+osvBatchSize, len(pkgs))
		chunk := pkgs[i:end]

		reqBody := osvBatchRequest{Queries: make([]osvQuery, len(chunk))}
		for idx, p := range chunk {
			reqBody.Queries[idx] = osvQuery{
				Package: osvPackage{Name: p.Name, Ecosystem: p.Ecosystem},
				Version: p.Version,
			}
		}
		bodyBytes, err := json.Marshal(reqBody)
		if err != nil {
			continue
		}

		var batchResp osvBatchResponse
		for attempt := 0; attempt < 3; attempt++ {
			if attempt > 0 {
				time.Sleep(time.Duration(attempt) * 500 * time.Millisecond)
			}
			resp, err := osvHTTPClient.Post(activeOSVURL+"/v1/querybatch", "application/json", bytes.NewReader(bodyBytes))
			if err != nil {
				log.Printf("OSV query failed: %v", err)
				continue
			}
			if resp.StatusCode == http.StatusTooManyRequests || resp.StatusCode >= http.StatusInternalServerError {
				_ = resp.Body.Close()
				log.Printf("OSV query returned status %d, retrying", resp.StatusCode)
				continue
			}
			if resp.StatusCode != http.StatusOK {
				_ = resp.Body.Close()
				log.Printf("OSV query returned status %d", resp.StatusCode)
				break
			}
			err = json.NewDecoder(resp.Body).Decode(&batchResp)
			_ = resp.Body.Close()
			if err != nil {
				log.Printf("OSV response decoding failed: %v", err)
				continue
			}
			for idx, res := range batchResp.Results {
				if idx >= len(chunk) {
					break
				}
				var vulns []Vulnerability
				for _, minimalVuln := range res.Vulns {
					idsToHydrate = append(idsToHydrate, minimalVuln.ID)
					vulns = append(vulns, Vulnerability{
						ID:      minimalVuln.ID,
						URL:     "https://osv.dev/vulnerability/" + url.PathEscape(minimalVuln.ID),
						Details: "",
					})
				}
				vulnCount += len(vulns)
				updates[chunk[idx]] = osvCacheEntry{Vulnerabilities: vulns, FetchedAt: now}
			}
			// Successful responses also cache "no vulnerabilities" results.
			for _, p := range chunk {
				if _, ok := updates[p]; !ok {
					updates[p] = osvCacheEntry{FetchedAt: now}
				}
			}
			break
		}
	}

	osvCacheMu.Lock()
	for key, entry := range updates {
		osvCache[key] = entry
	}
	osvCacheMu.Unlock()

	// STEP 1: Publish minimal data with all fields present in JSON.
	attachCachedOSV(hosts)
	saveOSVCacheToDisk()
	publishOSVPayload(hosts, newestTime, scanSeq, payloadSeq)
	log.Printf("OSV initial scan complete: found %d vulnerabilities.", vulnCount)

	if len(idsToHydrate) == 0 {
		return
	}

	// STEP 2: Hydrate CVSS scores in the background.
	hydrateVulnerabilities(idsToHydrate)

	// STEP 3: Enrich cache entries with the fetched scores.
	osvCacheMu.Lock()
	for key, entry := range osvCache {
		updated := false
		for idx, v := range entry.Vulnerabilities {
			vulnDetailsCacheMu.RLock()
			cached, ok := vulnDetailsCache[v.ID]
			vulnDetailsCacheMu.RUnlock()
			if !ok || time.Since(cached.FetchedAt) >= vulnDetailsTTL {
				continue
			}
			hydrated := cached.Vuln
			vulnURL := fmt.Sprintf("https://osv.dev/vulnerability/%s", url.PathEscape(hydrated.ID))
			for _, ref := range hydrated.References {
				if (ref.Type == "ADVISORY" || ref.Type == "WEB") && strings.HasPrefix(ref.URL, "http") {
					vulnURL = ref.URL
					break
				}
			}
			entry.Vulnerabilities[idx].Details = hydrated.Details
			entry.Vulnerabilities[idx].URL = vulnURL
			entry.Vulnerabilities[idx].Severity = extractHighestCVSSScore(hydrated)
			updated = true
		}
		if updated {
			osvCache[key] = entry
		}
	}
	osvCacheMu.Unlock()

	// STEP 4: Republish the fully enriched payload if no newer scan/files won.
	attachCachedOSV(hosts)
	saveOSVCacheToDisk()
	publishOSVPayload(hosts, newestTime, scanSeq, payloadSeq)
	log.Printf("OSV severity enrichment complete: payload and cache updated with CVSS scores.")
}

func validPSK(provided, expected string) bool {
	return subtle.ConstantTimeCompare([]byte(provided), []byte(expected)) == 1
}

func handlePackages(w http.ResponseWriter, r *http.Request) {
	if activePSK != "" && !validPSK(r.Header.Get("X-PSK"), activePSK) {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
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
	w.Header().Set("Vary", "Accept-Encoding")
	w.Header().Set("X-OSV-Enabled", strconv.FormatBool(activeOSVEnabled))
	if !modTime.IsZero() {
		w.Header().Set("Last-Modified", modTime.UTC().Format(http.TimeFormat))
	}

	if !modTime.IsZero() {
		if since, err := http.ParseTime(r.Header.Get("If-Modified-Since")); err == nil && !modTime.After(since) {
			w.WriteHeader(http.StatusNotModified)
			return
		}
	}

	if acceptsGzip(r.Header.Get("Accept-Encoding")) {
		w.Header().Set("Content-Encoding", "gzip")
		_, _ = w.Write(gzData)
		return
	}

	_, _ = w.Write(rawJSON)
}

// acceptsGzip honors quality values, so "gzip;q=0" does not enable gzip.
func acceptsGzip(header string) bool {
	for _, part := range strings.Split(header, ",") {
		name, params, err := mime.ParseMediaType(strings.TrimSpace(part))
		if err != nil || !strings.EqualFold(name, "gzip") {
			continue
		}
		if q, ok := params["q"]; ok {
			value, err := strconv.ParseFloat(q, 64)
			if err == nil && value <= 0 {
				continue
			}
		}
		return true
	}
	return false
}

func handleHistory(w http.ResponseWriter, r *http.Request) {
	if activePSK != "" && !validPSK(r.Header.Get("X-PSK"), activePSK) {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
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
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 62))
	if err != nil {
		return err
	}

	var dnsNames []string
	var ipAddresses []net.IP
	seen := make(map[string]bool)
	for _, host := range activeTLSHosts {
		if seen[host] {
			continue
		}
		seen[host] = true
		if ip := net.ParseIP(host); ip != nil {
			ipAddresses = append(ipAddresses, ip)
		} else {
			dnsNames = append(dnsNames, host)
		}
	}
	commonName := "pkgdashd"
	if len(dnsNames) > 0 {
		commonName = dnsNames[0]
	}
	template := x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: commonName, Organization: []string{"pkgdash Auto-TLS"}},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(3650 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		DNSNames:              dnsNames,
		IPAddresses:           ipAddresses,
	}
	derBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
	if err != nil {
		return err
	}

	certOut, err := os.OpenFile(certPath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0644)
	if err != nil {
		return err
	}
	if err := pem.Encode(certOut, &pem.Block{Type: "CERTIFICATE", Bytes: derBytes}); err != nil {
		_ = certOut.Close()
		return err
	}
	if err := certOut.Close(); err != nil {
		return err
	}

	keyOut, err := os.OpenFile(keyPath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		return err
	}
	privBytes, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		_ = keyOut.Close()
		return err
	}
	if err := pem.Encode(keyOut, &pem.Block{Type: "PRIVATE KEY", Bytes: privBytes}); err != nil {
		_ = keyOut.Close()
		return err
	}
	return keyOut.Close()
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

// systemdEnvValue quotes a value according to systemd EnvironmentFile rules:
// backslashes, quotes, dollar signs and backticks must be escaped because
// double-quoted values are subject to variable expansion.
func systemdEnvValue(value string) string {
	value = strings.ReplaceAll(value, `\`, `\\`)
	value = strings.ReplaceAll(value, `"`, `\"`)
	value = strings.ReplaceAll(value, `$`, `\$`)
	value = strings.ReplaceAll(value, "`", "\\`")
	return `"` + value + `"`
}

func installSystemdService(port, dataPath, psk string, tlsEnabled bool, tlsHosts, serviceUser string, osvEnabled bool, osvURL, osvProxy string, osvCacheTTL time.Duration) error {
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

	envContent := fmt.Sprintf(`PKGDASH_PORT=%s
PKGDASH_DATA_PATH=%s
PKGDASH_PSK=%s
PKGDASH_TLS="%t"
PKGDASH_TLS_HOSTS=%s
PKGDASH_ENABLE_OSV="%t"
PKGDASH_OSV_URL=%s
PKGDASH_OSV_PROXY=%s
PKGDASH_OSV_CACHE_TTL=%s
`, systemdEnvValue(port), systemdEnvValue(dataPath), systemdEnvValue(psk), tlsEnabled,
		systemdEnvValue(tlsHosts), osvEnabled, systemdEnvValue(osvURL), systemdEnvValue(osvProxy),
		systemdEnvValue(osvCacheTTL.String()))

	if err := os.WriteFile(envFilePath, []byte(envContent), 0600); err != nil {
		return fmt.Errorf("failed to write environment file %s: %w", envFilePath, err)
	}

	userDirective := ""
	if strings.TrimSpace(serviceUser) != "" {
		userDirective = "User=" + strings.TrimSpace(serviceUser) + "\n"
	}
	unitContent := fmt.Sprintf(`[Unit]
Description=pkgdash package listener daemon
After=network.target

[Service]
Type=simple
EnvironmentFile=-%s
ExecStart=%s
Restart=always
%s[Install]
WantedBy=multi-user.target
`, envFilePath, targetPath, userDirective)

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
	var errs []error
	unitPath := fmt.Sprintf("/etc/systemd/system/%s.service", serviceName)
	_, unitExists := os.Stat(unitPath)
	if unitExists == nil {
		if err := exec.Command("systemctl", "stop", serviceName).Run(); err != nil {
			errs = append(errs, fmt.Errorf("stop service: %w", err))
		}
		if err := exec.Command("systemctl", "disable", serviceName).Run(); err != nil {
			errs = append(errs, fmt.Errorf("disable service: %w", err))
		}
	}
	for _, path := range []string{unitPath, envFilePath, filepath.Join(installDir, serviceName)} {
		if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
			errs = append(errs, fmt.Errorf("remove %s: %w", path, err))
		}
	}
	if err := exec.Command("systemctl", "daemon-reload").Run(); err != nil {
		errs = append(errs, fmt.Errorf("daemon-reload: %w", err))
	}
	return errors.Join(errs...)
}
