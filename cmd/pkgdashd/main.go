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
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

const (
	defaultPort     = ":9876"
	defaultDataPath = "/tmp/pkgdash"
	serviceName     = "pkgdashd"
	installDir      = "/usr/local/bin"
)

var (
	activeDataPath string
	activePSK      string
)

// Cache structures
var (
	cacheMu        sync.RWMutex
	cachedRawJSON  []byte
	cachedGzip     []byte
	cachedModTime  time.Time
	lastCacheCheck time.Time
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

func main() {
	installFlag := flag.Bool("install", false, "Install binary to /usr/local/bin and enable systemd service")
	uninstallFlag := flag.Bool("uninstall", false, "Stop, disable, and remove the systemd service and binary")
	portFlag := flag.String("port", defaultPort, "Port to listen on")
	dataPathFlag := flag.String("data-path", defaultDataPath, "Path to the directory containing JSON files")
	pskFlag := flag.String("psk", "", "Pre-shared key for authentication (optional)")
	tlsFlag := flag.Bool("tls", false, "Enable TLS encryption (auto-generates certificates)")
	flag.Parse()

	activeDataPath = *dataPathFlag
	activePSK = *pskFlag

	if *installFlag && *uninstallFlag {
		log.Fatal("Cannot use --install and --uninstall at the same time")
	}

	if *installFlag {
		if err := installSystemdService(*portFlag, *dataPathFlag, *pskFlag, *tlsFlag); err != nil {
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

	http.HandleFunc("/packages", handlePackages)
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

	for _, file := range files {
		if info, err := os.Stat(file); err == nil && info.ModTime().After(newestTime) {
			newestTime = info.ModTime()
		}
		data, err := os.ReadFile(file)
		if err != nil {
			continue
		}
		var hosts []HostPayload
		if err := json.Unmarshal(data, &hosts); err == nil {
			allHosts = append(allHosts, hosts...)
		}
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

func installSystemdService(port, dataPath, psk string, tlsEnabled bool) error {
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
