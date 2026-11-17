package pkgdash

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"
)

// TLSConfig collects the client-side TLS settings. Verification is always on
// unless Insecure is explicitly set; the daemon's self-signed certificate can
// be trusted by pointing CAFile at its cert.pem.
type TLSConfig struct {
	CAFile     string
	CertFile   string
	KeyFile    string
	ServerName string
	Insecure   bool
}

// TLSConfigFromEnv reads the TLS settings shared by both clients.
func TLSConfigFromEnv() TLSConfig {
	insecure, _ := strconv.ParseBool(strings.TrimSpace(os.Getenv("PKGDASH_TLS_INSECURE")))
	return TLSConfig{
		CAFile:     strings.TrimSpace(os.Getenv("PKGDASH_CA_FILE")),
		CertFile:   strings.TrimSpace(os.Getenv("PKGDASH_CERT_FILE")),
		KeyFile:    strings.TrimSpace(os.Getenv("PKGDASH_KEY_FILE")),
		ServerName: strings.TrimSpace(os.Getenv("PKGDASH_TLS_SERVER_NAME")),
		Insecure:   insecure,
	}
}

// NewTLSConfig builds a verifying tls.Config from the supplied options.
func NewTLSConfig(opts TLSConfig) (*tls.Config, error) {
	cfg := &tls.Config{MinVersion: tls.VersionTLS12, ServerName: strings.TrimSpace(opts.ServerName)}
	if opts.Insecure {
		cfg.InsecureSkipVerify = true // #nosec G402 -- explicit, documented opt-in
		return cfg, nil
	}
	if opts.CAFile != "" {
		pemData, err := os.ReadFile(opts.CAFile)
		if err != nil {
			return nil, fmt.Errorf("read CA file: %w", err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(pemData) {
			return nil, fmt.Errorf("no certificates found in CA file %s", opts.CAFile)
		}
		cfg.RootCAs = pool
	}
	if opts.CertFile != "" || opts.KeyFile != "" {
		if opts.CertFile == "" || opts.KeyFile == "" {
			return nil, fmt.Errorf("both TLS certificate and key file are required")
		}
		cert, err := tls.LoadX509KeyPair(opts.CertFile, opts.KeyFile)
		if err != nil {
			return nil, fmt.Errorf("load client certificate: %w", err)
		}
		cfg.Certificates = []tls.Certificate{cert}
	}
	return cfg, nil
}

// NewHTTPClient returns an HTTP client with sensible timeouts and the given
// TLS settings. A nil TLS config uses the system roots.
func NewHTTPClient(timeout time.Duration, tlsCfg *tls.Config) *http.Client {
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.TLSClientConfig = tlsCfg
	transport.ResponseHeaderTimeout = timeout
	return &http.Client{Timeout: timeout, Transport: transport}
}

// Endpoint normalizes a daemon address and appends path. It refuses to send a
// PSK over plaintext HTTP, which would expose the shared secret on the wire.
func Endpoint(server, psk, path string) (string, error) {
	server = strings.TrimSpace(server)
	if server == "" {
		return "", fmt.Errorf("empty server address")
	}
	if !strings.Contains(server, "://") {
		server = "https://" + server
	}
	parsed, err := url.Parse(server)
	if err != nil {
		return "", fmt.Errorf("invalid server address %q: %w", server, err)
	}
	if parsed.Scheme != "http" && parsed.Scheme != "https" {
		return "", fmt.Errorf("unsupported scheme %q", parsed.Scheme)
	}
	if parsed.Host == "" {
		return "", fmt.Errorf("server address %q has no host", server)
	}
	if _, _, err := net.SplitHostPort(parsed.Host); err != nil {
		// No explicit port: use the daemon default. net.JoinHostPort keeps IPv6 valid.
		parsed.Host = net.JoinHostPort(parsed.Host, "9876")
	}
	if psk != "" && parsed.Scheme == "http" {
		return "", fmt.Errorf("refusing to send PSK to %s: use https:// or remove the PSK", parsed.Host)
	}
	parsed.Path = strings.TrimRight(parsed.Path, "/") + path
	return parsed.String(), nil
}

// HistoryURL builds a /history URL with properly encoded query parameters.
func HistoryURL(server, psk, hostname, pkgName string) (string, error) {
	endpoint, err := Endpoint(server, psk, "/history")
	if err != nil {
		return "", err
	}
	parsed, err := url.Parse(endpoint)
	if err != nil {
		return "", err
	}
	query := url.Values{}
	query.Set("host", hostname)
	query.Set("pkg", pkgName)
	parsed.RawQuery = query.Encode()
	return parsed.String(), nil
}
