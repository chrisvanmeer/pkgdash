package pkgdash

import (
	"bufio"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// ClientConfig is the configuration shared by the TUI and web clients.
type ClientConfig struct {
	Servers     []string
	PSK         string
	MinSeverity float64
	WebPort     string
	TLS         TLSConfig
}

// LoadClientConfig reads environment variables first and falls back to
// ~/.local/pkgdash.config. Environment values always win over file values.
//
// The file uses INI sections:
//
//	[server]
//	servers = https://daemon.example:9876
//	psk = your-secret-key
//
//	[client]
//	tls_insecure = true
//
// Flat, section-less files from older releases are still accepted.
func LoadClientConfig() ClientConfig {
	cfg := ClientConfig{WebPort: ":8080", TLS: TLSConfigFromEnv()}

	serversFromEnv := false
	if value := strings.TrimSpace(os.Getenv("PKGDASH_SERVERS")); value != "" {
		cfg.Servers = splitServers(value)
		serversFromEnv = true
	}
	cfg.PSK = strings.TrimSpace(os.Getenv("PKGDASH_PSK"))
	if value := strings.TrimSpace(os.Getenv("PKGDASH_MIN_SEVERITY")); value != "" {
		if parsed, err := strconv.ParseFloat(value, 64); err == nil {
			cfg.MinSeverity = parsed
		}
	}
	if value := strings.TrimSpace(os.Getenv("PKGDASH_WEB_PORT")); value != "" {
		cfg.WebPort = normalizePort(value)
	}

	home, err := os.UserHomeDir()
	if err != nil {
		return cfg
	}
	file, err := os.Open(filepath.Join(home, ".local", "pkgdash.config"))
	if err != nil {
		return cfg
	}
	defer func() { _ = file.Close() }()

	section := ""
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";") {
			continue
		}
		if strings.HasPrefix(line, "[") && strings.HasSuffix(line, "]") {
			section = strings.ToLower(strings.TrimSpace(line[1 : len(line)-1]))
			continue
		}

		key, value, hasValue := strings.Cut(line, "=")
		key = strings.ToLower(strings.TrimSpace(key))
		value = strings.TrimSpace(value)

		// Lines without a section are treated as legacy top-level settings.
		inServer := section == "server" || section == ""
		inClient := section == "client" || section == ""

		switch {
		case (key == "servers" || key == "server" || key == "addresses" || key == "address") && inServer:
			if !serversFromEnv && value != "" {
				cfg.Servers = append(cfg.Servers, splitServers(value)...)
			}
		case key == "psk" && inServer:
			if cfg.PSK == "" {
				cfg.PSK = value
			}
		case key == "min_severity" && inClient:
			if envMissing("PKGDASH_MIN_SEVERITY") {
				if parsed, err := strconv.ParseFloat(value, 64); err == nil {
					cfg.MinSeverity = parsed
				}
			}
		case key == "web_port" && inClient:
			if envMissing("PKGDASH_WEB_PORT") {
				cfg.WebPort = normalizePort(value)
			}
		case key == "tls_insecure" && inClient:
			if envMissing("PKGDASH_TLS_INSECURE") {
				cfg.TLS.Insecure, _ = strconv.ParseBool(value)
			}
		case key == "ca_file" && inClient:
			if envMissing("PKGDASH_CA_FILE") {
				cfg.TLS.CAFile = value
			}
		case key == "cert_file" && inClient:
			if envMissing("PKGDASH_CERT_FILE") {
				cfg.TLS.CertFile = value
			}
		case key == "key_file" && inClient:
			if envMissing("PKGDASH_KEY_FILE") {
				cfg.TLS.KeyFile = value
			}
		case key == "tls_server_name" && inClient:
			if envMissing("PKGDASH_TLS_SERVER_NAME") {
				cfg.TLS.ServerName = value
			}
		case !hasValue && inServer:
			// Legacy style: one bare server address per line.
			if !serversFromEnv {
				cfg.Servers = append(cfg.Servers, line)
			}
		}
	}
	_ = scanner.Err()
	return cfg
}

func envMissing(name string) bool {
	return strings.TrimSpace(os.Getenv(name)) == ""
}

func splitServers(value string) []string {
	var servers []string
	for _, server := range strings.Split(value, ",") {
		if server = strings.TrimSpace(server); server != "" {
			servers = append(servers, server)
		}
	}
	return servers
}

func normalizePort(port string) string {
	if port == "" {
		return ":8080"
	}
	if strings.HasPrefix(port, ":") {
		return port
	}
	return ":" + port
}
