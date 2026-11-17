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
}

// LoadClientConfig reads environment variables first and falls back to
// ~/.local/pkgdash.config. Environment values always win over file values.
func LoadClientConfig() ClientConfig {
	cfg := ClientConfig{WebPort: ":8080"}

	if value := strings.TrimSpace(os.Getenv("PKGDASH_SERVERS")); value != "" {
		for _, server := range strings.Split(value, ",") {
			if server = strings.TrimSpace(server); server != "" {
				cfg.Servers = append(cfg.Servers, server)
			}
		}
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

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		key, value, hasValue := strings.Cut(line, "=")
		key = strings.ToLower(strings.TrimSpace(key))
		value = strings.TrimSpace(value)

		switch {
		case hasValue && key == "psk":
			if cfg.PSK == "" {
				cfg.PSK = value
			}
		case hasValue && key == "min_severity":
			if os.Getenv("PKGDASH_MIN_SEVERITY") == "" {
				if parsed, err := strconv.ParseFloat(value, 64); err == nil {
					cfg.MinSeverity = parsed
				}
			}
		case hasValue && key == "web_port":
			if os.Getenv("PKGDASH_WEB_PORT") == "" {
				cfg.WebPort = normalizePort(value)
			}
		case len(cfg.Servers) == 0:
			cfg.Servers = append(cfg.Servers, line)
		}
	}
	_ = scanner.Err()
	return cfg
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
