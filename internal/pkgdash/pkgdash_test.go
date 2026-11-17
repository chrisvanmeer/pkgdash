package pkgdash

import (
	"bytes"
	"encoding/csv"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestNewMatcher(t *testing.T) {
	tests := []struct {
		name, query, value string
		want               bool
	}{
		{"empty matches all", "", "anything", true},
		{"substring", "ubuntu", "Ubuntu 24.04", true},
		{"and terms", "ubuntu 24", "Ubuntu 24.04", true},
		{"and terms missing", "ubuntu 22", "Ubuntu 24.04", false},
		{"regex anchor", "^Debian 12$", "Debian 12", true},
		{"regex alternation", "ubuntu|alpine", "Alpine 3.19", true},
		{"literal plus package", "libstdc++6", "libstdc++6", true},
		{"invalid regex falls back", "[", "a[b", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := NewMatcher(tt.query)(tt.value); got != tt.want {
				t.Fatalf("NewMatcher(%q)(%q) = %v, want %v", tt.query, tt.value, got, tt.want)
			}
		})
	}
}

func TestOSLabelAndFilter(t *testing.T) {
	if got := OSLabel("  ", ""); got != "Unknown" {
		t.Fatalf("OSLabel empty = %q", got)
	}
	items := []FlatItem{
		{Hostname: "host01", OSName: "Ubuntu", OSVersion: "24.04 LTS", PkgName: "bash", Version: "5.2"},
		{Hostname: "host02", OSName: "Debian", OSVersion: "12", PkgName: "bash", Version: "5.2"},
		{Hostname: "host03", OSName: "Alpine", OSVersion: "3.19", PkgName: "openssl", Version: "3.0", Vulnerabilities: []Vulnerability{{ID: "CVE-1"}}},
	}
	check := func(host, osName, pkg, ver string, vulnOnly bool, want ...string) {
		t.Helper()
		got := Filter(items, host, osName, pkg, ver, vulnOnly)
		if len(got) != len(want) {
			t.Fatalf("Filter(%q,%q,%q,%q,%v) = %d items, want %d", host, osName, pkg, ver, vulnOnly, len(got), len(want))
		}
		for i, name := range want {
			if got[i].Hostname != name {
				t.Fatalf("item %d = %s, want %s", i, got[i].Hostname, name)
			}
		}
	}
	check("host0[13]", "", "", "", false, "host01", "host03")
	check("", "ubuntu", "", "", false, "host01")
	check("", "^Debian 12$", "bash", "", false, "host02")
	check("", "alpine", "openssl", "", false, "host03")
	check("", "", "", "", true, "host03")
}

func TestFilterNoQueryReturnsOriginal(t *testing.T) {
	items := []FlatItem{
		{Hostname: "h1", PkgName: "a", Version: "1"},
		{Hostname: "h2", PkgName: "b", Version: "2"},
	}
	got := Filter(items, "", "", "", "", false)
	if len(got) != len(items) || got[0].Hostname != "h1" || got[1].Hostname != "h2" {
		t.Fatalf("Filter no-query = %+v, want original items", got)
	}
	// The fast path must not copy: callers rely on this to avoid O(N) work per
	// streaming chunk. Verify by checking the backing array is shared.
	if len(got) > 0 && &got[0] != &items[0] {
		t.Fatal("Filter no-query copied the slice; fast path was lost")
	}
}

func TestFilterAppendMatchesFullFilter(t *testing.T) {
	all := []FlatItem{
		{Hostname: "web-01", OSName: "Ubuntu", OSVersion: "24.04", PkgName: "nginx", Version: "1.25"},
		{Hostname: "db-01", OSName: "Debian", OSVersion: "12", PkgName: "postgres", Version: "16.2"},
		{Hostname: "web-02", OSName: "Ubuntu", OSVersion: "24.04", PkgName: "curl", Version: "8.6", Vulnerabilities: []Vulnerability{{ID: "CVE-1"}}},
		{Hostname: "db-02", OSName: "Debian", OSVersion: "12", PkgName: "nginx", Version: "1.24"},
	}

	queries := []struct {
		host, osName, pkg, ver string
		vulnOnly               bool
	}{
		{"web", "", "", "", false},
		{"", "ubuntu", "", "", false},
		{"", "", "nginx", "", false},
		{"", "", "", "1.2", false},
		{"", "", "", "", true},
		{"web", "ubuntu", "", "", false},
	}

	for _, q := range queries {
		want := Filter(all, q.host, q.osName, q.pkg, q.ver, q.vulnOnly)

		// Simulate two streaming chunks arriving one after the other.
		var got []FlatItem
		for _, chunk := range [][]FlatItem{all[:2], all[2:]} {
			got = FilterAppend(got, chunk, q.host, q.osName, q.pkg, q.ver, q.vulnOnly)
		}

		if len(got) != len(want) {
			t.Fatalf("FilterAppend(%q,%q,%q,%q,%v) = %d items, want %d", q.host, q.osName, q.pkg, q.ver, q.vulnOnly, len(got), len(want))
		}
		for i := range want {
			if got[i].Hostname != want[i].Hostname || got[i].PkgName != want[i].PkgName {
				t.Fatalf("item %d = %s/%s, want %s/%s", i, got[i].Hostname, got[i].PkgName, want[i].Hostname, want[i].PkgName)
			}
		}
	}
}

func TestSortItemsFieldsAndDescending(t *testing.T) {
	items := []FlatItem{
		{Hostname: "b", OSName: "Zorin", OSVersion: "17", PkgName: "zeta", Version: "1.9"},
		{Hostname: "a", OSName: "Alpine", OSVersion: "3.19", PkgName: "alpha", Version: "1.10"},
		{Hostname: "c", OSName: "Debian", OSVersion: "12", PkgName: "beta", Version: "1.2"},
	}

	tests := []struct {
		name       string
		field      SortField
		descending bool
		want       []string
	}{
		{"host asc", SortHost, false, []string{"a", "b", "c"}},
		{"host desc", SortHost, true, []string{"c", "b", "a"}},
		{"os asc", SortOS, false, []string{"a", "c", "b"}},
		{"pkg asc", SortPkg, false, []string{"a", "c", "b"}},
		{"ver asc", SortVer, false, []string{"c", "b", "a"}},
		{"ver desc", SortVer, true, []string{"a", "b", "c"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rows := append([]FlatItem(nil), items...)
			SortItems(rows, tt.field, tt.descending)
			for i, want := range tt.want {
				if rows[i].Hostname != want {
					t.Fatalf("row %d = %s, want %s", i, rows[i].Hostname, want)
				}
			}
		})
	}
}

func TestSortItemsNaturalVersions(t *testing.T) {
	items := []FlatItem{
		{Hostname: "h", PkgName: "p", Version: "1.9"},
		{Hostname: "h", PkgName: "p", Version: "1.10"},
		{Hostname: "h", PkgName: "p", Version: "1.2"},
	}
	SortItems(items, SortVer, false)
	want := []string{"1.2", "1.9", "1.10"}
	for i, v := range want {
		if items[i].Version != v {
			t.Fatalf("sorted[%d] = %s, want %s", i, items[i].Version, v)
		}
	}
}

func TestBuildDiffDataKeepsArchitectures(t *testing.T) {
	items := []FlatItem{
		{Hostname: "a", PkgName: "glibc", Arch: "amd64", Version: "2.1"},
		{Hostname: "a", PkgName: "glibc", Arch: "arm64", Version: "2.2"},
		{Hostname: "b", PkgName: "glibc", Arch: "amd64", Version: "2.3"},
	}
	rows := BuildDiffData("a", "b", items)
	if len(rows) != 2 {
		t.Fatalf("got %d rows, want 2: %+v", len(rows), rows)
	}
	if rows[0].VersionA != "2.1" || rows[1].VersionA != "2.2" {
		t.Fatalf("architectures collapsed: %+v", rows)
	}
}

func TestExports(t *testing.T) {
	items := []FlatItem{
		{Hostname: " host1 ", PkgName: "bash", Version: "5.2", Arch: "amd64", Vulnerabilities: []Vulnerability{{ID: "cve"}}},
		{Hostname: "bad\nhost", PkgName: "x", Version: "1"},
		{Hostname: "  ", PkgName: "y", Version: "1"},
	}

	var csvOut bytes.Buffer
	if err := WriteCSV(&csvOut, items); err != nil {
		t.Fatal(err)
	}
	records, err := csv.NewReader(strings.NewReader(csvOut.String())).ReadAll()
	if err != nil || len(records) != 4 {
		t.Fatalf("CSV records = %d, err = %v", len(records), err)
	}
	if records[1][4] != "1" {
		t.Fatalf("CVE count = %q", records[1][4])
	}

	var iniOut bytes.Buffer
	count, err := WriteINI(&iniOut, items)
	if err != nil || count != 2 {
		t.Fatalf("INI count = %d, err = %v", count, err)
	}
	if !strings.Contains(iniOut.String(), "[all]\nbad_host\nhost1\n") {
		t.Fatalf("unexpected INI: %q", iniOut.String())
	}
}

func TestEndpoint(t *testing.T) {
	url, err := Endpoint(" daemon.internal ", "secret", "/packages")
	if err != nil || url != "https://daemon.internal:9876/packages" {
		t.Fatalf("Endpoint = %q, %v", url, err)
	}
	url, err = Endpoint("http://[::1]:9000", "", "/packages")
	if err != nil || url != "http://[::1]:9000/packages" {
		t.Fatalf("IPv6 Endpoint = %q, %v", url, err)
	}
	if _, err := Endpoint("http://daemon.internal:9876", "secret", "/packages"); err == nil {
		t.Fatal("expected PSK over HTTP to be rejected")
	}
	history, err := HistoryURL("daemon.internal", "", "host+1", "libstdc++6")
	if err != nil || !strings.Contains(history, "host%2B1") || !strings.Contains(history, "libstdc%2B%2B6") {
		t.Fatalf("HistoryURL = %q, %v", history, err)
	}
}

func writeTestConfig(t *testing.T, content string) {
	t.Helper()
	configDir := filepath.Join(os.Getenv("HOME"), ".local")
	if err := os.MkdirAll(configDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(configDir, "pkgdash.config"), []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
}

func clearClientEnv(t *testing.T) {
	t.Helper()
	for _, name := range []string{
		"PKGDASH_SERVERS", "PKGDASH_PSK", "PKGDASH_MIN_SEVERITY", "PKGDASH_WEB_PORT",
		"PKGDASH_TLS_INSECURE", "PKGDASH_CA_FILE", "PKGDASH_CERT_FILE",
		"PKGDASH_KEY_FILE", "PKGDASH_TLS_SERVER_NAME",
	} {
		t.Setenv(name, "")
	}
}

func TestLoadClientConfigINI(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	clearClientEnv(t)
	writeTestConfig(t, `# daemon details
[server]
servers = https://one.example:9876, https://two.example:9876
psk = file-psk

[client]
tls_insecure = true
ca_file = /tmp/ca.pem
cert_file = /tmp/client.pem
key_file = /tmp/client.key
tls_server_name = daemon.example
min_severity = 6.5
web_port = :7070

[unused]
psk = ignored
`)

	cfg := LoadClientConfig()
	if len(cfg.Servers) != 2 || cfg.Servers[0] != "https://one.example:9876" || cfg.Servers[1] != "https://two.example:9876" {
		t.Fatalf("servers = %+v", cfg.Servers)
	}
	if cfg.PSK != "file-psk" {
		t.Fatalf("psk = %q", cfg.PSK)
	}
	if cfg.MinSeverity != 6.5 || cfg.WebPort != ":7070" {
		t.Fatalf("min severity = %v, web port = %q", cfg.MinSeverity, cfg.WebPort)
	}
	if !cfg.TLS.Insecure {
		t.Fatal("tls_insecure from [client] was ignored")
	}
	if cfg.TLS.CAFile != "/tmp/ca.pem" || cfg.TLS.CertFile != "/tmp/client.pem" ||
		cfg.TLS.KeyFile != "/tmp/client.key" || cfg.TLS.ServerName != "daemon.example" {
		t.Fatalf("tls = %+v", cfg.TLS)
	}

	tlsCfg, err := NewTLSConfig(cfg.TLS)
	if err != nil || !tlsCfg.InsecureSkipVerify {
		t.Fatalf("TLS config from file = %+v, %v", tlsCfg, err)
	}
}

func TestLoadClientConfigEnvironmentWinsOverINI(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	clearClientEnv(t)
	t.Setenv("PKGDASH_SERVERS", " https://env.example:9876 ")
	t.Setenv("PKGDASH_PSK", " env-psk ")
	t.Setenv("PKGDASH_WEB_PORT", "9090")
	t.Setenv("PKGDASH_TLS_INSECURE", "false")
	t.Setenv("PKGDASH_CA_FILE", "/env/ca.pem")
	writeTestConfig(t, `[server]
servers = https://file.example:9876
psk = file-psk

[client]
tls_insecure = true
ca_file = /file/ca.pem
web_port = :7070
`)

	cfg := LoadClientConfig()
	if len(cfg.Servers) != 1 || cfg.Servers[0] != "https://env.example:9876" {
		t.Fatalf("servers = %+v", cfg.Servers)
	}
	if cfg.PSK != "env-psk" || cfg.WebPort != ":9090" {
		t.Fatalf("psk = %q, web port = %q", cfg.PSK, cfg.WebPort)
	}
	if cfg.TLS.Insecure || cfg.TLS.CAFile != "/env/ca.pem" {
		t.Fatalf("env TLS settings did not win: %+v", cfg.TLS)
	}
}

func TestLoadClientConfigLegacyFlatFormat(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	clearClientEnv(t)
	writeTestConfig(t, `# old style, no sections
https://legacy.example:9876
psk = legacy-psk
min_severity = 7.0
web_port = :7070
tls_insecure = true
`)

	cfg := LoadClientConfig()
	if len(cfg.Servers) != 1 || cfg.Servers[0] != "https://legacy.example:9876" {
		t.Fatalf("servers = %+v", cfg.Servers)
	}
	if cfg.PSK != "legacy-psk" || cfg.MinSeverity != 7.0 || cfg.WebPort != ":7070" || !cfg.TLS.Insecure {
		t.Fatalf("legacy settings lost: %+v", cfg)
	}
}
