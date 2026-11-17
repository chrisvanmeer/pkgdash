// Package pkgdash contains the domain model and shared logic used by both
// clients (TUI and web UI). Keeping this code in one place prevents the two
// frontends from drifting apart.
package pkgdash

import "time"

type Vulnerability struct {
	ID       string   `json:"id"`
	CVE      []string `json:"cve,omitempty"`
	Summary  string   `json:"summary,omitempty"`
	Details  string   `json:"details,omitempty"`
	URL      string   `json:"url,omitempty"`
	Severity float64  `json:"severity,omitempty"`
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

// FlatItem is one package on one host, the basic row rendered by both clients.
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
	Action     string    `json:"action"` // ADDED, REMOVED, MODIFIED
}

// Flatten expands host payloads into one row per package.
func Flatten(hosts []HostPayload) []FlatItem {
	var items []FlatItem
	for _, host := range hosts {
		for _, pkg := range host.Packages {
			items = append(items, FlatItem{
				Hostname:        host.Hostname,
				IPAddress:       host.IPAddress,
				OSName:          host.OSName,
				OSVersion:       host.OSVersion,
				HostFunction:    host.HostFunction,
				PkgName:         pkg.Name,
				Version:         pkg.Version,
				Arch:            pkg.Arch,
				Vulnerabilities: pkg.Vulnerabilities,
				OSVEnabled:      host.OSVEnabled,
			})
		}
	}
	return items
}
