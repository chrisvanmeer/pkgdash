package pkgdash

import (
	"encoding/csv"
	"fmt"
	"io"
	"sort"
	"strings"
	"unicode"
)

// WriteCSV exports rows as CSV with the shared column layout.
func WriteCSV(w io.Writer, items []FlatItem) error {
	writer := csv.NewWriter(w)
	if err := writer.Write([]string{"Hostname", "Package", "Version", "Architecture", "CVE_Count"}); err != nil {
		return err
	}
	for _, item := range items {
		if err := writer.Write([]string{
			item.Hostname, item.PkgName, item.Version, item.Arch, fmt.Sprint(len(item.Vulnerabilities)),
		}); err != nil {
			return err
		}
	}
	writer.Flush()
	return writer.Error()
}

// WriteINI exports the unique hostnames as an Ansible-style inventory. It
// returns the number of hosts written.
func WriteINI(w io.Writer, items []FlatItem) (int, error) {
	hosts := make(map[string]bool)
	for _, item := range items {
		if host := sanitizeHostname(item.Hostname); host != "" {
			hosts[host] = true
		}
	}
	names := make([]string, 0, len(hosts))
	for host := range hosts {
		names = append(names, host)
	}
	sort.Strings(names)

	if _, err := io.WriteString(w, "[all]\n"); err != nil {
		return 0, err
	}
	for _, host := range names {
		if _, err := io.WriteString(w, host+"\n"); err != nil {
			return 0, err
		}
	}
	return len(names), nil
}

func sanitizeHostname(host string) string {
	host = strings.TrimSpace(host)
	return strings.Map(func(r rune) rune {
		if unicode.IsControl(r) || r == '[' || r == ']' {
			return '_'
		}
		return r
	}, host)
}
