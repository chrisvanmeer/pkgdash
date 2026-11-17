package pkgdash

import (
	"sort"
	"strconv"
	"strings"
)

type SortField string

const (
	SortHost SortField = "host"
	SortOS   SortField = "os"
	SortPkg  SortField = "pkg"
	SortVer  SortField = "ver"
)

// SortItems sorts rows by the requested field. Ties are broken consistently by
// hostname, package and version so both clients show the same order.
func SortItems(items []FlatItem, field SortField, descending bool) {
	sort.SliceStable(items, func(i, j int) bool {
		a, b := items[i], items[j]
		ah, bh := strings.ToLower(a.Hostname), strings.ToLower(b.Hostname)
		ao, bo := strings.ToLower(OSLabel(a.OSName, a.OSVersion)), strings.ToLower(OSLabel(b.OSName, b.OSVersion))
		ap, bp := strings.ToLower(a.PkgName), strings.ToLower(b.PkgName)

		var primaryLess, primaryEqual bool
		switch field {
		case SortOS:
			primaryLess, primaryEqual = ao < bo, ao == bo
		case SortPkg:
			primaryLess, primaryEqual = ap < bp, ap == bp
		case SortVer:
			primaryLess, primaryEqual = compareVersions(a.Version, b.Version), a.Version == b.Version
		default:
			primaryLess, primaryEqual = ah < bh, ah == bh
		}

		if primaryEqual {
			switch {
			case ah != bh:
				return ah < bh
			case ap != bp:
				return ap < bp
			default:
				return compareVersions(a.Version, b.Version)
			}
		}
		if descending {
			return !primaryLess
		}
		return primaryLess
	})
}

type versionToken struct {
	number bool
	value  int
	text   string
}

// compareVersions compares version strings naturally, so 1.10 sorts after 1.9.
func compareVersions(a, b string) bool {
	ta, tb := versionTokens(a), versionTokens(b)
	for i := 0; i < len(ta) && i < len(tb); i++ {
		x, y := ta[i], tb[i]
		switch {
		case x.number && y.number:
			if x.value != y.value {
				return x.value < y.value
			}
		case x.number != y.number:
			return y.number
		case x.text != y.text:
			return x.text < y.text
		}
	}
	return len(ta) < len(tb)
}

func versionTokens(s string) []versionToken {
	s = strings.ToLower(strings.TrimSpace(s))
	var tokens []versionToken
	for i := 0; i < len(s); {
		if s[i] >= '0' && s[i] <= '9' {
			end := i
			for end < len(s) && s[end] >= '0' && s[end] <= '9' {
				end++
			}
			value, err := strconv.Atoi(s[i:end])
			if err == nil {
				tokens = append(tokens, versionToken{number: true, value: value})
			}
			i = end
			continue
		}
		end := i + 1
		for end < len(s) && (s[end] < '0' || s[end] > '9') {
			end++
		}
		tokens = append(tokens, versionToken{text: s[i:end]})
		i = end
	}
	return tokens
}
