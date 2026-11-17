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

type sortKey struct {
	host    string
	os      string
	pkg     string
	version versionTokenList
}

// SortItems sorts rows by the requested field. Ties are broken consistently by
// hostname, package and version so both clients show the same order.
func SortItems(items []FlatItem, field SortField, descending bool) {
	// Compute the comparison keys once per row. The previous implementation
	// lowercased strings and tokenized versions inside every comparison,
	// which grew to millions of allocations for large inventories.
	type row struct {
		item FlatItem
		key  sortKey
	}
	rows := make([]row, len(items))
	for i, item := range items {
		rows[i] = row{
			item: item,
			key: sortKey{
				host:    strings.ToLower(item.Hostname),
				os:      strings.ToLower(OSLabel(item.OSName, item.OSVersion)),
				pkg:     strings.ToLower(item.PkgName),
				version: versionTokens(item.Version),
			},
		}
	}

	sort.SliceStable(rows, func(i, j int) bool {
		a, b := rows[i].key, rows[j].key

		var primaryLess, primaryEqual bool
		switch field {
		case SortOS:
			primaryLess, primaryEqual = a.os < b.os, a.os == b.os
		case SortPkg:
			primaryLess, primaryEqual = a.pkg < b.pkg, a.pkg == b.pkg
		case SortVer:
			primaryLess, primaryEqual = a.version.less(b.version), versionTokensEqual(a.version, b.version)
		default:
			primaryLess, primaryEqual = a.host < b.host, a.host == b.host
		}

		if primaryEqual {
			switch {
			case a.host != b.host:
				return a.host < b.host
			case a.pkg != b.pkg:
				return a.pkg < b.pkg
			default:
				return a.version.less(b.version)
			}
		}
		if descending {
			return !primaryLess
		}
		return primaryLess
	})
	for i, r := range rows {
		items[i] = r.item
	}
}

type versionToken struct {
	number bool
	value  int
	text   string
}

type versionTokenList []versionToken

func versionTokensEqual(a, b []versionToken) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func (tokens versionTokenList) less(other versionTokenList) bool {
	a, b := tokens, other
	for i := 0; i < len(a) && i < len(b); i++ {
		x, y := a[i], b[i]
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
	return len(a) < len(b)
}

func versionTokens(s string) versionTokenList {
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
