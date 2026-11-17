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
	host        string
	os          string
	pkg         string
	versionFrom int
	versionLen  int
}

// SortItems sorts rows by the requested field. Ties are broken consistently by
// hostname, package and version so both clients show the same order.
func SortItems(items []FlatItem, field SortField, descending bool) {
	n := len(items)
	if n < 2 {
		return
	}

	// Sort a compact key array plus a permutation instead of copying whole
	// FlatItem structs (with their vulnerability slices) into an intermediate
	// array. That intermediate was ~125 MB of allocations for 185k rows right
	// after loading, which triggered expensive GC pauses during the final sort.
	keys := make([]sortKey, n)
	perm := make([]int, n)
	tokens := make([]versionToken, 0, n*4)
	needOS := field == SortOS
	for i, item := range items {
		from := len(tokens)
		tokens = appendVersionTokens(tokens, item.Version)
		key := sortKey{
			host:        strings.ToLower(item.Hostname),
			pkg:         strings.ToLower(item.PkgName),
			versionFrom: from,
			versionLen:  len(tokens) - from,
		}
		if needOS {
			key.os = strings.ToLower(OSLabel(item.OSName, item.OSVersion))
		}
		keys[i] = key
		perm[i] = i
	}

	version := func(k sortKey) versionTokenList {
		return tokens[k.versionFrom : k.versionFrom+k.versionLen]
	}
	sameVersion := func(a, b sortKey) bool {
		return versionTokensEqual(version(a), version(b))
	}

	less := func(a, b sortKey) bool {
		var primaryLess, primaryEqual bool
		switch field {
		case SortOS:
			primaryLess, primaryEqual = a.os < b.os, a.os == b.os
		case SortPkg:
			primaryLess, primaryEqual = a.pkg < b.pkg, a.pkg == b.pkg
		case SortVer:
			primaryLess, primaryEqual = version(a).less(version(b)), sameVersion(a, b)
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
				return version(a).less(version(b))
			}
		}
		if descending {
			return !primaryLess
		}
		return primaryLess
	}

	sort.Slice(perm, func(i, j int) bool {
		return less(keys[perm[i]], keys[perm[j]])
	})

	// Apply the permutation in place with cycle rotation: each item is moved
	// at most once, without a second full-size temporary slice.
	for i := 0; i < n; i++ {
		if perm[i] == i {
			continue
		}
		tmp := items[i]
		j := i
		for {
			k := perm[j]
			perm[j] = j // mark visited so outer loop skips this cycle
			if k == i {
				break
			}
			items[j] = items[k]
			j = k
		}
		items[j] = tmp
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

// appendVersionTokens tokenizes s directly into dst. Callers sorting large
// inventories pass one shared buffer so no per-row slice is allocated.
func appendVersionTokens(dst []versionToken, s string) []versionToken {
	s = strings.ToLower(strings.TrimSpace(s))
	for i := 0; i < len(s); {
		if s[i] >= '0' && s[i] <= '9' {
			end := i
			for end < len(s) && s[end] >= '0' && s[end] <= '9' {
				end++
			}
			value, err := strconv.Atoi(s[i:end])
			if err == nil {
				dst = append(dst, versionToken{number: true, value: value})
			}
			i = end
			continue
		}
		end := i + 1
		for end < len(s) && (s[end] < '0' || s[end] > '9') {
			end++
		}
		dst = append(dst, versionToken{text: s[i:end]})
		i = end
	}
	return dst
}
