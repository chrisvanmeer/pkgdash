package pkgdash

import (
	"bytes"
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

	// The daemon delivers hosts and their packages in a stable order, so the
	// inventory is often already sorted by the default (host) field. Check
	// before building any keys: this makes the common initial-load case O(n)
	// with no allocations instead of an O(n log n) sort with ~86 MB of keys.
	if field == SortHost && !descending && sortedByHostPkg(items) {
		return
	}

	// Sort a compact key array plus a permutation instead of copying whole
	// FlatItem structs (with their vulnerability slices) into an intermediate
	// array. That intermediate was ~125 MB of allocations for 185k rows right
	// after loading, which triggered expensive GC pauses during the final sort.
	keys := make([]sortKey, n)
	perm := make([]int, n)
	// Real versions ("2:8.2.1-1ubuntu2.3~20.04.1") have ~10 tokens, not ~4.
	// Starting too small caused repeated doubling of a ~100 MB buffer (319 MB
	// of copy allocations in profiling). Packed tokens are 8 bytes, text lives
	// in one shared byte buffer, so the whole key set stays compact.
	tokens := make([]versionToken, 0, n*12)
	textBuf := make([]byte, 0, n*16)
	needOS := field == SortOS
	for i, item := range items {
		from := len(tokens)
		tokens, textBuf = appendVersionTokens(tokens, textBuf, item.Version)
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
	lessVersion := func(a, b sortKey) bool {
		less, _ := compareVersions(version(a), version(b), textBuf)
		return less
	}

	less := func(a, b sortKey) bool {
		var primaryLess, primaryEqual bool
		switch field {
		case SortOS:
			primaryLess, primaryEqual = a.os < b.os, a.os == b.os
		case SortPkg:
			primaryLess, primaryEqual = a.pkg < b.pkg, a.pkg == b.pkg
		case SortVer:
			primaryLess, primaryEqual = compareVersions(version(a), version(b), textBuf)
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
				return lessVersion(a, b)
			}
		}
		if descending {
			return !primaryLess
		}
		return primaryLess
	}

	// The daemon returns hosts and their packages in a stable order, so the
	// inventory is often already sorted by the default (host) field. Checking
	// adjacent keys is O(n) and lets us skip the O(n log n) sort entirely in
	// that common case -- a large win for the TUI's initial load.
	alreadySorted := true
	for i := 1; i < n; i++ {
		if !less(keys[perm[i-1]], keys[perm[i]]) {
			alreadySorted = false
			break
		}
	}
	if alreadySorted {
		return
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

// versionToken packs a version component into 8 bytes. Numeric components
// store their value in the low 32 bits with the top bit set; text components
// store an offset (high 32 bits) and length (low 32 bits) into a shared buffer.
// sortedByHostPkg reports whether items are in ascending (host, package)
// order, matching the tie-break order used by SortItems. It is a cheap pre-check
// for the common case where the daemon already returns sorted data.
func sortedByHostPkg(items []FlatItem) bool {
	prevHost := strings.ToLower(items[0].Hostname)
	prevPkg := ""
	for _, item := range items {
		host := strings.ToLower(item.Hostname)
		if host < prevHost {
			return false
		}
		if host == prevHost {
			pkg := strings.ToLower(item.PkgName)
			if pkg < prevPkg {
				return false
			}
			prevPkg = pkg
		} else {
			prevPkg = ""
		}
		prevHost = host
	}
	return true
}

type versionToken uint64

const (
	versionTokenNumberBit = uint64(1) << 63
	versionTokenValueMask = uint64(1)<<32 - 1
)

func numberToken(v int) versionToken {
	return versionToken(versionTokenNumberBit | uint64(uint32(v)))
}

func textToken(off, length int) versionToken {
	return versionToken(uint64(uint32(off))<<32 | uint64(uint32(length)))
}

func (t versionToken) isNumber() bool { return uint64(t)&versionTokenNumberBit != 0 }
func (t versionToken) number() int    { return int(int32(uint64(t) & versionTokenValueMask)) }
func (t versionToken) offset() int    { return int(uint64(t) >> 32) }
func (t versionToken) length() int    { return int(uint64(t) & versionTokenValueMask) }

type versionTokenList []versionToken

// compareVersions returns (less, equal) in a single pass. The old code called
// less() and versionTokensEqual() separately, doubling the work for version
// sorts. Numbers sort before text, matching the previous behaviour.
func compareVersions(a, b versionTokenList, buf []byte) (bool, bool) {
	common := len(a)
	if len(b) < common {
		common = len(b)
	}
	for i := 0; i < common; i++ {
		x, y := a[i], b[i]
		switch {
		case x.isNumber() && y.isNumber():
			xv, yv := x.number(), y.number()
			if xv != yv {
				return xv < yv, false
			}
		case x.isNumber() != y.isNumber():
			return y.isNumber(), false
		default:
			xs := buf[x.offset() : x.offset()+x.length()]
			ys := buf[y.offset() : y.offset()+y.length()]
			if c := bytes.Compare(xs, ys); c != 0 {
				return c < 0, false
			}
		}
	}
	return len(a) < len(b), len(a) == len(b)
}

// appendVersionTokens tokenizes s into dst and appends lowercased text
// components to buf. Callers pass one shared buffer pair for all rows.
func appendVersionTokens(dst []versionToken, buf []byte, s string) ([]versionToken, []byte) {
	s = strings.TrimSpace(s)
	for i := 0; i < len(s); {
		if s[i] >= '0' && s[i] <= '9' {
			end := i
			for end < len(s) && s[end] >= '0' && s[end] <= '9' {
				end++
			}
			value, err := strconv.Atoi(s[i:end])
			if err == nil {
				dst = append(dst, numberToken(value))
			}
			i = end
			continue
		}
		end := i + 1
		for end < len(s) && (s[end] < '0' || s[end] > '9') {
			end++
		}
		off := len(buf)
		for j := i; j < end; j++ {
			c := s[j]
			if c >= 'A' && c <= 'Z' {
				c += 'a' - 'A'
			}
			buf = append(buf, c)
		}
		dst = append(dst, textToken(off, end-i))
		i = end
	}
	return dst, buf
}
