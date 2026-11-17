package pkgdash

import (
	"strings"

	"github.com/dlclark/regexp2"
)

// OSLabel returns the display label for a host's OS.
func OSLabel(name, version string) string {
	label := strings.TrimSpace(strings.TrimSpace(name) + " " + strings.TrimSpace(version))
	if label == "" {
		return "Unknown"
	}
	return label
}

// NewMatcher builds a case-insensitive field matcher. Queries containing regex
// metacharacters are compiled as regexp2 patterns; everything else is treated
// as an AND-list of plain substrings.
func NewMatcher(query string) func(string) bool {
	query = strings.TrimSpace(query)
	if query == "" {
		return matchAll
	}

	if IsLikelyRegex(query) {
		re, err := regexp2.Compile(query, regexp2.IgnoreCase)
		if err == nil {
			return func(s string) bool {
				matched, _ := re.MatchString(s)
				return matched
			}
		}
		// An invalid regex falls through to literal substring matching.
	}

	terms := strings.Fields(strings.ToLower(query))
	return func(s string) bool {
		for _, term := range terms {
			if !containsFold(s, term) {
				return false
			}
		}
		return true
	}
}

func asciiOnly(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] >= 0x80 {
			return false
		}
	}
	return true
}

func asciiLower(b byte) byte {
	if b >= 'A' && b <= 'Z' {
		return b + ('a' - 'A')
	}
	return b
}

// containsFold reports whether s contains substr, ignoring case. For ASCII-only
// inputs it scans bytes directly without allocating. Non-ASCII inputs fall back
// to strings.ToLower so Unicode case folding stays correct.
func containsFold(s, substr string) bool {
	if substr == "" {
		return true
	}
	if len(substr) > len(s) {
		return false
	}
	if asciiOnly(s) && asciiOnly(substr) {
		for i := 0; i+len(substr) <= len(s); i++ {
			matched := true
			for j := 0; j < len(substr); j++ {
				if asciiLower(s[i+j]) != asciiLower(substr[j]) {
					matched = false
					break
				}
			}
			if matched {
				return true
			}
		}
		return false
	}
	return strings.Contains(strings.ToLower(s), strings.ToLower(substr))
}

// IsLikelyRegex reports whether a query should be attempted as a regex. A
// single '+' is common in package names (e.g. libstdc++6), so it alone is not
// enough to trigger regex mode.
func IsLikelyRegex(query string) bool {
	metaChars := []string{"^", "$", "*", "?", "[", "]", "(", ")", "{", "}", "|", "\\"}
	for _, char := range metaChars {
		if strings.Contains(query, char) {
			return true
		}
	}
	// '+' only counts when it is not part of a repeated-plus package name.
	if strings.Contains(query, "++") {
		return false
	}
	return strings.Contains(query, "+")
}

var matchAll = func(string) bool { return true }

// Filter applies all four client filters plus the optional vuln-only mode.
func Filter(items []FlatItem, host, osName, pkg, ver string, vulnOnly bool) []FlatItem {
	if noFilters(host, osName, pkg, ver, vulnOnly) {
		return items
	}

	// Reserve a modest capacity and let append grow it. Queries usually match
	// a small fraction of a large inventory; reserving len(items) up front made
	// every filtered query allocate the full inventory size (e.g. 16 MB per
	// 100k rows) even when only a handful of rows matched.
	return filterInto(make([]FlatItem, 0, min(len(items), 1024)), items, host, osName, pkg, ver, vulnOnly)
}

// FilterAppend appends the matching items from a newly arrived chunk to dst.
// Streaming clients use this instead of re-filtering the whole inventory on
// every chunk, which would be O(N²) for large inventories.
func FilterAppend(dst, chunk []FlatItem, host, osName, pkg, ver string, vulnOnly bool) []FlatItem {
	if len(chunk) == 0 {
		return dst
	}
	if noFilters(host, osName, pkg, ver, vulnOnly) {
		return append(dst, chunk...)
	}
	return filterInto(dst, chunk, host, osName, pkg, ver, vulnOnly)
}

func noFilters(host, osName, pkg, ver string, vulnOnly bool) bool {
	return host == "" && osName == "" && pkg == "" && ver == "" && !vulnOnly
}

func filterInto(dst, src []FlatItem, host, osName, pkg, ver string, vulnOnly bool) []FlatItem {
	// Only build matchers for fields that actually have a query. The guard on
	// each field also avoids evaluating OSLabel (which concatenates strings)
	// when no OS filter is active.
	var hMatch, oMatch, pMatch, vMatch func(string) bool
	if host != "" {
		hMatch = NewMatcher(host)
	}
	if osName != "" {
		oMatch = NewMatcher(osName)
	}
	if pkg != "" {
		pMatch = NewMatcher(pkg)
	}
	if ver != "" {
		vMatch = NewMatcher(ver)
	}

	for _, item := range src {
		if vulnOnly && len(item.Vulnerabilities) == 0 {
			continue
		}
		if hMatch != nil && !hMatch(item.Hostname) {
			continue
		}
		if oMatch != nil && !oMatch(OSLabel(item.OSName, item.OSVersion)) {
			continue
		}
		if pMatch != nil && !pMatch(item.PkgName) {
			continue
		}
		if vMatch != nil && !vMatch(item.Version) {
			continue
		}
		dst = append(dst, item)
	}
	return dst
}
