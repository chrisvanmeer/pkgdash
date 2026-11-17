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
		return func(string) bool { return true }
	}

	if IsLikelyRegex(query) && strings.TrimSpace(query) != "" {
		re, err := regexp2.Compile(query, regexp2.IgnoreCase)
		if err == nil {
			return func(s string) bool {
				matched, _ := re.MatchString(s)
				return matched
			}
		}
	}

	terms := strings.Fields(strings.ToLower(query))
	return func(s string) bool {
		lower := strings.ToLower(s)
		for _, term := range terms {
			if !strings.Contains(lower, term) {
				return false
			}
		}
		return true
	}
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
	if host == "" && osName == "" && pkg == "" && ver == "" && !vulnOnly {
		return items
	}

	// Only allocate a matcher for fields that actually have a query. For empty
	// fields this avoids building a closure and lowercasing every row value.
	hMatch, oMatch, pMatch, vMatch := matchAll, matchAll, matchAll, matchAll
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

	filtered := make([]FlatItem, 0, len(items))
	for _, item := range items {
		if vulnOnly && len(item.Vulnerabilities) == 0 {
			continue
		}
		if hMatch(item.Hostname) &&
			oMatch(OSLabel(item.OSName, item.OSVersion)) &&
			pMatch(item.PkgName) &&
			vMatch(item.Version) {
			filtered = append(filtered, item)
		}
	}
	return filtered
}
