package pkgdash

import (
	"fmt"
	"testing"
)

func benchItems(n int) []FlatItem {
	items := make([]FlatItem, 0, n)
	for i := 0; i < n; i++ {
		items = append(items, FlatItem{
			Hostname:  fmt.Sprintf("host-%03d.example.com", i%250),
			OSName:    "Ubuntu",
			OSVersion: fmt.Sprintf("24.0%d", i%4),
			PkgName:   fmt.Sprintf("libpackage-%05d", i%9000),
			Version:   fmt.Sprintf("%d.%d.%d-%d", i%9, i%17, i%7, i%5),
		})
	}
	return items
}

// BenchmarkFilterNoQuery guards the no-query fast path. It must not allocate
// or copy the inventory: clients call it for every streaming chunk.
func BenchmarkFilterNoQuery(b *testing.B) {
	items := benchItems(100000)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = Filter(items, "", "", "", "", false)
	}
}

func BenchmarkFilterWithQuery(b *testing.B) {
	items := benchItems(100000)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = Filter(items, "host-01", "", "libpackage", "", false)
	}
}

func BenchmarkSortHost(b *testing.B) {
	base := benchItems(100000)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		items := append([]FlatItem(nil), base...)
		SortItems(items, SortHost, false)
	}
}

func BenchmarkSortVersion(b *testing.B) {
	base := benchItems(100000)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		items := append([]FlatItem(nil), base...)
		SortItems(items, SortVer, false)
	}
}
