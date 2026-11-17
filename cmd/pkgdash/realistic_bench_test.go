package main

import (
	"fmt"
	"testing"

	"pkgdash-project/internal/pkgdash"
)

// buildRealisticItems mirrors the shape of the real inventory seen in the
// TUI timing logs: long FQDNs, Debian-style package names and versions with
// many tokens (epoch, revision, distro suffix).
func buildRealisticItems(hosts, perHost int) []pkgdash.FlatItem {
	items := make([]pkgdash.FlatItem, 0, hosts*perHost)
	vers := []string{
		"2:8.2.1-1ubuntu2.3~20.04.1",
		"1:1.24.0-2ubuntu1.7+deb11u1",
		"4.15.0-213.224-generic",
		"20240201-1ubuntu0.1~22.04.2",
		"3.11.2-1+deb12u5",
		"1.2.3~rc1-0ubuntu1.22.04.1",
	}
	pkgs := []string{
		"libssl3t64", "python3.12-minimal", "libc6-dev", "systemd-sysv",
		"openssl", "linux-image-generic", "bash", "perl-base",
	}
	for h := 0; h < hosts; h++ {
		host := fmt.Sprintf("sibvsu%04d.blueforce.intern", h)
		for p := 0; p < perHost; p++ {
			items = append(items, pkgdash.FlatItem{
				Hostname:  host,
				OSName:    "Ubuntu",
				OSVersion: "24.04 LTS",
				PkgName:   fmt.Sprintf("%s-%d", pkgs[p%len(pkgs)], p),
				Version:   vers[(h+p)%len(vers)],
				Arch:      "amd64",
			})
		}
	}
	return items
}

func BenchmarkSortRealistic(b *testing.B) {
	items := buildRealisticItems(227, 818)
	b.Logf("rows=%d", len(items))
	b.Run("Host", func(b *testing.B) {
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			rows := append([]pkgdash.FlatItem(nil), items...)
			pkgdash.SortItems(rows, pkgdash.SortHost, false)
			benchSink = rows
		}
	})
	b.Run("Pkg", func(b *testing.B) {
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			rows := append([]pkgdash.FlatItem(nil), items...)
			pkgdash.SortItems(rows, pkgdash.SortPkg, false)
			benchSink = rows
		}
	})
	b.Run("Ver", func(b *testing.B) {
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			rows := append([]pkgdash.FlatItem(nil), items...)
			pkgdash.SortItems(rows, pkgdash.SortVer, false)
			benchSink = rows
		}
	})
	b.Run("HostAlreadySorted", func(b *testing.B) {
		sorted := append([]pkgdash.FlatItem(nil), items...)
		pkgdash.SortItems(sorted, pkgdash.SortHost, false)
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			rows := append([]pkgdash.FlatItem(nil), sorted...)
			pkgdash.SortItems(rows, pkgdash.SortHost, false)
			benchSink = rows
		}
	})
}
