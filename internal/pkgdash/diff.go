package pkgdash

import (
	"sort"
	"strings"
)

// BuildDiffData compares the packages of two hosts. The architecture is part
// of the identity so multi-arch hosts do not overwrite each other's versions.
func BuildDiffData(hostA, hostB string, allItems []FlatItem) []DiffRow {
	type pkgKey struct{ name, arch string }
	pkgsA, pkgsB := make(map[pkgKey]string), make(map[pkgKey]string)
	labels := make(map[pkgKey]string)

	for _, item := range allItems {
		key := pkgKey{name: item.PkgName, arch: item.Arch}
		label := item.PkgName
		if item.Arch != "" {
			label += " (" + item.Arch + ")"
		}
		labels[key] = label
		if strings.EqualFold(item.Hostname, hostA) {
			pkgsA[key] = item.Version
		}
		if strings.EqualFold(item.Hostname, hostB) {
			pkgsB[key] = item.Version
		}
	}

	keys := make([]pkgKey, 0, len(labels))
	for key := range labels {
		keys = append(keys, key)
	}
	sort.Slice(keys, func(i, j int) bool {
		if keys[i].name != keys[j].name {
			return keys[i].name < keys[j].name
		}
		return keys[i].arch < keys[j].arch
	})

	rows := make([]DiffRow, 0, len(keys))
	for _, key := range keys {
		verA, hasA := pkgsA[key]
		if !hasA {
			verA = "-"
		}
		verB, hasB := pkgsB[key]
		if !hasB {
			verB = "-"
		}
		rows = append(rows, DiffRow{
			PkgName:  labels[key],
			VersionA: verA,
			VersionB: verB,
			IsDiff:   verA != verB,
		})
	}
	return rows
}
