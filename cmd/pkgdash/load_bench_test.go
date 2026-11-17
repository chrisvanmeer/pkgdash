package main

import (
	"bytes"
	"compress/gzip"
	"encoding/json"
	"fmt"
	"testing"

	"pkgdash-project/internal/pkgdash"
)

var benchSink any

// buildRepresentativePayload creates ~185k FlatItems spread over hosts,
// matching the shape of a real /packages response.
func buildRepresentativePayload(hosts, perHost int) []byte {
	var payload []pkgdash.HostPayload
	for h := 0; h < hosts; h++ {
		host := pkgdash.HostPayload{
			Hostname:  fmt.Sprintf("host-%03d.example.com", h),
			OSName:    "Ubuntu",
			OSVersion: "24.04 LTS",
			IPAddress: "10.0.0.1",
		}
		for p := 0; p < perHost; p++ {
			host.Packages = append(host.Packages, pkgdash.PackageInfo{
				Name:    fmt.Sprintf("libpackage-%05d", p),
				Version: fmt.Sprintf("%d.%d.%d-%d", h%9, p%17, h%7, p%5),
				Arch:    "amd64",
			})
		}
		payload = append(payload, host)
	}
	data, _ := json.Marshal(payload)
	return data
}

func BenchmarkLoadDecode(b *testing.B) {
	data := buildRepresentativePayload(100, 1856)
	var gzBuf bytes.Buffer
	zw := gzip.NewWriter(&gzBuf)
	_, _ = zw.Write(data)
	_ = zw.Close()

	b.Run("json-stream", func(b *testing.B) {
		b.SetBytes(int64(len(data)))
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			reader, _ := gzip.NewReader(bytes.NewReader(gzBuf.Bytes()))
			dec := json.NewDecoder(reader)
			_, _ = dec.Token() // [
			count := 0
			for dec.More() {
				var host pkgdash.HostPayload
				if err := dec.Decode(&host); err != nil {
					b.Fatal(err)
				}
				count += len(host.Packages)
			}
			_ = reader.Close()
			if count != 100*1856 {
				b.Fatalf("decoded %d packages", count)
			}
		}
	})

	b.Run("flatten", func(b *testing.B) {
		dec := json.NewDecoder(bytes.NewReader(data))
		_, _ = dec.Token()
		var hosts []pkgdash.HostPayload
		for dec.More() {
			var host pkgdash.HostPayload
			_ = dec.Decode(&host)
			hosts = append(hosts, host)
		}
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			items := make([]pkgdash.FlatItem, 0, 185600)
			for _, host := range hosts {
				for _, pkg := range host.Packages {
					items = append(items, pkgdash.FlatItem{
						Hostname:  host.Hostname,
						OSName:    host.OSName,
						OSVersion: host.OSVersion,
						PkgName:   pkg.Name,
						Version:   pkg.Version,
						Arch:      pkg.Arch,
					})
				}
			}
			benchSink = items
		}
	})

	b.Run("sort", func(b *testing.B) {
		items := make([]pkgdash.FlatItem, 0, 185600)
		for h := 0; h < 100; h++ {
			for p := 0; p < 1856; p++ {
				items = append(items, pkgdash.FlatItem{
					Hostname: fmt.Sprintf("host-%03d", h),
					PkgName:  fmt.Sprintf("libpackage-%05d", p),
					Version:  fmt.Sprintf("%d.%d.%d", h%9, p%17, p%5),
				})
			}
		}
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			rows := append([]pkgdash.FlatItem(nil), items...)
			pkgdash.SortItems(rows, pkgdash.SortHost, false)
		}
	})
}
