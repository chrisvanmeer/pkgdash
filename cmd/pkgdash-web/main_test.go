package main

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestWithSecurityAuthentication(t *testing.T) {
	oldAuth := authPSK
	oldTrust := trustProxy
	defer func() { authPSK, trustProxy = oldAuth, oldTrust }()

	authPSK = "s3cret"
	trustProxy = true
	handler := withSecurity(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("ok"))
	}))

	for _, tc := range []struct {
		name   string
		header func(*http.Request)
		want   int
	}{
		{"none", func(*http.Request) {}, http.StatusUnauthorized},
		{"xpsk", func(r *http.Request) { r.Header.Set("X-PSK", "s3cret") }, http.StatusOK},
		{"wrong xpsk", func(r *http.Request) { r.Header.Set("X-PSK", "wrong") }, http.StatusUnauthorized},
		{"basic", func(r *http.Request) { r.SetBasicAuth("user", "s3cret") }, http.StatusOK},
	} {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "/", nil)
			tc.header(req)
			rec := httptest.NewRecorder()
			handler.ServeHTTP(rec, req)
			if rec.Code != tc.want {
				t.Fatalf("status = %d, want %d", rec.Code, tc.want)
			}
			if rec.Code == http.StatusOK && rec.Header().Get("X-Frame-Options") != "DENY" {
				t.Fatal("missing security headers on successful response")
			}
			if rec.Code == http.StatusOK && rec.Header().Get("Content-Security-Policy") == "" {
				t.Fatal("missing CSP header on successful response")
			}
			if tc.want == http.StatusOK {
				req.Header.Set("X-Forwarded-Proto", "https")
				rec = httptest.NewRecorder()
				handler.ServeHTTP(rec, req)
				if rec.Header().Get("Strict-Transport-Security") == "" {
					t.Fatal("missing HSTS header behind trusted proxy")
				}
			}
		})
	}
}

func TestHandleHostModalNotFound(t *testing.T) {
	oldItems, oldErr := globalItems, syncError
	globalItems, syncError = nil, "No daemon responded"
	defer func() { globalItems, syncError = oldItems, oldErr }()

	req := httptest.NewRequest(http.MethodGet, "/modal/host?h=missing", nil)
	rec := httptest.NewRecorder()
	handleHostModal(rec, req)
	body := rec.Body.String()
	if !strings.Contains(body, "Host or package not found") || !strings.Contains(body, "No daemon responded") {
		t.Fatalf("unexpected modal body: %s", body)
	}
}

func TestHandleLatestOSVModal(t *testing.T) {
	oldItems := globalItems
	globalItems = []FlatItem{
		{Hostname: "host1", PkgName: "clean", Version: "1"},
		{Hostname: "host2", PkgName: "libc6", Version: "13", Vulnerabilities: []Vulnerability{{ID: "CVE-2026-1"}}},
	}
	defer func() { globalItems = oldItems }()

	req := httptest.NewRequest(http.MethodGet, "/modal/osv/latest", nil)
	rec := httptest.NewRecorder()
	handleLatestOSVModal(rec, req)
	body := rec.Body.String()
	if !strings.Contains(body, "libc6") || !strings.Contains(body, "CVE-2026-1") {
		t.Fatalf("unexpected modal body: %s", body)
	}
}

func TestHandleStatusShowsSyncError(t *testing.T) {
	oldUpdated, oldErr := lastUpdated, syncError
	lastUpdated, syncError = time.Now(), "No daemon responded (checked 2 server(s))"
	defer func() { lastUpdated, syncError = oldUpdated, oldErr }()

	req := httptest.NewRequest(http.MethodGet, "/status", nil)
	rec := httptest.NewRecorder()
	handleStatus(rec, req)
	if body := rec.Body.String(); !strings.Contains(body, "No daemon responded") {
		t.Fatalf("unexpected status body: %s", body)
	}
}
