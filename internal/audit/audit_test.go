package audit

import (
	"context"
	"crypto/tls"
	"net"
	"net/http"
	"testing"
	"time"
)

func TestParseTarget(t *testing.T) {
	tests := []struct {
		in        string
		wantHost  string
		wantPort  string
		wantHTTPS bool
		wantErr   bool
	}{
		{"example.com", "example.com", "443", true, false},
		{"  example.com  ", "example.com", "443", true, false},
		{"example.com:8443", "example.com", "8443", true, false},
		{"https://example.com/path", "example.com", "443", true, false},
		{"http://example.com", "example.com", "80", false, false},
		{"http://example.com:8080/x", "example.com", "8080", false, false},
		{"", "", "", false, true},
		{"ftp://example.com", "", "", false, true},
		{"https://", "", "", false, true},
	}
	for _, tc := range tests {
		t.Run(tc.in, func(t *testing.T) {
			got, err := ParseTarget(tc.in)
			if (err != nil) != tc.wantErr {
				t.Fatalf("err = %v, wantErr = %v", err, tc.wantErr)
			}
			if tc.wantErr {
				return
			}
			if got.Host != tc.wantHost || got.Port != tc.wantPort || got.HTTPS != tc.wantHTTPS {
				t.Errorf("got host=%s port=%s https=%v", got.Host, got.Port, got.HTTPS)
			}
		})
	}
}

func TestRunWellConfiguredSite(t *testing.T) {
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
		h.Set("Content-Security-Policy", "default-src 'self'; frame-ancestors 'none'")
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("Referrer-Policy", "no-referrer")
		h.Set("Permissions-Policy", "geolocation=()")
		http.SetCookie(w, &http.Cookie{
			Name: "sid", Value: "x", Secure: true, HttpOnly: true, SameSite: http.SameSiteStrictMode,
		})
		w.WriteHeader(http.StatusOK)
	})
	srv, _, _ := startTLSServer(t, tls.VersionTLS12, handler)

	rep, err := Run(context.Background(), srv.URL, Options{Timeout: 5 * time.Second, RootCAs: rootsFor(srv)})
	if err != nil {
		t.Fatal(err)
	}

	if !GradeAtLeast(rep.Grade, "A") {
		t.Errorf("grade = %s (score %d), want A or better; findings: %+v", rep.Grade, rep.Score, rep.Findings)
	}
	if rep.TLS == nil || len(rep.TLS.Versions) == 0 {
		t.Error("expected TLS info in the report")
	}
	if f := find(t, rep.Findings, "Strict-Transport-Security"); f.Status != StatusPass {
		t.Errorf("HSTS = %+v, want pass", f)
	}
	if rep.FinalURL == "" || rep.ScannedAt.IsZero() {
		t.Error("report is missing FinalURL or ScannedAt")
	}
}

func TestRunBareSiteGradesPoorly(t *testing.T) {
	srv, _, _ := startTLSServer(t, tls.VersionTLS12, nil) // sends no security headers

	rep, err := Run(context.Background(), srv.URL, Options{Timeout: 5 * time.Second, RootCAs: rootsFor(srv)})
	if err != nil {
		t.Fatal(err)
	}
	if rep.Grade != "F" {
		t.Errorf("grade = %s (score %d), want F for a site with no security headers", rep.Grade, rep.Score)
	}
	if f := find(t, rep.Findings, "Content-Security-Policy"); f.Status != StatusFail {
		t.Errorf("CSP = %+v, want fail", f)
	}
}

func TestRunUntrustedCertificateIsCritical(t *testing.T) {
	srv, _, _ := startTLSServer(t, tls.VersionTLS12, nil)

	rep, err := Run(context.Background(), srv.URL, Options{Timeout: 5 * time.Second}) // no RootCAs
	if err != nil {
		t.Fatal(err)
	}
	if rep.Grade != "F" {
		t.Errorf("grade = %s, want F for an untrusted certificate", rep.Grade)
	}
}

func TestRunUnreachableSite(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	ln.Close()

	if _, err := Run(context.Background(), "https://"+addr, Options{Timeout: time.Second}); err == nil {
		t.Error("expected an error for an unreachable site")
	}
}

func TestRunRejectsBadTarget(t *testing.T) {
	if _, err := Run(context.Background(), "ftp://example.com", Options{}); err == nil {
		t.Error("expected an error for an unsupported scheme")
	}
}

func TestCheckHTTPRedirect(t *testing.T) {
	tests := []struct {
		name string
		resp *http.Response
		want Status
	}{
		{"redirect to https", &http.Response{StatusCode: 301, Header: hdr("Location", "https://example.com/")}, StatusPass},
		{"redirect stays on http", &http.Response{StatusCode: 302, Header: hdr("Location", "http://example.com/login")}, StatusFail},
		{"relative redirect", &http.Response{StatusCode: 302, Header: hdr("Location", "/home")}, StatusFail},
		{"serves content", &http.Response{StatusCode: 200, Header: hdr()}, StatusFail},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := CheckHTTPRedirect(tc.resp).Status; got != tc.want {
				t.Errorf("status = %s, want %s", got, tc.want)
			}
		})
	}
}
