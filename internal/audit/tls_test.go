package audit

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// startTLSServer runs a local HTTPS server that accepts TLS versions from
// minVersion upward. It returns the server plus its host and port.
func startTLSServer(t *testing.T, minVersion uint16, handler http.Handler) (*httptest.Server, string, string) {
	t.Helper()
	if handler == nil {
		handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
		})
	}

	srv := httptest.NewUnstartedServer(handler)
	srv.TLS = &tls.Config{MinVersion: minVersion}
	srv.StartTLS()
	t.Cleanup(srv.Close)

	host, port, err := net.SplitHostPort(strings.TrimPrefix(srv.URL, "https://"))
	if err != nil {
		t.Fatal(err)
	}
	return srv, host, port
}

func rootsFor(srv *httptest.Server) *x509.CertPool {
	pool := x509.NewCertPool()
	pool.AddCert(srv.Certificate())
	return pool
}

func find(t *testing.T, findings []Finding, check string) Finding {
	t.Helper()
	for _, f := range findings {
		if f.Check == check {
			return f
		}
	}
	t.Fatalf("no finding named %q in %+v", check, findings)
	return Finding{}
}

func TestCheckTLSGoodServer(t *testing.T) {
	srv, host, port := startTLSServer(t, tls.VersionTLS12, nil)

	findings, info := CheckTLS(context.Background(), host, port,
		TLSOptions{Timeout: 3 * time.Second, RootCAs: rootsFor(srv)})

	for _, check := range []string{"Certificate trust", "Legacy protocols", "TLS 1.3", "Certificate expiry"} {
		if f := find(t, findings, check); f.Status != StatusPass {
			t.Errorf("%s: status = %s (%s), want pass", check, f.Status, f.Detail)
		}
	}

	joined := strings.Join(info.Versions, ",")
	if !strings.Contains(joined, "TLS 1.2") || !strings.Contains(joined, "TLS 1.3") {
		t.Errorf("supported versions = %v, want TLS 1.2 and 1.3", info.Versions)
	}
	if strings.Contains(joined, "TLS 1.0") || strings.Contains(joined, "TLS 1.1") {
		t.Errorf("supported versions = %v, legacy versions should be absent", info.Versions)
	}
	if info.DaysLeft <= 30 {
		t.Errorf("DaysLeft = %d, expected a long-lived test certificate", info.DaysLeft)
	}
}

func TestCheckTLSUntrustedCertificate(t *testing.T) {
	_, host, port := startTLSServer(t, tls.VersionTLS12, nil)

	// No RootCAs supplied, so the self-signed test certificate is untrusted.
	findings, info := CheckTLS(context.Background(), host, port, TLSOptions{Timeout: 3 * time.Second})

	trust := find(t, findings, "Certificate trust")
	if trust.Status != StatusFail || !trust.Critical {
		t.Errorf("trust finding = %+v, want critical fail", trust)
	}
	// The certificate details should still be reported.
	find(t, findings, "Certificate expiry")
	if info.Subject == "" && len(info.DNSNames) == 0 {
		t.Error("expected certificate details even when the certificate is untrusted")
	}
}

func TestCheckTLSLegacyProtocols(t *testing.T) {
	srv, host, port := startTLSServer(t, tls.VersionTLS10, nil)

	findings, _ := CheckTLS(context.Background(), host, port,
		TLSOptions{Timeout: 3 * time.Second, RootCAs: rootsFor(srv)})

	if f := find(t, findings, "Legacy protocols"); f.Status != StatusFail {
		t.Errorf("legacy finding = %+v, want fail", f)
	}
}

func TestCheckTLSNoServer(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	host, port, _ := net.SplitHostPort(ln.Addr().String())
	ln.Close() // nothing is listening on this port any more

	findings, _ := CheckTLS(context.Background(), host, port, TLSOptions{Timeout: 500 * time.Millisecond})
	f := find(t, findings, "TLS handshake")
	if f.Status != StatusFail || !f.Critical {
		t.Errorf("finding = %+v, want critical fail", f)
	}
}

func TestExpiryFinding(t *testing.T) {
	now := time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)
	day := 24 * time.Hour

	tests := []struct {
		name     string
		notAfter time.Time
		want     Status
		critical bool
	}{
		{"plenty of time", now.Add(90 * day), StatusPass, false},
		{"within 30 days", now.Add(20 * day), StatusWarn, false},
		{"within 14 days", now.Add(5 * day), StatusFail, false},
		{"expired", now.Add(-3 * day), StatusFail, true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			f := expiryFinding(tc.notAfter, now)
			if f.Status != tc.want || f.Critical != tc.critical {
				t.Errorf("got status=%s critical=%v, want status=%s critical=%v",
					f.Status, f.Critical, tc.want, tc.critical)
			}
		})
	}
}

func TestVersionFindings(t *testing.T) {
	tests := []struct {
		name         string
		ok           []bool
		wantLegacy   Status
		wantCritical bool
	}{
		{"modern only", []bool{false, false, true, true}, StatusPass, false},
		{"tls12 only", []bool{false, false, true, false}, StatusPass, false},
		{"legacy enabled", []bool{true, true, true, true}, StatusFail, false},
		{"only legacy", []bool{true, false, false, false}, StatusFail, true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			findings := versionFindings(tc.ok)
			if got := find(t, findings, "Legacy protocols").Status; got != tc.wantLegacy {
				t.Errorf("legacy status = %s, want %s", got, tc.wantLegacy)
			}
			hasCritical := false
			for _, f := range findings {
				if f.Critical {
					hasCritical = true
				}
			}
			if hasCritical != tc.wantCritical {
				t.Errorf("critical = %v, want %v", hasCritical, tc.wantCritical)
			}
		})
	}
}
