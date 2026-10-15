package audit

import (
	"net/http"
	"testing"
)

// hdr builds a header map from key, value, key, value... pairs.
func hdr(kv ...string) http.Header {
	h := http.Header{}
	for i := 0; i+1 < len(kv); i += 2 {
		h.Set(kv[i], kv[i+1])
	}
	return h
}

func TestParseMaxAge(t *testing.T) {
	tests := []struct {
		in   string
		want int
	}{
		{"max-age=31536000", 31536000},
		{"MAX-AGE=10; preload", 10},
		{`max-age="600"`, 600},
		{"includeSubDomains; max-age=300", 300},
		{"includeSubDomains", -1},
		{"max-age=abc", -1},
		{"max-age=-5", -1},
		{"", -1},
	}
	for _, tc := range tests {
		if got := parseMaxAge(tc.in); got != tc.want {
			t.Errorf("parseMaxAge(%q) = %d, want %d", tc.in, got, tc.want)
		}
	}
}

func TestCheckHSTS(t *testing.T) {
	tests := []struct {
		name string
		h    http.Header
		want Status
	}{
		{"missing", hdr(), StatusFail},
		{"too short", hdr("Strict-Transport-Security", "max-age=3600"), StatusWarn},
		{"no max-age", hdr("Strict-Transport-Security", "includeSubDomains"), StatusWarn},
		{"good", hdr("Strict-Transport-Security", "max-age=31536000; includeSubDomains"), StatusPass},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := checkHSTS(tc.h).Status; got != tc.want {
				t.Errorf("status = %s, want %s", got, tc.want)
			}
		})
	}
}

func TestCheckCSP(t *testing.T) {
	tests := []struct {
		name   string
		policy string
		want   Status
	}{
		{"missing", "", StatusFail},
		{"strict default", "default-src 'self'", StatusPass},
		{"strict script-src", "default-src *; script-src 'self'", StatusPass},
		{"unsafe-inline", "script-src 'self' 'unsafe-inline'", StatusWarn},
		{"unsafe-inline with nonce is fine", "script-src 'unsafe-inline' 'nonce-abc123'", StatusPass},
		{"unsafe-eval", "default-src 'self' 'unsafe-eval'", StatusWarn},
		{"wildcard", "default-src *", StatusWarn},
		{"no script restriction", "img-src 'self'", StatusWarn},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			h := hdr()
			if tc.policy != "" {
				h.Set("Content-Security-Policy", tc.policy)
			}
			if got := checkCSP(h).Status; got != tc.want {
				t.Errorf("status = %s, want %s", got, tc.want)
			}
		})
	}
}

func TestCheckFraming(t *testing.T) {
	tests := []struct {
		name string
		h    http.Header
		want Status
	}{
		{"none", hdr(), StatusFail},
		{"deny", hdr("X-Frame-Options", "deny"), StatusPass},
		{"sameorigin", hdr("X-Frame-Options", "SAMEORIGIN"), StatusPass},
		{"obsolete value", hdr("X-Frame-Options", "ALLOW-FROM https://x.com"), StatusWarn},
		{"csp frame-ancestors", hdr("Content-Security-Policy", "default-src 'self'; frame-ancestors 'none'"), StatusPass},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := checkFraming(tc.h).Status; got != tc.want {
				t.Errorf("status = %s, want %s", got, tc.want)
			}
		})
	}
}

func TestCheckNoSniff(t *testing.T) {
	if checkNoSniff(hdr("X-Content-Type-Options", "nosniff")).Status != StatusPass {
		t.Error("nosniff should pass")
	}
	if checkNoSniff(hdr()).Status != StatusWarn {
		t.Error("missing header should warn")
	}
	if checkNoSniff(hdr("X-Content-Type-Options", "other")).Status != StatusWarn {
		t.Error("wrong value should warn")
	}
}

func TestCheckReferrer(t *testing.T) {
	if checkReferrer(hdr("Referrer-Policy", "no-referrer")).Status != StatusPass {
		t.Error("no-referrer should pass")
	}
	if checkReferrer(hdr()).Status != StatusWarn {
		t.Error("missing should warn")
	}
	if checkReferrer(hdr("Referrer-Policy", "unsafe-url")).Status != StatusWarn {
		t.Error("unsafe-url should warn")
	}
}

func TestCheckPermissions(t *testing.T) {
	if checkPermissions(hdr("Permissions-Policy", "geolocation=()")).Status != StatusPass {
		t.Error("present header should pass")
	}
	if checkPermissions(hdr()).Status != StatusWarn {
		t.Error("missing header should warn")
	}
}

func TestCheckDisclosure(t *testing.T) {
	tests := []struct {
		name string
		h    http.Header
		want Status
	}{
		{"clean", hdr("Server", "cloudflare"), StatusPass},
		{"nothing", hdr(), StatusPass},
		{"versioned server", hdr("Server", "nginx/1.24.0"), StatusWarn},
		{"powered by", hdr("X-Powered-By", "PHP/8.2"), StatusWarn},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := checkDisclosure(tc.h).Status; got != tc.want {
				t.Errorf("status = %s, want %s", got, tc.want)
			}
		})
	}
}

func TestCheckHeadersSkipsHSTSOverHTTP(t *testing.T) {
	if n := len(CheckHeaders(hdr(), true)); n != 7 {
		t.Errorf("HTTPS: got %d findings, want 7", n)
	}
	if n := len(CheckHeaders(hdr(), false)); n != 6 {
		t.Errorf("HTTP: got %d findings, want 6", n)
	}
}

func TestCleanStripsControlCharacters(t *testing.T) {
	got := clean("nginx\x1b[31m/1.2\x00")
	if got != "nginx[31m/1.2" {
		t.Errorf("clean = %q", got)
	}
}
