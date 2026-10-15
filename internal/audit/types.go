// Package audit checks a website's HTTPS configuration, security headers
// and cookies, and turns the findings into a score and a letter grade.
package audit

import (
	"strings"
	"time"
	"unicode"
)

// Finding categories, in the order they appear in reports.
const (
	CatTransport = "transport"
	CatTLS       = "tls"
	CatHeaders   = "headers"
	CatCookies   = "cookies"
)

// Status is the outcome of a single check.
type Status string

// Possible statuses.
const (
	StatusPass Status = "pass"
	StatusInfo Status = "info"
	StatusWarn Status = "warn"
	StatusFail Status = "fail"
)

// Finding is the result of one check.
type Finding struct {
	Category string `json:"category"`
	Check    string `json:"check"`
	Status   Status `json:"status"`
	Detail   string `json:"detail"`
	Fix      string `json:"fix,omitempty"`
	Penalty  int    `json:"penalty"`
	Critical bool   `json:"critical,omitempty"`
}

// TLSInfo summarises what was learned about the server's TLS setup.
type TLSInfo struct {
	Versions []string  `json:"supported_versions"`
	Subject  string    `json:"subject,omitempty"`
	Issuer   string    `json:"issuer,omitempty"`
	NotAfter time.Time `json:"not_after,omitempty"`
	DaysLeft int       `json:"days_left"`
	DNSNames []string  `json:"dns_names,omitempty"`
	KeyType  string    `json:"key_type,omitempty"`
}

// Report is the full result of auditing one site.
type Report struct {
	Target    string    `json:"target"`
	FinalURL  string    `json:"final_url,omitempty"`
	Score     int       `json:"score"`
	Grade     string    `json:"grade"`
	Findings  []Finding `json:"findings"`
	TLS       *TLSInfo  `json:"tls,omitempty"`
	ScannedAt time.Time `json:"scanned_at"`
}

func pass(category, check, detail string) Finding {
	return Finding{Category: category, Check: check, Status: StatusPass, Detail: detail}
}

func problem(status Status, category, check, detail, fix string, penalty int) Finding {
	return Finding{
		Category: category, Check: check, Status: status,
		Detail: detail, Fix: fix, Penalty: penalty,
	}
}

// critical marks a finding as serious enough to force an F grade.
func critical(f Finding) Finding {
	f.Critical = true
	return f
}

// clean strips non-printable characters and caps the length. Header values,
// cookie names and certificate fields all come from the remote server, so
// they must never be able to inject terminal escape sequences into output.
func clean(s string) string {
	var sb strings.Builder
	for _, r := range s {
		if unicode.IsPrint(r) {
			sb.WriteRune(r)
		}
	}
	runes := []rune(sb.String())
	if len(runes) > 160 {
		return string(runes[:160]) + "..."
	}
	return string(runes)
}
