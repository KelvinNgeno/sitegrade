package report

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/kelvinngeno/sitegrade/internal/audit"
)

func sample() *audit.Report {
	return &audit.Report{
		Target:   "example.com",
		FinalURL: "https://example.com/",
		Score:    82,
		Grade:    "B",
		Findings: []audit.Finding{
			{Category: "tls", Check: "TLS 1.3", Status: audit.StatusPass, Detail: "TLS 1.3 is supported."},
			{Category: "headers", Check: "Content-Security-Policy", Status: audit.StatusFail,
				Detail: "Header is missing.", Fix: "Add a CSP.", Penalty: 20},
		},
		TLS:       &audit.TLSInfo{Versions: []string{"TLS 1.2", "TLS 1.3"}, Subject: "example.com", Issuer: "Test CA", KeyType: "RSA 2048", DaysLeft: 60},
		ScannedAt: time.Now(),
	}
}

func TestWriteTable(t *testing.T) {
	var buf bytes.Buffer
	if err := Write(&buf, "table", []*audit.Report{sample()}); err != nil {
		t.Fatal(err)
	}
	out := buf.String()

	for _, want := range []string{"Grade:   B", "82/100", "TLS 1.2, TLS 1.3", "FAIL", "PASS", "How to fix:", "Add a CSP."} {
		if !strings.Contains(out, want) {
			t.Errorf("table output is missing %q:\n%s", want, out)
		}
	}
}

func TestWriteTableOnlyListsFixesForProblems(t *testing.T) {
	var buf bytes.Buffer
	_ = Write(&buf, "table", []*audit.Report{sample()})
	if strings.Count(buf.String(), "  - ") != 1 {
		t.Errorf("expected exactly one fix line:\n%s", buf.String())
	}
}

func TestWriteJSON(t *testing.T) {
	var buf bytes.Buffer
	if err := Write(&buf, "json", []*audit.Report{sample()}); err != nil {
		t.Fatal(err)
	}
	var decoded []audit.Report
	if err := json.Unmarshal(buf.Bytes(), &decoded); err != nil {
		t.Fatalf("invalid JSON: %v\n%s", err, buf.String())
	}
	if len(decoded) != 1 || decoded[0].Grade != "B" || len(decoded[0].Findings) != 2 {
		t.Errorf("unexpected decoded report: %+v", decoded)
	}
}

func TestWriteJSONEmptyIsArray(t *testing.T) {
	var buf bytes.Buffer
	if err := Write(&buf, "json", nil); err != nil {
		t.Fatal(err)
	}
	if strings.TrimSpace(buf.String()) != "[]" {
		t.Errorf("got %q, want []", buf.String())
	}
}

func TestWriteUnknownFormat(t *testing.T) {
	if err := Write(&bytes.Buffer{}, "xml", nil); err == nil {
		t.Error("expected an error for an unknown format")
	}
}
