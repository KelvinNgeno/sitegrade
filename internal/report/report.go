// Package report renders audit results as text or JSON.
package report

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"text/tabwriter"

	"github.com/kelvinngeno/sitegrade/internal/audit"
)

// Formats lists the supported output formats.
var Formats = []string{"table", "json"}

// Write renders the reports to w in the requested format.
func Write(w io.Writer, format string, reports []*audit.Report) error {
	switch format {
	case "table":
		return writeTable(w, reports)
	case "json":
		return writeJSON(w, reports)
	default:
		return fmt.Errorf("unknown format %q (choose table or json)", format)
	}
}

func label(s audit.Status) string {
	return strings.ToUpper(string(s))
}

func writeTable(w io.Writer, reports []*audit.Report) error {
	for i, r := range reports {
		if i > 0 {
			fmt.Fprintln(w)
			fmt.Fprintln(w, strings.Repeat("-", 60))
			fmt.Fprintln(w)
		}

		fmt.Fprintf(w, "Target:  %s\n", r.Target)
		if r.FinalURL != "" {
			fmt.Fprintf(w, "Final:   %s\n", r.FinalURL)
		}
		fmt.Fprintf(w, "Grade:   %s   (score %d/100)\n", r.Grade, r.Score)

		if r.TLS != nil {
			if len(r.TLS.Versions) > 0 {
				fmt.Fprintf(w, "TLS:     %s\n", strings.Join(r.TLS.Versions, ", "))
			}
			if r.TLS.Subject != "" {
				fmt.Fprintf(w, "Cert:    %s, issued by %s, %s, expires %s (%d days)\n",
					r.TLS.Subject, r.TLS.Issuer, r.TLS.KeyType,
					r.TLS.NotAfter.UTC().Format("2006-01-02"), r.TLS.DaysLeft)
			}
		}
		fmt.Fprintln(w)

		tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
		fmt.Fprintln(tw, "STATUS\tCATEGORY\tCHECK\tDETAIL")
		for _, f := range r.Findings {
			fmt.Fprintf(tw, "%s\t%s\t%s\t%s\n", label(f.Status), f.Category, f.Check, f.Detail)
		}
		if err := tw.Flush(); err != nil {
			return err
		}

		wroteHeader := false
		for _, f := range r.Findings {
			if f.Status == audit.StatusPass || f.Fix == "" {
				continue
			}
			if !wroteHeader {
				fmt.Fprintln(w, "\nHow to fix:")
				wroteHeader = true
			}
			fmt.Fprintf(w, "  - %s: %s\n", f.Check, f.Fix)
		}
	}
	return nil
}

func writeJSON(w io.Writer, reports []*audit.Report) error {
	if reports == nil {
		reports = []*audit.Report{} // emit [] rather than null
	}
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(reports)
}
