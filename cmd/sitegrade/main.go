// Command sitegrade audits a website's HTTPS setup, security headers and
// cookies, and grades it from A+ to F.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"strings"
	"time"

	"github.com/kelvinngeno/sitegrade/internal/audit"
	"github.com/kelvinngeno/sitegrade/internal/report"
)

// version is overridden at build time: -ldflags "-X main.version=v1.0.0"
var version = "dev"

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

func run(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("sitegrade", flag.ContinueOnError)
	fs.SetOutput(stderr)

	var (
		timeout     = fs.Duration("timeout", 10*time.Second, "timeout for each network operation")
		format      = fs.String("format", "table", "output format: "+strings.Join(report.Formats, ", "))
		outFile     = fs.String("o", "", "write the report to this file instead of stdout")
		minGrade    = fs.String("min-grade", "", "exit with status 3 if any site grades below this (A+, A, B, C, D, F)")
		noRedirect  = fs.Bool("no-redirect-check", false, "skip the plain-HTTP (port 80) redirect check")
		showVersion = fs.Bool("version", false, "print version and exit")
	)

	fs.Usage = func() {
		fmt.Fprintf(stderr, `sitegrade %s - grade a website's HTTPS and security headers

Usage:
  sitegrade [flags] <site> [site...]

A site can be a hostname (example.com), host:port, or a full URL.

Flags:
`, version)
		fs.PrintDefaults()
		fmt.Fprint(stderr, `
Examples:
  sitegrade example.com
  sitegrade -format json example.com > report.json
  sitegrade -min-grade B example.com        (non-zero exit if worse than B)

Only audit sites you own or have permission to test.
`)
	}

	targets, err := parseArgs(fs, args)
	if err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		return 2
	}

	if *showVersion {
		fmt.Fprintln(stdout, "sitegrade", version)
		return 0
	}
	if len(targets) == 0 {
		fs.Usage()
		return 2
	}

	validFormat := false
	for _, f := range report.Formats {
		if *format == f {
			validFormat = true
		}
	}
	if !validFormat {
		fmt.Fprintf(stderr, "error: unknown format %q\n", *format)
		return 2
	}

	*minGrade = strings.ToUpper(strings.TrimSpace(*minGrade))
	if *minGrade != "" && audit.GradeRank(*minGrade) < 0 {
		fmt.Fprintf(stderr, "error: unknown grade %q (use A+, A, B, C, D or F)\n", *minGrade)
		return 2
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()

	opts := audit.Options{
		Timeout:           *timeout,
		UserAgent:         "sitegrade/" + version,
		SkipRedirectCheck: *noRedirect,
	}

	var reports []*audit.Report
	failed, belowMin := false, false
	for _, t := range targets {
		if ctx.Err() != nil {
			break
		}
		fmt.Fprintf(stderr, "Auditing %s ...\n", t)
		rep, err := audit.Run(ctx, t, opts)
		if err != nil {
			fmt.Fprintf(stderr, "error: %s: %v\n", t, err)
			failed = true
			continue
		}
		reports = append(reports, rep)
		if *minGrade != "" && !audit.GradeAtLeast(rep.Grade, *minGrade) {
			belowMin = true
		}
	}

	if len(reports) > 0 {
		dst := stdout
		if *outFile != "" {
			f, err := os.Create(*outFile)
			if err != nil {
				fmt.Fprintln(stderr, "error:", err)
				return 1
			}
			defer f.Close()
			dst = f
		}
		if err := report.Write(dst, *format, reports); err != nil {
			fmt.Fprintln(stderr, "error:", err)
			return 1
		}
	}

	switch {
	case ctx.Err() != nil:
		fmt.Fprintln(stderr, "Interrupted.")
		return 130
	case failed:
		return 1
	case belowMin:
		fmt.Fprintf(stderr, "At least one site graded below %s.\n", *minGrade)
		return 3
	}
	return 0
}

// parseArgs lets flags appear before, between or after targets.
func parseArgs(fs *flag.FlagSet, args []string) ([]string, error) {
	var targets []string
	for {
		if err := fs.Parse(args); err != nil {
			return nil, err
		}
		rest := fs.Args()
		if len(rest) == 0 {
			return targets, nil
		}
		targets = append(targets, rest[0])
		args = rest[1:]
	}
}
