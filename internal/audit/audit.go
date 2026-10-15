package audit

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"
)

// Options configures an audit.
type Options struct {
	Timeout           time.Duration
	UserAgent         string
	RootCAs           *x509.CertPool // nil means the system's trusted roots
	SkipRedirectCheck bool           // don't probe port 80
}

// Target is a parsed audit target.
type Target struct {
	URL   *url.URL
	Host  string
	Port  string
	HTTPS bool
}

// ParseTarget accepts "example.com", "example.com:8443" or a full URL.
// A bare host is audited over HTTPS.
func ParseTarget(raw string) (*Target, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil, errors.New("empty target")
	}
	if !strings.Contains(raw, "://") {
		raw = "https://" + raw
	}

	u, err := url.Parse(raw)
	if err != nil {
		return nil, fmt.Errorf("invalid target %q: %w", raw, err)
	}
	if u.Scheme != "https" && u.Scheme != "http" {
		return nil, fmt.Errorf("unsupported scheme %q (use http or https)", u.Scheme)
	}
	if u.Hostname() == "" {
		return nil, fmt.Errorf("no host in target %q", raw)
	}

	port := u.Port()
	if port == "" {
		port = "80"
		if u.Scheme == "https" {
			port = "443"
		}
	}
	if u.Path == "" {
		u.Path = "/"
	}
	return &Target{URL: u, Host: u.Hostname(), Port: port, HTTPS: u.Scheme == "https"}, nil
}

// Run audits one site and returns a graded report.
func Run(ctx context.Context, rawTarget string, opts Options) (*Report, error) {
	if opts.Timeout <= 0 {
		opts.Timeout = 10 * time.Second
	}
	if opts.UserAgent == "" {
		opts.UserAgent = "sitegrade"
	}

	target, err := ParseTarget(rawTarget)
	if err != nil {
		return nil, err
	}

	resp, err := fetch(ctx, target.URL.String(), opts, true)
	if err != nil {
		return nil, fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 1<<20))

	// Audit the site we actually landed on, after any redirects.
	final := resp.Request.URL
	isHTTPS := final.Scheme == "https"

	var findings []Finding
	var tlsInfo *TLSInfo

	if isHTTPS {
		port := final.Port()
		if port == "" {
			port = "443"
		}
		var tlsFindings []Finding
		tlsFindings, tlsInfo = CheckTLS(ctx, final.Hostname(), port,
			TLSOptions{Timeout: opts.Timeout, RootCAs: opts.RootCAs})
		findings = append(findings, tlsFindings...)
	} else {
		findings = append(findings, critical(problem(StatusFail, CatTransport, "HTTPS",
			"The site is served over plain HTTP, so all traffic can be read or altered in transit.",
			"Serve the site over HTTPS with a valid certificate and redirect HTTP to it.", 40)))
	}

	if target.HTTPS && target.Port == "443" && !opts.SkipRedirectCheck {
		findings = append(findings, redirectFinding(ctx, target.Host, opts))
	}

	findings = append(findings, CheckHeaders(resp.Header, isHTTPS)...)
	findings = append(findings, CheckCookies(resp.Cookies(), isHTTPS)...)

	order := map[string]int{CatTransport: 0, CatTLS: 1, CatHeaders: 2, CatCookies: 3}
	sort.SliceStable(findings, func(i, j int) bool {
		return order[findings[i].Category] < order[findings[j].Category]
	})

	score := Score(findings)
	return &Report{
		Target:    clean(rawTarget),
		FinalURL:  clean(final.String()),
		Score:     score,
		Grade:     Grade(score, findings),
		Findings:  findings,
		TLS:       tlsInfo,
		ScannedAt: time.Now().UTC(),
	}, nil
}

// fetch performs a GET. Certificate errors are ignored here on purpose: the
// TLS check reports them separately, and we still want to read the headers.
func fetch(ctx context.Context, rawURL string, opts Options, follow bool) (*http.Response, error) {
	client := &http.Client{
		Timeout: opts.Timeout,
		Transport: &http.Transport{
			Proxy: http.ProxyFromEnvironment,
			TLSClientConfig: &tls.Config{
				MinVersion:         tls.VersionTLS10, //nolint:gosec // legacy servers must still be auditable
				InsecureSkipVerify: true,             //nolint:gosec // cert problems are reported by CheckTLS
			},
			DisableKeepAlives: true,
		},
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if !follow {
				return http.ErrUseLastResponse
			}
			if len(via) >= 5 {
				return errors.New("stopped after 5 redirects")
			}
			return nil
		},
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", opts.UserAgent)
	return client.Do(req)
}

// redirectFinding probes plain HTTP on port 80 without following redirects.
func redirectFinding(ctx context.Context, host string, opts Options) Finding {
	if opts.Timeout > 5*time.Second {
		opts.Timeout = 5 * time.Second
	}
	if strings.Contains(host, ":") { // IPv6 literal
		host = "[" + host + "]"
	}

	resp, err := fetch(ctx, "http://"+host+"/", opts, false)
	if err != nil {
		return pass(CatTransport, "HTTP to HTTPS redirect",
			"Port 80 is not reachable, so there is no plain-HTTP entry point.")
	}
	defer resp.Body.Close()
	return CheckHTTPRedirect(resp)
}

// CheckHTTPRedirect grades the response a site gives to plain HTTP.
func CheckHTTPRedirect(resp *http.Response) Finding {
	const name = "HTTP to HTTPS redirect"
	const fix = "Redirect all HTTP requests to the https:// version of the site."

	if resp.StatusCode >= 300 && resp.StatusCode < 400 {
		loc := strings.ToLower(strings.TrimSpace(resp.Header.Get("Location")))
		if strings.HasPrefix(loc, "https://") {
			return pass(CatTransport, name,
				fmt.Sprintf("Plain HTTP redirects to HTTPS (status %d).", resp.StatusCode))
		}
		return problem(StatusFail, CatTransport, name,
			"Plain HTTP redirects, but not to an HTTPS address.", fix, 10)
	}
	return problem(StatusFail, CatTransport, name,
		fmt.Sprintf("Plain HTTP answers with status %d instead of redirecting to HTTPS.", resp.StatusCode),
		fix, 10)
}
