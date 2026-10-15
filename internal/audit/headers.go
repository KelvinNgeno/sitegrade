package audit

import (
	"fmt"
	"net/http"
	"strconv"
	"strings"
)

// minHSTSAge is 180 days in seconds.
const minHSTSAge = 15552000

// CheckHeaders audits the security-related response headers. HSTS is only
// meaningful over HTTPS, so it is skipped for plain-HTTP responses.
func CheckHeaders(h http.Header, isHTTPS bool) []Finding {
	var out []Finding
	if isHTTPS {
		out = append(out, checkHSTS(h))
	}
	out = append(out,
		checkCSP(h),
		checkFraming(h),
		checkNoSniff(h),
		checkReferrer(h),
		checkPermissions(h),
		checkDisclosure(h),
	)
	return out
}

func checkHSTS(h http.Header) Finding {
	const name = "Strict-Transport-Security"
	v := h.Get(name)
	if v == "" {
		return problem(StatusFail, CatHeaders, name,
			"Header is missing, so browsers may still try plain HTTP first.",
			"Add: Strict-Transport-Security: max-age=31536000; includeSubDomains", 15)
	}

	age := parseMaxAge(v)
	switch {
	case age < 0:
		return problem(StatusWarn, CatHeaders, name,
			"No valid max-age value found: "+clean(v),
			"Set max-age to at least 31536000 (one year).", 10)
	case age < minHSTSAge:
		return problem(StatusWarn, CatHeaders, name,
			fmt.Sprintf("max-age is %d seconds, under the recommended 180 days.", age),
			"Raise max-age to 31536000 or more.", 5)
	}

	detail := fmt.Sprintf("max-age=%d", age)
	if strings.Contains(strings.ToLower(v), "includesubdomains") {
		detail += ", includeSubDomains"
	}
	return pass(CatHeaders, name, detail)
}

// parseMaxAge extracts the max-age value, or -1 if absent or invalid.
func parseMaxAge(v string) int {
	for _, part := range strings.Split(v, ";") {
		part = strings.TrimSpace(part)
		if len(part) > 8 && strings.EqualFold(part[:8], "max-age=") {
			n, err := strconv.Atoi(strings.Trim(strings.TrimSpace(part[8:]), `"`))
			if err != nil || n < 0 {
				return -1
			}
			return n
		}
	}
	return -1
}

func checkCSP(h http.Header) Finding {
	const name = "Content-Security-Policy"
	v := h.Get(name)
	if v == "" {
		return problem(StatusFail, CatHeaders, name,
			"Header is missing, so the browser has no policy limiting scripts and other content.",
			"Start with: Content-Security-Policy: default-src 'self'", 20)
	}

	dirs := parseCSP(v)
	src, ok := dirs["script-src"]
	if !ok {
		src, ok = dirs["default-src"]
	}
	if !ok {
		return problem(StatusWarn, CatHeaders, name,
			"Policy has neither script-src nor default-src, so scripts are not restricted.",
			"Add default-src 'self' or an explicit script-src.", 8)
	}

	if weak := weakScriptSources(src); len(weak) > 0 {
		return problem(StatusWarn, CatHeaders, name,
			"Script sources allow risky values: "+clean(strings.Join(weak, " ")),
			"Remove 'unsafe-inline', 'unsafe-eval' and wildcards; use nonces or hashes instead.", 8)
	}
	return pass(CatHeaders, name, "Policy restricts script sources.")
}

// parseCSP splits a policy into directive name -> source list.
func parseCSP(v string) map[string][]string {
	dirs := make(map[string][]string)
	for _, d := range strings.Split(v, ";") {
		fields := strings.Fields(d)
		if len(fields) == 0 {
			continue
		}
		name := strings.ToLower(fields[0])
		if _, exists := dirs[name]; !exists {
			dirs[name] = fields[1:]
		}
	}
	return dirs
}

func weakScriptSources(src []string) []string {
	// With a nonce or hash present, browsers ignore 'unsafe-inline'.
	hasNonceOrHash := false
	for _, s := range src {
		l := strings.ToLower(s)
		if strings.HasPrefix(l, "'nonce-") || strings.HasPrefix(l, "'sha256-") ||
			strings.HasPrefix(l, "'sha384-") || strings.HasPrefix(l, "'sha512-") {
			hasNonceOrHash = true
		}
	}

	var weak []string
	for _, s := range src {
		switch strings.ToLower(s) {
		case "'unsafe-inline'":
			if !hasNonceOrHash {
				weak = append(weak, s)
			}
		case "'unsafe-eval'", "*", "data:", "http:", "https:":
			weak = append(weak, s)
		}
	}
	return weak
}

func checkFraming(h http.Header) Finding {
	const name = "Clickjacking protection"
	if _, ok := parseCSP(h.Get("Content-Security-Policy"))["frame-ancestors"]; ok {
		return pass(CatHeaders, name, "CSP frame-ancestors is set.")
	}

	xfo := strings.ToUpper(strings.TrimSpace(h.Get("X-Frame-Options")))
	switch xfo {
	case "DENY", "SAMEORIGIN":
		return pass(CatHeaders, name, "X-Frame-Options: "+xfo)
	case "":
		return problem(StatusFail, CatHeaders, name,
			"Neither X-Frame-Options nor CSP frame-ancestors is set, so other sites can frame this page.",
			"Add: Content-Security-Policy: frame-ancestors 'self' (or X-Frame-Options: DENY).", 8)
	default:
		return problem(StatusWarn, CatHeaders, name,
			"X-Frame-Options has a weak or obsolete value: "+clean(xfo),
			"Use DENY or SAMEORIGIN, or CSP frame-ancestors.", 4)
	}
}

func checkNoSniff(h http.Header) Finding {
	const name = "X-Content-Type-Options"
	if strings.EqualFold(strings.TrimSpace(h.Get(name)), "nosniff") {
		return pass(CatHeaders, name, "nosniff")
	}
	return problem(StatusWarn, CatHeaders, name,
		"Header is missing or not set to nosniff, so browsers may guess content types.",
		"Add: X-Content-Type-Options: nosniff", 5)
}

func checkReferrer(h http.Header) Finding {
	const name = "Referrer-Policy"
	v := strings.TrimSpace(h.Get(name))
	switch strings.ToLower(v) {
	case "":
		return problem(StatusWarn, CatHeaders, name,
			"Header is missing, so full page URLs may leak to other sites.",
			"Add: Referrer-Policy: strict-origin-when-cross-origin", 4)
	case "unsafe-url":
		return problem(StatusWarn, CatHeaders, name,
			"unsafe-url sends the full URL to every site you link to.",
			"Use strict-origin-when-cross-origin or no-referrer.", 3)
	}
	return pass(CatHeaders, name, clean(v))
}

func checkPermissions(h http.Header) Finding {
	const name = "Permissions-Policy"
	if h.Get(name) == "" {
		return problem(StatusWarn, CatHeaders, name,
			"Header is missing, so powerful browser features are not explicitly restricted.",
			"Add, for example: Permissions-Policy: camera=(), microphone=(), geolocation=()", 2)
	}
	return pass(CatHeaders, name, "Header is set.")
}

func checkDisclosure(h http.Header) Finding {
	const name = "Technology disclosure"
	var leaks []string
	if s := h.Get("Server"); strings.ContainsAny(s, "0123456789") {
		leaks = append(leaks, "Server: "+s)
	}
	if p := h.Get("X-Powered-By"); p != "" {
		leaks = append(leaks, "X-Powered-By: "+p)
	}
	if len(leaks) == 0 {
		return pass(CatHeaders, name, "No version details in Server or X-Powered-By.")
	}
	return problem(StatusWarn, CatHeaders, name,
		"Headers reveal software details: "+clean(strings.Join(leaks, "; ")),
		"Remove X-Powered-By and hide version numbers in the Server header.", 2*len(leaks))
}
