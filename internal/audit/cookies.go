package audit

import (
	"net/http"
	"strings"
)

// CheckCookies audits the cookies set on a response. Each cookie is checked
// for the Secure, HttpOnly and SameSite attributes.
func CheckCookies(cookies []*http.Cookie, isHTTPS bool) []Finding {
	if len(cookies) == 0 {
		return []Finding{pass(CatCookies, "Set-Cookie", "No cookies were set on this response.")}
	}

	var out []Finding
	for _, c := range cookies {
		name := "Cookie " + clean(c.Name)

		var missing []string
		penalty := 0
		status := StatusWarn

		if isHTTPS && !c.Secure {
			missing = append(missing, "Secure")
			penalty += 4
			status = StatusFail
		}
		if !c.HttpOnly {
			missing = append(missing, "HttpOnly")
			penalty += 3
		}
		if c.SameSite == 0 {
			missing = append(missing, "SameSite")
			penalty += 2
		}

		if len(missing) == 0 {
			out = append(out, pass(CatCookies, name, "Secure, HttpOnly and SameSite are all set."))
			continue
		}
		out = append(out, problem(status, CatCookies, name,
			"Missing: "+strings.Join(missing, ", "),
			"Session cookies should use: Secure; HttpOnly; SameSite=Lax (or Strict).", penalty))
	}
	return out
}
