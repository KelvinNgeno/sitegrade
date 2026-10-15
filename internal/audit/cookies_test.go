package audit

import (
	"net/http"
	"testing"
)

func TestCheckCookies(t *testing.T) {
	t.Run("no cookies", func(t *testing.T) {
		got := CheckCookies(nil, true)
		if len(got) != 1 || got[0].Status != StatusPass {
			t.Fatalf("got %+v", got)
		}
	})

	t.Run("fully protected", func(t *testing.T) {
		c := &http.Cookie{Name: "sid", Secure: true, HttpOnly: true, SameSite: http.SameSiteStrictMode}
		got := CheckCookies([]*http.Cookie{c}, true)
		if got[0].Status != StatusPass || got[0].Penalty != 0 {
			t.Fatalf("got %+v", got[0])
		}
	})

	t.Run("missing everything over https", func(t *testing.T) {
		got := CheckCookies([]*http.Cookie{{Name: "sid"}}, true)
		if got[0].Status != StatusFail {
			t.Errorf("status = %s, want fail (missing Secure)", got[0].Status)
		}
		if got[0].Penalty != 9 {
			t.Errorf("penalty = %d, want 9", got[0].Penalty)
		}
	})

	t.Run("secure not required over http", func(t *testing.T) {
		c := &http.Cookie{Name: "sid", HttpOnly: true, SameSite: http.SameSiteLaxMode}
		got := CheckCookies([]*http.Cookie{c}, false)
		if got[0].Status != StatusPass {
			t.Errorf("status = %s, want pass", got[0].Status)
		}
	})

	t.Run("missing HttpOnly only is a warning", func(t *testing.T) {
		c := &http.Cookie{Name: "pref", Secure: true, SameSite: http.SameSiteLaxMode}
		got := CheckCookies([]*http.Cookie{c}, true)
		if got[0].Status != StatusWarn {
			t.Errorf("status = %s, want warn", got[0].Status)
		}
	})
}
