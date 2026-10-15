package audit

import (
	"context"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
	"strings"
	"sync"
	"time"
)

// TLSOptions configures the TLS checks.
type TLSOptions struct {
	Timeout time.Duration
	RootCAs *x509.CertPool // nil means the system's trusted roots
}

// tlsVersions lists the protocol versions we probe, oldest first.
var tlsVersions = []struct {
	id   uint16
	name string
}{
	{tls.VersionTLS10, "TLS 1.0"},
	{tls.VersionTLS11, "TLS 1.1"},
	{tls.VersionTLS12, "TLS 1.2"},
	{tls.VersionTLS13, "TLS 1.3"},
}

// CheckTLS inspects the TLS configuration of host:port: which protocol
// versions are accepted, whether the certificate is trusted, when it
// expires, and how strong its key and signature are.
func CheckTLS(ctx context.Context, host, port string, opts TLSOptions) ([]Finding, *TLSInfo) {
	if opts.Timeout <= 0 {
		opts.Timeout = 10 * time.Second
	}
	addr := net.JoinHostPort(host, port)
	info := &TLSInfo{}
	var out []Finding

	supported := probeVersions(ctx, addr, host, opts.Timeout)
	for i, v := range tlsVersions {
		if supported[i] {
			info.Versions = append(info.Versions, v.name)
		}
	}
	if len(info.Versions) == 0 {
		out = append(out, critical(problem(StatusFail, CatTLS, "TLS handshake",
			"Could not complete a TLS handshake with "+clean(addr)+".",
			"Check that the server speaks TLS on this port and is reachable.", 25)))
		return out, info
	}
	out = append(out, versionFindings(supported)...)

	// First try with full verification; if that fails, look at the
	// certificate anyway so the report can still describe it.
	state, verifyErr := fetchState(ctx, addr, host, opts, true)
	if verifyErr != nil {
		out = append(out, critical(problem(StatusFail, CatTLS, "Certificate trust",
			"Certificate could not be verified: "+clean(verifyErr.Error()),
			"Install a valid certificate from a trusted CA that covers this hostname, including the full chain.", 25)))

		var err error
		state, err = fetchState(ctx, addr, host, opts, false)
		if err != nil {
			return out, info
		}
	} else {
		out = append(out, pass(CatTLS, "Certificate trust", "Certificate is trusted and matches the hostname."))
	}
	if len(state.PeerCertificates) == 0 {
		return out, info
	}

	cert := state.PeerCertificates[0]
	out = append(out, expiryFinding(cert.NotAfter, time.Now()))

	keyType, keyF, haveKey := keyFinding(cert)
	if haveKey {
		out = append(out, keyF)
	}
	out = append(out, sigFinding(cert))

	fillInfo(info, cert, keyType)
	return out, info
}

// probeVersions tries a handshake pinned to each protocol version in
// parallel and reports which ones the server accepted.
func probeVersions(ctx context.Context, addr, serverName string, timeout time.Duration) []bool {
	ok := make([]bool, len(tlsVersions))
	var wg sync.WaitGroup
	for i, v := range tlsVersions {
		wg.Add(1)
		go func(i int, id uint16) {
			defer wg.Done()
			d := tls.Dialer{
				NetDialer: &net.Dialer{Timeout: timeout},
				Config: &tls.Config{
					ServerName:         serverName,
					MinVersion:         id, //nolint:gosec // probing legacy versions on purpose
					MaxVersion:         id,
					InsecureSkipVerify: true, //nolint:gosec // only testing protocol support here
				},
			}
			conn, err := d.DialContext(ctx, "tcp", addr)
			if err == nil {
				conn.Close()
				ok[i] = true
			}
		}(i, v.id)
	}
	wg.Wait()
	return ok
}

// fetchState completes a handshake and returns the connection state,
// optionally verifying the certificate chain and hostname.
func fetchState(ctx context.Context, addr, host string, opts TLSOptions, verify bool) (tls.ConnectionState, error) {
	cfg := &tls.Config{
		ServerName: host,
		RootCAs:    opts.RootCAs,
		MinVersion: tls.VersionTLS10, //nolint:gosec // so version support never masks cert problems
	}
	if !verify {
		cfg.InsecureSkipVerify = true //nolint:gosec // inspecting an untrusted certificate
	}

	d := tls.Dialer{NetDialer: &net.Dialer{Timeout: opts.Timeout}, Config: cfg}
	conn, err := d.DialContext(ctx, "tcp", addr)
	if err != nil {
		return tls.ConnectionState{}, err
	}
	defer conn.Close()

	tc, ok := conn.(*tls.Conn)
	if !ok {
		return tls.ConnectionState{}, fmt.Errorf("unexpected connection type %T", conn)
	}
	return tc.ConnectionState(), nil
}

// versionFindings turns the probe results (indexed like tlsVersions) into findings.
func versionFindings(ok []bool) []Finding {
	var out []Finding

	var legacy []string
	if ok[0] {
		legacy = append(legacy, "TLS 1.0")
	}
	if ok[1] {
		legacy = append(legacy, "TLS 1.1")
	}
	if len(legacy) > 0 {
		out = append(out, problem(StatusFail, CatTLS, "Legacy protocols",
			"Server still accepts "+strings.Join(legacy, " and ")+".",
			"Disable TLS 1.0 and 1.1 and require TLS 1.2 or newer.", 15))
	} else {
		out = append(out, pass(CatTLS, "Legacy protocols", "TLS 1.0 and 1.1 are disabled."))
	}

	switch {
	case !ok[2] && !ok[3]:
		out = append(out, critical(problem(StatusFail, CatTLS, "Modern TLS",
			"Neither TLS 1.2 nor TLS 1.3 is supported.",
			"Enable TLS 1.2 and TLS 1.3.", 25)))
	case ok[3]:
		out = append(out, pass(CatTLS, "TLS 1.3", "TLS 1.3 is supported."))
	default:
		out = append(out, problem(StatusWarn, CatTLS, "TLS 1.3",
			"TLS 1.3 is not supported (TLS 1.2 is).",
			"Enable TLS 1.3 for better security and speed.", 3))
	}
	return out
}

// expiryFinding grades how close the certificate is to expiring.
func expiryFinding(notAfter, now time.Time) Finding {
	const name = "Certificate expiry"
	date := notAfter.UTC().Format("2006-01-02")

	if notAfter.Before(now) {
		days := int(now.Sub(notAfter).Hours() / 24)
		return critical(problem(StatusFail, CatTLS, name,
			fmt.Sprintf("Certificate expired %d day(s) ago (%s).", days, date),
			"Renew the certificate immediately.", 25))
	}

	days := int(notAfter.Sub(now).Hours() / 24)
	switch {
	case days <= 14:
		return problem(StatusFail, CatTLS, name,
			fmt.Sprintf("Certificate expires in %d day(s) (%s).", days, date),
			"Renew the certificate now and set up automatic renewal.", 15)
	case days <= 30:
		return problem(StatusWarn, CatTLS, name,
			fmt.Sprintf("Certificate expires in %d days (%s).", days, date),
			"Renew soon and consider automatic renewal (for example ACME).", 8)
	}
	return pass(CatTLS, name, fmt.Sprintf("Expires in %d days (%s).", days, date))
}

// keyFinding grades the certificate's public key. The bool is false for key
// types we don't grade.
func keyFinding(cert *x509.Certificate) (string, Finding, bool) {
	const name = "Key strength"
	switch pub := cert.PublicKey.(type) {
	case *rsa.PublicKey:
		bits := pub.N.BitLen()
		keyType := fmt.Sprintf("RSA %d", bits)
		if bits < 2048 {
			return keyType, problem(StatusFail, CatTLS, name,
				keyType+" bit key is too short.",
				"Use an RSA key of at least 2048 bits, or an ECDSA P-256 key.", 10), true
		}
		return keyType, pass(CatTLS, name, keyType+" bit key."), true
	case *ecdsa.PublicKey:
		keyType := "ECDSA " + pub.Curve.Params().Name
		return keyType, pass(CatTLS, name, keyType+" key."), true
	}
	return "", Finding{}, false
}

// sigFinding flags certificates signed with broken hash algorithms.
func sigFinding(cert *x509.Certificate) Finding {
	const name = "Signature algorithm"
	alg := cert.SignatureAlgorithm
	switch alg {
	case x509.MD2WithRSA, x509.MD5WithRSA, x509.SHA1WithRSA, x509.ECDSAWithSHA1, x509.DSAWithSHA1:
		return problem(StatusFail, CatTLS, name,
			"Certificate is signed with a weak algorithm: "+alg.String(),
			"Reissue the certificate with SHA-256 or stronger.", 10)
	}
	return pass(CatTLS, name, "Signed with "+alg.String()+".")
}

func fillInfo(info *TLSInfo, cert *x509.Certificate, keyType string) {
	info.Subject = clean(firstNonEmpty(cert.Subject.CommonName, firstOf(cert.DNSNames)))
	info.Issuer = clean(firstNonEmpty(cert.Issuer.CommonName, firstOf(cert.Issuer.Organization)))
	info.NotAfter = cert.NotAfter
	info.DaysLeft = int(time.Until(cert.NotAfter).Hours() / 24)
	info.KeyType = keyType

	for i, n := range cert.DNSNames {
		if i == 10 {
			break
		}
		info.DNSNames = append(info.DNSNames, clean(n))
	}
}

func firstOf(s []string) string {
	if len(s) == 0 {
		return ""
	}
	return s[0]
}

func firstNonEmpty(a, b string) string {
	if a != "" {
		return a
	}
	return b
}
