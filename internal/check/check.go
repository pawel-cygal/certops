package check

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"net"
	"net/http"
	"os"
	"strings"
	"time"

	crlcheck "certops/internal/crl"
)

type Options struct {
	WarnDays        int
	CriticalDays    int
	Timeout         time.Duration
	CABundle        string
	CRLSources      []string
	CRLCABundle     string
	CRLWarnDays     int
	CRLCriticalDays int
	CRLMaxAgeDays   int
}

type Finding struct {
	Severity string `json:"severity"`
	Scope    string `json:"scope"`
	Message  string `json:"message"`
}

type Certificate struct {
	Subject       string   `json:"subject,omitempty"`
	Issuer        string   `json:"issuer,omitempty"`
	SerialNumber  string   `json:"serial_number,omitempty"`
	DNSNames      []string `json:"dns_names,omitempty"`
	NotBefore     string   `json:"not_before,omitempty"`
	NotAfter      string   `json:"not_after,omitempty"`
	DaysRemaining int      `json:"days_remaining"`
	Trusted       bool     `json:"trusted"`
	MatchesHost   bool     `json:"matches_host"`
}

type TLSInfo struct {
	NegotiatedVersion string   `json:"negotiated_version,omitempty"`
	CipherSuite       string   `json:"cipher_suite,omitempty"`
	ALPN              string   `json:"alpn,omitempty"`
	OCSPStapling      bool     `json:"ocsp_stapling"`
	SupportedVersions []string `json:"supported_versions,omitempty"`
	HandshakeMS       int64    `json:"handshake_ms"`
}

type HTTPSInfo struct {
	HTTPRedirectChecked bool   `json:"http_redirect_checked"`
	HTTPRedirectOK      bool   `json:"http_redirect_ok"`
	HSTS                string `json:"hsts,omitempty"`
}

type RevocationInfo struct {
	Checked bool     `json:"checked"`
	Sources []string `json:"sources,omitempty"`
	Revoked bool     `json:"revoked"`
	Errors  []string `json:"errors,omitempty"`
}

type Report struct {
	Target      string         `json:"target"`
	Host        string         `json:"host"`
	Address     string         `json:"address"`
	Status      string         `json:"status"`
	Certificate Certificate    `json:"certificate"`
	TLS         TLSInfo        `json:"tls"`
	HTTPS       HTTPSInfo      `json:"https"`
	Revocation  RevocationInfo `json:"revocation"`
	Findings    []Finding      `json:"findings,omitempty"`
	Error       string         `json:"error,omitempty"`
}

func Run(ctx context.Context, host, address string, opts Options) Report {
	if opts.WarnDays == 0 {
		opts.WarnDays = 30
	}
	if opts.CriticalDays == 0 {
		opts.CriticalDays = 14
	}
	if opts.Timeout == 0 {
		opts.Timeout = 10 * time.Second
	}
	if opts.CRLWarnDays == 0 {
		opts.CRLWarnDays = 3
	}
	if opts.CRLCriticalDays == 0 {
		opts.CRLCriticalDays = 1
	}

	report := Report{
		Target:  address,
		Host:    host,
		Address: address,
		Status:  "ok",
	}

	start := time.Now()
	conn, err := dialTLS(ctx, host, address, opts.Timeout)
	if err != nil {
		report.Status = "error"
		report.Error = err.Error()
		add(&report, "critical", "tls", err.Error())
		return report
	}
	defer conn.Close()

	report.TLS.HandshakeMS = time.Since(start).Milliseconds()
	state := conn.ConnectionState()
	report.TLS.NegotiatedVersion = tlsVersionName(state.Version)
	report.TLS.CipherSuite = tls.CipherSuiteName(state.CipherSuite)
	report.TLS.ALPN = state.NegotiatedProtocol
	report.TLS.OCSPStapling = len(state.OCSPResponse) > 0
	report.TLS.SupportedVersions = probeVersions(ctx, host, address, opts.Timeout)

	if len(state.PeerCertificates) == 0 {
		add(&report, "critical", "certificate", "server did not present a certificate")
		report.Status = aggregateStatus(report.Findings)
		return report
	}

	leaf := state.PeerCertificates[0]
	report.Certificate = Certificate{
		Subject:       leaf.Subject.String(),
		Issuer:        leaf.Issuer.String(),
		SerialNumber:  leaf.SerialNumber.String(),
		DNSNames:      append([]string(nil), leaf.DNSNames...),
		NotBefore:     leaf.NotBefore.UTC().Format(time.RFC3339),
		NotAfter:      leaf.NotAfter.UTC().Format(time.RFC3339),
		DaysRemaining: int(time.Until(leaf.NotAfter).Hours() / 24),
		Trusted:       true,
		MatchesHost:   true,
	}

	if report.Certificate.DaysRemaining <= opts.CriticalDays {
		add(&report, "critical", "certificate", fmt.Sprintf("certificate expires in %d days", report.Certificate.DaysRemaining))
	} else if report.Certificate.DaysRemaining <= opts.WarnDays {
		add(&report, "warn", "certificate", fmt.Sprintf("certificate expires in %d days", report.Certificate.DaysRemaining))
	}
	if err := leaf.VerifyHostname(host); err != nil {
		report.Certificate.MatchesHost = false
		add(&report, "critical", "certificate", "certificate does not match hostname: "+err.Error())
	}
	_, systemTrustErr := leaf.Verify(x509.VerifyOptions{DNSName: host, Intermediates: intermediates(state.PeerCertificates)})
	if opts.CABundle != "" {
		if err := verifyWithCABundle(leaf, state.PeerCertificates, host, opts.CABundle); err != nil {
			report.Certificate.Trusted = false
			add(&report, "critical", "certificate", "certificate is not trusted by configured CA bundle: "+err.Error())
		}
	} else if systemTrustErr != nil {
		report.Certificate.Trusted = false
		add(&report, "critical", "certificate", "certificate chain is not trusted: "+systemTrustErr.Error())
	}
	checkRevocation(ctx, &report, state.PeerCertificates, opts)

	if supports(report.TLS.SupportedVersions, "TLS1.0") {
		add(&report, "warn", "tls", "TLS 1.0 is accepted")
	}
	if supports(report.TLS.SupportedVersions, "TLS1.1") {
		add(&report, "warn", "tls", "TLS 1.1 is accepted")
	}
	if !supports(report.TLS.SupportedVersions, "TLS1.2") && !supports(report.TLS.SupportedVersions, "TLS1.3") {
		add(&report, "critical", "tls", "TLS 1.2 and TLS 1.3 are not available")
	}
	if !report.TLS.OCSPStapling {
		add(&report, "warn", "tls", "OCSP stapling is not enabled")
	}

	report.HTTPS = checkHTTPS(ctx, host, address, opts.Timeout)
	if shouldCheckHTTPRedirect(address) && !report.HTTPS.HTTPRedirectOK {
		add(&report, "warn", "https", "HTTP to HTTPS redirect was not confirmed")
	}
	if strings.TrimSpace(report.HTTPS.HSTS) == "" {
		add(&report, "warn", "https", "HSTS header is missing")
	}

	report.Status = aggregateStatus(report.Findings)
	return report
}

func shouldCheckHTTPRedirect(address string) bool {
	_, port, err := net.SplitHostPort(address)
	return err != nil || port == "443"
}

func dialTLS(ctx context.Context, host, address string, timeout time.Duration) (*tls.Conn, error) {
	dialer := &net.Dialer{Timeout: timeout}
	raw, err := dialer.DialContext(ctx, "tcp", address)
	if err != nil {
		return nil, err
	}
	conn := tls.Client(raw, &tls.Config{
		ServerName:         host,
		MinVersion:         tls.VersionTLS10,
		NextProtos:         []string{"h2", "http/1.1"},
		InsecureSkipVerify: true,
	})
	if err := conn.SetDeadline(time.Now().Add(timeout)); err != nil {
		_ = conn.Close()
		return nil, err
	}
	if err := conn.HandshakeContext(ctx); err != nil {
		_ = conn.Close()
		return nil, err
	}
	return conn, nil
}

func probeVersions(ctx context.Context, host, address string, timeout time.Duration) []string {
	candidates := []struct {
		version uint16
		name    string
	}{
		{tls.VersionTLS10, "TLS1.0"},
		{tls.VersionTLS11, "TLS1.1"},
		{tls.VersionTLS12, "TLS1.2"},
		{tls.VersionTLS13, "TLS1.3"},
	}
	var out []string
	for _, candidate := range candidates {
		if probeVersion(ctx, host, address, candidate.version, timeout) {
			out = append(out, candidate.name)
		}
	}
	return out
}

func probeVersion(ctx context.Context, host, address string, version uint16, timeout time.Duration) bool {
	dialer := &net.Dialer{Timeout: timeout}
	raw, err := dialer.DialContext(ctx, "tcp", address)
	if err != nil {
		return false
	}
	defer raw.Close()
	conn := tls.Client(raw, &tls.Config{
		ServerName:         host,
		MinVersion:         version,
		MaxVersion:         version,
		InsecureSkipVerify: true,
	})
	_ = conn.SetDeadline(time.Now().Add(timeout))
	err = conn.HandshakeContext(ctx)
	_ = conn.Close()
	return err == nil
}

func checkHTTPS(ctx context.Context, host, address string, timeout time.Duration) HTTPSInfo {
	client := &http.Client{
		Timeout: timeout,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 10 {
				return http.ErrUseLastResponse
			}
			return nil
		},
	}
	info := HTTPSInfo{}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://"+address, nil)
	if err == nil {
		resp, err := client.Do(req)
		if err == nil {
			info.HSTS = resp.Header.Get("Strict-Transport-Security")
			_ = resp.Body.Close()
		}
	}
	_, port, err := net.SplitHostPort(address)
	if err == nil && port != "443" {
		return info
	}
	info.HTTPRedirectChecked = true
	req, err = http.NewRequestWithContext(ctx, http.MethodGet, "http://"+host, nil)
	if err != nil {
		return info
	}
	resp, err := client.Do(req)
	if err != nil {
		return info
	}
	defer resp.Body.Close()
	info.HTTPRedirectOK = resp.Request != nil && resp.Request.URL != nil && resp.Request.URL.Scheme == "https"
	return info
}

func intermediates(certs []*x509.Certificate) *x509.CertPool {
	pool := x509.NewCertPool()
	for _, cert := range certs[1:] {
		pool.AddCert(cert)
	}
	return pool
}

func verifyWithCABundle(leaf *x509.Certificate, certs []*x509.Certificate, host, path string) error {
	roots, err := loadCertPool(path)
	if err != nil {
		return err
	}
	_, err = leaf.Verify(x509.VerifyOptions{
		DNSName:       host,
		Roots:         roots,
		Intermediates: intermediates(certs),
	})
	return err
}

func checkRevocation(ctx context.Context, report *Report, certs []*x509.Certificate, opts Options) {
	if len(opts.CRLSources) == 0 {
		return
	}
	report.Revocation.Checked = true
	report.Revocation.Sources = append([]string(nil), opts.CRLSources...)
	lists := make([]*x509.RevocationList, 0, len(opts.CRLSources))
	for _, source := range opts.CRLSources {
		crlReport, list, err := crlcheck.Check(ctx, crlcheck.Options{
			Source:       source,
			CABundle:     opts.CRLCABundle,
			WarnDays:     opts.CRLWarnDays,
			CriticalDays: opts.CRLCriticalDays,
			MaxAgeDays:   opts.CRLMaxAgeDays,
			Timeout:      opts.Timeout,
		})
		for _, finding := range crlReport.Findings {
			add(report, finding.Severity, "revocation", fmt.Sprintf("CRL %s: %s", source, finding.Message))
		}
		if err != nil {
			report.Revocation.Errors = append(report.Revocation.Errors, err.Error())
			continue
		}
		if list != nil {
			lists = append(lists, list)
		}
	}
	for _, cert := range certs {
		revoked, issuer := crlcheck.CertificateRevoked(cert, lists)
		if !revoked {
			continue
		}
		report.Revocation.Revoked = true
		add(report, "critical", "revocation", fmt.Sprintf("certificate serial %s is revoked by CRL issuer %s", cert.SerialNumber.String(), issuer))
	}
}

func loadCertPool(path string) (*x509.CertPool, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	pool := x509.NewCertPool()
	for {
		block, rest := pem.Decode(data)
		if block == nil {
			break
		}
		data = rest
		if block.Type != "CERTIFICATE" {
			continue
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, err
		}
		pool.AddCert(cert)
	}
	if len(pool.Subjects()) == 0 {
		return nil, fmt.Errorf("no certificates found in %s", path)
	}
	return pool, nil
}

func add(report *Report, severity, scope, message string) {
	report.Findings = append(report.Findings, Finding{
		Severity: severity,
		Scope:    scope,
		Message:  message,
	})
}

func aggregateStatus(findings []Finding) string {
	status := "ok"
	for _, finding := range findings {
		switch finding.Severity {
		case "critical":
			return "critical"
		case "warn":
			status = "warn"
		}
	}
	return status
}

func supports(versions []string, want string) bool {
	for _, version := range versions {
		if version == want {
			return true
		}
	}
	return false
}

func tlsVersionName(version uint16) string {
	switch version {
	case tls.VersionTLS10:
		return "TLS1.0"
	case tls.VersionTLS11:
		return "TLS1.1"
	case tls.VersionTLS12:
		return "TLS1.2"
	case tls.VersionTLS13:
		return "TLS1.3"
	default:
		return fmt.Sprintf("0x%x", version)
	}
}
