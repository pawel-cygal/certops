package main

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"path/filepath"
	"strings"
	"time"
	"unicode"
)

func parseTrustCerts(data []byte) ([]trustCert, [][]byte, error) {
	var certs []trustCert
	var rawCerts [][]byte
	rest := data
	for {
		block, next := pem.Decode(rest)
		if block == nil {
			break
		}
		rest = next
		if block.Type != "CERTIFICATE" {
			continue
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, nil, err
		}
		sum := sha256.Sum256(block.Bytes)
		certs = append(certs, trustCert{
			Subject:   cert.Subject.String(),
			Issuer:    cert.Issuer.String(),
			NotBefore: cert.NotBefore.UTC().Format(time.RFC3339),
			NotAfter:  cert.NotAfter.UTC().Format(time.RFC3339),
			DaysLeft:  int(time.Until(cert.NotAfter).Hours() / 24),
			IsCA:      cert.IsCA,
			SHA256:    formatFingerprint(sum[:]),
			Serial:    cert.SerialNumber.String(),
		})
		rawCerts = append(rawCerts, block.Bytes)
	}
	if len(certs) == 0 {
		return nil, nil, fmt.Errorf("no PEM certificates found")
	}
	return certs, rawCerts, nil
}

func fingerprintMatches(rawCerts [][]byte, want string) bool {
	want = normalizeFingerprint(want)
	for _, raw := range rawCerts {
		if normalizeFingerprint(formatRawFingerprint(raw)) == want {
			return true
		}
	}
	return false
}

func formatRawFingerprint(raw []byte) string {
	sum := sha256.Sum256(raw)
	return formatFingerprint(sum[:])
}

func formatFingerprint(sum []byte) string {
	encoded := strings.ToUpper(hex.EncodeToString(sum))
	parts := make([]string, 0, len(encoded)/2)
	for i := 0; i < len(encoded); i += 2 {
		parts = append(parts, encoded[i:i+2])
	}
	return "SHA256:" + strings.Join(parts, ":")
}

func normalizeFingerprint(value string) string {
	value = strings.ToUpper(strings.TrimSpace(value))
	value = strings.TrimPrefix(value, "SHA256:")
	value = strings.ReplaceAll(value, ":", "")
	value = strings.ReplaceAll(value, " ", "")
	return value
}

func defaultTrustName(source string, certs []trustCert) string {
	if len(certs) > 0 {
		if cn := firstSubjectCN(certs[0].Subject); cn != "" {
			return cn
		}
	}
	base := filepath.Base(source)
	if base == "." || base == "/" || base == "" {
		return "certops-ca"
	}
	return strings.TrimSuffix(base, filepath.Ext(base))
}

func firstSubjectCN(subject string) string {
	for _, part := range strings.Split(subject, ",") {
		part = strings.TrimSpace(part)
		if strings.HasPrefix(part, "CN=") {
			return strings.TrimPrefix(part, "CN=")
		}
	}
	return ""
}

func sanitizeTrustName(value string) string {
	value = strings.ToLower(strings.TrimSpace(value))
	var b strings.Builder
	for _, r := range value {
		switch {
		case unicode.IsLetter(r), unicode.IsDigit(r):
			b.WriteRune(r)
		case r == '-', r == '_', r == '.':
			b.WriteRune(r)
		case unicode.IsSpace(r):
			b.WriteRune('-')
		}
	}
	out := strings.Trim(b.String(), "-_.")
	if out == "" {
		return "certops-ca"
	}
	return out
}
