package check

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestCheckRevocationMarksRevokedCertificateCritical(t *testing.T) {
	ca, key, caPEM := testCheckCA(t)
	leaf := &x509.Certificate{
		SerialNumber: big.NewInt(42),
		Issuer:       ca.Subject,
	}
	crlDER := testCheckCRL(t, ca, key, []*big.Int{leaf.SerialNumber})
	dir := t.TempDir()
	crlPath := filepath.Join(dir, "ca.crl")
	caPath := filepath.Join(dir, "ca.pem")
	if err := os.WriteFile(crlPath, pem.EncodeToMemory(&pem.Block{Type: "X509 CRL", Bytes: crlDER}), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(caPath, caPEM, 0644); err != nil {
		t.Fatal(err)
	}

	report := Report{Status: "ok"}
	checkRevocation(context.Background(), &report, []*x509.Certificate{leaf}, Options{
		CRLSources:  []string{crlPath},
		CRLCABundle: caPath,
	})

	if !report.Revocation.Checked || !report.Revocation.Revoked {
		t.Fatalf("revocation checked/revoked = %t/%t", report.Revocation.Checked, report.Revocation.Revoked)
	}
	if aggregateStatus(report.Findings) != "critical" {
		t.Fatalf("findings did not aggregate critical: %+v", report.Findings)
	}
}

func testCheckCA(t *testing.T) (*x509.Certificate, *rsa.PrivateKey, []byte) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Check Test CA"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		SubjectKeyId:          []byte{5, 6, 7, 8},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return cert, key, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}

func testCheckCRL(t *testing.T, ca *x509.Certificate, key *rsa.PrivateKey, serials []*big.Int) []byte {
	t.Helper()
	entries := make([]x509.RevocationListEntry, 0, len(serials))
	for _, serial := range serials {
		entries = append(entries, x509.RevocationListEntry{
			SerialNumber:   serial,
			RevocationTime: time.Now().Add(-time.Minute),
		})
	}
	der, err := x509.CreateRevocationList(rand.Reader, &x509.RevocationList{
		Number:                    big.NewInt(9),
		ThisUpdate:                time.Now().Add(-time.Hour),
		NextUpdate:                time.Now().Add(24 * time.Hour),
		RevokedCertificateEntries: entries,
		SignatureAlgorithm:        x509.SHA256WithRSA,
	}, ca, key)
	if err != nil {
		t.Fatal(err)
	}
	return der
}
