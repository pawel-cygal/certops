package crl

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

func TestRunValidatesFreshSignedCRL(t *testing.T) {
	ca, key, caPEM := testCA(t)
	crlDER := testCRL(t, ca, key, time.Now().Add(-time.Hour), time.Now().Add(96*time.Hour), []*big.Int{big.NewInt(42)})
	dir := t.TempDir()
	crlPath := filepath.Join(dir, "ca.crl")
	caPath := filepath.Join(dir, "ca.pem")
	if err := os.WriteFile(crlPath, pem.EncodeToMemory(&pem.Block{Type: "X509 CRL", Bytes: crlDER}), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(caPath, caPEM, 0644); err != nil {
		t.Fatal(err)
	}

	report := Run(context.Background(), Options{Source: crlPath, CABundle: caPath, WarnDays: 2, CriticalDays: 1})
	if report.Status != "ok" {
		t.Fatalf("status = %q, findings = %+v", report.Status, report.Findings)
	}
	if !report.SignatureChecked || !report.SignatureValid {
		t.Fatalf("signature checked/valid = %t/%t", report.SignatureChecked, report.SignatureValid)
	}
	if report.RevokedCertificates != 1 {
		t.Fatalf("revoked certs = %d, want 1", report.RevokedCertificates)
	}
}

func TestRunMarksExpiredCRLCritical(t *testing.T) {
	ca, key, caPEM := testCA(t)
	crlDER := testCRL(t, ca, key, time.Now().Add(-48*time.Hour), time.Now().Add(-time.Hour), nil)
	dir := t.TempDir()
	crlPath := filepath.Join(dir, "ca.crl")
	caPath := filepath.Join(dir, "ca.pem")
	if err := os.WriteFile(crlPath, crlDER, 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(caPath, caPEM, 0644); err != nil {
		t.Fatal(err)
	}

	report := Run(context.Background(), Options{Source: crlPath, CABundle: caPath})
	if report.Status != "critical" {
		t.Fatalf("status = %q, want critical", report.Status)
	}
}

func TestCertificateRevokedMatchesIssuerAndSerial(t *testing.T) {
	ca, key, _ := testCA(t)
	leaf := &x509.Certificate{
		SerialNumber: big.NewInt(7),
		Issuer:       ca.Subject,
	}
	crlDER := testCRL(t, ca, key, time.Now().Add(-time.Hour), time.Now().Add(24*time.Hour), []*big.Int{big.NewInt(7)})
	list, _, err := Parse(crlDER)
	if err != nil {
		t.Fatal(err)
	}

	revoked, issuer := CertificateRevoked(leaf, []*x509.RevocationList{list})
	if !revoked {
		t.Fatalf("revoked = false, issuer = %q", issuer)
	}
}

func testCA(t *testing.T) (*x509.Certificate, *rsa.PrivateKey, []byte) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Test CA"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		SubjectKeyId:          []byte{1, 2, 3, 4},
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

func testCRL(t *testing.T, ca *x509.Certificate, key *rsa.PrivateKey, thisUpdate, nextUpdate time.Time, serials []*big.Int) []byte {
	t.Helper()
	entries := make([]x509.RevocationListEntry, 0, len(serials))
	for _, serial := range serials {
		entries = append(entries, x509.RevocationListEntry{
			SerialNumber:   serial,
			RevocationTime: time.Now().Add(-time.Minute),
		})
	}
	der, err := x509.CreateRevocationList(rand.Reader, &x509.RevocationList{
		Number:                    big.NewInt(3),
		ThisUpdate:                thisUpdate,
		NextUpdate:                nextUpdate,
		RevokedCertificateEntries: entries,
		SignatureAlgorithm:        x509.SHA256WithRSA,
	}, ca, key)
	if err != nil {
		t.Fatal(err)
	}
	return der
}
