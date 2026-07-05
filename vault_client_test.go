package main

import (
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"
)

func TestRunVaultInfo(t *testing.T) {
	caPEM, err := os.ReadFile("/etc/ssl/certs/Actalis_Authentication_Root_CA.pem")
	if err != nil {
		t.Skip("system CA fixture not available")
	}
	certs, _, err := parseTrustCerts(caPEM)
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/sys/health":
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"initialized":true,"sealed":false,"standby":false,"version":"1.20.0"}`))
		case "/v1/pki/ca/pem":
			w.Header().Set("Content-Type", "application/x-pem-file")
			_, _ = w.Write(caPEM)
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	report, body, err := runVault("info", vaultOptions{
		BaseURL:     server.URL,
		Mount:       "pki",
		Fingerprint: certs[0].SHA256,
		Timeout:     time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}
	if report.Status != "ok" {
		t.Fatalf("status = %q, want ok", report.Status)
	}
	if !report.Health.Healthy || report.Health.Version != "1.20.0" {
		t.Fatalf("unexpected health: %+v", report.Health)
	}
	if report.CA.Count != 1 || len(body) == 0 {
		t.Fatalf("unexpected CA: %+v", report.CA)
	}
}

func TestRunVaultStandbyOK(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v1/sys/health" {
			w.WriteHeader(http.StatusTooManyRequests)
			_, _ = w.Write([]byte(`{"initialized":true,"sealed":false,"standby":true}`))
			return
		}
		http.NotFound(w, r)
	}))
	defer server.Close()

	report, _, err := runVault("health", vaultOptions{BaseURL: server.URL, Timeout: time.Second, StandbyOK: true})
	if err != nil {
		t.Fatal(err)
	}
	if report.Status != "ok" {
		t.Fatalf("status = %q, want ok", report.Status)
	}
}

func TestRunVaultFingerprintMismatch(t *testing.T) {
	caPEM, err := os.ReadFile("/etc/ssl/certs/Actalis_Authentication_Root_CA.pem")
	if err != nil {
		t.Skip("system CA fixture not available")
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v1/pki/ca/pem" {
			_, _ = w.Write(caPEM)
			return
		}
		http.NotFound(w, r)
	}))
	defer server.Close()

	report, _, err := runVault("ca", vaultOptions{BaseURL: server.URL, Mount: "pki", Fingerprint: "SHA256:00", Timeout: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	if report.Status != "critical" {
		t.Fatalf("status = %q, want critical", report.Status)
	}
}
