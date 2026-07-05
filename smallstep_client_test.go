package main

import (
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"
)

func TestRunSmallstepInfo(t *testing.T) {
	caPEM, err := os.ReadFile("/etc/ssl/certs/Actalis_Authentication_Root_CA.pem")
	if err != nil {
		t.Skip("system CA fixture not available")
	}
	certs, rawCerts, err := parseTrustCerts(caPEM)
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/health":
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"status":"ok"}`))
		case "/roots.pem":
			w.Header().Set("Content-Type", "application/x-pem-file")
			_, _ = w.Write(caPEM)
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	report, rootsPEM, err := runSmallstep("info", server.URL, certs[0].SHA256, time.Second, false)
	if err != nil {
		t.Fatal(err)
	}
	if report.Status != "ok" {
		t.Fatalf("status = %q, want ok", report.Status)
	}
	if !report.Health.Healthy {
		t.Fatal("health should be ok")
	}
	if report.Roots.Count != 1 {
		t.Fatalf("roots count = %d, want 1", report.Roots.Count)
	}
	if len(rootsPEM) == 0 || formatRawFingerprint(rawCerts[0]) != report.Roots.Certs[0].SHA256 {
		t.Fatal("root PEM or fingerprint mismatch")
	}
}

func TestRunSmallstepFingerprintMismatch(t *testing.T) {
	caPEM, err := os.ReadFile("/etc/ssl/certs/Actalis_Authentication_Root_CA.pem")
	if err != nil {
		t.Skip("system CA fixture not available")
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/roots.pem" {
			_, _ = w.Write(caPEM)
			return
		}
		http.NotFound(w, r)
	}))
	defer server.Close()

	report, _, err := runSmallstep("roots", server.URL, "SHA256:00", time.Second, false)
	if err != nil {
		t.Fatal(err)
	}
	if report.Status != "critical" {
		t.Fatalf("status = %q, want critical", report.Status)
	}
}
