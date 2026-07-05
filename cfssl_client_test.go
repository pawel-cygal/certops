package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"
)

func TestRunCFSSLInfo(t *testing.T) {
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
		case "/api/v1/cfssl/health":
			_ = json.NewEncoder(w).Encode(map[string]any{"success": true, "result": map[string]any{"healthy": true}})
		case "/api/v1/cfssl/info":
			if r.Method != http.MethodPost {
				t.Fatalf("method = %s, want POST", r.Method)
			}
			_ = json.NewEncoder(w).Encode(map[string]any{
				"success": true,
				"result":  map[string]any{"certificate": string(caPEM)},
			})
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	report, body, err := runCFSSL("info", cfsslOptions{
		BaseURL:     server.URL,
		Fingerprint: certs[0].SHA256,
		Timeout:     time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}
	if report.Status != "ok" {
		t.Fatalf("status = %q, want ok", report.Status)
	}
	if !report.Health.Healthy {
		t.Fatal("health should be ok")
	}
	if report.CA.Count != 1 || len(body) == 0 {
		t.Fatalf("unexpected CA: %+v", report.CA)
	}
}

func TestRunCFSSLFingerprintMismatch(t *testing.T) {
	caPEM, err := os.ReadFile("/etc/ssl/certs/Actalis_Authentication_Root_CA.pem")
	if err != nil {
		t.Skip("system CA fixture not available")
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/v1/cfssl/info" {
			_ = json.NewEncoder(w).Encode(map[string]any{
				"success": true,
				"result":  map[string]any{"certificate": string(caPEM)},
			})
			return
		}
		http.NotFound(w, r)
	}))
	defer server.Close()

	report, _, err := runCFSSL("info", cfsslOptions{BaseURL: server.URL, Fingerprint: "SHA256:00", Timeout: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	if report.Status != "critical" {
		t.Fatalf("status = %q, want critical", report.Status)
	}
}
