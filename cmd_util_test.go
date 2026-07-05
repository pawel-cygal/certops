package main

import "testing"

func TestNormalizeTarget(t *testing.T) {
	tests := []struct {
		name        string
		in          string
		wantHost    string
		wantAddress string
	}{
		{name: "bare host", in: "example.com", wantHost: "example.com", wantAddress: "example.com:443"},
		{name: "host port", in: "example.com:8443", wantHost: "example.com", wantAddress: "example.com:8443"},
		{name: "https url", in: "https://api.example.com/path", wantHost: "api.example.com", wantAddress: "api.example.com:443"},
		{name: "https url custom port", in: "https://api.example.com:9443/path", wantHost: "api.example.com", wantAddress: "api.example.com:9443"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			host, address, err := normalizeTarget(tt.in)
			if err != nil {
				t.Fatalf("normalizeTarget returned error: %v", err)
			}
			if host != tt.wantHost {
				t.Fatalf("host = %q, want %q", host, tt.wantHost)
			}
			if address != tt.wantAddress {
				t.Fatalf("address = %q, want %q", address, tt.wantAddress)
			}
		})
	}
}
