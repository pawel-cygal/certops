package main

import "time"

type vaultOptions struct {
	BaseURL     string
	Mount       string
	Issuer      string
	Fingerprint string
	Token       string
	Namespace   string
	Timeout     time.Duration
	StandbyOK   bool
}

type vaultReport struct {
	Provider string         `json:"provider" yaml:"provider"`
	Action   string         `json:"action" yaml:"action"`
	BaseURL  string         `json:"base_url" yaml:"base_url"`
	Mount    string         `json:"mount" yaml:"mount"`
	Issuer   string         `json:"issuer,omitempty" yaml:"issuer,omitempty"`
	Status   string         `json:"status" yaml:"status"`
	Health   vaultHealth    `json:"health,omitempty" yaml:"health,omitempty"`
	CA       vaultCA        `json:"ca,omitempty" yaml:"ca,omitempty"`
	Findings []vaultFinding `json:"findings,omitempty" yaml:"findings,omitempty"`
}

type vaultHealth struct {
	Endpoint    string `json:"endpoint" yaml:"endpoint"`
	HTTPStatus  int    `json:"http_status" yaml:"http_status"`
	Initialized bool   `json:"initialized" yaml:"initialized"`
	Sealed      bool   `json:"sealed" yaml:"sealed"`
	Standby     bool   `json:"standby" yaml:"standby"`
	Version     string `json:"version,omitempty" yaml:"version,omitempty"`
	Healthy     bool   `json:"healthy" yaml:"healthy"`
	Message     string `json:"message,omitempty" yaml:"message,omitempty"`
}

type vaultCA struct {
	Endpoint    string      `json:"endpoint" yaml:"endpoint"`
	HTTPStatus  int         `json:"http_status" yaml:"http_status"`
	Count       int         `json:"count" yaml:"count"`
	OutputPath  string      `json:"output_path,omitempty" yaml:"output_path,omitempty"`
	Fingerprint string      `json:"expected_fingerprint,omitempty" yaml:"expected_fingerprint,omitempty"`
	Certs       []vaultCert `json:"certs,omitempty" yaml:"certs,omitempty"`
}

type vaultCert struct {
	Subject  string `json:"subject" yaml:"subject"`
	Issuer   string `json:"issuer" yaml:"issuer"`
	NotAfter string `json:"not_after" yaml:"not_after"`
	DaysLeft int    `json:"days_left" yaml:"days_left"`
	IsCA     bool   `json:"is_ca" yaml:"is_ca"`
	SHA256   string `json:"sha256" yaml:"sha256"`
}

type vaultFinding struct {
	Severity string `json:"severity" yaml:"severity"`
	Message  string `json:"message" yaml:"message"`
}
