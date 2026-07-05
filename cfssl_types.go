package main

import "time"

type cfsslOptions struct {
	BaseURL     string
	Label       string
	Profile     string
	Fingerprint string
	Timeout     time.Duration
}

type cfsslReport struct {
	Provider string         `json:"provider" yaml:"provider"`
	Action   string         `json:"action" yaml:"action"`
	BaseURL  string         `json:"base_url" yaml:"base_url"`
	Label    string         `json:"label,omitempty" yaml:"label,omitempty"`
	Profile  string         `json:"profile,omitempty" yaml:"profile,omitempty"`
	Status   string         `json:"status" yaml:"status"`
	Health   cfsslHealth    `json:"health,omitempty" yaml:"health,omitempty"`
	CA       cfsslCA        `json:"ca,omitempty" yaml:"ca,omitempty"`
	Findings []cfsslFinding `json:"findings,omitempty" yaml:"findings,omitempty"`
	Messages []cfsslMessage `json:"messages,omitempty" yaml:"messages,omitempty"`
	Errors   []cfsslMessage `json:"errors,omitempty" yaml:"errors,omitempty"`
}

type cfsslHealth struct {
	Endpoint   string `json:"endpoint" yaml:"endpoint"`
	HTTPStatus int    `json:"http_status" yaml:"http_status"`
	Healthy    bool   `json:"healthy" yaml:"healthy"`
	Message    string `json:"message,omitempty" yaml:"message,omitempty"`
}

type cfsslCA struct {
	Endpoint    string      `json:"endpoint" yaml:"endpoint"`
	HTTPStatus  int         `json:"http_status" yaml:"http_status"`
	Count       int         `json:"count" yaml:"count"`
	OutputPath  string      `json:"output_path,omitempty" yaml:"output_path,omitempty"`
	Fingerprint string      `json:"expected_fingerprint,omitempty" yaml:"expected_fingerprint,omitempty"`
	Certs       []cfsslCert `json:"certs,omitempty" yaml:"certs,omitempty"`
}

type cfsslCert struct {
	Subject  string `json:"subject" yaml:"subject"`
	Issuer   string `json:"issuer" yaml:"issuer"`
	NotAfter string `json:"not_after" yaml:"not_after"`
	DaysLeft int    `json:"days_left" yaml:"days_left"`
	IsCA     bool   `json:"is_ca" yaml:"is_ca"`
	SHA256   string `json:"sha256" yaml:"sha256"`
}

type cfsslFinding struct {
	Severity string `json:"severity" yaml:"severity"`
	Message  string `json:"message" yaml:"message"`
}

type cfsslMessage struct {
	Code    int    `json:"code,omitempty" yaml:"code,omitempty"`
	Message string `json:"message" yaml:"message"`
}
