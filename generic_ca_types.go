package main

type genericCAReport struct {
	Provider string             `json:"provider" yaml:"provider"`
	Action   string             `json:"action" yaml:"action"`
	Source   string             `json:"source" yaml:"source"`
	Status   string             `json:"status" yaml:"status"`
	CA       genericCA          `json:"ca" yaml:"ca"`
	Findings []genericCAFinding `json:"findings,omitempty" yaml:"findings,omitempty"`
}

type genericCA struct {
	Count       int             `json:"count" yaml:"count"`
	OutputPath  string          `json:"output_path,omitempty" yaml:"output_path,omitempty"`
	Fingerprint string          `json:"expected_fingerprint,omitempty" yaml:"expected_fingerprint,omitempty"`
	Certs       []genericCACert `json:"certs,omitempty" yaml:"certs,omitempty"`
}

type genericCACert struct {
	Subject  string `json:"subject" yaml:"subject"`
	Issuer   string `json:"issuer" yaml:"issuer"`
	NotAfter string `json:"not_after" yaml:"not_after"`
	DaysLeft int    `json:"days_left" yaml:"days_left"`
	IsCA     bool   `json:"is_ca" yaml:"is_ca"`
	SHA256   string `json:"sha256" yaml:"sha256"`
}

type genericCAFinding struct {
	Severity string `json:"severity" yaml:"severity"`
	Message  string `json:"message" yaml:"message"`
}
