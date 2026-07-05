package main

type smallstepReport struct {
	Provider string                 `json:"provider" yaml:"provider"`
	Action   string                 `json:"action" yaml:"action"`
	BaseURL  string                 `json:"base_url" yaml:"base_url"`
	Insecure bool                   `json:"insecure,omitempty" yaml:"insecure,omitempty"`
	Status   string                 `json:"status" yaml:"status"`
	Health   smallstepHealth        `json:"health,omitempty" yaml:"health,omitempty"`
	Roots    smallstepRoots         `json:"roots,omitempty" yaml:"roots,omitempty"`
	Findings []smallstepFinding     `json:"findings,omitempty" yaml:"findings,omitempty"`
	Raw      map[string]interface{} `json:"raw,omitempty" yaml:"raw,omitempty"`
}

type smallstepHealth struct {
	Endpoint   string `json:"endpoint" yaml:"endpoint"`
	HTTPStatus int    `json:"http_status" yaml:"http_status"`
	Healthy    bool   `json:"healthy" yaml:"healthy"`
	Message    string `json:"message,omitempty" yaml:"message,omitempty"`
}

type smallstepRoots struct {
	Endpoint    string          `json:"endpoint" yaml:"endpoint"`
	HTTPStatus  int             `json:"http_status" yaml:"http_status"`
	Count       int             `json:"count" yaml:"count"`
	OutputPath  string          `json:"output_path,omitempty" yaml:"output_path,omitempty"`
	Fingerprint string          `json:"expected_fingerprint,omitempty" yaml:"expected_fingerprint,omitempty"`
	Certs       []smallstepCert `json:"certs,omitempty" yaml:"certs,omitempty"`
}

type smallstepCert struct {
	Subject  string `json:"subject" yaml:"subject"`
	Issuer   string `json:"issuer" yaml:"issuer"`
	NotAfter string `json:"not_after" yaml:"not_after"`
	DaysLeft int    `json:"days_left" yaml:"days_left"`
	IsCA     bool   `json:"is_ca" yaml:"is_ca"`
	SHA256   string `json:"sha256" yaml:"sha256"`
}

type smallstepFinding struct {
	Severity string `json:"severity" yaml:"severity"`
	Message  string `json:"message" yaml:"message"`
}
