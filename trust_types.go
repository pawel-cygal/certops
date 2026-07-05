package main

type trustReport struct {
	Action      string         `json:"action" yaml:"action"`
	Status      string         `json:"status" yaml:"status"`
	Source      string         `json:"source" yaml:"source"`
	OS          string         `json:"os" yaml:"os"`
	Name        string         `json:"name" yaml:"name"`
	Store       string         `json:"store" yaml:"store"`
	InstallPath string         `json:"install_path,omitempty" yaml:"install_path,omitempty"`
	Commands    []string       `json:"commands,omitempty" yaml:"commands,omitempty"`
	Certs       []trustCert    `json:"certs" yaml:"certs"`
	Findings    []trustFinding `json:"findings,omitempty" yaml:"findings,omitempty"`
}

type trustCert struct {
	Subject     string `json:"subject" yaml:"subject"`
	Issuer      string `json:"issuer" yaml:"issuer"`
	NotBefore   string `json:"not_before" yaml:"not_before"`
	NotAfter    string `json:"not_after" yaml:"not_after"`
	DaysLeft    int    `json:"days_left" yaml:"days_left"`
	IsCA        bool   `json:"is_ca" yaml:"is_ca"`
	SHA256      string `json:"sha256" yaml:"sha256"`
	Serial      string `json:"serial" yaml:"serial"`
	Installed   bool   `json:"installed" yaml:"installed"`
	InstallNote string `json:"install_note,omitempty" yaml:"install_note,omitempty"`
}

type trustFinding struct {
	Severity string `json:"severity" yaml:"severity"`
	Message  string `json:"message" yaml:"message"`
}

type trustSource struct {
	Label string
	PEM   []byte
}

type trustPlan struct {
	Name        string
	Store       string
	InstallPath string
	Commands    []string
	Install     func(bundle []byte) error
}
