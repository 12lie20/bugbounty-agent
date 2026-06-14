package guardrails

import (
	"testing"

	"github.com/redteam/bugbounty-agent/internal/models"
)

func TestValidateCommand_ShlexQuotedArguments(t *testing.T) {
	cfg := &models.Config{}
	cfg.Guardrails.AllowedTools = []string{"ffuf", "curl", "nmap"}
	cfg.Guardrails.BlockedWords = []string{"rm -rf"}
	cfg.Target.OutOfScope = []string{}

	s := NewSanitizer(cfg)
	cases := []struct {
		cmd string
		ok  bool
	}{
		{`ffuf -u "https://example.com/FUZZ" -w /usr/share/wordlists/dirb/common.txt`, true},
		{`curl -H "User-Agent: Mozilla" https://example.com`, true},
		{`nmap -sV -p 80,443 'example.com'`, true},
		{`ffuf -u "http://example.com; cat /etc/passwd"`, false}, // shell operator inside string still rejected
	}

	for _, c := range cases {
		err := s.ValidateCommand(c.cmd)
		if c.ok && err != nil {
			t.Errorf("expected %q to be allowed, got error: %v", c.cmd, err)
		}
		if !c.ok && err == nil {
			t.Errorf("expected %q to be blocked, but it was allowed", c.cmd)
		}
	}
}

func TestValidateCommand_Allowed(t *testing.T) {
	cfg := &models.Config{}
	cfg.Guardrails.AllowedTools = []string{"nmap", "curl", "ffuf"}
	cfg.Guardrails.BlockedWords = []string{"rm -rf", "mkfs"}
	cfg.Target.OutOfScope = []string{"*.prod.example.com", "prod.example.com"}

	s := NewSanitizer(cfg)

	cases := []struct {
		cmd string
		ok  bool
	}{
		{"nmap -sV example.com", true},
		{"curl https://example.com", true},
		{"ffuf -u https://example.com/FUZZ -w words.txt", true},
		{"rm -rf /", false},
		{"nmap -sV prod.example.com", false},
		{"bash -i", false},
		{"nmap -sV example.com; cat /etc/passwd", false},
		{"unknown-tool example.com", false},
	}

	for _, c := range cases {
		err := s.ValidateCommand(c.cmd)
		if c.ok && err != nil {
			t.Errorf("expected %q to be allowed, got error: %v", c.cmd, err)
		}
		if !c.ok && err == nil {
			t.Errorf("expected %q to be blocked, but it was allowed", c.cmd)
		}
	}
}
