package parser

import (
	"testing"
)

func TestParseNmap(t *testing.T) {
	output := `
Starting Nmap...
22/tcp  open  ssh     OpenSSH 8.2
80/tcp  open  http    Apache httpd 2.4
443/tcp closed https
`
	findings := parseNmap(output)
	if len(findings) != 2 {
		t.Fatalf("expected 2 open port findings, got %d", len(findings))
	}
	if findings[0].Tool != "nmap" {
		t.Errorf("expected tool nmap, got %q", findings[0].Tool)
	}
}

func TestParseFFUF(t *testing.T) {
	output := `
admin                   [Status: 200, Size: 1234, Words: 56, Lines: 7]
login                   [Status: 301, Size: 0, Words: 1, Lines: 1]
config                  [Status: 403, Size: 9, Words: 2, Lines: 2]
`
	findings := parseFFUF(output, "ffuf -u https://example.com/FUZZ -w words.txt")
	if len(findings) != 1 {
		t.Fatalf("expected 1 200-status finding, got %d", len(findings))
	}
	if findings[0].Host != "https://example.com/FUZZ" {
		t.Errorf("expected host https://example.com/FUZZ, got %q", findings[0].Host)
	}
}

func TestParseHttpx(t *testing.T) {
	output := `
https://example.com [200]
https://admin.example.com [403]
`
	findings := parseHttpx(output)
	if len(findings) != 2 {
		t.Fatalf("expected 2 live hosts, got %d", len(findings))
	}
}
