package memory

import (
	"strings"
	"testing"

	"github.com/redteam/bugbounty-agent/internal/models"
)

func TestFilterOutput_InterestingLines(t *testing.T) {
	cfg := &models.Config{}
	cfg.Agent.ContextMaxLines = 10
	cfg.Agent.MaxOutputChars = 1000

	m := NewManager(cfg)
	output := strings.Join([]string{
		"some noise line",
		"80/tcp open http",
		"443/tcp open https",
		"another noise",
		"Discovered subdomain: admin.example.com",
	}, "\n")

	filtered := m.FilterOutput(output, "nmap example.com")
	if !strings.Contains(filtered, "80/tcp open") {
		t.Errorf("expected open port line to be preserved")
	}
	if strings.Contains(filtered, "some noise line") {
		t.Errorf("expected noise to be filtered out")
	}
}

func TestAddSubdomain_Deduplicates(t *testing.T) {
	cfg := &models.Config{}
	m := NewManager(cfg)
	m.AddSubdomain("a.example.com")
	m.AddSubdomain("a.example.com")
	m.AddSubdomain("b.example.com")
	if len(m.State().TargetMap.Subdomains) != 2 {
		t.Fatalf("expected 2 unique subdomains, got %d", len(m.State().TargetMap.Subdomains))
	}
}
