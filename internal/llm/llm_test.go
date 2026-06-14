package llm

import (
	"testing"

	"github.com/kaptinlin/jsonrepair"
	"github.com/redteam/bugbounty-agent/internal/models"
)

func TestParseAdvancedResponse_ExtractsJSONFromChatter(t *testing.T) {
	c := &Client{cfg: &models.Config{}}
	input := `Sure, here is the JSON:
{
  "strategy": "scan ports",
  "reasoning": "we need to know open ports",
  "target_tool": "nmap",
  "command": "nmap -sV example.com",
  "risk_level": "Medium",
  "status": "hunting"
}
Hope that helps!`

	resp, err := c.parseAdvancedResponse(input)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp.Strategy != "scan ports" {
		t.Errorf("expected strategy 'scan ports', got %q", resp.Strategy)
	}
	if resp.Command != "nmap -sV example.com" {
		t.Errorf("expected command 'nmap -sV example.com', got %q", resp.Command)
	}
}

func TestParseAdvancedResponse_RepairsBrokenJSON(t *testing.T) {
	// Missing closing brace and trailing comma.
	input := `{
  "strategy": "scan ports",
  "reasoning": "we need to know open ports",
  "target_tool": "nmap",
  "command": "nmap -sV example.com",
  "risk_level": "Medium",
  "status": "hunting",
`

	c := &Client{cfg: &models.Config{}}
	if _, err := c.parseAdvancedResponse(input); err == nil {
		t.Fatal("expected initial parse to fail on broken JSON")
	}

	repaired, err := jsonrepair.Repair(input)
	if err != nil {
		t.Fatalf("jsonrepair failed: %v", err)
	}

	resp, err := c.parseAdvancedResponse(repaired)
	if err != nil {
		t.Fatalf("repaired JSON invalid: %v", err)
	}
	if resp.Status != "hunting" {
		t.Errorf("expected status 'hunting', got %q", resp.Status)
	}
}
