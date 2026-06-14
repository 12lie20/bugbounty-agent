package parser

import (
	"regexp"
	"strconv"
	"strings"

	"github.com/redteam/bugbounty-agent/internal/models"
)

// ExtractFindings parses tool output and returns structured findings.
func ExtractFindings(tool, output, command string) []models.Finding {
	switch strings.ToLower(tool) {
	case "nmap":
		return parseNmap(output)
	case "ffuf":
		return parseFFUF(output, command)
	case "httpx":
		return parseHttpx(output)
	case "nikto":
		return parseNikto(output)
	default:
		return nil
	}
}

// parseNmap extracts open port lines.
func parseNmap(output string) []models.Finding {
	re := regexp.MustCompile(`(?i)^([0-9]+)/(tcp|udp)\s+open\s+(\S+)\s*(.*)$`)
	var findings []models.Finding
	for _, line := range strings.Split(output, "\n") {
		line = strings.TrimSpace(line)
		m := re.FindStringSubmatch(line)
		if len(m) < 4 {
			continue
		}
		port, _ := strconv.Atoi(m[1])
		findings = append(findings, models.Finding{
			Title:    "Open Port",
			Severity: "Info",
			Host:     "",
			Tool:     "nmap",
			Evidence: line,
			Phase:    models.PhaseScanning,
			Confirmed: true,
		})
		_ = port
	}
	return findings
}

// parseFFUF extracts successful fuzz hits.
func parseFFUF(output, command string) []models.Finding {
	// Typical ffuf output: [Status: 200, Size: 1234, Words: 56, Lines: 7]
	re := regexp.MustCompile(`(?i)(\S+)\s+\[Status:\s*(\d+),\s*Size:\s*(\d+)`)
	var findings []models.Finding
	for _, line := range strings.Split(output, "\n") {
		m := re.FindStringSubmatch(line)
		if len(m) < 3 {
			continue
		}
		status, _ := strconv.Atoi(m[2])
		if status >= 200 && status < 300 {
			findings = append(findings, models.Finding{
				Title:     "Discovered Endpoint",
				Severity:  "Info",
				Host:      extractHostFromCommand(command),
				Tool:      "ffuf",
				Evidence:  line,
				Phase:     models.PhaseExploitation,
				Confirmed: true,
			})
		}
	}
	return findings
}

// parseHttpx extracts live hosts and technologies.
func parseHttpx(output string) []models.Finding {
	var findings []models.Finding
	for _, line := range strings.Split(output, "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "http") {
			findings = append(findings, models.Finding{
				Title:     "Live Host",
				Severity:  "Info",
				Host:      line,
				Tool:      "httpx",
				Evidence:  line,
				Phase:     models.PhaseScanning,
				Confirmed: true,
			})
		}
	}
	return findings
}

// parseNikto extracts vulnerability lines.
func parseNikto(output string) []models.Finding {
	re := regexp.MustCompile(`(?i)\+\s*(/.*):\s*(.*)$`)
	var findings []models.Finding
	for _, line := range strings.Split(output, "\n") {
		m := re.FindStringSubmatch(line)
		if len(m) < 3 {
			continue
		}
		findings = append(findings, models.Finding{
			Title:     "Nikto Finding",
			Severity:  "Medium",
			Host:      "",
			Tool:      "nikto",
			Evidence:  line,
			Phase:     models.PhaseExploitation,
			Confirmed: false,
		})
	}
	return findings
}

func extractHostFromCommand(command string) string {
	parts := strings.Fields(command)
	for i, p := range parts {
		if strings.EqualFold(p, "-u") && i+1 < len(parts) {
			return parts[i+1]
		}
	}
	return ""
}
