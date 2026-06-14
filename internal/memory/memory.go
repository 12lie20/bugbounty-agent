package memory

import (
	"bufio"
	"fmt"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/redteam/bugbounty-agent/internal/models"
)

// Manager keeps the evolving target map and iteration history.
type Manager struct {
	mu      sync.RWMutex
	state   models.ReActState
	cfg     *models.Config
}

// NewManager initializes a memory manager.
func NewManager(cfg *models.Config) *Manager {
	return &Manager{
		state: models.ReActState{
			CurrentPhase:  models.PhaseRecon,
			Iteration:     0,
			MaxIterations: cfg.Agent.MaxIterations,
			History:       []models.IterationRecord{},
			TargetMap: models.TargetMap{
				RootDomain:     cfg.Target.RootDomain,
				InScopeDomains: cfg.Target.InScopeDomains,
				OutOfScope:     cfg.Target.OutOfScope,
				OpenPorts:      []models.PortFinding{},
				Subdomains:     []string{},
				Technologies:   []string{},
				Findings:       []models.Finding{},
				Metadata:       map[string]string{},
			},
		},
		cfg: cfg,
	}
}

// State returns a deep-ish copy of the current state.
func (m *Manager) State() models.ReActState {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.state
}

// Restore replaces the current state with a saved one.
func (m *Manager) Restore(state models.ReActState) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.state = state
}

// AdvancePhase transitions to the next strategic phase.
func (m *Manager) AdvancePhase() {
	m.mu.Lock()
	defer m.mu.Unlock()
	switch m.state.CurrentPhase {
	case models.PhaseRecon:
		m.state.CurrentPhase = models.PhaseScanning
	case models.PhaseScanning:
		m.state.CurrentPhase = models.PhaseAnalysis
	case models.PhaseAnalysis:
		m.state.CurrentPhase = models.PhaseExploitation
	case models.PhaseExploitation:
		m.state.CurrentPhase = models.PhaseReporting
	case models.PhaseReporting:
		m.state.CurrentPhase = models.PhaseFinished
	}
}

// SetPhase forces a phase (used for adaptation).
func (m *Manager) SetPhase(p models.Phase) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.state.CurrentPhase = p
}

// RecordIteration appends an iteration to history.
func (m *Manager) RecordIteration(rec models.IterationRecord) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.state.Iteration++
	rec.Iteration = m.state.Iteration
	rec.Timestamp = time.Now().UTC()
	m.state.History = append(m.state.History, rec)
}

// AddFinding adds a finding to the target map.
func (m *Manager) AddFinding(f models.Finding) {
	m.mu.Lock()
	defer m.mu.Unlock()
	f.ID = fmt.Sprintf("FND-%d", len(m.state.TargetMap.Findings)+1)
	f.Timestamp = time.Now().UTC()
	m.state.TargetMap.Findings = append(m.state.TargetMap.Findings, f)
}

// AddSubdomain appends a unique subdomain.
func (m *Manager) AddSubdomain(sd string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, existing := range m.state.TargetMap.Subdomains {
		if existing == sd {
			return
		}
	}
	m.state.TargetMap.Subdomains = append(m.state.TargetMap.Subdomains, sd)
}

// AddOpenPort appends a unique open port finding.
func (m *Manager) AddOpenPort(p models.PortFinding) {
	m.mu.Lock()
	defer m.mu.Unlock()
	key := fmt.Sprintf("%s:%d/%s", p.Host, p.Port, p.Protocol)
	for _, existing := range m.state.TargetMap.OpenPorts {
		ek := fmt.Sprintf("%s:%d/%s", existing.Host, existing.Port, existing.Protocol)
		if ek == key {
			return
		}
	}
	m.state.TargetMap.OpenPorts = append(m.state.TargetMap.OpenPorts, p)
}

// ContextPrompt builds a compact prompt representing the current state.
func (m *Manager) ContextPrompt() string {
	m.mu.RLock()
	defer m.mu.RUnlock()

	var b strings.Builder
	b.WriteString(fmt.Sprintf("Current Phase: %s\n", m.state.CurrentPhase))
	b.WriteString(fmt.Sprintf("Iteration: %d / %d\n", m.state.Iteration, m.state.MaxIterations))
	b.WriteString(fmt.Sprintf("Root Domain: %s\n", m.state.TargetMap.RootDomain))
	b.WriteString(fmt.Sprintf("In Scope: %v\n", m.state.TargetMap.InScopeDomains))
	b.WriteString(fmt.Sprintf("Out of Scope: %v\n", m.state.TargetMap.OutOfScope))
	b.WriteString(fmt.Sprintf("Known Subdomains (%d): %v\n", len(m.state.TargetMap.Subdomains), truncateSlice(m.state.TargetMap.Subdomains, 20)))
	b.WriteString(fmt.Sprintf("Known Open Ports (%d): %v\n", len(m.state.TargetMap.OpenPorts), summarizePorts(m.state.TargetMap.OpenPorts)))
	b.WriteString(fmt.Sprintf("Technologies: %v\n", m.state.TargetMap.Technologies))
	b.WriteString(fmt.Sprintf("Confirmed Findings (%d): %v\n", len(m.state.TargetMap.Findings), summarizeFindings(m.state.TargetMap.Findings)))
	b.WriteString("Recent History (last 3 commands):\n")
	start := len(m.state.History) - 3
	if start < 0 {
		start = 0
	}
	for _, rec := range m.state.History[start:] {
		status := "OK"
		if !rec.Allowed {
			status = "BLOCKED"
		} else if rec.Error != "" {
			status = "ERROR"
		}
		b.WriteString(fmt.Sprintf("  [%s] %s (%s): %s -> %s\n", rec.Phase, rec.Tool, status, rec.Command, truncate(rec.Output, 80)))
	}
	return b.String()
}

// CompactUpdatePrompt returns only the latest changes to avoid context ballooning.
func (m *Manager) CompactUpdatePrompt() string {
	m.mu.RLock()
	defer m.mu.RUnlock()

	var b strings.Builder
	b.WriteString(fmt.Sprintf("Current Phase: %s | Iteration: %d/%d\n", m.state.CurrentPhase, m.state.Iteration, m.state.MaxIterations))

	if len(m.state.TargetMap.Subdomains) > 0 {
		b.WriteString(fmt.Sprintf("Subdomains (%d): %v\n", len(m.state.TargetMap.Subdomains), truncateSlice(m.state.TargetMap.Subdomains, 15)))
	}
	if len(m.state.TargetMap.OpenPorts) > 0 {
		b.WriteString(fmt.Sprintf("Open Ports (%d): %v\n", len(m.state.TargetMap.OpenPorts), summarizePorts(m.state.TargetMap.OpenPorts)))
	}
	if len(m.state.TargetMap.Findings) > 0 {
		b.WriteString(fmt.Sprintf("Confirmed Findings (%d): %v\n", len(m.state.TargetMap.Findings), summarizeFindings(m.state.TargetMap.Findings)))
	}

	b.WriteString("Last 2 commands (with outcomes):\n")
	start := len(m.state.History) - 2
	if start < 0 {
		start = 0
	}
	for _, rec := range m.state.History[start:] {
		status := "OK"
		if !rec.Allowed {
			status = "BLOCKED"
		} else if rec.Error != "" {
			status = "ERROR"
		}
		out := truncate(rec.Output, 60)
		if rec.Adaptation != nil {
			out += fmt.Sprintf(" [adapt: %s]", rec.Adaptation.Trigger)
		}
		b.WriteString(fmt.Sprintf("  [%s] %s (%s): %s -> %s\n", rec.Phase, rec.Tool, status, rec.Command, out))
	}
	return b.String()
}

// FilterOutput minimizes terminal output for the LLM context.
func (m *Manager) FilterOutput(output string, command string) string {
	if len(output) == 0 {
		return ""
	}

	lines := strings.Split(output, "\n")
	interesting := extractInterestingLines(lines)

	maxLines := m.cfg.Agent.ContextMaxLines
	if len(interesting) > maxLines {
		interesting = interesting[:maxLines]
	}

	filtered := strings.Join(interesting, "\n")
	if len(filtered) > m.cfg.Agent.MaxOutputChars {
		filtered = filtered[:m.cfg.Agent.MaxOutputChars]
		filtered = filtered[:strings.LastIndex(filtered, "\n")]
		filtered += "\n... [truncated]"
	}

	if filtered == "" {
		filtered = summarizeToolOutput(output, maxLines)
	}

	return filtered
}

// securityKeywords are high-signal tokens we never want to drop.
var securityKeywords = []string{
	"open", "filtered", "vulnerable", "vulnerability", "exploit", "cve-",
	"unauthenticated", "authenticated", "allowed", "forbidden", "blocked",
	"bypass", "injection", "sqli", "xss", "ssrf", "lfi", "rfi", "rce",
	"redirect", "admin", "login", "api", "internal", "staging", "dev",
	"200 ok", "201 created", "204 no content", "301 moved", "302 found",
	"401 unauthorized", "403 forbidden", "404 not found", "500 internal",
	"subdomain", "found:", "discovered", "dns", "status", "error", "timeout",
	"waf", "rate limit", "too many requests", "cloudflare", "akamai",
}

var interestingPatterns = []*regexp.Regexp{
	regexp.MustCompile(`(?i)\d+/(tcp|udp)\s+(open|filtered|closed)`),
	regexp.MustCompile(`(?i)\bstatus\s*[:=]?\s*\d{3}\b`),
	regexp.MustCompile(`(?i)https?://\S+`),
	regexp.MustCompile(`(?i)\bCVE-\d{4}-\d+\b`),
	regexp.MustCompile(`(?i)\[[0-9]+[KMG]?\]`), // ffuf size marker
	regexp.MustCompile(`(?i)\bFUZZ\b`),
}

func extractInterestingLines(lines []string) []string {
	var out []string
	seen := make(map[string]bool)

	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		// Drop noisy repeated 403 lines unless they are the first few.
		if strings.Contains(strings.ToLower(line), "403") {
			if seen["403-bucket"] {
				continue
			}
			seen["403-bucket"] = true
		}

		if isInterestingLine(line) {
			hash := simpleHash(line)
			if !seen[hash] {
				seen[hash] = true
				out = append(out, line)
			}
		}
	}
	return out
}

func isInterestingLine(line string) bool {
	lower := strings.ToLower(line)
	for _, kw := range securityKeywords {
		if strings.Contains(lower, kw) {
			return true
		}
	}
	for _, re := range interestingPatterns {
		if re.MatchString(line) {
			return true
		}
	}
	return false
}

func simpleHash(s string) string {
	// Lightweight dedup key; normalized to ignore spacing/case.
	return strings.ToLower(strings.Join(strings.Fields(s), " "))
}

func summarizeToolOutput(output string, maxLines int) string {
	scanner := bufio.NewScanner(strings.NewReader(output))
	var lines []string
	for scanner.Scan() {
		lines = append(lines, scanner.Text())
	}

	if len(lines) <= maxLines {
		return strings.Join(lines, "\n")
	}

	headCount := maxLines / 2
	tailCount := maxLines - headCount
	selected := append(lines[:headCount], "\n... [output truncated, showing head and tail] ...\n")
	selected = append(selected, lines[len(lines)-tailCount:]...)
	return strings.Join(selected, "\n")
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}

func truncateSlice(s []string, n int) []string {
	if len(s) <= n {
		return s
	}
	return append(s[:n], "...")
}

func summarizePorts(ports []models.PortFinding) []string {
	var out []string
	for _, p := range ports {
		out = append(out, fmt.Sprintf("%s:%d/%s (%s)", p.Host, p.Port, p.Protocol, p.Service))
	}
	return out
}

func summarizeFindings(findings []models.Finding) []string {
	var out []string
	for _, f := range findings {
		out = append(out, fmt.Sprintf("[%s] %s on %s", f.Severity, f.Title, f.Host))
	}
	return out
}
