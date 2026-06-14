package selfheal

import (
	"regexp"
	"strings"

	"github.com/redteam/bugbounty-agent/internal/models"
)

// Adapter analyzes failures and proposes safe adaptations.
type Adapter struct {
	cfg *models.Config
}

// NewAdapter creates a new self-healing adapter.
func NewAdapter(cfg *models.Config) *Adapter {
	return &Adapter{cfg: cfg}
}

// Analyze inspects output and error text to detect blockers.
func (a *Adapter) Analyze(output, stderr string, exitCode int, tool string) *models.AdaptationPlan {
	combined := strings.ToLower(output + "\n" + stderr)

	// Rate limit / WAF block detection
	if matchesAny(combined, []string{
		"rate limit", "too many requests", "429", "403", "forbidden",
		"blocked", "waf", "cloudflare", "akamai", "incapsula", "sucuri",
		"unauthorized", "access denied",
	}) {
		return &models.AdaptationPlan{
			Trigger:          "rate_limit_or_waf_block",
			SuggestedAction:  "reduce request rate and rotate user-agent / proxy",
			AlternateTool:    a.slowerTool(tool),
			AlternatePayload: "-rate 1 -timeout 10",
			DelaySeconds:     a.cfg.Agent.AdaptationDelaySec,
		}
	}

	// Timeout detection
	if exitCode != 0 && (strings.Contains(combined, "timeout") || strings.Contains(combined, "deadline exceeded")) {
		return &models.AdaptationPlan{
			Trigger:          "tool_timeout",
			SuggestedAction:  "reduce target scope or increase per-command timeout",
			AlternateTool:    tool,
			AlternatePayload: "-timeout 30s -retries 2",
			DelaySeconds:     5,
		}
	}

	// Tool not installed
	if strings.Contains(combined, "not found") || strings.Contains(combined, "not recognized") {
		return &models.AdaptationPlan{
			Trigger:          "tool_missing",
			SuggestedAction:  "use an installed alternative tool",
			AlternateTool:    a.fallbackTool(tool),
			AlternatePayload: "",
			DelaySeconds:     0,
		}
	}

	return nil
}

// slowerTool suggests a lower-rate alternative.
func (a *Adapter) slowerTool(tool string) string {
	switch strings.ToLower(tool) {
	case "ffuf":
		return "ffuf"
	case "gobuster":
		return "gobuster"
	case "httpx":
		return "curl"
	default:
		return tool
	}
}

// fallbackTool suggests an alternative when a tool is missing.
func (a *Adapter) fallbackTool(tool string) string {
	switch strings.ToLower(tool) {
	case "amass":
		return "subfinder"
	case "subfinder":
		return "dig"
	case "dalfox":
		return "curl"
	case "katana":
		return "gau"
	default:
		return "curl"
	}
}

func matchesAny(text string, patterns []string) bool {
	for _, p := range patterns {
		re := regexp.MustCompile(`(?i)` + regexp.QuoteMeta(p))
		if re.MatchString(text) {
			return true
		}
	}
	return false
}
