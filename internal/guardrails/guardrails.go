package guardrails

import (
	"fmt"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/google/shlex"
	"github.com/redteam/bugbounty-agent/internal/models"
)

// Sanitizer validates and sanitizes commands before execution.
type Sanitizer struct {
	cfg            *models.Config
	blockedWords   []string
	allowedTools   map[string]bool
	blockedPattern *regexp.Regexp
}

// NewSanitizer creates a new sanitizer from configuration.
func NewSanitizer(cfg *models.Config) *Sanitizer {
	allowed := make(map[string]bool, len(cfg.Guardrails.AllowedTools))
	for _, t := range cfg.Guardrails.AllowedTools {
		allowed[strings.ToLower(strings.TrimSpace(t))] = true
	}

	escaped := make([]string, 0, len(cfg.Guardrails.BlockedWords))
	for _, w := range cfg.Guardrails.BlockedWords {
		escaped = append(escaped, regexp.QuoteMeta(strings.ToLower(w)))
	}

	pattern := regexp.MustCompile(`(?i)(` + strings.Join(escaped, "|") + `)`)

	return &Sanitizer{
		cfg:            cfg,
		blockedWords:   cfg.Guardrails.BlockedWords,
		allowedTools:   allowed,
		blockedPattern: pattern,
	}
}

// ValidateCommand checks if a command is allowed to run.
func (s *Sanitizer) ValidateCommand(command string) error {
	command = strings.TrimSpace(command)
	if command == "" {
		return fmt.Errorf("empty command")
	}

	parts, err := shlex.Split(command)
	if err != nil {
		return fmt.Errorf("failed to parse command with shlex: %w", err)
	}
	if len(parts) == 0 {
		return fmt.Errorf("empty command")
	}

	tool := filepath.Base(parts[0])
	if !s.allowedTools[strings.ToLower(tool)] {
		return fmt.Errorf("tool %q is not in the allowlist", tool)
	}

	lower := strings.ToLower(command)
	if matches := s.blockedPattern.FindStringSubmatch(lower); len(matches) > 0 {
		return fmt.Errorf("command contains blocked pattern %q", matches[0])
	}

	if err := s.validateScope(parts); err != nil {
		return err
	}

	if err := s.validateShellMetacharacters(command); err != nil {
		return err
	}

	return nil
}

// BuildSafeCommand returns an os/exec.Command after validation.
func (s *Sanitizer) BuildSafeCommand(command string) (*exec.Cmd, []string, error) {
	if err := s.ValidateCommand(command); err != nil {
		return nil, nil, err
	}

	parts, err := shlex.Split(command)
	if err != nil {
		return nil, nil, err
	}

	cmd := exec.Command(parts[0], parts[1:]...)
	return cmd, parts, nil
}

// IsToolAllowed checks if a tool name is in the allowlist.
func (s *Sanitizer) IsToolAllowed(tool string) bool {
	return s.allowedTools[strings.ToLower(tool)]
}

// validateScope ensures the command does not target out-of-scope hosts.
func (s *Sanitizer) validateScope(parts []string) error {
	for _, arg := range parts[1:] {
		arg = strings.ToLower(arg)
		for _, oos := range s.cfg.Target.OutOfScope {
			oos = strings.ToLower(oos)
			if strings.Contains(arg, oos) || matchWildcard(arg, oos) {
				return fmt.Errorf("target %q is out of scope", arg)
			}
		}
	}
	return nil
}

// validateShellMetacharacters blocks dangerous shell operators and command chaining.
func (s *Sanitizer) validateShellMetacharacters(command string) error {
	// These operators are never allowed because they imply shell execution or chaining.
	dangerous := []string{
		";", "&&", "||", "|", "`", "$()", "$(", ">>", "<(", ">(", "&\n", "\n",
		"bash -i", "sh -i", "bash -c", "sh -c", "exec ", "eval ",
	}
	lower := strings.ToLower(command)
	for _, op := range dangerous {
		if strings.Contains(lower, op) {
			return fmt.Errorf("command contains disallowed shell operator %q; only single-tool commands are permitted", op)
		}
	}

	// Also reject any argument that looks like command substitution after shlex.
	parts, err := shlex.Split(command)
	if err != nil {
		return fmt.Errorf("failed to parse command: %w", err)
	}
	for _, p := range parts {
		if strings.Contains(p, "$(") || strings.Contains(p, "`") {
			return fmt.Errorf("argument %q contains command substitution", p)
		}
	}
	return nil
}

// matchWildcard matches a host against a wildcard pattern like *.example.com.
func matchWildcard(host, pattern string) bool {
	if !strings.HasPrefix(pattern, "*.") {
		return host == pattern
	}
	suffix := pattern[1:] // .example.com
	return strings.HasSuffix(host, suffix)
}
