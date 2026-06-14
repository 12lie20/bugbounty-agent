package executor

import (
	"bytes"
	"context"
	"fmt"
	"os/exec"
	"strings"
	"sync"
	"time"

	"github.com/redteam/bugbounty-agent/internal/guardrails"
	"github.com/redteam/bugbounty-agent/internal/models"
)

// Executor runs validated CLI commands with timeouts and output limits.
type Executor struct {
	sanitizer *guardrails.Sanitizer
	timeout   time.Duration
	mu        sync.Mutex
}

// NewExecutor creates a new executor.
func NewExecutor(s *guardrails.Sanitizer, timeout time.Duration) *Executor {
	return &Executor{
		sanitizer: s,
		timeout:   timeout,
	}
}

// Run validates and executes a command, returning a structured result.
func (e *Executor) Run(command string) (*models.CommandResult, error) {
	cmd, parts, err := e.sanitizer.BuildSafeCommand(command)
	if err != nil {
		return nil, fmt.Errorf("guardrails rejected command: %w", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), e.timeout)
	defer cancel()

	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	result := &models.CommandResult{
		Command:   command,
		Args:      parts,
		StartedAt: time.Now().UTC(),
	}

	done := make(chan error, 1)
	go func() {
		done <- cmd.Run()
	}()

	select {
	case err := <-done:
		result.FinishedAt = time.Now().UTC()
		result.Duration = result.FinishedAt.Sub(result.StartedAt)
		result.Stdout = stdout.String()
		result.Stderr = stderr.String()
		if exitErr, ok := err.(*exec.ExitError); ok {
			result.ExitCode = exitErr.ExitCode()
		} else if err != nil {
			result.ExitCode = -1
			return result, err
		}
		return result, nil

	case <-ctx.Done():
		_ = cmd.Process.Kill()
		<-done
		result.FinishedAt = time.Now().UTC()
		result.Duration = result.FinishedAt.Sub(result.StartedAt)
		result.TimedOut = true
		result.ExitCode = -1
		result.Stdout = stdout.String()
		result.Stderr = stderr.String() + "\n[executor] command timed out after " + e.timeout.String()
		return result, fmt.Errorf("command timed out after %s", e.timeout)
	}
}

// IsToolInstalled checks if a required tool exists on the system.
func (e *Executor) IsToolInstalled(name string) bool {
	_, err := exec.LookPath(name)
	return err == nil
}

// IsBlockedError returns true if the error is from guardrails.
func (e *Executor) IsBlockedError(err error) bool {
	return err != nil && strings.Contains(err.Error(), "guardrails rejected command")
}

// IsTimeoutError returns true if the error is a timeout.
func (e *Executor) IsTimeoutError(err error) bool {
	return err != nil && strings.Contains(err.Error(), "timed out")
}

// KillTree is a placeholder for process tree cleanup; kept simple intentionally.
func (e *Executor) KillTree(cmd *exec.Cmd) error {
	if cmd != nil && cmd.Process != nil {
		return cmd.Process.Kill()
	}
	return nil
}
