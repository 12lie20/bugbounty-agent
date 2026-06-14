package executor

import (
	"context"
	"sync"

	"github.com/redteam/bugbounty-agent/internal/models"
)

// ParallelResult holds the outcome of one parallel command.
type ParallelResult struct {
	Command string
	Result  *models.CommandResult
	Error   error
}

// RunParallel executes multiple validated commands concurrently with a shared timeout.
func (e *Executor) RunParallel(ctx context.Context, commands []string) []ParallelResult {
	var wg sync.WaitGroup
	results := make([]ParallelResult, len(commands))
	sem := make(chan struct{}, 4) // max 4 concurrent commands

	for i, cmd := range commands {
		wg.Add(1)
		go func(idx int, command string) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()

			res, err := e.Run(command)
			results[idx] = ParallelResult{
				Command: command,
				Result:  res,
				Error:   err,
			}
		}(i, cmd)
	}

	wg.Wait()
	return results
}
