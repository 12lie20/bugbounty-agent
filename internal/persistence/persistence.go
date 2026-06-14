package persistence

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"sync"

	"github.com/redteam/bugbounty-agent/internal/models"
)

// Store persists agent state to a JSONL file.
type Store struct {
	path string
	mu   sync.Mutex
}

// NewStore creates a new state store.
func NewStore(path string) *Store {
	return &Store{path: path}
}

// Save writes the current ReAct state as JSONL (one record per iteration).
func (s *Store) Save(state models.ReActState) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	f, err := os.OpenFile(s.path, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0644)
	if err != nil {
		return fmt.Errorf("failed to open state file: %w", err)
	}
	defer f.Close()

	enc := json.NewEncoder(f)
	// Write a header with the current state snapshot.
	header := map[string]interface{}{
		"type":       "snapshot",
		"phase":      state.CurrentPhase,
		"iteration":  state.Iteration,
		"target_map": state.TargetMap,
	}
	if err := enc.Encode(header); err != nil {
		return fmt.Errorf("failed to encode snapshot: %w", err)
	}

	// Write each iteration record.
	for _, rec := range state.History {
		record := map[string]interface{}{
			"type":       "iteration",
			"data":       rec,
		}
		if err := enc.Encode(record); err != nil {
			return fmt.Errorf("failed to encode iteration: %w", err)
		}
	}
	return nil
}

// Load restores the latest snapshot and iteration history.
func (s *Store) Load() (*models.ReActState, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	f, err := os.Open(s.path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("failed to open state file: %w", err)
	}
	defer f.Close()

	var state models.ReActState
	var history []models.IterationRecord

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := scanner.Bytes()
		var wrapper struct {
			Type string          `json:"type"`
			Data json.RawMessage `json:"data,omitempty"`
		}
		if err := json.Unmarshal(line, &wrapper); err != nil {
			continue
		}

		switch wrapper.Type {
		case "snapshot":
			var snap struct {
				Phase      models.Phase    `json:"phase"`
				Iteration  int             `json:"iteration"`
				TargetMap  models.TargetMap `json:"target_map"`
			}
			if err := json.Unmarshal(line, &snap); err != nil {
				continue
			}
			state.CurrentPhase = snap.Phase
			state.Iteration = snap.Iteration
			state.TargetMap = snap.TargetMap
		case "iteration":
			var rec models.IterationRecord
			if err := json.Unmarshal(wrapper.Data, &rec); err != nil {
				continue
			}
			history = append(history, rec)
		}
	}

	state.History = history
	return &state, nil
}

// Exists returns true if a state file exists.
func (s *Store) Exists() bool {
	_, err := os.Stat(s.path)
	return err == nil
}
