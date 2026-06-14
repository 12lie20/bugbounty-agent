package persistence

import (
	"os"
	"testing"

	"github.com/redteam/bugbounty-agent/internal/models"
)

func TestStoreSaveAndLoad(t *testing.T) {
	path := "test_state.jsonl"
	defer os.Remove(path)

	store := NewStore(path)
	state := models.ReActState{
		CurrentPhase:  models.PhaseScanning,
		Iteration:     5,
		MaxIterations: 50,
		History: []models.IterationRecord{
			{Iteration: 1, Command: "nmap -sV example.com"},
			{Iteration: 2, Command: "ffuf -u example.com/FUZZ -w words.txt"},
		},
		TargetMap: models.TargetMap{
			RootDomain: "example.com",
			Subdomains: []string{"www.example.com", "admin.example.com"},
		},
	}

	if err := store.Save(state); err != nil {
		t.Fatalf("save failed: %v", err)
	}

	loaded, err := store.Load()
	if err != nil {
		t.Fatalf("load failed: %v", err)
	}
	if loaded == nil {
		t.Fatal("loaded state is nil")
	}
	if loaded.CurrentPhase != models.PhaseScanning {
		t.Errorf("expected phase scanning, got %s", loaded.CurrentPhase)
	}
	if loaded.Iteration != 5 {
		t.Errorf("expected iteration 5, got %d", loaded.Iteration)
	}
	if len(loaded.History) != 2 {
		t.Errorf("expected 2 history records, got %d", len(loaded.History))
	}
	if len(loaded.TargetMap.Subdomains) != 2 {
		t.Errorf("expected 2 subdomains, got %d", len(loaded.TargetMap.Subdomains))
	}
}
