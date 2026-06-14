package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"

	"github.com/redteam/bugbounty-agent/internal/config"
	"github.com/redteam/bugbounty-agent/internal/interactive"
	"github.com/redteam/bugbounty-agent/internal/planner"
)

func main() {
	var configPath string
	flag.StringVar(&configPath, "config", "config.yaml", "path to configuration file")
	flag.Parse()

	if !filepath.IsAbs(configPath) {
		wd, err := os.Getwd()
		if err != nil {
			fmt.Fprintf(os.Stderr, "failed to get working directory: %v\n", err)
			os.Exit(1)
		}
		configPath = filepath.Join(wd, configPath)
	}

	// Ensure the API key is available (ask once and persist to .env).
	if os.Getenv("BB_AGENT_LLM_API_KEY") == "" {
		key, err := interactive.PromptForAPIKey()
		if err != nil {
			fmt.Fprintf(os.Stderr, "api key error: %v\n", err)
			os.Exit(1)
		}
		os.Setenv("BB_AGENT_LLM_API_KEY", key)
	}

	// Interactive model picker runs on every startup.
	selected := interactive.PickModel()
	os.Setenv("BB_AGENT_LLM_API_TYPE", selected.APIType)
	os.Setenv("BB_AGENT_LLM_BASE_URL", selected.BaseURL)
	os.Setenv("BB_AGENT_LLM_MODEL", selected.Model)

	cfg, err := config.Load(configPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "configuration error: %v\n", err)
		os.Exit(1)
	}

	fmt.Println("Configuration loaded successfully.")
	fmt.Printf("Model: %s (%s)\n", cfg.LLM.Model, cfg.LLM.APIType)
	fmt.Printf("Target: %s\n", cfg.Target.RootDomain)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-sigCh
		fmt.Println("\nReceived interrupt signal. Shutting down gracefully...")
		cancel()
	}()

	engine, err := planner.NewEngine(cfg)
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to create engine: %v\n", err)
		os.Exit(1)
	}
	if err := engine.Run(ctx); err != nil {
		fmt.Fprintf(os.Stderr, "agent error: %v\n", err)
		os.Exit(1)
	}

	fmt.Println("Agent finished.")
}
