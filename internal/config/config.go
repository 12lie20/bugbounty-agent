package config

import (
	"fmt"
	"os"
	"strings"

	"github.com/joho/godotenv"
	"github.com/redteam/bugbounty-agent/internal/models"
	"github.com/spf13/viper"
)

// Load reads configuration from config.yaml, .env file, and environment variables.
func Load(path string) (*models.Config, error) {
	// Load .env if present; ignore errors if the file does not exist.
	_ = godotenv.Load(".env")

	v := viper.New()
	v.SetConfigFile(path)
	v.SetEnvPrefix("BB_AGENT")
	v.SetEnvKeyReplacer(strings.NewReplacer(".", "_"))
	v.AutomaticEnv()

	if err := v.ReadInConfig(); err != nil {
		return nil, fmt.Errorf("failed to read config: %w", err)
	}

	var cfg models.Config
	if err := v.Unmarshal(&cfg); err != nil {
		return nil, fmt.Errorf("failed to unmarshal config: %w", err)
	}

	if err := applyEnvOverrides(&cfg); err != nil {
		return nil, err
	}

	if err := validate(&cfg); err != nil {
		return nil, err
	}

	return &cfg, nil
}

func applyEnvOverrides(cfg *models.Config) error {
	if key := os.Getenv("BB_AGENT_LLM_API_KEY"); key != "" {
		cfg.LLM.APIKey = key
	}
	if apiType := os.Getenv("BB_AGENT_LLM_API_TYPE"); apiType != "" {
		cfg.LLM.APIType = apiType
	}
	if url := os.Getenv("BB_AGENT_LLM_BASE_URL"); url != "" {
		cfg.LLM.BaseURL = url
	}
	if model := os.Getenv("BB_AGENT_LLM_MODEL"); model != "" {
		cfg.LLM.Model = model
	}
	return nil
}

func validate(cfg *models.Config) error {
	if cfg.LLM.APIKey == "" {
		return fmt.Errorf("llm.api_key is required (set BB_AGENT_LLM_API_KEY)")
	}
	if cfg.LLM.BaseURL == "" {
		return fmt.Errorf("llm.base_url is required")
	}
	if cfg.LLM.Model == "" {
		return fmt.Errorf("llm.model is required")
	}
	if cfg.Target.RootDomain == "" {
		return fmt.Errorf("target.root_domain is required")
	}
	if cfg.Agent.CommandTimeoutMin <= 0 {
		cfg.Agent.CommandTimeoutMin = 10
	}
	if cfg.Agent.MaxIterations <= 0 {
		cfg.Agent.MaxIterations = 50
	}
	if cfg.Agent.ContextMaxLines <= 0 {
		cfg.Agent.ContextMaxLines = 100
	}
	if cfg.Agent.MaxOutputChars <= 0 {
		cfg.Agent.MaxOutputChars = 16000
	}
	if cfg.Target.RateLimitRPS <= 0 {
		cfg.Target.RateLimitRPS = 1
	}
	return nil
}
