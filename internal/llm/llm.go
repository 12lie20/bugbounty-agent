package llm

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/kaptinlin/jsonrepair"
	"github.com/redteam/bugbounty-agent/internal/models"
)

// Client talks to an OpenAI-compatible chat completions endpoint.
type Client struct {
	cfg    *models.Config
	client *http.Client
}

// NewClient creates a new LLM client.
func NewClient(cfg *models.Config) *Client {
	timeout := time.Duration(cfg.LLM.TimeoutSec) * time.Second
	if timeout <= 0 {
		timeout = 180 * time.Second
	}
	return &Client{
		cfg: cfg,
		client: &http.Client{
			Timeout: timeout,
		},
	}
}

// Chat sends messages and returns a strict AdvancedResponse.
func (c *Client) Chat(ctx context.Context, systemPrompt, userPrompt string) (*models.AdvancedResponse, error) {
	provider := strings.ToLower(c.cfg.LLM.Provider)
	if provider == "" {
		provider = "openai"
	}

	switch provider {
	case "anthropic":
		return c.chatAnthropic(ctx, systemPrompt, userPrompt)
	case "openai":
		return c.chatOpenAI(ctx, systemPrompt, userPrompt)
	default:
		return nil, fmt.Errorf("unsupported llm provider: %s", c.cfg.LLM.Provider)
	}
}

// chatOpenAI uses the OpenAI-compatible chat completions endpoint.
func (c *Client) chatOpenAI(ctx context.Context, systemPrompt, userPrompt string) (*models.AdvancedResponse, error) {
	reqBody := models.LLMRequest{
		Model:       c.cfg.LLM.Model,
		Temperature: c.cfg.LLM.Temperature,
		MaxTokens:   c.cfg.LLM.MaxTokens,
		Messages: []models.LLMMessage{
			{Role: "system", Content: systemPrompt},
			{Role: "user", Content: userPrompt},
		},
	}
	reqBody.ResponseFormat.Type = "json_object"

	payload, err := json.Marshal(reqBody)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal request: %w", err)
	}

	url := strings.TrimRight(c.cfg.LLM.BaseURL, "/") + "/chat/completions"
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(payload))
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+c.cfg.LLM.APIKey)

	resp, err := c.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("llm request failed: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response body: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("llm api returned status %d: %s", resp.StatusCode, string(body))
	}

	var llmResp models.LLMResponse
	if err := json.Unmarshal(body, &llmResp); err != nil {
		return nil, fmt.Errorf("failed to unmarshal llm response: %w", err)
	}

	if llmResp.Error != nil {
		return nil, fmt.Errorf("llm api error: %s", llmResp.Error.Message)
	}

	if len(llmResp.Choices) == 0 {
		return nil, fmt.Errorf("llm response contained no choices")
	}

	content := llmResp.Choices[0].Message.Content
	return c.extractAndValidate(content)
}

// chatAnthropic uses the Anthropic-compatible messages endpoint.
func (c *Client) chatAnthropic(ctx context.Context, systemPrompt, userPrompt string) (*models.AdvancedResponse, error) {
	reqBody := models.AnthropicRequest{
		Model:       c.cfg.LLM.Model,
		Temperature: c.cfg.LLM.Temperature,
		MaxTokens:   c.cfg.LLM.MaxTokens,
		System:      systemPrompt,
		Messages: []models.LLMMessage{
			{Role: "user", Content: userPrompt},
		},
	}

	payload, err := json.Marshal(reqBody)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal anthropic request: %w", err)
	}

	url := strings.TrimRight(c.cfg.LLM.BaseURL, "/") + "/messages"
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(payload))
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("x-api-key", c.cfg.LLM.APIKey)
	req.Header.Set("anthropic-version", "2023-06-01")

	resp, err := c.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("llm request failed: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response body: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("llm api returned status %d: %s", resp.StatusCode, string(body))
	}

	var anthResp models.AnthropicResponse
	if err := json.Unmarshal(body, &anthResp); err != nil {
		return nil, fmt.Errorf("failed to unmarshal anthropic response: %w", err)
	}

	if anthResp.Error != nil {
		return nil, fmt.Errorf("llm api error: %s", anthResp.Error.Message)
	}

	if len(anthResp.Content) == 0 {
		return nil, fmt.Errorf("anthropic response contained no content")
	}

	content := anthResp.Content[0].Text
	return c.extractAndValidate(content)
}

// extractAndValidate parses, repairs, and validates the AdvancedResponse.
func (c *Client) extractAndValidate(content string) (*models.AdvancedResponse, error) {
	content = cleanJSON(content)

	adv, err := c.parseAdvancedResponse(content)
	if err != nil {
		// Attempt automatic repair for common LLM JSON mistakes.
		repaired, repairErr := jsonrepair.Repair(content)
		if repairErr != nil {
			return nil, fmt.Errorf("failed to unmarshal advanced response and repair failed: %w (content: %s)", err, truncate(content, 200))
		}
		repaired = cleanJSON(repaired)
		adv, err = c.parseAdvancedResponse(repaired)
		if err != nil {
			return nil, fmt.Errorf("repaired JSON still invalid: %w (original: %s, repaired: %s)", err, truncate(content, 150), truncate(repaired, 150))
		}
	}

	if err := c.validate(adv); err != nil {
		return nil, err
	}

	return adv, nil
}

// parseAdvancedResponse extracts the first JSON object from text and unmarshals it.
func (c *Client) parseAdvancedResponse(content string) (*models.AdvancedResponse, error) {
	// If the model added chatter before JSON, find the first '{' and last '}'.
	start := strings.Index(content, "{")
	end := strings.LastIndex(content, "}")
	if start == -1 || end == -1 || end <= start {
		return nil, fmt.Errorf("no JSON object found")
	}
	jsonBlock := content[start : end+1]

	var adv models.AdvancedResponse
	if err := json.Unmarshal([]byte(jsonBlock), &adv); err != nil {
		return nil, err
	}
	return &adv, nil
}

// validate ensures the response conforms to allowed values.
func (c *Client) validate(resp *models.AdvancedResponse) error {
	resp.Strategy = strings.TrimSpace(resp.Strategy)
	resp.Reasoning = strings.TrimSpace(resp.Reasoning)
	resp.TargetTool = strings.TrimSpace(resp.TargetTool)
	resp.Command = strings.TrimSpace(resp.Command)
	resp.RiskLevel = models.RiskLevel(strings.TrimSpace(string(resp.RiskLevel)))
	resp.Status = models.Status(strings.TrimSpace(string(resp.Status)))

	if resp.Strategy == "" {
		return fmt.Errorf("missing strategy")
	}
	if resp.Reasoning == "" {
		return fmt.Errorf("missing reasoning")
	}
	if resp.Command == "" {
		return fmt.Errorf("missing command")
	}
	if resp.RiskLevel == "" {
		resp.RiskLevel = models.RiskMedium
	}
	if resp.Status == "" {
		resp.Status = models.StatusHunting
	}
	return nil
}

// cleanJSON removes markdown fences and stray characters before parsing.
func cleanJSON(input string) string {
	input = strings.TrimSpace(input)
	re := regexp.MustCompile("(?s)^```(?:json)?\\s*(.*?)\\s*```$")
	if m := re.FindStringSubmatch(input); len(m) > 1 {
		input = m[1]
	}
	input = strings.TrimSpace(input)
	return input
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}
