package models

import "time"

// OpencodeModel describes a selectable model on opencode.ai Go.
type OpencodeModel struct {
	DisplayName string
	APIType     string
	Model       string
	BaseURL     string
}

// OpencodeModels is the curated list shown in the interactive picker.
var OpencodeModels = []OpencodeModel{
	// /v1/messages models
	{DisplayName: "Qwen3.7 Max", APIType: "opencode-messages", Model: "qwen3.7-max", BaseURL: "https://opencode.ai/zen/go/v1"},
	{DisplayName: "Qwen3.7 Plus", APIType: "opencode-messages", Model: "qwen3.7-plus", BaseURL: "https://opencode.ai/zen/go/v1"},
	{DisplayName: "Qwen3.6 Plus", APIType: "opencode-messages", Model: "qwen3.6-plus", BaseURL: "https://opencode.ai/zen/go/v1"},
	{DisplayName: "MiniMax M3", APIType: "opencode-messages", Model: "minimax-m3", BaseURL: "https://opencode.ai/zen/go/v1"},
	{DisplayName: "MiniMax M2.7", APIType: "opencode-messages", Model: "minimax-m2.7", BaseURL: "https://opencode.ai/zen/go/v1"},
	{DisplayName: "MiniMax M2.5", APIType: "opencode-messages", Model: "minimax-m2.5", BaseURL: "https://opencode.ai/zen/go/v1"},
	// /v1/chat/completions models
	{DisplayName: "GLM-5.1", APIType: "opencode-chat", Model: "glm-5.1", BaseURL: "https://opencode.ai/zen/go/v1"},
	{DisplayName: "GLM-5", APIType: "opencode-chat", Model: "glm-5", BaseURL: "https://opencode.ai/zen/go/v1"},
	{DisplayName: "Kimi K2.7", APIType: "opencode-chat", Model: "kimi-k2.7", BaseURL: "https://opencode.ai/zen/go/v1"},
	{DisplayName: "Kimi K2.6", APIType: "opencode-chat", Model: "kimi-k2.6", BaseURL: "https://opencode.ai/zen/go/v1"},
	{DisplayName: "DeepSeek V4 Pro", APIType: "opencode-chat", Model: "deepseek-v4-pro", BaseURL: "https://opencode.ai/zen/go/v1"},
	{DisplayName: "DeepSeek V4 Flash", APIType: "opencode-chat", Model: "deepseek-v4-flash", BaseURL: "https://opencode.ai/zen/go/v1"},
	{DisplayName: "MiMo-V2.5", APIType: "opencode-chat", Model: "mimo-v2.5", BaseURL: "https://opencode.ai/zen/go/v1"},
	{DisplayName: "MiMo-V2.5-Pro", APIType: "opencode-chat", Model: "mimo-v2.5-pro", BaseURL: "https://opencode.ai/zen/go/v1"},
}

// Phase represents the strategic phase of the bug bounty workflow.
type Phase string

const (
	PhaseRecon        Phase = "recon"
	PhaseScanning     Phase = "scanning"
	PhaseAnalysis     Phase = "analysis"
	PhaseExploitation Phase = "exploitation"
	PhaseReporting    Phase = "reporting"
	PhaseFinished     Phase = "finished"
)

// RiskLevel represents the risk level of a command.
type RiskLevel string

const (
	RiskLow    RiskLevel = "Low"
	RiskMedium RiskLevel = "Medium"
	RiskHigh   RiskLevel = "High"
)

// Status represents the agent status.
type Status string

const (
	StatusHunting    Status = "hunting"
	StatusExploiting Status = "exploiting"
	StatusBlocked    Status = "blocked"
	StatusFinished   Status = "finished"
)

// AdvancedResponse is the strict JSON schema the LLM must return.
type AdvancedResponse struct {
	Strategy   string    `json:"strategy"`
	Reasoning  string    `json:"reasoning"`
	TargetTool string    `json:"target_tool"`
	Command    string    `json:"command"`
	RiskLevel  RiskLevel `json:"risk_level"`
	Status     Status    `json:"status"`
}

// TargetMap holds the evolving understanding of the target.
type TargetMap struct {
	RootDomain     string            `json:"root_domain"`
	InScopeDomains []string          `json:"in_scope_domains"`
	OutOfScope     []string          `json:"out_of_scope"`
	OpenPorts      []PortFinding     `json:"open_ports"`
	Subdomains     []string          `json:"subdomains"`
	Technologies   []string          `json:"technologies"`
	Findings       []Finding         `json:"findings"`
	Metadata       map[string]string `json:"metadata"`
}

// PortFinding represents an open port discovery.
type PortFinding struct {
	Host     string `json:"host"`
	Port     int    `json:"port"`
	Protocol string `json:"protocol"`
	Service  string `json:"service"`
	Version  string `json:"version"`
}

// Finding represents a security finding or vulnerability candidate.
type Finding struct {
	ID          string    `json:"id"`
	Title       string    `json:"title"`
	Severity    string    `json:"severity"`
	Host        string    `json:"host"`
	Tool        string    `json:"tool"`
	Evidence    string    `json:"evidence"`
	Phase       Phase     `json:"phase"`
	Confirmed   bool      `json:"confirmed"`
	Timestamp   time.Time `json:"timestamp"`
}

// IterationRecord records a single agent loop iteration.
type IterationRecord struct {
	Iteration  int             `json:"iteration"`
	Phase      Phase           `json:"phase"`
	Strategy   string          `json:"strategy"`
	Reasoning  string          `json:"reasoning"`
	Command    string          `json:"command"`
	Tool       string          `json:"tool"`
	RiskLevel  RiskLevel       `json:"risk_level"`
	Status     Status          `json:"status"`
	Output     string          `json:"output"`
	Filtered   bool            `json:"filtered"`
	Allowed    bool            `json:"allowed"`
	Error      string          `json:"error,omitempty"`
	Timestamp  time.Time       `json:"timestamp"`
	Adaptation *AdaptationPlan `json:"adaptation,omitempty"`
}

// AdaptationPlan is produced when the agent hits a blocker.
type AdaptationPlan struct {
	Trigger          string   `json:"trigger"`
	SuggestedAction  string   `json:"suggested_action"`
	AlternateTool    string   `json:"alternate_tool"`
	AlternatePayload string   `json:"alternate_payload,omitempty"`
	DelaySeconds     int      `json:"delay_seconds"`
}

// ReActState tracks the ReAct loop state.
type ReActState struct {
	CurrentPhase  Phase             `json:"current_phase"`
	Iteration     int               `json:"iteration"`
	MaxIterations int               `json:"max_iterations"`
	History       []IterationRecord `json:"history"`
	TargetMap     TargetMap         `json:"target_map"`
}

// CommandResult holds the result of executing a CLI command.
type CommandResult struct {
	Command    string        `json:"command"`
	Args       []string      `json:"args"`
	Stdout     string        `json:"stdout"`
	Stderr     string        `json:"stderr"`
	ExitCode   int           `json:"exit_code"`
	Duration   time.Duration `json:"duration"`
	TimedOut   bool          `json:"timed_out"`
	StartedAt  time.Time     `json:"started_at"`
	FinishedAt time.Time     `json:"finished_at"`
}

// LLMMessage represents a chat message for the LLM API.
type LLMMessage struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

// LLMRequest is the request body for OpenAI-compatible APIs.
type LLMRequest struct {
	Model          string       `json:"model"`
	Messages       []LLMMessage `json:"messages"`
	Temperature    float64      `json:"temperature"`
	MaxTokens      int          `json:"max_tokens"`
	ResponseFormat struct {
		Type string `json:"type"`
	} `json:"response_format"`
}

// LLMResponse is the response body from OpenAI-compatible APIs.
type LLMResponse struct {
	ID      string `json:"id"`
	Object  string `json:"object"`
	Created int64  `json:"created"`
	Model   string `json:"model"`
	Choices []struct {
		Index        int        `json:"index"`
		Message      LLMMessage `json:"message"`
		FinishReason string     `json:"finish_reason"`
	} `json:"choices"`
	Error *struct {
		Message string `json:"message"`
		Type    string `json:"type"`
	} `json:"error,omitempty"`
}

// AnthropicRequest is the request body for Anthropic-compatible APIs.
type AnthropicRequest struct {
	Model       string       `json:"model"`
	Messages    []LLMMessage `json:"messages"`
	System      string       `json:"system"`
	MaxTokens   int          `json:"max_tokens"`
	Temperature float64      `json:"temperature"`
}

// AnthropicResponse is the response body from Anthropic-compatible APIs.
type AnthropicResponse struct {
	ID      string `json:"id"`
	Model   string `json:"model"`
	Role    string `json:"role"`
	Content []struct {
		Type string `json:"type"`
		Text string `json:"text"`
	} `json:"content"`
	StopReason string `json:"stop_reason"`
	Error      *struct {
		Type    string `json:"type"`
		Message string `json:"message"`
	} `json:"error,omitempty"`
}

// Config holds the application configuration.
type Config struct {
	LLM struct {
		APIType      string  `mapstructure:"api_type"`
		APIKey       string  `mapstructure:"api_key"`
		BaseURL      string  `mapstructure:"base_url"`
		Model        string  `mapstructure:"model"`
		Temperature  float64 `mapstructure:"temperature"`
		MaxTokens    int     `mapstructure:"max_tokens"`
		TimeoutSec   int     `mapstructure:"timeout_sec"`
	} `mapstructure:"llm"`
	Agent struct {
		MaxIterations       int `mapstructure:"max_iterations"`
		CommandTimeoutMin   int `mapstructure:"command_timeout_min"`
		ContextMaxLines     int `mapstructure:"context_max_lines"`
		MaxOutputChars      int `mapstructure:"max_output_chars"`
		AdaptationDelaySec  int `mapstructure:"adaptation_delay_sec"`
	} `mapstructure:"agent"`
	Target struct {
		RootDomain     string   `mapstructure:"root_domain"`
		InScopeDomains []string `mapstructure:"in_scope_domains"`
		OutOfScope     []string `mapstructure:"out_of_scope"`
		RateLimitRPS   int      `mapstructure:"rate_limit_rps"`
		Proxy          string   `mapstructure:"proxy"`
		UserAgents     []string `mapstructure:"user_agents"`
	} `mapstructure:"target"`
	Guardrails struct {
		AllowedTools   []string `mapstructure:"allowed_tools"`
		BlockedWords   []string `mapstructure:"blocked_words"`
		AllowedModes   []string `mapstructure:"allowed_modes"`
	} `mapstructure:"guardrails"`
}
