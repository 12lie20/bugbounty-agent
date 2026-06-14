package planner

import (
	"context"
	"fmt"
	"math/rand"
	"strings"
	"time"

	"github.com/redteam/bugbounty-agent/internal/executor"
	"github.com/redteam/bugbounty-agent/internal/guardrails"
	"github.com/redteam/bugbounty-agent/internal/llm"
	"github.com/redteam/bugbounty-agent/internal/memory"
	"github.com/redteam/bugbounty-agent/internal/models"
	"github.com/redteam/bugbounty-agent/internal/parser"
	"github.com/redteam/bugbounty-agent/internal/persistence"
	"github.com/redteam/bugbounty-agent/internal/ratelimit"
	"github.com/redteam/bugbounty-agent/internal/selfheal"
)

// Engine drives the ReAct planning and execution loop.
type Engine struct {
	cfg       *models.Config
	mem       *memory.Manager
	llm       *llm.Client
	exec      *executor.Executor
	sanitizer *guardrails.Sanitizer
	adapter   *selfheal.Adapter
	store     *persistence.Store
	limiter   *ratelimit.AdaptiveLimiter
}

// NewEngine creates a new planning engine, optionally resuming from disk.
func NewEngine(cfg *models.Config) (*Engine, error) {
	sanitizer := guardrails.NewSanitizer(cfg)
	timeout := time.Duration(cfg.Agent.CommandTimeoutMin) * time.Minute

	store := persistence.NewStore("state.jsonl")
	mem := memory.NewManager(cfg)

	if store.Exists() {
		saved, err := store.Load()
		if err != nil {
			return nil, fmt.Errorf("failed to resume state: %w", err)
		}
		if saved != nil {
			mem.Restore(*saved)
			fmt.Printf("Resumed from state.jsonl at iteration %d, phase %s\n", saved.Iteration, saved.CurrentPhase)
		}
	}

	return &Engine{
		cfg:       cfg,
		mem:       mem,
		llm:       llm.NewClient(cfg),
		exec:      executor.NewExecutor(sanitizer, timeout),
		sanitizer: sanitizer,
		adapter:   selfheal.NewAdapter(cfg),
		store:     store,
		limiter:   ratelimit.NewAdaptiveLimiter(cfg.Target.RateLimitRPS),
	}, nil
}

// Run starts the autonomous loop.
func (e *Engine) Run(ctx context.Context) error {
	fmt.Println("=== Autonomous Bug Bounty Agent Started ===")
	fmt.Printf("Target: %s\n", e.cfg.Target.RootDomain)
	fmt.Printf("Max iterations: %d\n", e.cfg.Agent.MaxIterations)
	fmt.Println("============================================")

	// Optional fast parallel recon for the first iteration.
	if e.mem.State().Iteration == 0 && e.mem.State().CurrentPhase == models.PhaseRecon {
		e.runParallelRecon(ctx)
	}

	for {
		state := e.mem.State()
		if state.Iteration >= state.MaxIterations {
			fmt.Println("Reached maximum iterations. Stopping.")
			_ = e.saveState()
			return nil
		}
		if state.CurrentPhase == models.PhaseFinished {
			fmt.Println("Agent reached finished phase. Stopping.")
			_ = e.saveState()
			return nil
		}

		resp, err := e.plan(ctx)
		if err != nil {
			_ = e.saveState()
			return fmt.Errorf("planning failed at iteration %d: %w", state.Iteration+1, err)
		}

		if err := e.act(ctx, resp); err != nil {
			if strings.Contains(err.Error(), "context canceled") {
				_ = e.saveState()
				return err
			}
		}

		e.limiter.Wait()
	}
}

// runParallelRecon runs safe recon commands in parallel once at startup.
func (e *Engine) runParallelRecon(ctx context.Context) {
	fmt.Println("\n[Boost] Running parallel recon commands...")
	commands := []string{
		fmt.Sprintf("subfinder -d %s -silent", e.cfg.Target.RootDomain),
		fmt.Sprintf("dig +short %s", e.cfg.Target.RootDomain),
		fmt.Sprintf("whois %s", e.cfg.Target.RootDomain),
	}

	results := e.exec.RunParallel(ctx, commands)
	for _, pr := range results {
		if pr.Error != nil || pr.Result == nil {
			continue
		}
		rec := models.IterationRecord{
			Phase:     models.PhaseRecon,
			Strategy:  "parallel recon",
			Reasoning: "bootstrap target map quickly",
			Command:   pr.Command,
			Tool:      strings.Fields(pr.Command)[0],
			RiskLevel: models.RiskLow,
			Status:    models.StatusHunting,
			Allowed:   true,
			Output:    e.mem.FilterOutput(pr.Result.Stdout+"\n"+pr.Result.Stderr, pr.Command),
		}
		e.mem.RecordIteration(rec)
	}
	fmt.Println("[Boost] Parallel recon complete.")
}

// plan asks the LLM for the next strategic action.
func (e *Engine) plan(ctx context.Context) (*models.AdvancedResponse, error) {
	system := e.buildSystemPrompt()
	user := e.buildUserPrompt()

	return e.llm.Chat(ctx, system, user)
}

// act validates, executes, and records a single LLM-planned action.
func (e *Engine) act(ctx context.Context, resp *models.AdvancedResponse) error {
	rec := models.IterationRecord{
		Phase:     e.mem.State().CurrentPhase,
		Strategy:  resp.Strategy,
		Reasoning: resp.Reasoning,
		Command:   resp.Command,
		Tool:      resp.TargetTool,
		RiskLevel: resp.RiskLevel,
		Status:    resp.Status,
	}

	fmt.Printf("\n[Iter %d | %s | %s] %s\n", e.mem.State().Iteration+1, rec.Phase, resp.TargetTool, resp.Strategy)
	fmt.Printf("Reasoning: %s\n", resp.Reasoning)
	fmt.Printf("Command: %s\n", resp.Command)

	if err := e.sanitizer.ValidateCommand(resp.Command); err != nil {
		rec.Allowed = false
		rec.Error = fmt.Sprintf("BLOCKED by guardrails: %v", err)
		e.mem.RecordIteration(rec)
		_ = e.saveState()
		fmt.Printf("!!! BLOCKED: %v\n", err)
		return nil
	}

	rec.Allowed = true
	result, err := e.exec.Run(resp.Command)
	if err != nil {
		rec.Error = err.Error()
		rec.Output = result.Stdout + "\n" + result.Stderr
		rec.Status = models.StatusBlocked
		if adapt := e.adapter.Analyze(rec.Output, result.Stderr, result.ExitCode, resp.TargetTool); adapt != nil {
			rec.Adaptation = adapt
			rec.Status = models.StatusHunting
			e.limiter.RecordBlock()
			fmt.Printf("Adaptation triggered: %s -> %s (delay %ds)\n", adapt.Trigger, adapt.SuggestedAction, adapt.DelaySeconds)
		}
		e.mem.RecordIteration(rec)
		_ = e.saveState()
		return nil
	}

	rec.Output = e.mem.FilterOutput(result.Stdout+"\n"+result.Stderr, resp.Command)
	rec.Status = resp.Status

	// Extract structured findings from known tools.
	findings := parser.ExtractFindings(resp.TargetTool, result.Stdout+"\n"+result.Stderr, resp.Command)
	for _, f := range findings {
		e.mem.AddFinding(f)
	}

	// If output indicates a blocker, trigger adaptation even on success exit code.
	if adapt := e.adapter.Analyze(result.Stdout, result.Stderr, result.ExitCode, resp.TargetTool); adapt != nil {
		rec.Adaptation = adapt
		rec.Status = models.StatusBlocked
		e.limiter.RecordBlock()
		fmt.Printf("Adaptation triggered: %s -> %s (delay %ds)\n", adapt.Trigger, adapt.SuggestedAction, adapt.DelaySeconds)
	} else {
		e.limiter.RecordSuccess()
	}

	e.mem.RecordIteration(rec)
	_ = e.saveState()

	// Phase advancement heuristic: after a few commands in the current phase, advance.
	if e.shouldAdvancePhase(rec.Phase) {
		e.mem.AdvancePhase()
		fmt.Printf("Advanced to phase: %s\n", e.mem.State().CurrentPhase)
	}

	return nil
}

// saveState persists the current state.
func (e *Engine) saveState() error {
	return e.store.Save(e.mem.State())
}

// shouldAdvancePhase decides whether to move to the next phase.
func (e *Engine) shouldAdvancePhase(phase models.Phase) bool {
	history := e.mem.State().History
	count := 0
	for _, rec := range history {
		if rec.Phase == phase {
			count++
		}
	}
	switch phase {
	case models.PhaseRecon:
		return count >= 3
	case models.PhaseScanning:
		return count >= 5
	case models.PhaseAnalysis:
		return count >= 3
	case models.PhaseExploitation:
		return count >= 5
	case models.PhaseReporting:
		return count >= 1
	}
	return false
}

// buildSystemPrompt instructs the LLM on behavior and JSON schema.
func (e *Engine) buildSystemPrompt() string {
	return "You are an elite autonomous bug bounty hunter on Kali Linux. Be precise, fast, and safe.\n" +
		"You must ONLY target hosts explicitly listed as in-scope. You must NEVER run destructive commands.\n\n" +
		"Available tools (single-tool commands only, no pipes/semicolons/operators): nmap, ffuf, subfinder, amass, httpx, curl, wget, whois, dig, nslookup, whatweb, nikto, gau, katona, dalfox, jq, grep, sed, awk, cat, head, tail, wc.\n\n" +
		"Workflow phases:\n" +
		"1. recon: passive/active reconnaissance (subfinder, amass, dig, whois)\n" +
		"2. scanning: service and endpoint discovery (nmap, httpx, katana, gau, whatweb)\n" +
		"3. analysis: correlate findings and identify vulnerability classes\n" +
		"4. exploitation: safely verify issues with low-risk payloads (nikto, dalfox, ffuf)\n" +
		"5. reporting: summarize confirmed findings\n\n" +
		"For every response return valid JSON exactly matching this schema:\n" +
		"{\n" +
		"  \"strategy\": \"short step description\",\n" +
		"  \"reasoning\": \"why this command now\",\n" +
		"  \"target_tool\": \"tool name\",\n" +
		"  \"command\": \"exact single command line\",\n" +
		"  \"risk_level\": \"Low|Medium|High\",\n" +
		"  \"status\": \"hunting|exploiting|finished\"\n" +
		"}\n\n" +
		"Rules:\n" +
		"- The command must be a single executable line with no shell operators.\n" +
		"- Use only the allowed tools.\n" +
		"- Respect adaptive rate limits; use -rate 1 and -timeout when helpful.\n" +
		"- Do not target out-of-scope hosts.\n" +
		"- If blocked by WAF/rate-limit, slow down, rotate User-Agent, or use a proxy.\n" +
		"- When complete, set status to \"finished\" and command to \"echo mission complete\"."
}

// buildUserPrompt provides a compact context snapshot to the LLM.
func (e *Engine) buildUserPrompt() string {
	state := e.mem.State()
	compact := e.mem.CompactUpdatePrompt()

	var phaseHint string
	switch state.CurrentPhase {
	case models.PhaseRecon:
		phaseHint = "Recon: gather subdomains, DNS records, WHOIS. Use subfinder, amass, dig, whois."
	case models.PhaseScanning:
		phaseHint = "Scanning: discover open ports, live hosts, endpoints, technologies. Use nmap, httpx, katana, gau, whatweb."
	case models.PhaseAnalysis:
		phaseHint = "Analysis: correlate collected data and identify likely vulnerability classes."
	case models.PhaseExploitation:
		phaseHint = "Exploitation: run only safe verification commands with low-risk payloads. Use nikto, dalfox, ffuf."
	case models.PhaseReporting:
		phaseHint = "Reporting: summarize confirmed findings with severity and evidence."
	}

	hints := e.buildRuntimeHints()

	return fmt.Sprintf("Target State Snapshot:\n%s\n\nPhase Guidance: %s\n%s\nNow produce the next JSON action. Be concise.", compact, phaseHint, hints)
}

// buildRuntimeHints injects proxy/user-agent/rate hints into the prompt.
func (e *Engine) buildRuntimeHints() string {
	var hints []string
	if e.cfg.Target.Proxy != "" {
		hints = append(hints, fmt.Sprintf("Proxy available: %s (tools like curl/ffuf can use it)", e.cfg.Target.Proxy))
	}
	if len(e.cfg.Target.UserAgents) > 0 {
		ua := e.cfg.Target.UserAgents[rand.Intn(len(e.cfg.Target.UserAgents))]
		hints = append(hints, fmt.Sprintf("Example User-Agent: %s", ua))
	}
	hints = append(hints, fmt.Sprintf("Current adaptive delay: %v", e.limiter.CurrentDelay()))

	if len(hints) == 0 {
		return ""
	}
	return "Runtime Hints:\n" + strings.Join(hints, "\n") + "\n"
}
