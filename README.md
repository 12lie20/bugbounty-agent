# Autonomous Bug Bounty Agent (Educational / Authorized Use Only)

A production-oriented Go framework for an autonomous LLM-driven bug bounty agent that runs on Kali Linux. It implements a strict ReAct planning loop, command guardrails, context minimization, and self-healing adaptation.

## ⚠️ Legal & Ethical Warning

This tool is intended **only** for:
- Bug bounty programs with explicit written authorization.
- Penetration testing engagements with signed contracts.
- Lab environments you own.

**Never** point this agent at systems you do not have permission to test.

## Features

- **Advanced ReAct Planning Loop**: Strategic phases (recon -> scanning -> analysis -> exploitation -> reporting).
- **Strict JSON Output + Repair**: LLM must return `AdvancedResponse` JSON; Go validates, extracts the JSON block, and auto-repairs common LLM JSON mistakes with `github.com/kaptinlin/jsonrepair` before giving up.
- **Command Guardrails**: Allowlist of tools, blacklist of dangerous patterns, out-of-scope checks, and POSIX-style argument splitting via `github.com/google/shlex`.
- **Smart Context Minimization**: Filters tool output by security keywords and regex patterns (open ports, status codes, CVEs, endpoints, etc.) instead of blind head/tail truncation, and deduplicates noisy lines like repeated 403s.
- **Context Ballooning Protection**: Sends the LLM a compact state snapshot with recent updates only, not the full target map + full history on every turn.
- **Self-Healing Adapter**: Detects WAF/rate-limit blocks, timeouts, and missing tools and adapts.
- **Safe Execution**: Uses `os/exec` without a shell, rejects pipes/semicolons/command substitution, and enforces a 10-minute timeout per command.
- **Parallel Recon Boost**: Runs independent recon commands concurrently at startup for faster target mapping.
- **Adaptive Rate Limiting**: Slows down automatically when blocked and speeds up when responses are clean.
- **Tool Result Parsers**: Automatically extracts structured findings from `nmap`, `ffuf`, `httpx`, and `nikto` outputs.
- **Persistent State**: Saves progress to `state.jsonl` after every iteration and can resume from it.
- **Proxy & User-Agent Rotation**: Configurable proxy and rotating user-agents in `config.yaml`.

## Quick Start

1. Install Go 1.26+ and required tools on Kali Linux:
   ```bash
   sudo apt update
   sudo apt install -y nmap ffuf subfinder amass httpx whatweb nikto gau katana dalfox jq
   ```

2. Edit `config.yaml` to set the target domain, scope, and other preferences.

3. Build and run:
   ```bash
   go mod tidy
   go build -o bugbounty-agent ./cmd/main.go
   ./bugbounty-agent -config config.yaml
   ```

4. On the first run, the agent will ask for your opencode.ai API key and save it to `.env`.

5. Every time you run the agent, an interactive menu lets you pick the opencode Go model with one keystroke:
   ```
   Select an opencode.ai Go model:
   --------------------------------------------------
   [ 1] Qwen3.7 Max        (opencode-messages)
   [ 2] Qwen3.7 Plus       (opencode-messages)
   [ 3] Qwen3.6 Plus       (opencode-messages)
   [ 4] MiniMax M3         (opencode-messages)
   [ 5] MiniMax M2.7       (opencode-messages)
   [ 6] MiniMax M2.5       (opencode-messages)
   [ 7] GLM-5.1            (opencode-chat)
   [ 8] GLM-5              (opencode-chat)
   [ 9] Kimi K2.7          (opencode-chat)
   [10] Kimi K2.6          (opencode-chat)
   [11] DeepSeek V4 Pro    (opencode-chat)
   [12] DeepSeek V4 Flash  (opencode-chat)
   [13] MiMo-V2.5          (opencode-chat)
   [14] MiMo-V2.5-Pro      (opencode-chat)
   --------------------------------------------------
   Choice: 1
   ```

## Configuration

See `config.yaml`. Key settings:
- `llm.api_type`: `"opencode-chat"` or `"opencode-messages"` (also accepts `"openai"` and `"anthropic"`).
- `llm.api_key`: API key for the chosen endpoint.
- `llm.base_url`: Endpoint such as `https://api.openai.com/v1` or `https://opencode.ai/zen/go/v1`.
- `llm.model`: Model name such as `qwen3.7-max`, `deepseek-v4-pro`, or `glm-5.1`.

### opencode.ai Go Models

The agent supports all opencode.ai Go models by selecting the correct `api_type`:

| API Type | Endpoint | Models |
|---|---|---|
| `opencode-chat` | `/v1/chat/completions` | GLM-5.1, GLM-5, Kimi K2.7, Kimi K2.6, DeepSeek V4 Pro, DeepSeek V4 Flash, MiMo-V2.5, MiMo-V2.5-Pro |
| `opencode-messages` | `/v1/messages` | Qwen3.7 Max, Qwen3.7 Plus, Qwen3.6 Plus, MiniMax M3, MiniMax M2.7, MiniMax M2.5 |

Example for Qwen3.7 Max:
```yaml
llm:
  api_type: "opencode-messages"
  api_key: "${BB_AGENT_LLM_API_KEY}"
  base_url: "https://opencode.ai/zen/go/v1"
  model: "qwen3.7-max"
```

Example for DeepSeek V4 Pro:
```yaml
llm:
  api_type: "opencode-chat"
  api_key: "${BB_AGENT_LLM_API_KEY}"
  base_url: "https://opencode.ai/zen/go/v1"
  model: "deepseek-v4-pro"
```
- `target.root_domain`: Root target domain.
- `target.in_scope_domains`: Allowed target patterns.
- `target.out_of_scope`: Forbidden target patterns.
- `guardrails.allowed_tools`: Tools the agent may invoke.
- `guardrails.blocked_words`: Dangerous patterns that always reject the command.

## Architecture

```
cmd/main.go                 # Entry point
internal/config/            # Configuration loading
internal/models/            # Shared data models and JSON schema
internal/memory/            # Target map, history, output filtering
internal/guardrails/        # Command sanitizer and scope checks
internal/executor/          # Secure CLI execution + parallel runner
internal/llm/               # OpenAI/Anthropic-compatible chat client + JSON repair
internal/parser/            # Tool output parsers (nmap, ffuf, httpx, nikto)
internal/persistence/       # Save/resume state to JSONL
internal/ratelimit/         # Adaptive rate limiter
internal/selfheal/          # Failure analysis and adaptation
internal/planner/           # ReAct loop and system/user prompts
```

## Resuming a Scan

The agent saves its state to `state.jsonl` after every iteration. To resume a previous scan, just run the agent again in the same directory. It will load the saved state and continue from the last iteration.

To start fresh, delete `state.jsonl` before running.

## Safety Notes

- Commands are parsed without a shell; pipes, semicolons, backticks, and other operators are rejected.
- Destructive keywords (`rm -rf`, `mkfs`, `dd`, etc.) are blocked.
- Out-of-scope hosts are rejected.
- Each command has a configurable timeout (default 10 minutes).
- The LLM is forced to return JSON with `response_format: { "type": "json_object" }`.

## License

MIT — Use responsibly and only on systems you are authorized to test.
