# AI engine

You ask the AI for something from the desktop app, a phone or the CLI, and
the task runs **on the server**, in the background: you can close the app,
and it lets you know when it needs your approval. The tools work on your
hosts with the same SSH engine as the rest of Termoak.

The AI is optional and runs with your own API keys or subscriptions: those
of the server and, per user, the API keys each user adds in Settings → AI
(see [Per-user access](#per-user-access-own-keys-and-ai-credit)).

## Providers

A provider is written as `provider` or `provider::model`:

| Provider | Driver | Credentials | Default model |
|---|---|---|---|
| `claude` | Anthropic API (Messages) | `ANTHROPIC_API_KEY` | `claude-opus-5` |
| `gpt` | OpenAI API (Responses) | `OPENAI_API_KEY` | `gpt-5.6-sol` |
| `codex` | `codex exec` CLI with your **ChatGPT subscription** | `CODEX_HOME/auth.json` | Codex's own |
| `codex-api` | OpenAI Responses | `CODEX_API_KEY` or `OPENAI_API_KEY` | `gpt-5-codex` |
| `opencode-api` | **OpenCode Go** (OpenAI Chat compatible) | `OPENCODE_GO_KEY` | `deepseek-v4-flash` |
| `openrouter` | **OpenRouter** (OpenAI Chat compatible, `https://openrouter.ai/api/v1`) | `OPENROUTER_API_KEY` | `openrouter/auto` (`OPENROUTER_MODEL`) |
| `opencode` | Local OpenCode server (`opencode serve`) | `OPENCODE_SERVER_PASSWORD` | OpenCode's own |
| `local` | Ollama, LM Studio or vLLM (OpenAI Chat) | `LOCAL_AI_BASE_URL`, `LOCAL_AI_MODEL` | — |

Default configuration:

```toml
[ai]
default = "codex"
fallback = ["opencode-api::deepseek-v4-flash", "opencode-api::kimi-k2.6"]
```

Each provider can be overridden in `[ai.providers.<name>]`: driver,
`base_url`, `model`, `models`, `effort`, `max_tokens`, `api_key_env`,
`command`, `codex_home`, `key_check_path`... See `termoak-server
example-config`.

`termoak-server ai-providers` and `GET /api/v1/ai/providers` show which
providers are available and, for those that are not, why (the detailed
cause only to administrators; users get a `reason_code`).

### Codex with your ChatGPT subscription

On the server:

```sh
sudo -u termoak env CODEX_HOME=/var/lib/termoak/codex codex login --device-auth
```

The command shows a code to confirm on chatgpt.com from any device. The
session is saved in `CODEX_HOME/auth.json`.

If you copy `codex` somewhere else (for example `/usr/local/bin`), also copy
`codex-code-mode-host`, which lives in the same folder of the Codex
installation: Codex calls the tools through it and, without it, can only
answer (it runs nothing on your hosts). `ai-providers` warns if it is
missing.

Codex runs **sandboxed**:

- No shell and no network for commands.
- It works in a temporary directory and does not read your configuration.
- **It never runs anything on the server machine.**

Its only tools are Termoak's, which it gets over MCP with a token valid only
for that task. So every action goes through the same permissions, approvals
and audit log as with the other providers.

### OpenCode Go

Get the key at opencode.ai and put it in `OPENCODE_GO_KEY`. Models are
listed from the endpoint. Pick one with, for example,
`opencode-api::kimi-k2.6`.

### Claude

The Messages API is used with streaming and these options:

- Adaptive thinking (`thinking: {type: "adaptive"}`) and configurable
  `effort`.
- Automatic prompt caching.
- Early streaming of tool arguments.

On models that support it, Anthropic's server-side fallback is enabled. If
Claude refuses to answer (`refusal`), the task continues with the next
provider in the chain.

### Agents installed on a computer: Claude Code, Antigravity, Codex, OpenCode

These drivers run an agent that is installed on the same computer, with its
own sign-in or subscription. They are not built-in providers: the desktop
app configures them (see [AI on this computer](#ai-on-this-computer-desktop-app)),
and a server can add them in `[ai.providers.<name>]` with `driver =
"claude_code"`, `"antigravity"`, `"codex_cli"` or `"opencode_server"`. Each one
runs in a new private temporary directory (removed at the end) and gets
Termoak's tools only through MCP, with a token valid only for that run.
`command` is the executable (name or absolute path) and `path_env` the
`PATH` of its process (npm installs need `node`).

| Driver | Invocation |
|---|---|
| `claude_code` | `claude -p --output-format stream-json --verbose --include-partial-messages --no-session-persistence --disable-slash-commands --tools "" --permission-mode dontAsk --strict-mcp-config --mcp-config <dir>/mcp.json --allowedTools mcp__termoak --system-prompt <Termoak's> [--model M] [--effort E]`, the conversation on stdin |
| `antigravity` | `agy -p <prompt> --output-format stream-json --sandbox --dangerously-skip-permissions --disable-slash-commands --print-timeout 30m [--model M] [--effort low\|medium\|high]` under a pseudo-terminal, MCP in `<dir>/.agents/mcp_config.json` |
| `codex_cli` | `codex exec --json ...` (see above), MCP through `-c mcp_servers.termoak.*` |
| `opencode_server` with `command` | `opencode serve --hostname 127.0.0.1 --port <free> ` with a random `OPENCODE_SERVER_PASSWORD` and `OPENCODE_CONFIG_CONTENT` (its own tools off, Termoak's MCP server), stopped at the end |

- **Claude Code** has no tools of its own (`--tools ""`); `dontAsk` denies
  whatever is not allowed, and only the `termoak` MCP server is loaded.
  `total_cost_usd` is not taken as a cost (it is an estimate even on a
  subscription). "Not logged in" answers become `not_logged_in`.
- **Antigravity** prints nothing when its output is not a terminal (it
  checks `isatty()`), so it runs under a pseudo-terminal (`termoak-ai`
  feature `pty`) and each line is cleaned of terminal decoration before
  being read as JSON (see github.com/rhishi99/agy-headless-bridge). It has
  no flag to restrict its own tools: it runs with `--sandbox` in the empty
  temporary directory, and `--dangerously-skip-permissions` because nobody
  can answer its prompts headless; Termoak's tools keep Termoak's
  approvals. The prompt goes on the command line (its last 24,000
  characters).
- Errors carry a stable code (`AiError::code()`): `not_installed`,
  `not_logged_in`, `timeout`, `key_rejected`, `rate_limited`...

## Per-user access: own keys and AI credit

Each user can add their own API key for `claude`, `gpt`, `openrouter` and
`opencode-api` (`PUT /api/v1/me/ai/keys/{provider}`, see [API.md](https://github.com/TermoakSSH/server/blob/main/docs/API.md)).
It is stored encrypted with the master key (bound to the user and the
provider) and never returned; the API only shows its last 4 characters.

For every request (tasks, messages and the terminal assistant) the engine
builds the user's chain:

1. The user's own key for a provider replaces the server's key for it, with
   the user's model if they chose one. These go first.
2. The server's providers (its API keys, the Codex subscription...) only if
   the user's plan has `server_ai`, and while its monthly credit lasts
   (`ai_credit_usd`). They are also checked before every turn, so a long
   task stops using them when the credit runs out.
3. Anything else is skipped. With nothing left, the request fails with
   `ai_key_required` (no server AI, no usable key) or `ai_budget_exceeded`
   (credit spent).

The CLI-based providers (`codex`, `opencode`) and `local` never take a
user's key. Administrators have no limits.

The plans decide (`[[plans.catalog]]` → `limits`): the built-in Free plan
has `server_ai = false` (AI only with your own keys); Pro has `server_ai =
true` and `ai_credit_usd = 5.0`. A plan without these fields keeps the
server's AI, so to share it with every user of a self-hosted server it is
enough to give their plan `server_ai = true`. `[ai] monthly_budget_usd` is
the credit of plans that allow the server's AI without their own
`ai_credit_usd`.

`POST /api/v1/me/ai/keys/{provider}/test` checks a key with a call that
spends nothing: `GET /v1/models` on Anthropic, `GET /models` on the
OpenAI-compatible ones and `GET /key` on OpenRouter (`key_check_path`).
Some endpoints may answer without checking the key.

## Fallback chain

If a provider fails (network, 5xx, 429, out of credit, refusal...), the turn
is repeated with the next one in the chain.

- A `reset` event is emitted so clients discard the half-written text, and
  two answers never get mixed.
- Native blocks of a provider, such as Claude's signed reasoning or OpenAI's
  encrypted items, are only sent back to that same model. The others get the
  conversation in the common format.

## Permissions

| Mode | Read-only actions | Changes |
|---|---|---|
| `read_only` | Run | Denied |
| `ask` (default) | Run | Wait for your approval from the desktop app, a phone or the CLI |
| `confirm` | Those that run on a host (`run_command`, `send_to_terminal`) wait for your approval; reading files or the terminal does not | Wait for your approval |
| `auto` | Run | Run without asking |

- **Classifier.** Decides whether a command is read-only, and is
  **conservative**. Only known commands and flags count as read-only (`ls`,
  `cat`, `df`, `systemctl status`, `journalctl`, `git log`, `docker ps`...).
  Any shell operator (`;`, `|`, `>`, `$( )`...) or dangerous flag
  (`find -delete`, `-exec`...) counts as a change.
- **Always approve.** Approving with `always: true` switches the task to
  `auto`.
- **Expiry.** An unanswered approval expires after 30 minutes
  (`approval_timeout_secs`) and counts as denied.

### Approvals: what you see and how you answer

Every approval (the `approval_requested` event and the task's
`pending_approvals`) carries a `preview` (`termoak_ai::ApprovalPreview`;
absent on approvals made before 0.5):

| `kind` | Shows |
|---|---|
| `command` (`run_command`) | the exact `command`, the `host`, the model's `explanation`, the `risk` (`low`, `medium`, `high`) and the classifier's `reasons` |
| `terminal` (`send_to_terminal`) | the text typed (`command`), the terminal's title (`host`), risk and reasons |
| `file` (`write_file`) | `host`, `path` and a unified `diff` of the current file against the new content (`added`, `removed`, `new_file`; at most 64 KiB, `diff_truncated`; files over 512 KiB or binary give a `diff_error` instead), with the risk of the path |
| `plan` | the numbered `plan` of a "plan before acting" task |

The reasons have a stable `code` and an English `text`: `pipe`, `chain`,
`redirect`, `substitution`, `sudo`, `rm_rf` ("deletes files recursively (rm
-rf)"), `delete`, `disk`, `reboot`, `service`, `packages`, `firewall`,
`permissions`, `kill`, `users`, `remote_script` (a download piped into a
shell), `containers`, `cron`, `git_history`, `system_path` ("writes to
/etc"), `critical_file` (`sshd_config`, `sudoers`, `fstab`...), `redacted`
(the command contains a hidden secret) and `changes`. Read-only commands are
`low`; destructive ones (`rm -rf`, disks, reboots, firewall flushes, `curl
| sh`, critical files) are `high`.

The answer (`POST /api/v1/ai/tasks/{id}/approvals/{approval_id}`,
`AiEngine::decide_with`, `termoak_ai::ApprovalDecision`) is additive over
the old `{approve, always}`:

- `edited`: for `run_command` and `send_to_terminal`, the command the user
  approved instead of the model's. It is what runs (and what the audit log
  and the runbook record), and the model's result starts with "The user
  edited the command before approving it; this is what ran instead of
  yours". For a plan, the edited plan the model must follow.
- `reason`: why it was denied, sent to the model with the denial ("Their
  reason: …"); with an approval, a note for the model.
- `always: true`: approve this one and the rest of the task (`auto`).

The `approval_decided` event carries `edited` and `reason`.

## Plan before acting

With `plan_first: true` in `POST /api/v1/ai/tasks`, the model first writes a
short numbered plan with no tools offered (`PLAN_PROMPT` is added to the
system prompt). The plan is an approval with `tool: "plan"` (and
`preview.kind: "plan"`, editable), so apps that do not know it still show it
and can approve it. Approved (possibly `edited`), the model is told to carry
out that plan and gets its tools; denied with a `reason`, it proposes a new
plan (up to 3); denied without one (or expired), the task ends `cancelled`
with the error "the plan was not approved". The task view has `plan_first`
and `plan` (`text`, `approved`, `edited`). A follow-up message to a task whose
plan was not approved plans again.

## Multi-host tasks

`POST /api/v1/ai/tasks` accepts, besides `host_ids`, a `group_id` (the
group and its subgroups) and a `tag`; the hosts they name become the task's
scope. With `fan_out: true` and more than one host, the same request runs as
**one conversation per host** (each limited to its host, with its own
approvals, transcript, usage and cost) under a multi-host task, at most
`[ai] fan_out_concurrency` (4) at a time and `max_fan_out_hosts` (50) hosts.
Without `fan_out`, a single conversation goes through the hosts (as before).

- The multi-host task runs no model: it waits for its hosts and then sums
  them up. Its `result` has one line per host (`- **web1**: completed —
  …`), its cost and usage are the hosts' total, and it is `failed` if a host
  failed, `cancelled` if it was cancelled.
- `GET /api/v1/ai/tasks/{id}` of a multi-host task has `fan_out: true` and
  `hosts`: per host `host_id`, `label`, `task_id` (its conversation, to drill
  down: `GET /api/v1/ai/tasks/{task_id}`), `status`, `summary`, `error`,
  `duration_ms`, `cost_micros` and `pending_approvals`. A host's
  conversation has `parent_id`.
- The list shows only the multi-host task, not its hosts. Events of each
  host come with the host's `task_id`; the multi-host task gets a `notice`
  ("web1: completed") as each host ends.
- Cancelling it cancels its hosts; a follow-up message goes to every host;
  changing its mode changes theirs; deleting it deletes theirs. A host's
  conversation can also be continued on its own (the summary is updated
  when it ends).
- The hosts of a multi-host task count as one task for
  `max_concurrent_tasks`.

## Stop and continue

`POST /api/v1/ai/tasks/{id}/cancel` stops a running task right away: a
command or file transfer in progress is abandoned ("Stopped by the user
before it finished"), a pending approval counts as denied, and the task ends
`cancelled` keeping its conversation. A new message
(`POST /api/v1/ai/tasks/{id}/messages`) continues it with all its context.
Tool calls left without a result (for example when the app or the server
stopped in the middle) get one saying they did not run, so every provider
accepts the conversation.

## Runbooks

A task records the commands and file writes it ran, in order
(`steps` in the task view with its messages: tool, host, command or path,
`ok`, `edited`, the model's `explanation`). `AiEngine::runbook` turns them
into a snippet (`termoak_ai::runbook::build`): the successful commands, each
with a comment from the model's explanation (its `reason`, or the line it
wrote before the call), files as `cat > path <<'TERMOAK_EOF'` blocks, and
the host's label and address replaced with `{{host}}` when the task ran on
one host. `AiEngine::save_runbook` saves it in the user's personal vault
(tags `ai`, `runbook`). For a multi-host task, the first host that ran
commands is used. Tasks without recorded steps (older ones) are rebuilt
from the transcript. Clients can build it themselves from a task view with
`termoak_ai::runbook::build`.

## Secret redaction

Before anything goes to a provider, tool results (command output, files
read over SFTP, terminal screens) and the terminal context (`<context>`
blocks of a request, the screen and text of the terminal assistant) go
through `termoak_ai::redact()`, which replaces secrets with `[redacted]`:

- private key blocks (`-----BEGIN … PRIVATE KEY-----`, also inside JSON with
  escaped newlines);
- `Authorization`, `Proxy-Authorization`, `X-Api-Key`, `X-Auth-Token`,
  `Cookie` and `Set-Cookie` values;
- the password in `scheme://user:password@host`;
- values of secret-looking keys in `.env`, YAML, JSON, INI and command
  lines: `password=`, `DB_PASSWORD=`, `"api_key": "…"`, `client_secret:`,
  `export GITHUB_TOKEN=`, `--password …` (settings such as
  `PasswordAuthentication` or `password_file`, empty values, `${VAR}`
  references and placeholders are kept);
- known token formats: AWS access key ids, Google API keys and OAuth tokens,
  GitHub, GitLab, Slack, Stripe, OpenAI/Anthropic, npm and Hugging Face
  tokens, JWTs.

It is on by default (`[ai] redact_secrets = true`; also in the desktop
app). Since the model only sees files with their secrets hidden,
`write_file` refuses content that contains `[redacted]` (writing it back
would replace the secrets) and tells the model to change only the lines it
needs; a command containing `[redacted]` is flagged in its approval. The
redaction is a heuristic: it hides more rather than less, but it cannot
recognise every secret, so keep the permission modes and the approvals.

## Tools

| Tool | Effect |
|---|---|
| `list_hosts` | Read |
| `run_command` | Depends on the classifier |
| `read_file` | Read (SFTP) |
| `write_file` | Change. Keeps a copy of the original |
| `list_directory` | Read |
| `list_snippets` | Read |
| `remember` | Saves a fact about your infrastructure for future tasks (`memories` entity, synced) |
| `list_sessions` | Read. Terminals open on the server |
| `read_terminal` | Read. The latest content of a terminal (for "what does this error mean?") |
| `send_to_terminal` | Change. Types into an open terminal |

A task can be limited to specific hosts with `host_ids` (or a `group_id` or
`tag`, see [Multi-host tasks](#multi-host-tasks)). Then the tools cannot
leave them.

## Terminal assistant

- `POST /ai/suggest` turns a natural-language request into a command, with
  an explanation and a risk level.
- `POST /ai/explain` explains an output or an error.

Both are fast, create no task, and are used from the terminal's command bar.

## Cost

- Each turn (and each terminal assistant call) records in a usage ledger the
  tokens, whether it ran with the user's own key or the server's provider,
  and two amounts:
  - the **real cost**: what the server pays, from the price table in
    `crates/termoak-ai/src/pricing.rs` (Claude, OpenAI, and the models
    OpenCode Go serves, at list prices), the provider's `price`, or the cost
    the provider reports. On a subscription (Codex, OpenCode Go, local) it
    is 0 unless the provider reports one;
  - the **credit cost**: what it takes from the plan's monthly AI credit. It
    is 0 with the user's own key. Otherwise, in this order: tokens × the
    provider's `credit_price` if set; else the real cost if there is one;
    else tokens × the model's price (`price` or the built-in table, e.g.
    `codex::gpt-5.6-sol` is charged like `gpt-5.6-sol` on the OpenAI API);
    else tokens × a reference price: GPT-5.3-codex for Codex
    ($1.75 / $14 per million input / output tokens, $0.175 cached), and a
    conservative $2 / $10 ($0.20 cached) for any other provider.
- So the server's subscriptions spend the credit too. To change what they
  charge, set `credit_price` on the provider (e.g. `credit_price = { input =
  0, output = 0 }` for a free local model).
- Codex reports its tokens (`turn.completed`) and OpenCode its tokens and
  cost. If an external agent reports no usage, the tokens are estimated from
  the size of the prompt and the answer (about 4 characters per token), a
  lower bound since the agent's own instructions and tool calls are not seen.
- Only the server's providers count against the plan's monthly credit
  (`ai_credit_usd`, or `[ai] monthly_budget_usd` as the fallback), by their
  credit cost. Deleting tasks does not give the credit back.
  `GET /api/v1/me/ai/access` and `GET /api/v1/me/plan` show this month's
  spending; a task's `cost_micros` is its real cost.

## MCP for external agents

`POST /api/v1/mcp` implements MCP (JSON-RPC 2.0 over HTTP, version
`2025-06-18`). You can connect Claude Code, Codex, OpenCode or any MCP
client with your access token:

```sh
claude mcp add --transport http termoak https://termoak.example.com/api/v1/mcp \
  --header "Authorization: Bearer <token>"
```

With a user token the `mcp_user_mode` mode applies, `read_only` by default:
there is nowhere to ask for approval, so actions that change something are
denied. To allow them, switch the mode to `auto`, at your own risk.

## AI on this computer (desktop app)

In Settings → AI the desktop app can run the AI on the computer instead of
the account's server ("This computer"): the copilot next to each terminal,
the quick assistant (explain, which command) and the AI tasks. Nothing is
sent to the Termoak server in this mode, even when signed in.

- **With your own API key** stored in the app (Anthropic, OpenAI,
  OpenRouter, OpenCode Go; sealed with the local vault key), the app runs
  the same agent loop as the server, in process (`termoak_ai::agent`).
- **With an agent installed** (Codex, Claude Code, Antigravity, OpenCode),
  the agent runs on its own and gets the tools through a local MCP endpoint
  (`termoak_ai::mcp_http::LocalMcpServer`).
- The **tools** are the server copilot's: hosts, commands, files and
  memories from the local vault over the app's SSH engine (known host keys
  only), and the terminals open in the app (`list_sessions`,
  `read_terminal`, `send_to_terminal`). The same permission modes apply and
  approvals appear in the copilot.
- **AI tasks** use the same engine as the server (`AiEngine`) over the
  local database: tasks, their events and approvals are kept there and
  survive restarts. They only run while the app is open: on the next start,
  a task that was running is marked as failed ("stopped because the app was
  closed") and can be continued with a new message or the Continue button.
  The chain of each request comes from the settings
  (`AiEngine::set_chain_source`), so plans and credit do not apply. The app
  shows a notification when a local task needs approval or ends.
- There are no plan limits; usage is recorded in the local database
  (`ai_usage`) and the month's cost (real cost: own keys at list prices,
  agents on a subscription at 0) is shown in Settings → AI.
- **Antigravity is experimental** and off by default: it can run commands
  on the computer without Termoak's approvals (it has no option to limit its
  own tools). It appears with an "Experimental" badge and can only be chosen
  after a confirmation that says so, that it runs in a temporary sandboxed
  folder, and that Codex, Claude Code and OpenCode are limited to Termoak's
  tools. The choice is saved in the desktop settings (`ai.agy_opt_in`,
  `false` by default); without it the app refuses to start `agy`.

The local MCP endpoint listens only on `127.0.0.1` (random port) and
requires `Authorization: Bearer <token>`: for the copilot, an endpoint that
exists only while a message runs, with a random token for that run
(compared in constant time); for AI tasks, one endpoint for the app's
engine that only accepts the token of a task that is running
(`LocalMcpServer::start_for_tasks`). It rejects a
`Host` that is not that address and any `Origin` from another site (DNS
rebinding, web pages), and limits headers (16 KiB) and bodies (4 MiB). The
token reaches the agent in a file readable only by the user (Claude Code,
Antigravity), an environment variable (Codex, OpenCode), never in the
command line.
