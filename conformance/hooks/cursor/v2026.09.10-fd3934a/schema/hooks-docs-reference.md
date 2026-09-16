<!-- verbatim slice (Configuration through Reference) of https://cursor.com/docs/hooks.md fetched 2026-09-16, full page sha256 7294a2d63b19d79a5283c948afe174cba8b06a7585563d34a2c41b90f5df0d39 -->
## Configuration

Define hooks in a `hooks.json` file. Configuration can exist at multiple levels. All matching hooks from every source run, and Cursor merges their responses: any `deny` wins over `ask`, and `ask` wins over `allow`, regardless of source. `user_message` and `agent_message` values are concatenated. For other fields, such as `followup_message`, the last response wins. Responses merge in the priority order below, so for those fields a lower-priority source overrides a higher-priority one:

```sh
~/.cursor/
├── hooks.json
└── hooks/
    ├── audit.sh
    └── block-git.sh
```

- **Enterprise** (MDM-managed, system-wide):
  - macOS: `/Library/Application Support/Cursor/hooks.json`
  - Linux/WSL: `/etc/cursor/hooks.json`
  - Windows: `C:\\ProgramData\\Cursor\\hooks.json`
- **Team** (Cloud-distributed, enterprise only):
  - Configured in the [web dashboard](https://cursor.com/dashboard/team-content?section=hooks) and synced to all team members automatically
- **Project** (Project-specific):
  - `<project-root>/.cursor/hooks.json`
  - Project hooks run in any trusted workspace and are checked into version control with your project
- **User** (User-specific):
  - `~/.cursor/hooks.json`

Priority order (highest to lowest): Enterprise → Team → Project → User

The `hooks` object maps hook names to arrays of hook definitions. Each definition currently supports a `command` property that can be a shell string, an absolute path, or a relative path. The working directory depends on the hook source:

- **Project hooks** (`.cursor/hooks.json` in a repository): Run from the **project root**
- **User hooks** (`~/.cursor/hooks.json`): Run from `~/.cursor/`
- **Enterprise hooks** (system-wide config): Run from the enterprise config directory
- **Team hooks** (cloud-distributed): Run from the managed hooks directory

For project hooks, use paths like `.cursor/hooks/script.sh` (relative to project root), not `./hooks/script.sh` (which would look for `<project>/hooks/script.sh`).

### Configuration file

This example shows a user-level hooks file (`~/.cursor/hooks.json`). For project-level hooks, change paths like `./hooks/script.sh` to `.cursor/hooks/script.sh`:

```json
{
  "version": 1,
  "hooks": {
    "sessionStart": [{ "command": "./session-init.sh" }],
    "sessionEnd": [{ "command": "./audit.sh" }],
    "preToolUse": [
      {
        "command": "./hooks/validate-tool.sh",
        "matcher": "Shell|Read|Write"
      }
    ],
    "postToolUse": [{ "command": "./hooks/audit-tool.sh" }],
    "subagentStart": [{ "command": "./hooks/validate-subagent.sh" }],
    "subagentStop": [{ "command": "./hooks/audit-subagent.sh" }],
    "beforeShellExecution": [{ "command": "./script.sh" }],
    "afterShellExecution": [{ "command": "./script.sh" }],
    "afterMCPExecution": [{ "command": "./script.sh" }],
    "afterFileEdit": [{ "command": "./format.sh" }],
    "preCompact": [{ "command": "./audit.sh" }],
    "stop": [{ "command": "./audit.sh", "loop_limit": 10 }],
    "beforeTabFileRead": [{ "command": "./redact-secrets-tab.sh" }],
    "afterTabFileEdit": [{ "command": "./format-tab.sh" }],
    "workspaceOpen": [{ "command": "./register-workspace-plugins.sh" }]
  }
}
```

The Agent hooks (`sessionStart`, `sessionEnd`, `preToolUse`, `postToolUse`, `postToolUseFailure`, `subagentStart`, `subagentStop`, `beforeShellExecution`, `afterShellExecution`, `beforeMCPExecution`, `afterMCPExecution`, `beforeReadFile`, `afterFileEdit`, `beforeSubmitPrompt`, `preCompact`, `stop`, `afterAgentResponse`, `afterAgentThought`) apply to Cmd+K and Agent Chat operations. The Tab hooks (`beforeTabFileRead`, `afterTabFileEdit`) apply specifically to inline Tab completions. The app lifecycle hook (`workspaceOpen`) fires when a workspace opens and on workspace folder changes, independent of any agent session.

### Global Configuration Options

| Option    | Type   | Default  | Description                                                  |
| --------- | ------ | -------- | ------------------------------------------------------------ |
| `version` | number | required | Config schema version. Must be a positive integer (use `1`). |

### Per-Script Configuration Options

| Option       | Type                      | Default          | Description                                                                                                                                                                                                                                              |
| ------------ | ------------------------- | ---------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `command`    | string                    | required         | Script path or command                                                                                                                                                                                                                                   |
| `type`       | `"command"` \| `"prompt"` | `"command"`      | Hook execution type                                                                                                                                                                                                                                      |
| `timeout`    | number                    | platform default | Execution timeout in seconds                                                                                                                                                                                                                             |
| `loop_limit` | number \| null            | `5`              | Per-script loop limit for stop/subagentStop hooks. `null` means no limit. Default is `5` for Cursor hooks, `null` for Claude Code hooks.                                                                                                                 |
| `failClosed` | boolean                   | `false`          | When `true`, hook failures (crash, timeout, non-zero exit code, no output) block the action instead of allowing it through. Permission hooks block on invalid JSON or an invalid response even when this is `false`. Useful for security-critical hooks. |
| `matcher`    | string                    | -                | Regex that filters when the hook runs. An empty string or `"*"` matches everything.                                                                                                                                                                      |

### Matcher Configuration

Matchers let you filter when a hook runs. A matcher is a regex string; an empty string or `"*"` matches everything. Which value the regex is tested against depends on the hook:

```json
{
  "version": 1,
  "hooks": {
    "preToolUse": [
      {
        "command": "./validate-shell.sh",
        "matcher": "Shell"
      }
    ],
    "subagentStart": [
      {
        "command": "./validate-explore.sh",
        "matcher": "explore|shell"
      }
    ],
    "beforeShellExecution": [
      {
        "command": "./approve-network.sh",
        "matcher": "curl|wget|nc "
      }
    ]
  }
}
```

- **subagentStart**: The matcher runs against the **subagent type** (e.g. `explore`, `shell`, `generalPurpose`). Use it to run hooks only when a specific kind of subagent is started. The example above runs `validate-explore.sh` only for explore or shell subagents.
- **beforeShellExecution**: The matcher runs against the **shell command** string. Use it to run hooks only when the command matches a pattern (e.g. network calls, file deletions). The example above runs `approve-network.sh` only when the command contains `curl`, `wget`, or `nc `.

**Available matchers by hook:**

- **preToolUse / postToolUse / postToolUseFailure**: Filter by tool type. Values include `Shell`, `Read`, `Write`, `Grep`, `Delete`, `Task`, and MCP tools using the `MCP:<tool_name>` format.
- **subagentStart / subagentStop**: Filter by subagent type (`generalPurpose`, `explore`, `shell`, etc.).
- **beforeShellExecution / afterShellExecution**: Filter by the shell command text; the matcher is matched against the full command string.
- **beforeReadFile**: Matched against the value `Read`.
- **afterFileEdit**: Matched against the value `Write`.
- **beforeTabFileRead**: Matched against the value `TabRead`.
- **afterTabFileEdit**: Matched against the value `TabWrite`.
- **beforeSubmitPrompt**: Matched against the value `UserPromptSubmit`.
- **stop**: Matched against the value `Stop`.
- **afterAgentResponse**: Matched against the value `AgentResponse`.
- **afterAgentThought**: Matched against the value `AgentThought`.

## Team Distribution

Hooks can be distributed to team members using project hooks (via version control), MDM tools, or Cursor's cloud distribution system.

### Project Hooks (Version Control)

Project hooks are the simplest way to share hooks with your team. Place a `hooks.json` file at `<project-root>/.cursor/hooks.json` and commit it to your repository. When team members open the project in a trusted workspace, Cursor automatically loads and runs the project hooks.

Cloud agents also load these project hooks when they work on your repository in
the cloud.

Project hooks:

- Are stored in version control alongside your code
- Automatically load for all team members in trusted workspaces
- Can be project-specific (e.g., enforce formatting standards for a particular codebase)
- Require the workspace to be trusted to run (for security)

### MDM Distribution

Distribute hooks across your organization using Mobile Device Management (MDM) tools. Place the `hooks.json` file and hook scripts in the target directories on each machine.

**User home directory** (per-user distribution):

- `~/.cursor/hooks.json`
- `~/.cursor/hooks/` (for hook scripts)

**Global directories** (system-wide distribution):

- macOS: `/Library/Application Support/Cursor/hooks.json`
- Linux/WSL: `/etc/cursor/hooks.json`
- Windows: `C:\\ProgramData\\Cursor\\hooks.json`

Note: MDM-based distribution is fully managed by your organization. Cursor does not deploy or manage files through your MDM solution. Ensure your internal IT or security team handles configuration, deployment, and updates in accordance with your organization's policies.

### Cloud Distribution (Enterprise Only)

Enterprise teams can use Cursor's native cloud distribution to automatically sync hooks to all team members. Configure hooks in the [web dashboard](https://cursor.com/dashboard/team-content?section=hooks). Cursor automatically delivers configured hooks to all client machines when team members log in.

Cloud distribution provides:

- Automatic synchronization to all team members (every thirty minutes)
- Operating system targeting for platform-specific hooks
- Centralized management through the dashboard

Enterprise administrators can create, edit, and manage team hooks from the dashboard without requiring access to individual machines.

[Contact sales](https://cursor.com/contact-sales?source=docs-hooks-cloud) to get Enterprise cloud hook distribution.

## Reference

### Common schema

#### Input (all hooks)

All hooks receive a base set of fields in addition to their hook-specific fields:

```json
{
  "conversation_id": "string",
  "generation_id": "string",
  "model": "string",
  "model_id": "string",
  "model_params": [{ "id": "string", "value": "string" }],
  "hook_event_name": "string",
  "cursor_version": "string",
  "workspace_roots": ["<path>"],
  "user_email": "string | null",
  "transcript_path": "string | null"
}
```

| Field             | Type              | Description                                                                                               |
| ----------------- | ----------------- | --------------------------------------------------------------------------------------------------------- |
| `conversation_id` | string            | Stable ID of the conversation across many turns                                                           |
| `generation_id`   | string            | The current generation that changes with every user message                                               |
| `model`           | string            | Legacy model slug configured for the composer that triggered the hook                                     |
| `model_id`        | string (optional) | Structured ID for the selected model, when available                                                      |
| `model_params`    | array (optional)  | Selected model parameters, such as thinking, context, or effort. Each item has an `id` and `value`.       |
| `hook_event_name` | string            | Which hook is being run                                                                                   |
| `cursor_version`  | string            | Cursor application version (e.g. "1.7.2")                                                                 |
| `workspace_roots` | string\[]         | The list of root folders in the workspace (normally just one, but multiroot workspaces can have multiple) |
| `user_email`      | string \| null    | Email address of the authenticated user, if available                                                     |
| `transcript_path` | string \| null    | Path to the main conversation transcript file (null if transcripts disabled)                              |

App lifecycle hooks (`workspaceOpen`) fire outside any agent session, so the request omits `conversation_id`, `generation_id`, `model`, `session_id`, and `transcript_path`. They still receive `hook_event_name`, `cursor_version`, `workspace_roots`, and `user_email`.

### Hook events

#### preToolUse

Called before any tool execution. This is a generic hook that fires for all tool types (Shell, Read, Write, MCP, Task, etc.). Use matchers to filter by specific tools.

```json
// Input
{
  "tool_name": "Shell",
  "tool_input": { "command": "npm install", "working_directory": "/project" },
  "tool_use_id": "abc123",
  "cwd": "/project",
  "model": "claude-opus-4-7-thinking-max",
  "model_id": "claude-opus-4-7",
  "model_params": [
    { "id": "thinking", "value": "true" },
    { "id": "context", "value": "1m" },
    { "id": "effort", "value": "max" }
  ],
  "agent_message": "Installing dependencies..."
}

// Output
{
  "permission": "allow" | "deny",
  "user_message": "<message shown in client when denied>",
  "agent_message": "<message sent to agent when denied>",
  "updated_input": { "command": "npm ci" }
}
```

| Output Field    | Type              | Description                                                                                                         |
| --------------- | ----------------- | ------------------------------------------------------------------------------------------------------------------- |
| `permission`    | string            | `"allow"` to proceed, `"deny"` to block. `"ask"` is accepted by the schema but not enforced for `preToolUse` today. |
| `user_message`  | string (optional) | Message shown to the user when the action is denied                                                                 |
| `agent_message` | string (optional) | Message fed back to the agent when the action is denied                                                             |
| `updated_input` | object (optional) | Modified tool input to use instead                                                                                  |

#### postToolUse

Called after successful tool execution. Useful for auditing, analytics, and injecting context.

```json
// Input
{
  "tool_name": "Shell",
  "tool_input": { "command": "npm test" },
  "tool_output": "{\"exitCode\":0,\"stdout\":\"All tests passed\"}",
  "tool_use_id": "abc123",
  "cwd": "/project",
  "duration": 5432,
  "model": "claude-opus-4-7-thinking-max",
  "model_id": "claude-opus-4-7",
  "model_params": [
    { "id": "thinking", "value": "true" },
    { "id": "context", "value": "1m" },
    { "id": "effort", "value": "max" }
  ]
}

// Output
{
  "updated_mcp_tool_output": { "modified": "output" },
  "additional_context": "Test coverage report attached."
}
```

| Input Field   | Type   | Description                                                           |
| ------------- | ------ | --------------------------------------------------------------------- |
| `duration`    | number | Execution time in milliseconds                                        |
| `tool_output` | string | JSON-stringified result payload from the tool (not raw terminal text) |

| Output Field              | Type              | Description                                                        |
| ------------------------- | ----------------- | ------------------------------------------------------------------ |
| `updated_mcp_tool_output` | object (optional) | For MCP tools only: replaces the tool output seen by the model     |
| `additional_context`      | string (optional) | Extra context injected into the conversation after the tool result |

#### postToolUseFailure

Called when a tool fails, times out, or is denied. Useful for error tracking and recovery logic.

```json
// Input
{
  "tool_name": "Shell",
  "tool_input": { "command": "npm test" },
  "tool_use_id": "abc123",
  "cwd": "/project",
  "error_message": "Command timed out after 30s",
  "failure_type": "timeout" | "error" | "permission_denied",
  "duration": 5000,
  "is_interrupt": false
}

// Output
{
  "additional_context": "Tests time out on CI runners. Retry with --maxWorkers=2."
}
```

| Input Field     | Type    | Description                                                       |
| --------------- | ------- | ----------------------------------------------------------------- |
| `error_message` | string  | Description of the failure                                        |
| `failure_type`  | string  | Type of failure: `"error"`, `"timeout"`, or `"permission_denied"` |
| `duration`      | number  | Time in milliseconds until the failure occurred                   |
| `is_interrupt`  | boolean | Whether this failure was caused by a user interrupt/cancellation  |

| Output Field         | Type              | Description                                                               |
| -------------------- | ----------------- | ------------------------------------------------------------------------- |
| `additional_context` | string (optional) | Extra context injected into the conversation after the failed tool result |

#### subagentStart

Called before spawning a subagent (Task tool). Can allow or deny subagent creation.

```json
// Input
{
  "subagent_id": "abc-123",
  "subagent_type": "generalPurpose",
  "task": "Explore the authentication flow",
  "parent_conversation_id": "conv-456",
  "tool_call_id": "tc-789",
  "subagent_model": "claude-sonnet-4-20250514",
  "is_parallel_worker": false,
  "git_branch": "feature/auth"
}

// Output
{
  "permission": "allow" | "deny",
  "user_message": "<message shown when denied>"
}
```

| Input Field              | Type              | Description                                                  |
| ------------------------ | ----------------- | ------------------------------------------------------------ |
| `subagent_id`            | string            | Unique identifier for this subagent instance                 |
| `subagent_type`          | string            | Type of subagent: `generalPurpose`, `explore`, `shell`, etc. |
| `task`                   | string            | The task description given to the subagent                   |
| `parent_conversation_id` | string            | Conversation ID of the parent agent session                  |
| `tool_call_id`           | string            | ID of the tool call that triggered the subagent              |
| `subagent_model`         | string            | Model the subagent will use                                  |
| `is_parallel_worker`     | boolean           | Whether this subagent is running as a parallel worker        |
| `git_branch`             | string (optional) | Git branch the subagent will operate on, if applicable       |

| Output Field   | Type              | Description                                                                                                       |
| -------------- | ----------------- | ----------------------------------------------------------------------------------------------------------------- |
| `permission`   | string            | `"allow"` to proceed, `"deny"` to block. `"ask"` is not supported for `subagentStart` and is treated as `"deny"`. |
| `user_message` | string (optional) | Message shown to the user when the subagent is denied                                                             |

#### subagentStop

Called when a subagent completes, errors, or is aborted. Can trigger follow-up actions.

```json
// Input
{
  "subagent_type": "generalPurpose",
  "status": "completed" | "error" | "aborted",
  "task": "Explore the authentication flow",
  "description": "Exploring auth flow",
  "summary": "<subagent output summary>",
  "duration_ms": 45000,
  "message_count": 12,
  "tool_call_count": 8,
  "loop_count": 0,
  "modified_files": ["src/auth.ts"],
  "agent_transcript_path": "/path/to/subagent/transcript.txt"
}

// Output
{
  "followup_message": "<auto-continue with this message>"
}
```

| Input Field             | Type           | Description                                                                                      |
| ----------------------- | -------------- | ------------------------------------------------------------------------------------------------ |
| `subagent_type`         | string         | Type of subagent: `generalPurpose`, `explore`, `shell`, etc.                                     |
| `status`                | string         | `"completed"`, `"error"`, or `"aborted"`                                                         |
| `task`                  | string         | The task description given to the subagent                                                       |
| `description`           | string         | Short description of the subagent's purpose                                                      |
| `summary`               | string         | Output summary from the subagent                                                                 |
| `duration_ms`           | number         | Execution time in milliseconds                                                                   |
| `message_count`         | number         | Number of messages exchanged during the subagent session                                         |
| `tool_call_count`       | number         | Number of tool calls the subagent made                                                           |
| `loop_count`            | number         | Number of times a `subagentStop` follow-up has already triggered for this subagent (starts at 0) |
| `modified_files`        | string\[]      | Files the subagent modified                                                                      |
| `agent_transcript_path` | string \| null | Path to the subagent's own transcript file (separate from the parent conversation)               |

| Output Field       | Type              | Description                                                                    |
| ------------------ | ----------------- | ------------------------------------------------------------------------------ |
| `followup_message` | string (optional) | Auto-continue with this message. Only consumed when `status` is `"completed"`. |

The `followup_message` field enables loop-style flows where subagent completion triggers the next iteration. Follow-ups are subject to the same configurable loop limit as the `stop` hook (default 5, configurable via `loop_limit`).

#### beforeShellExecution / beforeMCPExecution

Called before any shell command or MCP tool is executed. Return a permission decision.

Invalid JSON or a response that doesn't match the hook's schema blocks the action. Crashes, timeouts, and non-zero exit codes other than `2` fail open by default: Cursor logs the failure and allows the action through. Set `failClosed: true` on the hook definition to block on those failures too. This is recommended for security-critical `beforeMCPExecution` hooks.

```json
// beforeShellExecution input
{
  "command": "<full terminal command>",
  "cwd": "<current working directory>",
  "sandbox": false
}

// beforeMCPExecution input
{
  "tool_name": "<tool name>",
  "tool_input": "<json params>",
  "mcp_server_name": "<server name from mcp.json>"
}
// Plus either (HTTP/SSE servers):
{ "url": "<server url>", "mcp_server_url": "<server url>" }
// Or (stdio servers):
{ "command": "<launch command and args>" }

// Output
{
  "permission": "allow" | "deny" | "ask",
  "user_message": "<message shown in client>",
  "agent_message": "<message sent to agent>"
}
```

| Field             | Type   | Description                                                                                          |
| ----------------- | ------ | ---------------------------------------------------------------------------------------------------- |
| `tool_name`       | string | Name of the MCP tool about to run                                                                    |
| `tool_input`      | string | JSON params string that will be passed to the tool                                                   |
| `mcp_server_name` | string | The server's key in its `mcp.json` (for example, `linear`). Use this to recognize a specific server. |
| `mcp_server_url`  | string | Server URL, present only for HTTP/SSE servers                                                        |
| `url`             | string | Same as `mcp_server_url`; present only for HTTP/SSE servers                                          |
| `command`         | string | The stdio launch command and arguments joined with spaces; present only for stdio servers            |

Match on `mcp_server_name` (and `tool_name`) to decide whether a call targets your server. `command` is the launch string from the server's config and can differ between installs: relative paths, `${CURSOR_PLUGIN_ROOT}` expansion, or an HTTP transport (which has no `command` at all). A hook that allows anything it does not recognize should treat a missing or unexpected `mcp_server_name` as a deny.

#### afterShellExecution

Fires after a shell command executes; useful for auditing or collecting metrics from command output.

```json
// Input
{
  "command": "<full terminal command>",
  "output": "<full terminal output>",
  "duration": 1234,
  "sandbox": false
}
```

| Field      | Type    | Description                                                                              |
| ---------- | ------- | ---------------------------------------------------------------------------------------- |
| `command`  | string  | The full terminal command that was executed                                              |
| `output`   | string  | Full output captured from the terminal                                                   |
| `duration` | number  | Duration in milliseconds spent executing the shell command (excludes approval wait time) |
| `sandbox`  | boolean | Whether the command ran in a sandboxed environment                                       |

#### afterMCPExecution

Fires after an MCP tool executes; includes the tool's input parameters and full JSON result.

```json
// Input
{
  "tool_name": "<tool name>",
  "tool_input": "<json params>",
  "mcp_server_name": "<server name from mcp.json>",
  "result_json": "<tool result json>",
  "duration": 1234
}
```

| Field             | Type   | Description                                                                         |
| ----------------- | ------ | ----------------------------------------------------------------------------------- |
| `tool_name`       | string | Name of the MCP tool that was executed                                              |
| `tool_input`      | string | JSON params string passed to the tool                                               |
| `mcp_server_name` | string | The server's key in its `mcp.json`                                                  |
| `mcp_server_url`  | string | Server URL, present only for HTTP/SSE servers                                       |
| `result_json`     | string | JSON string of the tool response                                                    |
| `duration`        | number | Duration in milliseconds spent executing the MCP tool (excludes approval wait time) |

#### afterFileEdit

Fires after the Agent edits a file; useful for formatters or accounting of agent-written code.

```json
// Input
{
  "file_path": "<absolute path>",
  "edits": [{ "old_string": "<search>", "new_string": "<replace>" }]
}
```

#### beforeReadFile

Called before Agent reads a file. Use for access control to block sensitive files from being sent to the model.

Invalid JSON or a response that doesn't match the hook's schema blocks the read. Crashes, timeouts, and non-zero exit codes other than `2` are logged and the read is allowed through by default. Set `failClosed: true` on the hook definition to block the read on those failures too.

```json
// Input
{
  "file_path": "<absolute path>",
  "content": "<file contents>",
  "attachments": [
    {
      "type": "file" | "rule",
      "file_path": "<absolute path>"
    }
  ]
}

// Output
{
  "permission": "allow" | "deny",
  "user_message": "<message shown when denied>"
}
```

| Input Field   | Type   | Description                                                                                                       |
| ------------- | ------ | ----------------------------------------------------------------------------------------------------------------- |
| `file_path`   | string | Absolute path to the file being read                                                                              |
| `content`     | string | Full contents of the file                                                                                         |
| `attachments` | array  | Context attachments associated with the prompt. Each entry has a `type` (`"file"` or `"rule"`) and a `file_path`. |

| Output Field   | Type              | Description                             |
| -------------- | ----------------- | --------------------------------------- |
| `permission`   | string            | `"allow"` to proceed, `"deny"` to block |
| `user_message` | string (optional) | Message shown to user when denied       |

#### beforeTabFileRead

Called before Tab (inline completions) reads a file. Enable redaction or access control before Tab accesses file contents.

**Key differences from `beforeReadFile`:**

- Only triggered by Tab, not Agent
- Does not include `attachments` field (Tab doesn't use prompt attachments)
- Useful for applying different policies to autonomous Tab operations

```json
// Input
{
  "file_path": "<absolute path>",
  "content": "<file contents>"
}

// Output
{
  "permission": "allow" | "deny"
}
```

#### afterTabFileEdit

Called after Tab (inline completions) edits a file. Useful for formatters or auditing of Tab-written code.

**Key differences from `afterFileEdit`:**

- Only triggered by Tab, not Agent
- Includes detailed edit information: `range`, `old_line`, and `new_line` for precise edit tracking
- Useful for fine-grained formatting or analysis of Tab edits

```json
// Input
{
  "file_path": "<absolute path>",
  "edits": [
    {
      "old_string": "<search>",
      "new_string": "<replace>",
      "range": {
        "start_line_number": 10,
        "start_column": 5,
        "end_line_number": 10,
        "end_column": 20
      },
      "old_line": "<line before edit>",
      "new_line": "<line after edit>"
    }
  ]
}

// Output
{
  // No output fields currently supported
}
```

#### beforeSubmitPrompt

Called right after user hits send but before backend request. Can prevent submission.

```json
// Input
{
  "prompt": "<user prompt text>",
  "attachments": [
    {
      "type": "file" | "rule",
      "file_path": "<absolute path>"
    }
  ]
}

// Output
{
  "continue": true | false,
  "user_message": "<message shown to user when blocked>"
}
```

| Output Field   | Type              | Description                                          |
| -------------- | ----------------- | ---------------------------------------------------- |
| `continue`     | boolean           | Whether to allow the prompt submission to proceed    |
| `user_message` | string (optional) | Message shown to the user when the prompt is blocked |

#### afterAgentResponse

Called after the agent has completed an assistant message.

```json
// Input
{
  "text": "<assistant final text>"
}
```

#### afterAgentThought

Called after the agent completes a thinking block. Useful for observing the agent's reasoning process.

```json
// Input
{
  "text": "<fully aggregated thinking text>",
  "duration_ms": 5000
}

// Output
{
  // No output fields currently supported
}
```

| Field         | Type              | Description                                            |
| ------------- | ----------------- | ------------------------------------------------------ |
| `text`        | string            | Fully aggregated thinking text for the completed block |
| `duration_ms` | number (optional) | Duration in milliseconds for the thinking block        |

#### stop

Called when the agent loop ends. Can optionally auto-submit a follow-up user message to keep iterating.

```json
// Input
{
  "status": "completed" | "aborted" | "error",
  "loop_count": 0
}
```

```json
// Output
{
  "followup_message": "<message text>"
}
```

- The optional `followup_message` is a string. When provided and non-empty, Cursor will automatically submit it as the next user message. This enables loop-style flows (e.g., iterate until a goal is met).
- The `loop_count` field indicates how many times the stop hook has already triggered an automatic follow-up for this conversation (starts at 0). The default limit is 5 auto follow-ups per script, configurable via the `loop_limit` option. Set `loop_limit` to `null` to remove the cap. The same limit applies to `subagentStop` follow-ups.

#### sessionStart

Called when a new composer conversation is created. This hook runs as fire-and-forget; the agent loop does not wait for or enforce a blocking response. Use it to set up session-specific environment variables or inject additional context.

```json
// Input
{
  "session_id": "<unique session identifier>",
  "is_background_agent": true | false,
  "composer_mode": "agent" | "ask" | "edit"
}
```

```json
// Output
{
  "env": { "<key>": "<value>" },
  "additional_context": "<context to add to conversation>"
}
```

| Input Field           | Type              | Description                                                         |
| --------------------- | ----------------- | ------------------------------------------------------------------- |
| `session_id`          | string            | Unique identifier for this session (same as `conversation_id`)      |
| `is_background_agent` | boolean           | Whether this is a background agent session vs interactive session   |
| `composer_mode`       | string (optional) | The mode the composer is starting in (e.g., "agent", "ask", "edit") |

| Output Field         | Type              | Description                                                                                |
| -------------------- | ----------------- | ------------------------------------------------------------------------------------------ |
| `env`                | object (optional) | Environment variables to set for this session. Available to all subsequent hook executions |
| `additional_context` | string (optional) | Additional context to add to the conversation's initial system context                     |

The schema also accepts `continue` and `user_message` fields, but current callers do not enforce them. Session creation is not blocked even when `continue` is `false`.

#### sessionEnd

Called when a composer conversation ends. This is a fire-and-forget hook useful for logging, analytics, or cleanup tasks. The response is logged but not used.

```json
// Input
{
  "session_id": "<unique session identifier>",
  "reason": "completed" | "aborted" | "error" | "window_close" | "user_close",
  "duration_ms": 45000,
  "is_background_agent": true | false,
  "final_status": "<status string>",
  "error_message": "<error details if reason is 'error'>"
}
```

```json
// Output
{
  // No output fields - fire and forget
}
```

| Input Field           | Type              | Description                                                                               |
| --------------------- | ----------------- | ----------------------------------------------------------------------------------------- |
| `session_id`          | string            | Unique identifier for the session that is ending                                          |
| `reason`              | string            | How the session ended: "completed", "aborted", "error", "window\_close", or "user\_close" |
| `duration_ms`         | number            | Total duration of the session in milliseconds                                             |
| `is_background_agent` | boolean           | Whether this was a background agent session                                               |
| `final_status`        | string            | Final status of the session                                                               |
| `error_message`       | string (optional) | Error message if reason is "error"                                                        |

#### preCompact

Called before context window compaction/summarization occurs. This is an observational hook that cannot block or modify the compaction behavior. Useful for logging when compaction happens or notifying users.

```json
// Input
{
  "trigger": "auto" | "manual",
  "context_usage_percent": 85,
  "context_tokens": 120000,
  "context_window_size": 128000,
  "message_count": 45,
  "messages_to_compact": 30,
  "is_first_compaction": true | false
}
```

```json
// Output
{
  "user_message": "<message to show when compaction occurs>"
}
```

| Input Field             | Type    | Description                                                |
| ----------------------- | ------- | ---------------------------------------------------------- |
| `trigger`               | string  | What triggered the compaction: "auto" or "manual"          |
| `context_usage_percent` | number  | Current context window usage as a percentage (0-100)       |
| `context_tokens`        | number  | Current context window token count                         |
| `context_window_size`   | number  | Maximum context window size in tokens                      |
| `message_count`         | number  | Number of messages in the conversation                     |
| `messages_to_compact`   | number  | Number of messages that will be summarized                 |
| `is_first_compaction`   | boolean | Whether this is the first compaction for this conversation |

| Output Field   | Type              | Description                                        |
| -------------- | ----------------- | -------------------------------------------------- |
| `user_message` | string (optional) | Message to show to the user when compaction occurs |

#### workspaceOpen

Fires once when Cursor opens a workspace and again on every workspace folder change. Skipped when the window has zero workspace folders. Runs in the Cursor desktop app and CLI.

```json
// Input
{
  "hook_event_name": "workspaceOpen",
  "cursor_version": "string",
  "workspace_roots": ["<absolute path>"],
  "user_email": "string | null"
}

// Output
{
  "pluginPaths": ["<absolute path>", "..."]
}
```

| Output Field  | Type                 | Description                                                             |
| ------------- | -------------------- | ----------------------------------------------------------------------- |
| `pluginPaths` | string\[] (optional) | Absolute paths to plugin directories to load for the current workspace. |

