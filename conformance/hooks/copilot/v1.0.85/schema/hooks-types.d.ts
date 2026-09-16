// verbatim slice of copilot-sdk/types.d.ts (@github/copilot-linux-x64@1.0.85, sha256 2911ecb4aac830b7c129f2accf01086ae47a5250700dc050e95dfa33def862c4): BaseHookInput through SessionHooks
/**
 * Base interface for all hook inputs
 */
export interface BaseHookInput {
    /** The runtime session ID of the session that triggered the hook.
     * For sub-agent hooks this differs from `invocation.sessionId`. */
    sessionId: string;
    /** Time at which the hook event was emitted by the runtime. */
    timestamp: Date;
    workingDirectory: string;
}
/**
 * Input for pre-tool-use hook
 */
export interface PreToolUseHookInput extends BaseHookInput {
    toolName: string;
    toolArgs: unknown;
}
/**
 * Output for pre-tool-use hook
 */
export interface PreToolUseHookOutput {
    permissionDecision?: "allow" | "deny" | "ask";
    permissionDecisionReason?: string;
    modifiedArgs?: unknown;
    additionalContext?: string;
    suppressOutput?: boolean;
}
/**
 * Handler for pre-tool-use hook
 */
export type PreToolUseHandler = (input: PreToolUseHookInput, invocation: {
    sessionId: string;
}) => Promise<PreToolUseHookOutput | void> | PreToolUseHookOutput | void;
/**
 * Input for pre-MCP-tool-call hook
 */
export interface PreMcpToolCallHookInput extends BaseHookInput {
    toolCallId?: string;
    serverName: string;
    toolName: string;
    arguments: unknown;
    _meta?: Record<string, unknown>;
}
/**
 * Output for pre-MCP-tool-call hook
 */
export interface PreMcpToolCallHookOutput {
    /**
     * Hook-controlled metadata to use for the outgoing MCP request.
     * - undefined/absent: preserve the current request `_meta`
     * - object: use this object as request `_meta`
     * - null: omit `_meta`
     */
    metaToUse?: Record<string, unknown> | null;
}
/**
 * Handler for pre-MCP-tool-call hook
 */
export type PreMcpToolCallHandler = (input: PreMcpToolCallHookInput, invocation: {
    sessionId: string;
}) => Promise<PreMcpToolCallHookOutput | void> | PreMcpToolCallHookOutput | void;
/**
 * Input for post-tool-use hook
 */
export interface PostToolUseHookInput extends BaseHookInput {
    toolName: string;
    toolArgs: unknown;
    toolResult: ToolResultObject;
}
/**
 * Output for post-tool-use hook
 */
export interface PostToolUseHookOutput {
    modifiedResult?: ToolResultObject;
    additionalContext?: string;
    suppressOutput?: boolean;
}
/**
 * Handler for post-tool-use hook
 */
export type PostToolUseHandler = (input: PostToolUseHookInput, invocation: {
    sessionId: string;
}) => Promise<PostToolUseHookOutput | void> | PostToolUseHookOutput | void;
/**
 * Input for post-tool-use-failure hook.
 *
 * Dispatched after a tool execution whose `resultType` is `"failure"`.
 * The input differs from {@link PostToolUseHookInput}: the host CLI does not
 * forward the full `ToolResultObject` to failure hooks — only `error`, the
 * stringified failure message extracted from the tool's result, is provided.
 */
export interface PostToolUseFailureHookInput extends BaseHookInput {
    toolName: string;
    toolArgs: unknown;
    /**
     * Failure message from the tool's result (the `error` field of the
     * underlying `ToolResultObject`, falling back to its text/log fields).
     */
    error: string;
}
/**
 * Output for post-tool-use-failure hook.
 *
 * Only `additionalContext` is consumed by the host CLI — it is appended as
 * hidden guidance to the model alongside the failed tool result. Other fields
 * such as `modifiedResult` or `suppressOutput` are not honored for failure
 * hooks (see {@link PostToolUseHookOutput} for the success-only hook).
 */
export interface PostToolUseFailureHookOutput {
    additionalContext?: string;
}
/**
 * Handler for post-tool-use-failure hook.
 *
 * Fires after a tool execution whose result was `"failure"`. `onPostToolUse`
 * only fires for successful results, so register this handler to observe or
 * react to failed tool outcomes.
 *
 * Note: `"rejected"`, `"denied"`, and `"timeout"` results do not currently
 * trigger this hook either — only `"failure"` does.
 */
export type PostToolUseFailureHandler = (input: PostToolUseFailureHookInput, invocation: {
    sessionId: string;
}) => Promise<PostToolUseFailureHookOutput | void> | PostToolUseFailureHookOutput | void;
/**
 * Input for user-prompt-submitted hook
 */
export interface UserPromptSubmittedHookInput extends BaseHookInput {
    prompt: string;
}
/**
 * Output for user-prompt-submitted hook
 */
export interface UserPromptSubmittedHookOutput {
    modifiedPrompt?: string;
    additionalContext?: string;
    suppressOutput?: boolean;
}
/**
 * Handler for user-prompt-submitted hook
 */
export type UserPromptSubmittedHandler = (input: UserPromptSubmittedHookInput, invocation: {
    sessionId: string;
}) => Promise<UserPromptSubmittedHookOutput | void> | UserPromptSubmittedHookOutput | void;
/**
 * Input for the user-prompt-transformed hook.
 *
 * This hook runs after the runtime has transformed the submitted prompt with
 * generated context, but before it is persisted to session history or sent to
 * the model.
 */
export interface UserPromptTransformedHookInput extends BaseHookInput {
    prompt: string;
    transformedPrompt: string;
}
/**
 * Output for the user-prompt-transformed hook.
 */
export interface UserPromptTransformedHookOutput {
    modifiedTransformedPrompt?: string;
}
/**
 * Handler for the user-prompt-transformed hook.
 */
export type UserPromptTransformedHandler = (input: UserPromptTransformedHookInput, invocation: {
    sessionId: string;
}) => Promise<UserPromptTransformedHookOutput | void> | UserPromptTransformedHookOutput | void;
/**
 * Input for session-start hook
 */
export interface SessionStartHookInput extends BaseHookInput {
    source: "startup" | "resume" | "new";
    initialPrompt?: string;
}
/**
 * Output for session-start hook
 */
export interface SessionStartHookOutput {
    additionalContext?: string;
    modifiedConfig?: Record<string, unknown>;
}
/**
 * Handler for session-start hook
 */
export type SessionStartHandler = (input: SessionStartHookInput, invocation: {
    sessionId: string;
}) => Promise<SessionStartHookOutput | void> | SessionStartHookOutput | void;
/**
 * Input for session-end hook
 */
export interface SessionEndHookInput extends BaseHookInput {
    reason: "complete" | "error" | "abort" | "timeout" | "user_exit";
    finalMessage?: string;
    error?: string;
}
/**
 * Output for session-end hook
 */
export interface SessionEndHookOutput {
    suppressOutput?: boolean;
    cleanupActions?: string[];
    sessionSummary?: string;
}
/**
 * Handler for session-end hook
 */
export type SessionEndHandler = (input: SessionEndHookInput, invocation: {
    sessionId: string;
}) => Promise<SessionEndHookOutput | void> | SessionEndHookOutput | void;
/**
 * Input for error-occurred hook
 */
export interface ErrorOccurredHookInput extends BaseHookInput {
    error: string;
    errorContext: "model_call" | "tool_execution" | "system" | "user_input";
    recoverable: boolean;
}
/**
 * Output for error-occurred hook
 */
export interface ErrorOccurredHookOutput {
    suppressOutput?: boolean;
    errorHandling?: "retry" | "skip" | "abort";
    retryCount?: number;
    userNotification?: string;
}
/**
 * Handler for error-occurred hook
 */
export type ErrorOccurredHandler = (input: ErrorOccurredHookInput, invocation: {
    sessionId: string;
}) => Promise<ErrorOccurredHookOutput | void> | ErrorOccurredHookOutput | void;
/**
 * Input for the agent-stop hook.
 *
 * Fires for the top-level (main) agent when it reaches a natural terminal stop
 * — i.e. the agent has gone idle without a pending non-terminal tool call and
 * was not aborted or blocked by a rejected tool. (For sub-agents, the runtime
 * fires a separate sub-agent stop lifecycle.)
 */
export interface AgentStopHookInput extends BaseHookInput {
    /** Why the agent stopped (for example, `"end_turn"`). */
    stopReason?: string;
    /** Path to the on-disk session transcript, when available. */
    transcriptPath?: string;
    /**
     * True when this stop is a re-entry triggered by a previous agent-stop
     * `block` decision (Claude-compatible `stop_hook_active` semantics). Lets a
     * handler avoid blocking indefinitely.
     */
    stopHookActive?: boolean;
}
/**
 * Output for the agent-stop hook.
 *
 * Return `{ decision: "block", reason }` to keep the agent running: the
 * `reason` is enqueued as a follow-up user message so the agent continues
 * working (for example, to remediate findings surfaced by the hook). The
 * runtime caps consecutive blocks to prevent runaway loops. Returning nothing
 * (or omitting `decision`) lets the agent stop normally.
 */
export interface AgentStopHookOutput {
    decision?: "block";
    reason?: string;
}
/**
 * Handler for the agent-stop hook.
 */
export type AgentStopHandler = (input: AgentStopHookInput, invocation: {
    sessionId: string;
}) => Promise<AgentStopHookOutput | void> | AgentStopHookOutput | void;
/**
 * Configuration for session hooks
 */
export interface SessionHooks {
    /**
     * Called before a tool is executed
     */
    onPreToolUse?: PreToolUseHandler;
    /**
     * Called before an MCP tool is called
     */
    onPreMcpToolCall?: PreMcpToolCallHandler;
    /**
     * Called after a tool is executed with a successful result.
     *
     * For failed tool executions, register {@link onPostToolUseFailure} instead;
     * this handler does not fire for non-success results.
     */
    onPostToolUse?: PostToolUseHandler;
    /**
     * Called after a tool execution whose result was `"failure"`.
     *
     * Register this handler alongside {@link onPostToolUse} to observe failed
     * tool calls — `onPostToolUse` only fires for successful results, so
     * without this hook failed tool calls are invisible to extensions.
     */
    onPostToolUseFailure?: PostToolUseFailureHandler;
    /**
     * Called when the user submits a prompt
     */
    onUserPromptSubmitted?: UserPromptSubmittedHandler;
    /**
     * Called after the runtime transforms a submitted prompt and before it is stored.
     */
    onUserPromptTransformed?: UserPromptTransformedHandler;
    /**
     * Called when a session starts
     */
    onSessionStart?: SessionStartHandler;
    /**
     * Called when a session ends
     */
    onSessionEnd?: SessionEndHandler;
    /**
     * Called when an error occurs
     */
    onErrorOccurred?: ErrorOccurredHandler;
    /**
     * Called when the top-level agent reaches a natural terminal stop (it went
     * idle without pending work and was not aborted). Return
     * `{ decision: "block", reason }` to keep the agent running with `reason`
     * enqueued as a follow-up message — for example, to have the agent
     * remediate findings the handler surfaced. Returning nothing lets the
     * agent stop.
     */
    onAgentStop?: AgentStopHandler;
}
