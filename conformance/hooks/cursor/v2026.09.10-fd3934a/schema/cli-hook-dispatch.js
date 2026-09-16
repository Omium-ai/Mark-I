// pretty-printed (prettier 3, no semantic change) from the pinned cursor-agent CLI bundle 2026.09.10-fd3934a; see README.md
// source: index.js, the agent-runtime hook request switch (the 10 steps the CLI dispatches at this pin); wrapped in a generator stub for the formatter
function* dispatch(P, i, Me, Fe) {
  var e,
    n,
    r,
    s,
    o,
    a,
    l,
    u,
    c,
    d,
    m,
    p,
    A,
    f,
    h,
    g,
    C,
    _,
    y,
    E,
    w,
    v,
    I,
    S,
    T,
    k,
    b,
    B,
    R,
    Q,
    N,
    D;
  switch (P.request.case) {
    case "preCompact": {
      const t = P.request.value,
        s = Object.assign(
          Object.assign(
            {
              conversation_id:
                null !== (e = t.conversationId) && void 0 !== e ? e : "",
              generation_id:
                null !== (n = t.generationId) && void 0 !== n ? n : "",
              model: null !== (r = t.model) && void 0 !== r ? r : "",
            },
            (0, Fe.U4)(t),
          ),
          {
            trigger: "manual" === t.trigger ? "manual" : "auto",
            context_usage_percent: t.contextUsagePercent,
            context_tokens: Number(t.contextTokens),
            context_window_size: Number(t.contextWindowSize),
            message_count: t.messageCount,
            messages_to_compact: t.messagesToCompact,
            is_first_compaction: t.isFirstCompaction,
          },
        ),
        o = yield this.hookExecutor.executeHookForStep(Fe._E.preCompact, s);
      return new i.S1({
        response: new i.w5({
          response: {
            case: "preCompact",
            value: new Me.$_({
              userMessage: null == o ? void 0 : o.user_message,
            }),
          },
        }),
      });
    }
    case "subagentStart": {
      const e = P.request.value,
        t = Object.assign(
          Object.assign(
            {
              conversation_id:
                null !== (s = e.conversationId) && void 0 !== s ? s : "",
              generation_id:
                null !== (o = e.generationId) && void 0 !== o ? o : "",
              model: null !== (a = e.model) && void 0 !== a ? a : "",
            },
            (0, Fe.U4)(e),
          ),
          {
            subagent_id: e.subagentId,
            subagent_type: e.subagentType,
            task: e.task,
            parent_conversation_id: e.parentConversationId,
            tool_call_id: e.toolCallId,
            subagent_model: e.subagentModel,
            is_parallel_worker: e.isParallelWorker,
            git_branch: e.gitBranch,
          },
        ),
        n = yield this.hookExecutor.executeHookForStep(Fe._E.subagentStart, t);
      return new i.S1({
        response: new i.w5({
          response: {
            case: "subagentStart",
            value: new Me.W0({
              permission: null == n ? void 0 : n.permission,
              userMessage: null == n ? void 0 : n.user_message,
              additionalContext: null == n ? void 0 : n.additional_context,
            }),
          },
        }),
      });
    }
    case "subagentStop": {
      const e = P.request.value,
        t = Object.assign(
          Object.assign(
            {
              conversation_id:
                null !== (l = e.conversationId) && void 0 !== l ? l : "",
              generation_id:
                null !== (u = e.generationId) && void 0 !== u ? u : "",
              model: null !== (c = e.model) && void 0 !== c ? c : "",
            },
            (0, Fe.U4)(e),
          ),
          {
            subagent_id: e.subagentId,
            subagent_type: e.subagentType,
            status: e.status,
            duration_ms: Number(e.durationMs),
            summary: e.summary,
            parent_conversation_id: e.parentConversationId,
            message_count: e.messageCount,
            tool_call_count: e.toolCallCount,
            error_message: e.errorMessage,
            modified_files: e.modifiedFiles,
            git_branch: e.gitBranch,
            loop_count: null !== (d = e.loopCount) && void 0 !== d ? d : 0,
            task: e.task,
            description: e.description,
          },
        ),
        n = yield this.hookExecutor.executeHookForStep(Fe._E.subagentStop, t);
      return new i.S1({
        response: new i.w5({
          response: {
            case: "subagentStop",
            value: new Me.AH({
              followupMessage: null == n ? void 0 : n.followup_message,
              additionalContext: null == n ? void 0 : n.additional_context,
            }),
          },
        }),
      });
    }
    case "beforeSubmitPrompt": {
      const e = P.request.value,
        t = yield this.hookExecutor.executeHookForStep(
          Fe._E.beforeSubmitPrompt,
          Object.assign(
            Object.assign(
              {
                conversation_id:
                  null !== (m = e.conversationId) && void 0 !== m ? m : "",
                generation_id:
                  null !== (p = e.generationId) && void 0 !== p ? p : "",
                model: null !== (A = e.model) && void 0 !== A ? A : "",
              },
              (0, Fe.U4)(e),
            ),
            {
              prompt: e.prompt,
              attachments:
                ((D = e.attachments),
                D.flatMap((e) =>
                  "file" === e.type || "rule" === e.type
                    ? [{ type: e.type, file_path: e.filePath }]
                    : [],
                )),
              composer_mode: e.composerMode,
            },
          ),
        );
      return new i.S1({
        response: new i.w5({
          response: {
            case: "beforeSubmitPrompt",
            value: new Me.u1({
              continue: null == t ? void 0 : t.continue,
              userMessage: null == t ? void 0 : t.user_message,
              additionalContext: null == t ? void 0 : t.additional_context,
            }),
          },
        }),
      });
    }
    case "afterAgentResponse": {
      const e = P.request.value;
      return (
        yield this.hookExecutor.executeHookForStep(
          Fe._E.afterAgentResponse,
          Object.assign(
            Object.assign(
              {
                conversation_id:
                  null !== (f = e.conversationId) && void 0 !== f ? f : "",
                generation_id:
                  null !== (h = e.generationId) && void 0 !== h ? h : "",
                model: null !== (g = e.model) && void 0 !== g ? g : "",
              },
              (0, Fe.U4)(e),
            ),
            {
              text: e.text,
              input_tokens:
                void 0 !== e.inputTokens ? Number(e.inputTokens) : void 0,
              output_tokens:
                void 0 !== e.outputTokens ? Number(e.outputTokens) : void 0,
              cache_read_tokens:
                void 0 !== e.cacheReadTokens
                  ? Number(e.cacheReadTokens)
                  : void 0,
              cache_write_tokens:
                void 0 !== e.cacheWriteTokens
                  ? Number(e.cacheWriteTokens)
                  : void 0,
            },
          ),
        ),
        new i.S1({
          response: new i.w5({
            response: { case: "afterAgentResponse", value: new Me.FW() },
          }),
        })
      );
    }
    case "afterAgentThought": {
      const e = P.request.value;
      return (
        yield this.hookExecutor.executeHookForStep(
          Fe._E.afterAgentThought,
          Object.assign(
            Object.assign(
              {
                conversation_id:
                  null !== (C = e.conversationId) && void 0 !== C ? C : "",
                generation_id:
                  null !== (_ = e.generationId) && void 0 !== _ ? _ : "",
                model: null !== (y = e.model) && void 0 !== y ? y : "",
              },
              (0, Fe.U4)(e),
            ),
            {
              text: e.text,
              duration_ms:
                void 0 !== e.durationMs ? Number(e.durationMs) : void 0,
            },
          ),
        ),
        new i.S1({
          response: new i.w5({
            response: { case: "afterAgentThought", value: new Me.H() },
          }),
        })
      );
    }
    case "stop": {
      const e = P.request.value,
        t = yield this.hookExecutor.executeHookForStep(
          Fe._E.stop,
          Object.assign(
            Object.assign(
              {
                conversation_id:
                  null !== (E = e.conversationId) && void 0 !== E ? E : "",
                generation_id:
                  null !== (w = e.generationId) && void 0 !== w ? w : "",
                model: null !== (v = e.model) && void 0 !== v ? v : "",
              },
              (0, Fe.U4)(e),
            ),
            {
              status: e.status,
              loop_count: e.loopCount,
              input_tokens:
                void 0 !== e.inputTokens ? Number(e.inputTokens) : void 0,
              output_tokens:
                void 0 !== e.outputTokens ? Number(e.outputTokens) : void 0,
              cache_read_tokens:
                void 0 !== e.cacheReadTokens
                  ? Number(e.cacheReadTokens)
                  : void 0,
              cache_write_tokens:
                void 0 !== e.cacheWriteTokens
                  ? Number(e.cacheWriteTokens)
                  : void 0,
            },
          ),
        );
      return new i.S1({
        response: new i.w5({
          response: {
            case: "stop",
            value: new Me.rT({
              followupMessage: null == t ? void 0 : t.followup_message,
            }),
          },
        }),
      });
    }
    case "preToolUse": {
      const e = P.request.value,
        t = e.toolInput ? e.toolInput.toJson() : {},
        n = Object.assign(
          Object.assign(
            {
              conversation_id:
                null !== (I = e.conversationId) && void 0 !== I ? I : "",
              generation_id:
                null !== (S = e.generationId) && void 0 !== S ? S : "",
              model: null !== (T = e.model) && void 0 !== T ? T : "",
            },
            (0, Fe.U4)(e),
          ),
          {
            tool_name: e.toolName,
            tool_input: t,
            tool_use_id: e.toolUseId,
            cwd: e.cwd,
          },
        ),
        r = yield this.hookExecutor.executeHookForStep(Fe._E.preToolUse, n);
      return new i.S1({
        response: new i.w5({
          response: {
            case: "preToolUse",
            value: new Me.Wn({
              permission: null == r ? void 0 : r.permission,
              userMessage: null == r ? void 0 : r.user_message,
              agentMessage: null == r ? void 0 : r.agent_message,
              updatedInput: (null == r ? void 0 : r.updated_input)
                ? JSON.stringify(r.updated_input)
                : void 0,
              additionalContext: null == r ? void 0 : r.additional_context,
            }),
          },
        }),
      });
    }
    case "postToolUse": {
      const e = P.request.value,
        t = e.toolInput ? e.toolInput.toJson() : {},
        n = Object.assign(
          Object.assign(
            {
              conversation_id:
                null !== (k = e.conversationId) && void 0 !== k ? k : "",
              generation_id:
                null !== (b = e.generationId) && void 0 !== b ? b : "",
              model: null !== (B = e.model) && void 0 !== B ? B : "",
            },
            (0, Fe.U4)(e),
          ),
          {
            tool_name: e.toolName,
            tool_input: t,
            tool_output: e.toolOutput,
            duration: Number(e.durationMs),
            tool_use_id: e.toolUseId,
            cwd: e.cwd,
          },
        ),
        r = yield this.hookExecutor.executeHookForStep(Fe._E.postToolUse, n);
      return new i.S1({
        response: new i.w5({
          response: {
            case: "postToolUse",
            value: new Me.uB({
              additionalContext: null == r ? void 0 : r.additional_context,
            }),
          },
        }),
      });
    }
    case "postToolUseFailure": {
      const e = P.request.value,
        t = e.toolInput ? e.toolInput.toJson() : {},
        n = Object.assign(
          Object.assign(
            {
              conversation_id:
                null !== (R = e.conversationId) && void 0 !== R ? R : "",
              generation_id:
                null !== (Q = e.generationId) && void 0 !== Q ? Q : "",
              model: null !== (N = e.model) && void 0 !== N ? N : "",
            },
            (0, Fe.U4)(e),
          ),
          {
            tool_name: e.toolName,
            tool_input: t,
            error_message: e.errorMessage,
            failure_type: e.failureType,
            duration: Number(e.durationMs),
            tool_use_id: e.toolUseId,
            is_interrupt: e.isInterrupt,
          },
        ),
        r = yield this.hookExecutor.executeHookForStep(
          Fe._E.postToolUseFailure,
          n,
        );
      return new i.S1({
        response: new i.w5({
          response: {
            case: "postToolUseFailure",
            value: new Me.U1({
              additionalContext: null == r ? void 0 : r.additional_context,
            }),
          },
        }),
      });
    }
    default:
      return new i.S1({ response: void 0 });
  }
}
