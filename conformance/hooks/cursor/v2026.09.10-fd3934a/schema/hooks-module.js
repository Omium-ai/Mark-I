// pretty-printed (prettier 3, no semantic change) from the pinned cursor-agent CLI bundle 2026.09.10-fd3934a; see README.md
// source: index.js module "../hooks/dist/index.js" (index.js sha256 3f26b0fe79c6788e7c0fc59bbf20956fcfce5950e7db8ab5dfc7e42c50eb6a80)
({
  "../hooks/dist/index.js"(e, t, n) {
    "use strict";
    n.d(t, {
      yB: () => T,
      aX: () => k,
      LQ: () => R,
      Qu: () => S,
      _E: () => r,
      q3: () => Z,
      D3: () => j,
      FS: () => q,
      fp: () => f,
      eg: () => p,
      bi: () => h,
      Qk: () => g,
      Uv: () => U,
      S6: () => K,
      Vf: () => M,
      DP: () => A,
      Xz: () => B,
      uu: () => b,
      yW: () => x,
      wb: () => O,
      x9: () => H,
      U4: () => I,
      sl: () => m,
      jO: () => N,
      RV: () => te,
    });
    const r = {
        beforeShellExecution: "beforeShellExecution",
        beforeMCPExecution: "beforeMCPExecution",
        afterShellExecution: "afterShellExecution",
        afterMCPExecution: "afterMCPExecution",
        beforeReadFile: "beforeReadFile",
        afterFileEdit: "afterFileEdit",
        beforeTabFileRead: "beforeTabFileRead",
        afterTabFileEdit: "afterTabFileEdit",
        stop: "stop",
        beforeSubmitPrompt: "beforeSubmitPrompt",
        afterAgentResponse: "afterAgentResponse",
        afterAgentThought: "afterAgentThought",
        sessionStart: "sessionStart",
        sessionEnd: "sessionEnd",
        preCompact: "preCompact",
        subagentStart: "subagentStart",
        subagentStop: "subagentStop",
        preToolUse: "preToolUse",
        postToolUse: "postToolUse",
        postToolUseFailure: "postToolUseFailure",
        workspaceOpen: "workspaceOpen",
      },
      s = {
        PreToolUse: r.preToolUse,
        PermissionRequest: null,
        PostToolUse: r.postToolUse,
        UserPromptSubmit: r.beforeSubmitPrompt,
        Stop: r.stop,
        SubagentStop: r.subagentStop,
        SessionStart: r.sessionStart,
        SessionEnd: r.sessionEnd,
        PreCompact: r.preCompact,
        Notification: null,
      },
      i = Object.fromEntries(
        Object.entries(s)
          .filter((e) => null !== e[1])
          .map(([e, t]) => [t, e]),
      ),
      o = {
        Bash: "Shell",
        Read: "Read",
        Write: "Write",
        Edit: "Write",
        Glob: null,
        Grep: "Grep",
        WebFetch: "WebFetch",
        WebSearch: "WebSearch",
        Task: "Task",
      },
      a = ["Glob"],
      l = ["Notification", "PermissionRequest"],
      u = { warn: () => {}, info: () => {} };
    function c(e, t) {
      const n = { loop_limit: null, failClosed: !1 };
      return (
        t && "*" !== t && (n.matcher = t),
        void 0 !== e.timeout && (n.timeout = e.timeout),
        "prompt" === e.type
          ? e.prompt
            ? Object.assign({ type: "prompt", prompt: e.prompt }, n)
            : null
          : e.command
            ? Object.assign({ type: "command", command: e.command }, n)
            : null
      );
    }
    function d(e, t, n = u) {
      const r = [];
      let s;
      if ("PreToolUse" === t || "PostToolUse" === t) {
        const t = (function (e, t = u) {
          if (!e || "*" === e) return "*";
          const n = e.split("|"),
            r = [],
            s = [];
          for (const e of n) {
            const t = e.trim();
            if (t.startsWith("mcp__")) {
              const e = t.split("__");
              if (e.length >= 3) {
                const t = e.slice(2).join("__");
                r.push(`MCP:${t}`);
                continue;
              }
            }
            const n = o[t];
            null !== n
              ? void 0 !== n
                ? r.includes(n) || r.push(n)
                : r.push(t)
              : a.includes(t) &&
                s.push(
                  `Tool "${t}" is not supported in Cursor and will be ignored`,
                );
          }
          for (const e of s) t.warn(e);
          return 0 === r.length ? null : r.join("|");
        })(e.matcher, n);
        if (null === t)
          return (
            n.warn(
              `All tools in matcher "${e.matcher}" are unsupported, skipping hooks`,
            ),
            []
          );
        s = "*" === t ? void 0 : t;
      } else
        "SessionStart" === t || "PreCompact" === t
          ? (e.matcher &&
              "*" !== e.matcher &&
              "" !== e.matcher &&
              ("SessionStart" === t
                ? ["startup", "resume", "clear", "compact"].includes(e.matcher)
                : ["manual", "auto"].includes(e.matcher)) &&
              n.warn(
                `${t} trigger matcher "${e.matcher}" is not supported in Cursor, hooks will fire for all triggers`,
              ),
            (s = void 0))
          : (s = void 0);
      for (const t of e.hooks) {
        const e = c(t, s);
        e && r.push(e);
      }
      return r;
    }
    function m(e, t = u) {
      const n = {};
      for (const [r, i] of Object.entries(e)) {
        const e = r;
        if (l.includes(e)) {
          t.warn(
            `Claude Code event "${e}" is not supported in Cursor and will be ignored`,
          );
          continue;
        }
        const o = s[e];
        if (!o) {
          t.warn(`Unknown Claude Code event "${e}", skipping`);
          continue;
        }
        const a = [];
        if (Array.isArray(i))
          for (const n of i) {
            const r = d(n, e, t);
            a.push(...r);
          }
        else
          void 0 !== i &&
            t.warn(
              `Claude Code event "${e}" has invalid value (expected array), skipping`,
            );
        if (a.length > 0) {
          const e = n[o] || [];
          n[o] = [...e, ...a];
        }
      }
      return { version: 1, hooks: n };
    }
    function p(e) {
      return e.hooks;
    }
    function A(e, t = {}) {
      if ("object" != typeof e || null === e) return !1;
      if (!("hooks" in e)) return !1;
      const n = e.hooks;
      if ("object" != typeof n || null === n) return !1;
      const r = n;
      for (const [e, n] of Object.entries(r))
        if (e in s && Array.isArray(n)) {
          const r = !0 === t.allowMatcherlessStop && "Stop" === e;
          for (const e of n)
            if (
              "object" == typeof e &&
              null !== e &&
              "hooks" in e &&
              Array.isArray(e.hooks) &&
              ("matcher" in e || r)
            )
              return !0;
        }
      return !1;
    }
    function f(e) {
      if ("object" != typeof e || null === e) return "unknown";
      const t = e,
        n = "object" == typeof t.hooks && null !== t.hooks ? t.hooks : null;
      if (!n) return "unknown";
      for (const e of Object.values(n)) {
        if (!Array.isArray(e) || 0 === e.length) continue;
        const t = e[0];
        if ("object" != typeof t || null === t) continue;
        const n = t;
        if ("hooks" in n && Array.isArray(n.hooks)) return "claude-code";
        if ("command" in n || "prompt" in n || "type" in n) return "cursor";
      }
      return "unknown";
    }
    function h(e, t) {
      switch (e) {
        case "beforeShellExecution":
        case "afterShellExecution":
          return t.command || void 0;
        case "beforeMCPExecution":
        case "afterMCPExecution": {
          const e = t;
          return e.tool_name ? `MCP:${e.tool_name}` : void 0;
        }
        case "beforeReadFile":
          return "Read";
        case "afterFileEdit":
          return "Write";
        case "beforeTabFileRead":
          return "TabRead";
        case "afterTabFileEdit":
          return "TabWrite";
        case "beforeSubmitPrompt":
          return "UserPromptSubmit";
        case "stop":
          return "Stop";
        case "afterAgentResponse":
          return "AgentResponse";
        case "afterAgentThought":
          return "AgentThought";
        case "subagentStart":
        case "subagentStop":
          return t.subagent_type || void 0;
        case "preToolUse":
        case "postToolUse":
        case "postToolUseFailure":
          return t.tool_name || void 0;
        default:
          return;
      }
    }
    function g(e, t) {
      return e.filter((e) =>
        (function (e, t) {
          if (!e.matcher || "" === e.matcher || "*" === e.matcher) return !0;
          if (void 0 === t) return !0;
          try {
            return new RegExp(e.matcher).test(t);
          } catch (e) {
            return !0;
          }
        })(e, t),
      );
    }
    const C = (e) => "string" == typeof e,
      _ = (e) => null !== e && "object" == typeof e && !Array.isArray(e),
      y = (e, t = []) => ({ isValid: e, errors: t });
    function E(e, t, n) {
      void 0 === e || C(e) || n.push(`${t} must be a string if provided`);
    }
    const w = (e) => {
        const t = [];
        return _(e) ? y(!0) : (t.push("Expected an object"), y(!1, t));
      },
      v = (e) => {
        const t = [],
          n = w(e);
        if (!n.isValid) return n;
        if (void 0 !== e.permission) {
          const n = ["allow", "deny", "ask"];
          n.includes(e.permission) ||
            t.push(
              `Invalid permission value. Expected one of: ${n.join(", ")}, or undefined`,
            );
        }
        return (
          void 0 !== e.user_message &&
            "string" != typeof e.user_message &&
            t.push("Invalid user_message value. Expected a string if provided"),
          void 0 !== e.agent_message &&
            "string" != typeof e.agent_message &&
            t.push(
              "Invalid agent_message value. Expected a string if provided",
            ),
          y(0 === t.length, t)
        );
      };
    function I(e) {
      const t = e.modelId,
        n = e.modelParams;
      return Object.assign(
        Object.assign({}, void 0 !== t && { model_id: t }),
        void 0 !== n && n.length > 0
          ? { model_params: n.map((e) => ({ id: e.id, value: e.value })) }
          : {},
      );
    }
    const S = new Set([
        r.sessionStart,
        r.beforeSubmitPrompt,
        r.preToolUse,
        r.postToolUse,
        r.postToolUseFailure,
      ]),
      T = 60,
      k = 5;
    function b(e) {
      return "prompt" === e.type;
    }
    function B(e) {
      return "command" === e.type || void 0 === e.type;
    }
    const R = 2,
      Q = {
        [r.beforeShellExecution]: v,
        [r.beforeMCPExecution]: v,
        [r.afterShellExecution]: (e) => {
          const t = w(e);
          return (t.isValid, t);
        },
        [r.afterMCPExecution]: (e) => {
          const t = w(e);
          return (t.isValid, t);
        },
        [r.beforeReadFile]: (e) => {
          const t = [],
            n = w(e);
          if (!n.isValid) return n;
          if (void 0 !== e.permission) {
            const n = ["allow", "deny"];
            n.includes(e.permission) ||
              t.push(
                `Invalid permission value. Expected one of: ${n.join(", ")}, or undefined`,
              );
          }
          return (
            void 0 !== e.user_message &&
              "string" != typeof e.user_message &&
              t.push("user_message must be a string if provided"),
            y(0 === t.length, t)
          );
        },
        [r.afterFileEdit]: (e) => {
          const t = w(e);
          return (t.isValid, t);
        },
        [r.beforeTabFileRead]: (e) => {
          const t = [],
            n = w(e);
          if (!n.isValid) return n;
          if (void 0 !== e.permission) {
            const n = ["allow", "deny"];
            n.includes(e.permission) ||
              t.push(
                `Invalid permission value. Expected one of: ${n.join(", ")}, or undefined`,
              );
          }
          return (
            void 0 !== e.user_message &&
              "string" != typeof e.user_message &&
              t.push("user_message must be a string if provided"),
            y(0 === t.length, t)
          );
        },
        [r.afterTabFileEdit]: (e) => w(e),
        [r.beforeSubmitPrompt]: (e) => {
          const t = w(e);
          if (!t.isValid) return t;
          const n = [];
          return (
            void 0 !== e.continue &&
              "boolean" != typeof e.continue &&
              n.push("continue must be a boolean if provided"),
            void 0 !== e.user_message &&
              "string" != typeof e.user_message &&
              n.push("user_message must be a string if provided"),
            void 0 === e.additional_context ||
              C(e.additional_context) ||
              n.push("additional_context must be a string if provided"),
            y(0 === n.length, n)
          );
        },
        [r.stop]: (e) => {
          const t = w(e);
          if (!t.isValid) return t;
          const n = [];
          return (
            void 0 !== e.followup_message &&
              "string" != typeof e.followup_message &&
              n.push("followup_message must be a string if provided"),
            y(0 === n.length, n)
          );
        },
        [r.afterAgentResponse]: (e) => {
          const t = w(e);
          return (t.isValid, t);
        },
        [r.afterAgentThought]: (e) => {
          const t = w(e);
          return (t.isValid, t);
        },
        [r.sessionStart]: (e) => {
          const t = w(e);
          if (!t.isValid) return t;
          const n = [];
          if (void 0 !== e.env)
            if (_(e.env))
              for (const [t, r] of Object.entries(e.env))
                (C(t) || n.push(`env key "${t}" must be a string`),
                  C(r) || n.push(`env value for "${t}" must be a string`));
            else n.push("env must be an object if provided");
          return (
            void 0 === e.additional_context ||
              C(e.additional_context) ||
              n.push("additional_context must be a string if provided"),
            void 0 !== e.continue &&
              "boolean" != typeof e.continue &&
              n.push("continue must be a boolean if provided"),
            void 0 === e.user_message ||
              C(e.user_message) ||
              n.push("user_message must be a string if provided"),
            y(0 === n.length, n)
          );
        },
        [r.sessionEnd]: (e) => {
          const t = w(e);
          return t.isValid ? y(!0, []) : t;
        },
        [r.preCompact]: (e) => {
          const t = w(e);
          if (!t.isValid) return t;
          if (null == e || 0 === Object.keys(e).length) return y(!0, []);
          const n = [];
          if (!_(e))
            return (n.push("PreCompact response must be an object"), y(!1, n));
          const r = e;
          return (
            void 0 === r.user_message ||
              ((e) => "string" == typeof e)(r.user_message) ||
              n.push("user_message must be a string"),
            y(0 === n.length, n)
          );
        },
        [r.subagentStart]: (e) => {
          const t = w(e);
          if (!t.isValid) return t;
          const n = [],
            r = e;
          if (void 0 !== r.permission) {
            const e = ["allow", "deny", "ask"];
            e.includes(r.permission) ||
              n.push(
                `Invalid permission value. Expected one of: ${e.join(", ")}, or undefined`,
              );
          }
          return (
            void 0 === r.user_message ||
              C(r.user_message) ||
              n.push("user_message must be a string if provided"),
            y(0 === n.length, n)
          );
        },
        [r.subagentStop]: (e) => {
          const t = w(e);
          if (!t.isValid) return t;
          const n = [];
          return (
            void 0 !== e &&
              "object" == typeof e &&
              null !== e &&
              void 0 !== e.followup_message &&
              "string" != typeof e.followup_message &&
              n.push("followup_message must be a string if provided"),
            y(0 === n.length, n)
          );
        },
        [r.preToolUse]: (e) => {
          const t = [],
            n = w(e);
          if (!n.isValid) return n;
          if (void 0 !== e.permission) {
            const n = ["allow", "deny", "ask"];
            n.includes(e.permission) ||
              t.push(
                `Invalid permission value. Expected one of: ${n.join(", ")}, or undefined`,
              );
          }
          return (
            void 0 !== e.user_message &&
              "string" != typeof e.user_message &&
              t.push(
                "Invalid user_message value. Expected a string if provided",
              ),
            void 0 !== e.agent_message &&
              "string" != typeof e.agent_message &&
              t.push(
                "Invalid agent_message value. Expected a string if provided",
              ),
            void 0 !== e.updated_input &&
              ("object" != typeof e.updated_input ||
                null === e.updated_input ||
                Array.isArray(e.updated_input)) &&
              t.push(
                "Invalid updated_input value. Expected a plain object if provided",
              ),
            E(e.additional_context, "additional_context", t),
            y(0 === t.length, t)
          );
        },
        [r.postToolUse]: (e) => {
          const t = [],
            n = w(e);
          return n.isValid
            ? (E(e.additional_context, "additional_context", t),
              y(0 === t.length, t))
            : n;
        },
        [r.postToolUseFailure]: (e) => {
          const t = w(e);
          if (!t.isValid) return t;
          const n = [];
          return (
            E(e.additional_context, "additional_context", n),
            y(0 === n.length, n)
          );
        },
        [r.workspaceOpen]: (e) => {
          const t = w(e);
          if (!t.isValid) return t;
          const n = [];
          return (
            void 0 !== e.pluginPaths &&
              (Array.isArray(e.pluginPaths)
                ? e.pluginPaths.forEach((e, t) => {
                    C(e)
                      ? 0 === e.trim().length &&
                        n.push(`pluginPaths[${t}] must be a non-empty string`)
                      : n.push(`pluginPaths[${t}] must be a string`);
                  })
                : n.push(
                    "pluginPaths must be an array of strings if provided",
                  )),
            y(0 === n.length, n)
          );
        },
      },
      N = (e, t, n) => {
        const s = (function (e, t, n) {
            let s;
            return (
              (s =
                e === r.preToolUse
                  ? (function (e, t) {
                      if (!V(e)) return e;
                      const n = e;
                      if (
                        void 0 !== n.permission ||
                        void 0 !== n.user_message ||
                        void 0 !== n.agent_message ||
                        void 0 !== n.updated_input
                      )
                        return n;
                      if (!Y(t)) return n;
                      const r = W(e);
                      if (!$(r, "PreToolUse")) return n;
                      const s = Object.assign({}, n);
                      let i = !1;
                      return (
                        void 0 !== r.permissionDecision &&
                          ((s.permission = r.permissionDecision), (i = !0)),
                        "string" == typeof r.permissionDecisionReason &&
                          ((s.user_message = r.permissionDecisionReason),
                          (i = !0)),
                        V(r.updatedInput) &&
                          ((s.updated_input = r.updatedInput), (i = !0)),
                        i ? s : n
                      );
                    })(t, n)
                  : e === r.stop
                    ? z(t, n, "Stop")
                    : e === r.subagentStop
                      ? z(t, n, "SubagentStop")
                      : t),
              (function (e, t, n, r) {
                var s;
                if (!S.has(e) || !V(n) || void 0 !== n.additional_context)
                  return n;
                const o = V(t)
                  ? null !==
                      (s = (function (e) {
                        return "string" == typeof e.additionalContext
                          ? e.additionalContext
                          : void 0;
                      })(t)) && void 0 !== s
                    ? s
                    : (function (e, t, n) {
                        if (!Y(n)) return;
                        const r = i[e];
                        if (void 0 === r) return;
                        const s = W(t);
                        return $(s, r) && "string" == typeof s.additionalContext
                          ? s.additionalContext
                          : void 0;
                      })(e, t, r)
                  : void 0;
                return void 0 === o
                  ? n
                  : Object.assign(Object.assign({}, n), {
                      additional_context: o,
                    });
              })(e, t, s, n)
            );
          })(e, t, n),
          o = (0, Q[e])(s);
        return o.isValid
          ? { success: !0, data: s }
          : { success: !1, errors: o.errors };
      },
      P = [
        r.beforeShellExecution,
        r.beforeMCPExecution,
        r.beforeReadFile,
        r.beforeTabFileRead,
        r.subagentStart,
        r.preToolUse,
      ],
      D = [r.workspaceOpen];
    function x(e) {
      return D.includes(e);
    }
    function J(e, t) {
      const n = [];
      return (
        (null == e ? void 0 : e.trim()) && n.push(e.trim()),
        (null == t ? void 0 : t.trim()) && n.push(t.trim()),
        n.length > 0 ? n.join("\n\n---\n\n") : void 0
      );
    }
    function L(e, t) {
      if (e || t) return Object.assign(Object.assign({}, e || {}), t || {});
    }
    function O(e, t) {
      var n;
      if (0 === t.length) return;
      if (1 === t.length) return t[0];
      const s = P.includes(e),
        i = e === r.sessionStart,
        o = e === r.workspaceOpen,
        a = S.has(e),
        l = {};
      for (const e of t) {
        const t = e;
        for (const [e, r] of Object.entries(t))
          if (void 0 !== r)
            if (o && "pluginPaths" === e && Array.isArray(r)) {
              const t = null !== (n = l[e]) && void 0 !== n ? n : [],
                s = new Set(t),
                i = [...t];
              for (const e of r)
                "string" != typeof e || s.has(e) || (s.add(e), i.push(e));
              l[e] = i;
            } else
              "permission" === e && s
                ? (l[e] =
                    ((c = r),
                    "deny" === (u = l[e]) || "deny" === c
                      ? "deny"
                      : "ask" === u || "ask" === c
                        ? "ask"
                        : "allow" === u || "allow" === c
                          ? "allow"
                          : void 0))
                : "user_message" !== e && "agent_message" !== e
                  ? a && "additional_context" === e && "string" == typeof r
                    ? (l[e] = J(l[e], r))
                    : "continue" !== e || "boolean" != typeof r
                      ? (l[e] =
                          i && "env" === e && "object" == typeof r && null !== r
                            ? L(l[e], r)
                            : r)
                      : void 0 === l[e]
                        ? (l[e] = r)
                        : (l[e] = l[e] && r)
                  : (l[e] = J(l[e], r));
      }
      var u, c;
      return l;
    }
    function F(e) {
      return P.includes(e);
    }
    function M({ step: e, command: t, failClosed: n, kind: r }) {
      const s = F(e);
      if (!n && !s) return { shouldNotifyUser: !1 };
      const i = n
        ? "Tool blocked because this hook is configured to fail closed (block when it fails). " +
          ("invalid_json" === r
            ? `Hook "${t}" returned invalid JSON.`
            : `Hook "${t}" returned invalid response.`)
        : "invalid_json" === r
          ? `Hook "${t}" returned invalid JSON. The command was blocked for safety.`
          : `Hook "${t}" returned an invalid response for this hook step. The command was blocked for safety.`;
      return {
        blockResponse: q(e, i),
        cause: n ? "script_fail_closed" : "permission_hook_invalid_output",
        reason: i,
        shouldNotifyUser: s && !n,
      };
    }
    function U(e, t, n) {
      const r = e.trim(),
        s = t.trim();
      return (
        r ||
        (s
          ? `Hook blocked with message: ${s}`
          : `Hook "${n}" blocked this action (exit code 2) but provided no reason.`)
      );
    }
    function q(e, t) {
      return F(e)
        ? { permission: "deny", user_message: t }
        : e === r.beforeSubmitPrompt || e === r.sessionStart
          ? { continue: !1, user_message: t }
          : e === r.stop
            ? {}
            : void 0;
    }
    function j(e) {
      return F(e)
        ? { permission: "allow" }
        : e === r.beforeSubmitPrompt || e === r.sessionStart
          ? { continue: !0 }
          : e === r.stop
            ? {}
            : void 0;
    }
    function G(e) {
      try {
        return { value: JSON.parse(e) };
      } catch (e) {
        return;
      }
    }
    function H(e) {
      const t = e.trim();
      if (0 === t.length) return;
      const n = G(t);
      if (void 0 !== n) return n.value;
      if (t.endsWith("}"))
        for (let e = t.length - 1; e >= 0; e--) {
          if ("{" !== t[e]) continue;
          const n = G(t.slice(e));
          if (void 0 !== n) return n.value;
        }
    }
    function Y(e) {
      var t;
      return (
        null !==
          (t =
            null == e
              ? void 0
              : e.enableClaudeNestedHookSpecificOutputCompatibility) &&
        void 0 !== t &&
        t
      );
    }
    function V(e) {
      return null !== e && "object" == typeof e && !Array.isArray(e);
    }
    function W(e) {
      if (!V(e)) return;
      const t = e.hookSpecificOutput;
      return V(t) ? t : void 0;
    }
    function $(e, t) {
      if (!e) return !1;
      const n = e.hookEventName;
      return void 0 === n || "" === n || n === t;
    }
    function z(e, t, n) {
      if (!V(e)) return e;
      const r = e;
      if (void 0 !== r.followup_message) return r;
      if (
        "block" === r.decision &&
        "string" == typeof r.reason &&
        r.reason.trim().length > 0
      )
        return Object.assign(Object.assign({}, r), {
          followup_message: r.reason.trim(),
        });
      if (!Y(t)) return r;
      const s = W(e),
        i = $(s, n) ? s : void 0,
        o = void 0 !== i ? Object.assign(Object.assign({}, r), i) : r;
      return "block" === o.decision &&
        "string" == typeof o.reason &&
        o.reason.trim().length > 0
        ? Object.assign(Object.assign({}, o), {
            followup_message: o.reason.trim(),
          })
        : r;
    }
    function K(e) {
      return !0 === e ? "stdin" : "legacy";
    }
    function Z(e, t) {
      const n = e.replace(/'/g, "''"),
        r = (function (e) {
          const t = e.trimStart();
          if (0 === t.length) return e;
          if (t.startsWith("&")) return e;
          const n = t.charAt(0);
          return "'" === n || '"' === n ? `& ${e}` : e;
        })(t);
      return `$OutputEncoding = [System.Text.Encoding]::UTF8; Get-Content -LiteralPath '${n}' -Raw | & { $input | ${r} }`;
    }
    const X = (e) => {
        const t = [];
        if (!_(e))
          return (
            t.push(
              "Hook script must be an object with either a 'command' property (command hook) or 'type: \"prompt\"' with a 'prompt' property (prompt hook)",
            ),
            y(!1, t)
          );
        const n = e.type;
        return (
          "prompt" === n
            ? ((e, t) => {
                (C(e.prompt)
                  ? "" === e.prompt.trim() &&
                    t.push("Prompt hook 'prompt' property cannot be empty")
                  : t.push(
                      "Prompt hook must have a 'prompt' property (string)",
                    ),
                  void 0 !== e.model &&
                    (C(e.model)
                      ? "" === e.model.trim() &&
                        t.push("Prompt hook 'model' cannot be an empty string")
                      : t.push(
                          "Prompt hook 'model' must be a string if provided",
                        )));
              })(e, t)
            : "command" === n || void 0 === n
              ? ((e, t) => {
                  C(e.command) ||
                    t.push("Hook script command must be a string");
                })(e, t)
              : t.push(
                  `Invalid hook type: "${n}". Must be "command", "prompt", or omitted (defaults to "command")`,
                ),
          ((e, t) => {
            var n;
            if (void 0 !== e.matcher)
              if (C(e.matcher)) {
                if ("" !== e.matcher && "*" !== e.matcher)
                  try {
                    new RegExp(e.matcher);
                  } catch (r) {
                    t.push(
                      `Hook script matcher "${e.matcher}" is not a valid regex: ${null !== (n = null == r ? void 0 : r.message) && void 0 !== n ? n : String(r)}`,
                    );
                  }
              } else t.push("Hook script matcher must be a string if provided");
            if (
              (void 0 !== e.timeout &&
                ("number" != typeof e.timeout
                  ? t.push("Hook script timeout must be a number (seconds)")
                  : e.timeout <= 0
                    ? t.push("Hook script timeout must be a positive number")
                    : e.timeout > 3600 &&
                      console.warn(
                        `[hooks] Hook timeout of ${e.timeout}s is very long (>1 hour)`,
                      )),
              void 0 !== e.loop_limit)
            ) {
              const n = e.loop_limit;
              null !== n &&
                ("number" != typeof n
                  ? t.push(
                      "Hook script loop_limit must be a positive integer or null",
                    )
                  : Number.isInteger(n)
                    ? n <= 0 &&
                      t.push(
                        "Hook script loop_limit must be a positive integer (use null for no limit)",
                      )
                    : t.push("Hook script loop_limit must be an integer"));
            }
            void 0 !== e.failClosed &&
              "boolean" != typeof e.failClosed &&
              t.push("Hook script failClosed must be a boolean");
          })(e, t),
          y(0 === t.length, t)
        );
      },
      ee = (e, t) => {
        const n = [];
        if (!Array.isArray(e))
          return (n.push(`${t} must be an array of hook scripts`), y(!1, n));
        for (let r = 0; r < e.length; r++) {
          const s = X(e[r]);
          s.isValid || n.push(`${t}[${r}]: ${s.errors.join(", ")}`);
        }
        return y(0 === n.length, n);
      },
      te = (e) => {
        const t = [];
        if (!_(e)) return (t.push("Hooks config must be an object"), y(!1, t));
        if (
          ("number" != typeof e.version
            ? t.push("Config version must be a number")
            : (!Number.isInteger(e.version) || e.version < 1) &&
              t.push("Config version must be a positive integer"),
          !_(e.hooks))
        )
          return (t.push("Config hooks must be an object"), y(!1, t));
        void 0 !== e.stop_hook_loop_limit &&
          console.warn(
            "[hooks] DEPRECATION WARNING: 'stop_hook_loop_limit' is deprecated. Use 'loop_limit' on individual hook scripts instead. The configured value is being ignored.",
          );
        const n = Object.values(r),
          s = e.hooks;
        for (const [e, r] of Object.entries(s))
          if (n.includes(e)) {
            if (void 0 !== r) {
              const n = ee(r, e);
              n.isValid || t.push(...n.errors);
            }
          } else
            t.push(`Unknown hook type: ${e}. Valid types are: ${n.join(", ")}`);
        return y(0 === t.length, t);
      };
  },
});
