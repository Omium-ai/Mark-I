// pretty-printed (prettier 3, no semantic change) from the pinned cursor-agent CLI bundle 2026.09.10-fd3934a; see README.md
// source: 190.index.js (sha256 07d06c8059faeb725bba1a96be909b96e365d6f18fc13258214d4fdc0c70e715): config paths + executeHookForStep, the stdin payload assembly
      function D(e) {
        switch (null != e ? e : (0, k.platform)()) {
          case "darwin":
            return d.join(
              "/Library",
              "Application Support",
              "Cursor",
              "hooks.json",
            );
          case "win32":
            return d.join("C:\\", "ProgramData", "Cursor", "hooks.json");
          default:
            return d.join("/etc", "cursor", "hooks.json");
        }
      }
      function L(e) {
        return d.join(
          e,
          ".cursor",
          "managed",
          "active-team-hooks",
          "hooks.json",
        );
      }
      function U(e) {
        return {
          enterpriseConfigPath: D(),
          userConfigPath: d.join((0, k.homedir)(), ".cursor", "hooks.json"),
          projectConfigPath: d.join(e, ".cursor", "hooks.json"),
          claudeUserConfigPath: d.join(
            (0, k.homedir)(),
            ".claude",
            "settings.json",
          ),
          claudeProjectConfigPath: d.join(e, ".claude", "settings.json"),
          claudeProjectLocalConfigPath: d.join(
            e,
            ".claude",
            "settings.local.json",
          ),
        };
      }
// ...
        executeHookForStep(e, t, o) {
          return F(this, void 0, void 0, function* () {
            var n, s, r, i, a, c, l, u, d, h, f, p;
            this.configReadyPromises.length > 0 &&
              (yield Promise.all(this.configReadyPromises));
            const v = (0, _.yW)(e),
              m = t,
              y = v
                ? null
                : m.conversation_id
                  ? yield this.getTranscriptPathIfExists(m.conversation_id)
                  : null;
            let g;
            if (e === _._E.subagentStop) {
              const e = t;
              g = e.subagent_id
                ? yield this.getSubagentTranscriptPathIfExists({
                    subagentId: e.subagent_id,
                    parentConversationId: e.parent_conversation_id,
                  })
                : null;
            }
            const k = v
                ? void 0
                : null !== (h = m.session_id) && void 0 !== h
                  ? h
                  : m.conversation_id,
              w = Object.assign(
                Object.assign(
                  Object.assign(
                    Object.assign(
                      Object.assign({}, t),
                      void 0 !== k && { session_id: k },
                    ),
                    {
                      hook_event_name: e,
                      cursor_version: this.globalContext.cursor_version,
                      workspace_roots: [this.workspacePath],
                      user_email: this.resolveUserEmail(m),
                    },
                  ),
                  !v && { transcript_path: y },
                ),
                e === _._E.subagentStop && {
                  agent_transcript_path: null != g ? g : null,
                },
              ),
              b = (0, _.bi)(e, w),
              x = [],
              E = (e, t) => {
                var n;
                if (!e) return;
                const s = (0, _.Qk)(e, b),
                  r =
                    null !== (n = null == o ? void 0 : o.cwd) && void 0 !== n
                      ? n
                      : this.getCwdForSource(t);
                for (const e of s)
                  (0, _.uu)(e)
                    ? this.promptHookClient &&
                      x.push({ type: "prompt", script: e, source: t })
                    : (0, _.Xz)(e) &&
                      x.push({
                        type: "command",
                        script: e,
                        cwd: r,
                        env: null == o ? void 0 : o.env,
                        source: t,
                      });
              };
            (E(
              null === (n = this.config.enterpriseHooks) || void 0 === n
                ? void 0
                : n.hooks[e],
              "enterprise",
            ),
              E(
                null === (s = this.config.teamHooks) || void 0 === s
                  ? void 0
                  : s.hooks[e],
                "team",
              ),
              E(
                null === (r = this.config.projectHooks) || void 0 === r
                  ? void 0
                  : r.hooks[e],
                "project",
              ),
              E(
                null === (i = this.config.userHooks) || void 0 === i
                  ? void 0
                  : i.hooks[e],
                "user",
              ),
              E(
                null ===
                  (c =
                    null === (a = this.options) || void 0 === a
                      ? void 0
                      : a.runtimeHooks) || void 0 === c
                  ? void 0
                  : c.hooks[e],
                "runtime",
              ),
              E(
                null === (l = this.config.claudeProjectLocalHooks) ||
                  void 0 === l
                  ? void 0
                  : l.hooks[e],
                "claude-project-local",
              ),
              E(
                null === (u = this.config.claudeProjectHooks) || void 0 === u
                  ? void 0
                  : u.hooks[e],
                "claude-project",
              ),
              E(
                null === (d = this.config.claudeUserHooks) || void 0 === d
                  ? void 0
                  : d.hooks[e],
                "claude-user",
              ));
            for (const t of null !== (f = this.config.pluginHooks) &&
            void 0 !== f
              ? f
              : []) {
              const n = t.config.hooks[e];
              if (!(null == n ? void 0 : n.length)) continue;
              const s =
                  null !== (p = null == o ? void 0 : o.cwd) && void 0 !== p
                    ? p
                    : e === _._E.stop || e === _._E.subagentStop
                      ? this.workspacePath
                      : t.installPath,
                r = Object.assign(
                  Object.assign(
                    Object.assign(
                      Object.assign(
                        {},
                        void 0 !== t.plugin && { plugin: t.plugin },
                      ),
                      void 0 !== t.marketplace && {
                        marketplace: t.marketplace,
                      },
                    ),
                    void 0 !== t.pluginId && { pluginId: t.pluginId },
                  ),
                  void 0 !== t.marketplaceId && {
                    marketplaceId: t.marketplaceId,
                  },
                );
              for (const e of (0, _.Qk)(n, b))
                (0, _.Xz)(e) &&
                  x.push({
                    type: "command",
                    script: e,
                    cwd: s,
                    env: null == o ? void 0 : o.env,
                    source: "claude-plugin",
                    attribution: r,
                    pluginInstallPath: t.installPath,
                  });
            }
            if (0 !== x.length) return this.executeAllAndMerge(e, x, w);
          });
        }
