// mark1 opencode plugin: lifecycle hooks exec mark1-hookshim (JSON on stdin, fire-and-forget); usage lines and the person's prompts land in a per-session JSONL mark1d reads locally.
import { spawn } from "node:child_process"
import { createHash } from "node:crypto"
import { appendFileSync, existsSync, mkdirSync, readdirSync, readFileSync, realpathSync, statSync, unlinkSync } from "node:fs"
import { homedir } from "node:os"
import { isAbsolute, join, relative, resolve, sep } from "node:path"

const SHIM = "__MARK1_SHIM__"
const NAMESPACE_URL = Buffer.from("6ba7b8119dad11d180b400c04fd430c8", "hex")
const home = homedir()
const root = join(home, ".omium", "mark1")
const capture = join(root, "capture", "opencode")
const shim = SHIM.startsWith("~/") ? join(home, SHIM.slice(2)) : SHIM

const off = () => process.env.MARK1_DISABLE === "1" || existsSync(join(root, "OFF"))

// m1p session_id := UUIDv5(NameSpaceURL, "opencode:" + sessionID): opencode ids are ses_<26 chars>, not UUIDs.
function sessionUUID(id) {
  const h = createHash("sha1").update(NAMESPACE_URL).update("opencode:" + id).digest()
  h[6] = (h[6] & 0x0f) | 0x50
  h[8] = (h[8] & 0x3f) | 0x80
  const x = h.subarray(0, 16).toString("hex")
  return `${x.slice(0, 8)}-${x.slice(8, 12)}-${x.slice(12, 16)}-${x.slice(16, 20)}-${x.slice(20, 32)}`
}

function hook(name, cwd, fields) {
  if (off() || typeof fields.sessionID !== "string") return
  try {
    const p = spawn(shim, [], { env: { ...process.env, MARK1_AGENT: "opencode" }, stdio: ["pipe", "ignore", "ignore"] })
    p.on("error", () => {})
    p.stdin.on("error", () => {})
    p.stdin.end(JSON.stringify({ hook_event_name: name, session_id: sessionUUID(fields.sessionID), cwd, ...fields }))
  } catch {}
}

// ponytail: append-only, no retention sweep; add one if capture dirs ever matter on disk.
function record(sessionID, type, properties) {
  if (off() || typeof sessionID !== "string") return
  try {
    mkdirSync(capture, { recursive: true, mode: 0o700 })
    appendFileSync(join(capture, sessionID + ".jsonl"), JSON.stringify({ type, properties }) + "\n", { mode: 0o600 })
  } catch {}
}

const canon = (p) => {
  try {
    return realpathSync(p)
  } catch {
    return resolve(p)
  }
}

// the enabled set is mark1's own workspaces.json (the file `mark1 enable` writes and mark1d reads); unreadable, loosely permissioned or absent means nothing is enabled
function enabled(dir) {
  try {
    const f = join(root, "workspaces.json")
    if (process.platform !== "win32" && statSync(f).mode & 0o077) return false
    const d = canon(dir)
    return (JSON.parse(readFileSync(f, "utf8")).workspaces ?? []).some((w) => {
      if (typeof w?.path !== "string" || w.path === "") return false
      const rel = relative(canon(w.path), d)
      return rel === "" || (rel !== ".." && !rel.startsWith(".." + sep) && !isAbsolute(rel))
    })
  } catch {
    return false
  }
}

// prompts go beside the usage capture, never into it: the usage tailer and its corpus read those files verbatim; only for a directory inside an enabled workspace
function note(sessionID, line) {
  if (off() || typeof sessionID !== "string" || !enabled(line.properties.cwd)) return
  try {
    const dir = join(capture, "intent")
    mkdirSync(dir, { recursive: true, mode: 0o700 })
    appendFileSync(join(dir, sessionID + ".jsonl"), JSON.stringify(line) + "\n", { mode: 0o600 })
  } catch {}
}

// prompt notes live as long as Claude Code keeps its own transcripts by default (30 days), then go
function pruneNotes() {
  try {
    const dir = join(capture, "intent")
    for (const f of readdirSync(dir)) {
      const p = join(dir, f)
      if (Date.now() - statSync(p).mtimeMs > 30 * 86400e3) unlinkSync(p)
    }
  } catch {}
}

export default {
  id: "mark1",
  server: async ({ directory }) => (pruneNotes(), {
    event: async ({ event }) => {
      const p = event.properties ?? {}
      if (event.type === "session.created" || event.type === "session.idle") hook(event.type, directory, { sessionID: p.sessionID })
      if (event.type === "message.updated" && p.info?.role === "assistant") record(p.sessionID, event.type, p)
      if (event.type === "message.part.updated" && p.part?.type === "step-finish") record(p.sessionID, event.type, p)
    },
    "chat.message": async (input, output) => {
      hook("chat.message", directory, input)
      // the person's own words, local only: mark1d reads them as the task's intent (opencode keeps its transcript in SQLite)
      const text = (output?.parts ?? []).filter((p) => p.type === "text" && !p.synthetic && !p.ignored).map((p) => p.text).join("\n")
      if (text) note(input.sessionID, { type: "chat.message", properties: { sessionID: input.sessionID, cwd: directory, timestamp: new Date().toISOString(), text } })
    },
    "tool.execute.before": async (input) => hook("tool.execute.before", directory, input),
    "tool.execute.after": async (input) =>
      hook("tool.execute.after", directory, { tool: input.tool, sessionID: input.sessionID, callID: input.callID }),
  }),
}
