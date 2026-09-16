// mark1 opencode plugin: lifecycle hooks exec mark1-hookshim (JSON on stdin, fire-and-forget); usage lines land in a per-session JSONL mark1d tails.
import { spawn } from "node:child_process"
import { createHash } from "node:crypto"
import { appendFileSync, existsSync, mkdirSync } from "node:fs"
import { homedir } from "node:os"
import { join } from "node:path"

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

export default {
  id: "mark1",
  server: async ({ directory }) => ({
    event: async ({ event }) => {
      const p = event.properties ?? {}
      if (event.type === "session.created" || event.type === "session.idle") hook(event.type, directory, { sessionID: p.sessionID })
      if (event.type === "message.updated" && p.info?.role === "assistant") record(p.sessionID, event.type, p)
      if (event.type === "message.part.updated" && p.part?.type === "step-finish") record(p.sessionID, event.type, p)
    },
    "chat.message": async (input) => hook("chat.message", directory, input),
    "tool.execute.before": async (input) => hook("tool.execute.before", directory, input),
    "tool.execute.after": async (input) =>
      hook("tool.execute.after", directory, { tool: input.tool, sessionID: input.sessionID, callID: input.callID }),
  }),
}
