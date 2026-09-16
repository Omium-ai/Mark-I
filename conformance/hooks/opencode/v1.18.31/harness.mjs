// Drives go/mark1d/adapters/opencode/mark1.js with inputs/plugin-inputs.json under a scratch HOME whose shim records every stdin body.
import { readFileSync, writeFileSync, mkdirSync, chmodSync } from "node:fs"
import { join } from "node:path"
import { pathToFileURL } from "node:url"
const [inputs, pluginSrc, home] = process.argv.slice(2)
const shim = join(home, "shim.sh")
writeFileSync(shim, '#!/bin/sh\n[ "$MARK1_AGENT" = opencode ] || exit 0\ncat > "$MARK1_FAKE_OUT/$$.json"\n')
chmodSync(shim, 0o755)
const out = join(home, "hooks")
mkdirSync(out, { recursive: true })
process.env.MARK1_FAKE_OUT = out
process.env.HOME = home
const plugin = join(home, "mark1.js")
writeFileSync(plugin, readFileSync(pluginSrc, "utf8").replace("__MARK1_SHIM__", shim))
const mod = (await import(pathToFileURL(plugin).href)).default
const spec = JSON.parse(readFileSync(inputs, "utf8"))
for (const inst of spec.instances) {
  const hooks = await mod.server({ directory: inst.directory, worktree: inst.worktree })
  for (const call of inst.calls) {
    if (call.hook === "event") await hooks.event({ event: call.event })
    else await hooks[call.hook](call.input, call.output)
  }
}
await new Promise((r) => setTimeout(r, 300))
