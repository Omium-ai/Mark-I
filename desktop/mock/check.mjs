import { spawn } from 'node:child_process';
import readline from 'node:readline';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { LOCAL_ROUTES, CLOUD_ROUTES, FIXTURE_NOW, scenarioMeta, loadScenario } from './server.mjs';

const HERE = path.dirname(fileURLToPath(import.meta.url));
// every dir but controld's goldens, overlays included
const SCENARIOS = fs.readdirSync(path.join(HERE, 'fixtures')).filter((d) => d !== 'controld');
const LOCAL_PORT = Number(process.env.MOCK_CHECK_LOCAL_PORT || 4501);
const CLOUD_PORT = Number(process.env.MOCK_CHECK_CLOUD_PORT || 4502);

const failures = [];
const fail = (msg) => failures.push(msg);

function startServer(scenario) {
  return new Promise((resolve, reject) => {
    const child = spawn('node', [path.join(HERE, 'server.mjs'), '--scenario', scenario, '--local-port', String(LOCAL_PORT), '--cloud-port', String(CLOUD_PORT)], { stdio: ['ignore', 'pipe', 'pipe'] });
    const rl = readline.createInterface({ input: child.stdout });
    const timer = setTimeout(() => reject(new Error(`${scenario}: server did not report READY in time`)), 5000);
    rl.on('line', (line) => {
      if (line.startsWith('READY')) {
        clearTimeout(timer);
        resolve(child);
      }
    });
    child.on('error', reject);
    child.stderr.on('data', (d) => process.stderr.write(`[${scenario}] ${d}`));
  });
}

async function stopServer(child) {
  child.kill('SIGTERM');
  await new Promise((resolve) => child.once('exit', resolve));
}

async function checkJson(scenario, method, url, headers, wantStatus) {
  try {
    const res = await fetch(url, { method, headers });
    if (res.status !== wantStatus) {
      fail(`${scenario} ${method} ${url}: status ${res.status}, want ${wantStatus}`);
      return;
    }
    if (wantStatus !== 401) {
      const text = await res.text();
      if ((res.headers.get('content-type') || '').includes('application/x-ndjson')) {
        for (const line of text.split('\n').filter(Boolean)) JSON.parse(line);
      } else {
        JSON.parse(text);
      }
    }
  } catch (err) {
    fail(`${scenario} ${method} ${url}: ${err.message}`);
  }
}

async function checkSSE(scenario, token, expectEvents) {
  const url = `http://127.0.0.1:${LOCAL_PORT}/v1/events`;
  try {
    const res = await fetch(url, { headers: { authorization: `Bearer ${token}` } });
    const ct = res.headers.get('content-type') || '';
    if (res.status !== 200 || !ct.includes('text/event-stream')) {
      fail(`${scenario} GET /v1/events: status ${res.status} content-type ${ct}`);
      return;
    }
    const reader = res.body.getReader();
    const timeout = new Promise((resolve) => setTimeout(() => resolve(null), 2000));
    const result = await Promise.race([reader.read(), timeout]);
    await reader.cancel().catch(() => {});
    const gotChunk = Boolean(result && !result.done && result.value && result.value.length);
    if (expectEvents && !gotChunk) fail(`${scenario} GET /v1/events: expected a replayed event, got none within 2s`);
  } catch (err) {
    fail(`${scenario} GET /v1/events: ${err.message}`);
  }
}

async function checkOfflineCloud(scenario) {
  try {
    await fetch(`http://127.0.0.1:${CLOUD_PORT}${CLOUD_ROUTES[0][1]}`, { headers: { authorization: 'Bearer x' } });
    fail(`${scenario}: cloud port ${CLOUD_PORT} answered but should be unreachable`);
  } catch {
    // expected: connection refused
  }
}

async function run(scenario) {
  const child = await startServer(scenario);
  try {
    const control = JSON.parse(fs.readFileSync(path.join(HERE, 'control.json'), 'utf8'));
    const token = control.token;
    const authHeaders = { authorization: `Bearer ${token}` };
    const { fixtures, status } = loadScenario(scenario);

    await checkJson(scenario, 'GET', `http://127.0.0.1:${LOCAL_PORT}/v1/status`, {}, 401);

    for (const [method, p, fixture] of LOCAL_ROUTES) {
      await checkJson(scenario, method, `http://127.0.0.1:${LOCAL_PORT}${p}`, authHeaders, status.get(fixture) ?? 200);
    }
    await checkSSE(scenario, token, (fixtures.get('local-events') ?? []).length > 0);

    if (scenario === 'offline') {
      await checkOfflineCloud(scenario);
    } else {
      for (const [method, p, fixture] of CLOUD_ROUTES) {
        await checkJson(scenario, method, `http://127.0.0.1:${CLOUD_PORT}${p}`, authHeaders, status.get(fixture) ?? 200);
      }
    }
  } finally {
    await stopServer(child);
  }
}

for (const scenario of SCENARIOS) {
  const meta = scenarioMeta(scenario);
  if (meta.extends && !SCENARIOS.includes(meta.extends)) fail(`${scenario}: extends unknown scenario "${meta.extends}"`);
  await run(scenario);
}

// the relative clock: a fixture date keeps its distance from "now" whatever day the mock runs
{
  const at = Date.parse('2027-01-02T08:00:00Z');
  const shifted = loadScenario('active', at).fixtures.get('cloud-sessions')[0].time;
  const raw = JSON.parse(fs.readFileSync(path.join(HERE, 'fixtures', 'active', 'cloud-sessions.json'), 'utf8'))[0].time;
  if (at - Date.parse(shifted) !== FIXTURE_NOW - Date.parse(raw)) fail(`relative dates: ${raw} became ${shifted} at ${new Date(at).toISOString()}`);
}

if (failures.length) {
  console.error(`FAIL — ${failures.length} problem(s):`);
  for (const f of failures) console.error(`  - ${f}`);
  process.exit(1);
}
console.log(`OK — all ${SCENARIOS.length} scenarios, ${LOCAL_ROUTES.length} local + ${CLOUD_ROUTES.length} cloud endpoints, SSE, and the 401 check passed.`);
