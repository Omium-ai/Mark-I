import http from 'node:http';
import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';
import { fileURLToPath } from 'node:url';

const HERE = path.dirname(fileURLToPath(import.meta.url));

export const LOCAL_ROUTES = [
  ['GET', '/v1/status', 'local-status'],
  ['GET', '/v1/agents', 'local-agents'],
  ['GET', '/v1/projects', 'local-projects'],
  ['POST', '/v1/projects', 'local-projects-add'],
  ['DELETE', '/v1/projects', 'local-projects-remove'],
  ['GET', '/v1/anchors', 'local-anchors'],
  ['POST', '/v1/anchors/consent', 'local-anchors-consent'],
  ['POST', '/v1/anchors/probe', 'local-anchors-probe'],
  ['GET', '/v1/optins', 'local-optins'],
  ['PUT', '/v1/optins', 'local-optins-update'],
  ['POST', '/v1/pause', 'local-pause'],
  ['POST', '/v1/resume', 'local-resume'],
  ['GET', '/v1/doctor', 'local-doctor'],
  ['GET', '/v1/plan', 'local-plan'],
  ['POST', '/v1/shutdown', 'local-shutdown'],
  ['GET', '/v1/receipts', 'local-receipts'],
  ['POST', '/v1/receipts/verify', 'local-receipts-verify'],
  ['GET', '/v1/verify/events', 'local-verify-events'],
  ['POST', '/v1/enroll/keygen', 'local-enroll-keygen'],
  ['POST', '/v1/enroll', 'local-enroll'],
  ['GET', '/v1/enroll', 'local-enroll-state'],
  ['DELETE', '/v1/enroll', 'local-enroll-signout'],
  // {name} routes carry a literal agent, as the cloud sessions detail does; last, because the daemon's disable really reverts the fragment the rows above show.
  ['POST', '/v1/agents/claudecode/provision', 'local-agents-provision'],
  ['POST', '/v1/agents/claudecode/disable', 'local-agents-disable'],
  ['POST', '/v1/agents/claudecode/pause', 'local-agents-pause'],
  ['POST', '/v1/agents/claudecode/resume', 'local-agents-resume'],
];

export const CLOUD_ROUTES = [
  ['GET', '/api/v1/reports/tvo', 'cloud-reports-tvo'],
  ['GET', '/api/v1/reports/interventions', 'cloud-reports-interventions'],
  ['GET', '/api/v1/sessions', 'cloud-sessions'],
  ['GET', '/api/v1/sessions/0191c7a0-5b1e-7c2d-9e4f-0123456789a0', 'cloud-sessions-detail'],
  ['GET', '/api/v1/moments', 'cloud-moments'],
  ['GET', '/api/v1/memory/artifacts', 'cloud-memory-artifacts'],
  ['GET', '/api/v1/memory/injections', 'cloud-memory-injections'],
  ['GET', '/api/v1/memory/outcomes', 'cloud-memory-outcomes'],
  // {id} routes carry a literal artifact (art_pit_7 in every scenario's cloud-memory-artifacts), as the sessions detail does.
  ['POST', '/api/v1/memory/artifacts/art_pit_7/retire', 'cloud-memory-retire'],
  ['POST', '/api/v1/memory/artifacts/art_pit_7/pin', 'cloud-memory-pin'],
  ['POST', '/api/v1/memory/artifacts/art_pit_7/unpin', 'cloud-memory-unpin'],
  ['POST', '/api/v1/memory/artifacts/art_pit_7/share', 'cloud-memory-share'],
  ['POST', '/api/v1/memory/artifacts/art_pit_7/unshare', 'cloud-memory-unshare'],
  ['GET', '/api/v1/verify/certificates', 'cloud-verify-certificates'],
  ['GET', '/api/v1/verify/labels', 'cloud-verify-labels'],
  ['POST', '/api/v1/verify/labels', 'cloud-verify-labels'],
  ['GET', '/api/v1/verify/cloud-judge', 'cloud-verify-cloud-judge'],
  ['PUT', '/api/v1/verify/cloud-judge', 'cloud-verify-cloud-judge'],
  ['GET', '/api/v1/verify/cloud-rm', 'cloud-verify-cloud-rm'],
  ['PUT', '/api/v1/verify/cloud-rm', 'cloud-verify-cloud-rm'],
  ['GET', '/api/v1/memory/extract-consent', 'cloud-memory-extract-consent'],
  ['PUT', '/api/v1/memory/extract-consent', 'cloud-memory-extract-consent'],
  ['GET', '/api/v1/route/decisions', 'cloud-route-decisions'],
  ['GET', '/api/v1/route/bundle', 'cloud-route-bundle'],
  ['GET', '/api/v1/receipts/export', 'cloud-receipts-export'],
  ['GET', '/api/v1/receipts/witness', 'cloud-receipts-witness'],
  ['GET', '/api/v1/team', 'cloud-team'],
  ['POST', '/api/v1/team/invites', 'cloud-team-invites'],
  ['POST', '/api/v1/team/invites/accept', 'cloud-team-invites-accept'],
  ['POST', '/api/v1/team/leave', 'cloud-team-leave'],
  // {id} carries a literal member (usr_2, a member in the team-* scenarios), as the memory actions do.
  ['DELETE', '/api/v1/team/members/usr_2', 'cloud-team-members-remove'],
  ['PUT', '/api/v1/team', 'cloud-team-update'],
  // {id} carries the live invite of the team-owner scenario, as the member removal does.
  ['DELETE', '/api/v1/team/invites/0191d000-0000-7000-8000-000000000001', 'cloud-team-invites-cancel'],
  ['GET', '/api/v1/me/notifications', 'cloud-me-notifications'],
  ['PUT', '/api/v1/me/notifications', 'cloud-me-notifications-update'],
  ['GET', '/api/v1/me', 'cloud-me'],
];

const SSE_EVENT_NAME = 'local-events';
// controld streams the export as application/x-ndjson (one ExportRow per line); the fixture holds the rows as an array.
const NDJSON_FIXTURES = new Set(['cloud-receipts-export']);

// Fixtures are written as of FIXTURE_NOW. Every string that is a whole date or date-time moves by (now - FIXTURE_NOW) at load,
// so "this week" and "last 7 days" hold on any day the mock runs; dates inside other strings (receipt payloads) stay put.
export const FIXTURE_NOW = Date.parse('2026-09-16T15:00:00Z');
const DATE_RE = /^\d{4}-\d{2}-\d{2}(T\d{2}:\d{2}:\d{2}(\.\d{3})?Z)?$/;

export function shiftDates(v, ms) {
  if (typeof v === 'string' && DATE_RE.test(v)) {
    if (v.length === 10) return new Date(Date.parse(`${v}T15:00:00Z`) + ms).toISOString().slice(0, 10);
    const s = new Date(Date.parse(v) + ms).toISOString();
    return v.includes('.') ? s : s.replace(/\.\d{3}Z$/, 'Z');
  }
  if (Array.isArray(v)) return v.map((x) => shiftDates(x, ms));
  if (v && typeof v === 'object') return Object.fromEntries(Object.entries(v).map(([k, x]) => [k, shiftDates(x, ms)]));
  return v;
}

// routes whose success is 202, not 200: the probe answers before its runs land in GET /v1/anchors
const ACCEPTED = [['local-anchors-probe', 202]];

// A scenario dir with scenario.json holds only what differs from the one it `extends`; its `status` maps a fixture to a non-200 reply.
export function scenarioMeta(scenario) {
  const p = path.join(HERE, 'fixtures', scenario, 'scenario.json');
  return fs.existsSync(p) ? JSON.parse(fs.readFileSync(p, 'utf8')) : {};
}

function readScenario(scenario) {
  const meta = scenarioMeta(scenario);
  const base = meta.extends ? readScenario(meta.extends) : { fixtures: new Map(), status: new Map(ACCEPTED) };
  const dir = path.join(HERE, 'fixtures', scenario);
  for (const f of fs.readdirSync(dir)) {
    if (f === 'scenario.json') continue;
    base.fixtures.set(f.replace(/\.json$/, ''), JSON.parse(fs.readFileSync(path.join(dir, f), 'utf8')));
  }
  for (const [fixture, code] of Object.entries(meta.status ?? {})) base.status.set(fixture, code);
  return base;
}

export function loadScenario(scenario, now = Date.now()) {
  const { fixtures, status } = readScenario(scenario);
  const ms = Math.floor((now - FIXTURE_NOW) / 60_000) * 60_000;
  for (const [k, v] of fixtures) fixtures.set(k, shiftDates(v, ms));
  return { fixtures, status };
}

function drain(req) {
  return new Promise((resolve) => {
    let body = '';
    req.on('data', (c) => {
      body += c;
    });
    req.on('end', () => resolve(body));
  });
}

function json(res, code, body) {
  const buf = Buffer.from(JSON.stringify(body));
  res.writeHead(code, { 'content-type': 'application/json', 'content-length': buf.length });
  res.end(buf);
}

function ndjson(res, rows) {
  const buf = Buffer.from(rows.map((r) => JSON.stringify(r) + '\n').join(''));
  res.writeHead(200, { 'content-type': 'application/x-ndjson', 'content-length': buf.length });
  res.end(buf);
}

function matchRoute(routes, method, pathname) {
  for (const [m, p, fixture] of routes) {
    if (m === method && p === pathname) return fixture;
  }
  return null;
}

// mark1d grants cloud_judge, cloud_rm or training only under the consent copy this release shows (X-Mark1-Consent-Copy: 2); an off never needs it
export const CONSENT_COPY = '2';
export function copyRefusal(headers, body) {
  let put;
  try {
    put = JSON.parse(body || '{}');
  } catch {
    return null;
  }
  const c = put.consents ?? {};
  if (!['cloud_judge', 'cloud_rm', 'training'].some((k) => c[k] === true) || headers['x-mark1-consent-copy'] === CONSENT_COPY) return null;
  return {
    error: {
      code: 'M1E-2014',
      message: 'this app shows older consent copy; update Mark 1 to turn it on',
      reason: 'consent_copy_outdated',
    },
  };
}

export function mergeOptins(was, body) {
  let put;
  try {
    put = JSON.parse(body || '{}');
  } catch {
    return was;
  }
  return { ...was, ...put, tests_by_project: { ...was.tests_by_project, ...put.tests_by_project }, consents: { ...was.consents, ...put.consents } };
}

export function startLocal(scenario, port, token) {
  const { fixtures, status } = loadScenario(scenario);
  let optins = null;
  const server = http.createServer(async (req, res) => {
    const body = await drain(req);
    const url = new URL(req.url, 'http://localhost');
    if (req.headers.authorization !== `Bearer ${token}`) {
      return json(res, 401, { error: 'missing or invalid bearer token' });
    }
    if (req.method === 'GET' && url.pathname === '/v1/events') {
      res.writeHead(200, { 'content-type': 'text/event-stream', 'cache-control': 'no-cache', connection: 'keep-alive' });
      res.flushHeaders();
      const stream = fixtures.get(SSE_EVENT_NAME) || [];
      let i = 0;
      let timer;
      const tick = () => {
        if (stream.length === 0) return;
        const item = stream[i % stream.length];
        res.write(`event: ${item.event}\ndata: ${JSON.stringify(item.data)}\n\n`);
        i += 1;
        timer = setTimeout(tick, item.delayMs);
      };
      if (stream.length) timer = setTimeout(tick, stream[0].delayMs);
      req.on('close', () => clearTimeout(timer));
      return;
    }
    let fixture = matchRoute(LOCAL_ROUTES, req.method, url.pathname);
    if (!fixture) return json(res, 404, { error: 'not found' });
    if (fixture === 'local-optins-update') {
      const refused = copyRefusal(req.headers, body);
      if (refused) return json(res, 409, refused);
      optins = mergeOptins(optins ?? fixtures.get('local-optins'), body);
    }
    // like mark1d, a PUT merges into the record and GET reads it back, so an app that re-reads after a write sees what it wrote
    if ((fixture === 'local-optins' || fixture === 'local-optins-update') && optins) return json(res, 200, optins);
    // consent-all shares the consent route and answers the project's rows, the GET shape
    if (fixture === 'local-anchors-consent' && /"all_static"\s*:\s*true/.test(body)) fixture = 'local-anchors';
    return json(res, status.get(fixture) ?? 200, fixtures.get(fixture));
  });
  return listen(server, port);
}

function listen(server, port) {
  return new Promise((resolve, reject) => {
    server.once('error', reject);
    server.listen(port, '127.0.0.1', () => resolve(server));
  });
}

// controld refuses an enable that does not name the register key the app showed copy for (the fixture's judge_id)
const CONSENT_ROWS = new Set(['cloud-verify-cloud-judge', 'cloud-verify-cloud-rm', 'cloud-memory-extract-consent']);

export function consentRefusal(row, body) {
  let put;
  try {
    put = JSON.parse(body || '{}');
  } catch {
    return null;
  }
  if (put.enabled !== true || put.judge_id === row.judge_id) return null;
  return {
    error: {
      code: 'M1E-2014',
      message: 'this app describes a different processor for this setting; update Mark 1 to turn it on',
      reason: 'consent_copy_outdated',
    },
  };
}

export function startCloud(scenario, port) {
  const { fixtures, status } = loadScenario(scenario);
  const server = http.createServer(async (req, res) => {
    const body = await drain(req);
    if (!req.headers.authorization) return json(res, 401, { error: 'missing session bearer' });
    const url = new URL(req.url, 'http://localhost');
    const fixture = matchRoute(CLOUD_ROUTES, req.method, url.pathname);
    if (!fixture) return json(res, 404, { error: 'not found' });
    if (req.method === 'PUT' && CONSENT_ROWS.has(fixture)) {
      const refused = consentRefusal(fixtures.get(fixture), body);
      if (refused) return json(res, 409, refused);
    }
    if (NDJSON_FIXTURES.has(fixture)) return ndjson(res, fixtures.get(fixture));
    return json(res, status.get(fixture) ?? 200, fixtures.get(fixture));
  });
  return listen(server, port);
}

function parseArgs(argv) {
  const args = { scenario: 'active', localPort: 4001, cloudPort: 4002 };
  for (let i = 0; i < argv.length; i += 1) {
    if (argv[i] === '--scenario') args.scenario = argv[++i];
    else if (argv[i] === '--local-port') args.localPort = Number(argv[++i]);
    else if (argv[i] === '--cloud-port') args.cloudPort = Number(argv[++i]);
  }
  return args;
}

const isMain = process.argv[1] && fileURLToPath(import.meta.url) === path.resolve(process.argv[1]);
if (isMain) {
  const { scenario, localPort, cloudPort } = parseArgs(process.argv.slice(2));
  const scenarios = fs.readdirSync(path.join(HERE, 'fixtures')).filter((d) => d !== 'controld');
  if (!scenarios.includes(scenario)) {
    process.stderr.write(`unknown scenario "${scenario}", want one of ${scenarios.join('|')}\n`);
    process.exit(1);
  }
  const token = crypto.randomBytes(16).toString('hex');
  const controlPath = path.join(HERE, 'control.json');
  fs.writeFileSync(controlPath, JSON.stringify({ port: localPort, token: token }, null, 2) + '\n');

  await startLocal(scenario, localPort, token);
  if (scenario === 'offline') {
    console.log(`READY ${localPort} -`);
  } else {
    await startCloud(scenario, cloudPort);
    console.log(`READY ${localPort} ${cloudPort}`);
  }

  process.on('SIGINT', () => process.exit(0));
  process.on('SIGTERM', () => process.exit(0));
}
