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
  ['GET', '/v1/optins', 'local-optins'],
  ['PUT', '/v1/optins', 'local-optins-update'],
  ['POST', '/v1/pause', 'local-pause'],
  ['POST', '/v1/resume', 'local-resume'],
  ['GET', '/v1/doctor', 'local-doctor'],
  ['POST', '/v1/shutdown', 'local-shutdown'],
  ['GET', '/v1/receipts', 'local-receipts'],
  ['POST', '/v1/receipts/verify', 'local-receipts-verify'],
  ['GET', '/v1/verify/events', 'local-verify-events'],
  ['POST', '/v1/enroll/keygen', 'local-enroll-keygen'],
  ['POST', '/v1/enroll', 'local-enroll'],
  ['GET', '/v1/enroll', 'local-enroll-state'],
  ['DELETE', '/v1/enroll', 'local-enroll-signout'],
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
  ['GET', '/api/v1/verify/certificates', 'cloud-verify-certificates'],
  ['GET', '/api/v1/route/decisions', 'cloud-route-decisions'],
  ['GET', '/api/v1/route/bundle', 'cloud-route-bundle'],
  ['GET', '/api/v1/receipts/export', 'cloud-receipts-export'],
  ['GET', '/api/v1/receipts/witness', 'cloud-receipts-witness'],
  ['GET', '/api/v1/team', 'cloud-team'],
  ['POST', '/api/v1/team/invites', 'cloud-team-invites'],
  ['GET', '/api/v1/me', 'cloud-me'],
];

const SSE_EVENT_NAME = 'local-events';
// controld streams the export as application/x-ndjson (one ExportRow per line); the fixture holds the rows as an array.
const NDJSON_FIXTURES = new Set(['cloud-receipts-export']);

function loadFixtures(scenario) {
  const dir = path.join(HERE, 'fixtures', scenario);
  const cache = new Map();
  for (const f of fs.readdirSync(dir)) {
    cache.set(f.replace(/\.json$/, ''), JSON.parse(fs.readFileSync(path.join(dir, f), 'utf8')));
  }
  return cache;
}

function drain(req) {
  return new Promise((resolve) => {
    req.on('data', () => {});
    req.on('end', resolve);
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

export function startLocal(scenario, port, token) {
  const fixtures = loadFixtures(scenario);
  const server = http.createServer(async (req, res) => {
    await drain(req);
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
    const fixture = matchRoute(LOCAL_ROUTES, req.method, url.pathname);
    if (!fixture) return json(res, 404, { error: 'not found' });
    return json(res, 200, fixtures.get(fixture));
  });
  return listen(server, port);
}

function listen(server, port) {
  return new Promise((resolve, reject) => {
    server.once('error', reject);
    server.listen(port, '127.0.0.1', () => resolve(server));
  });
}

export function startCloud(scenario, port) {
  const fixtures = loadFixtures(scenario);
  const server = http.createServer(async (req, res) => {
    await drain(req);
    if (!req.headers.authorization) return json(res, 401, { error: 'missing session bearer' });
    const url = new URL(req.url, 'http://localhost');
    const fixture = matchRoute(CLOUD_ROUTES, req.method, url.pathname);
    if (!fixture) return json(res, 404, { error: 'not found' });
    if (NDJSON_FIXTURES.has(fixture)) return ndjson(res, fixtures.get(fixture));
    return json(res, 200, fixtures.get(fixture));
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
  const scenarios = fs.readdirSync(path.join(HERE, 'fixtures'));
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
