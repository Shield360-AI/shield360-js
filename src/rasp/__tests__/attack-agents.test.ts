/**
 * AI attack agents (sdk/rasp/README.md "AI attack agents"): the shared
 * conformance vectors (testdata/ai-attack-agents.json), the tracker's bounds,
 * and the middleware: deter answer, verdict for Edge, events, tripwire page.
 */
import { createHmac } from 'crypto';
import { createServer, request as httpRequest, type IncomingMessage, type Server, type ServerResponse } from 'http';
import type { AddressInfo } from 'net';
import { identifyRaspUser } from '../agents';
import {
  AttackAgentTracker,
  attackFingerprint,
  clientKey,
  DEFAULT_ATTACK_AGENTS,
  findCallbackDomain,
  parseAttackAgents,
  setAttackAgentTracker,
  tripwirePage,
  userKey,
  type AttackAgentConfig,
} from '../attack-agents';
import { configureEngine, setEventSink, setRemoteConfig } from '../engine';
import { pathHash, verifyVerdict, type EdgeKey } from '../edge-context';
import { toRemote } from '../index';
import { raspHttp, withRasp } from '../middleware';
import { setSuspiciousTable, SuspiciousTable } from '../deception';
import type { RaspClaims } from '../config-client';
import { loadJson } from './corpus';
import { classifyClient } from '../../client-type';
import { clientTypeMatches } from '../../defend/engine';

const V = loadJson('testdata/ai-attack-agents.json');

describe('conformance (testdata/ai-attack-agents.json)', () => {
  it.each(V.config as any[])('config: $name', (c: any) => {
    expect(parseAttackAgents(c.value)).toEqual(c.expect);
  });

  it.each(V.clientKey as any[])('client key: $ip', (c: any) => {
    expect(clientKey(c.ip)).toBe(c.key);
  });

  it.each(V.userKey as any[])('user key: %#', (c: any) => {
    expect(userKey(c.user)).toBe(c.key);
  });

  it.each(V.fingerprint as any[])('fingerprint: $name', (c: any) => {
    expect(attackFingerprint(c.headers)).toEqual(c.expect);
  });

  it.each(V.oast as any[])('oast: $value', (c: any) => {
    expect(findCallbackDomain(c.value)).toBe(c.expect);
  });

  it.each(V.sequences as any[])('sequence ($kind): $name', (sq: any) => {
    const cfg = parseAttackAgents({ ...DEFAULT_ATTACK_AGENTS, ...(sq.config ?? {}) });
    const t = new AttackAgentTracker();
    sq.steps.forEach((st: any, i: number) => {
      const now = st.at * 1000;
      const r = { ip: st.ip, user: st.user, path: st.path, headers: st.headers ?? V.defaultHeaders, inputs: st.inputs ?? [], verified: st.verified };
      let deter = false;
      let mark = null;
      if (!st.decoy) {
        const b = t.before(r, cfg, now);
        deter = b.marked !== null;
        mark = b.mark;
        if (!deter && !b.tripwire) mark = t.after(r, { status: st.status, route: st.route, finding: st.finding }, cfg, now) ?? mark;
      } else {
        mark = t.after(r, { status: st.status, decoy: true }, cfg, now);
      }
      expect({ step: i, deter, mark }).toEqual({ step: i, ...st.expect });
    });
  });

  it.each(V.clientTypeRules as any[])('defend rule $rule covers $clientType: $match', (c: any) => {
    expect(clientTypeMatches(c.rule, c.clientType ?? undefined)).toBe(c.match);
  });

  it('every attack sequence marks and no benign one does', () => {
    const kinds = new Set((V.sequences as any[]).map((s) => s.kind));
    expect(kinds).toEqual(new Set(['attack', 'benign']));
    for (const sq of V.sequences as any[]) {
      const marks = sq.steps.filter((s: any) => s.expect.mark).length;
      expect([sq.name, marks > 0]).toEqual([sq.name, sq.kind === 'attack']);
    }
  });
});

describe('tracker bounds', () => {
  const cfg = DEFAULT_ATTACK_AGENTS as AttackAgentConfig;
  it('keeps at most maxKeys scored keys and maxMarks marks', () => {
    const t = new AttackAgentTracker(50, 20);
    for (let i = 0; i < 500; i++) {
      t.after({ ip: `10.0.${i >> 8}.${i & 255}`, path: `/x${i}`, headers: {} }, { status: 404 }, cfg, 1_000_000);
      t.before({ ip: `10.1.${i >> 8}.${i & 255}`, path: '/', headers: { 'user-agent': 'sqlmap/1' } }, cfg, 1_000_000);
    }
    expect(t.sizes.keys).toBeLessThanOrEqual(50);
    expect(t.sizes.marks).toBeLessThanOrEqual(20);
  });

  it('a mark expires after markTtlSeconds', () => {
    const t = new AttackAgentTracker();
    const r = { ip: '192.0.2.1', path: '/', headers: { 'user-agent': 'nikto/2.5' } };
    expect(t.before(r, cfg, 0).marked).toEqual({ kind: 'scanner', reason: 'fingerprint' });
    const browser = { ...r, headers: V.defaultHeaders };
    expect(t.before(browser, cfg, 1_799_000).marked).not.toBeNull();
    expect(t.before(browser, cfg, 1_800_000).marked).toBeNull();
  });

  it('costs little per request (100k observations)', () => {
    const t = new AttackAgentTracker();
    const started = process.hrtime.bigint();
    for (let i = 0; i < 100_000; i++) {
      const r = { ip: `10.${(i >> 16) & 255}.${(i >> 8) & 255}.${i & 255}`, path: `/api/items/${i}`, headers: V.defaultHeaders, inputs: ['hello world', 'a@b.example'] };
      t.before(r, cfg, i);
      t.after(r, { status: 200, route: '/api/items/:id' }, cfg, i);
    }
    const perReqUs = Number(process.hrtime.bigint() - started) / 1000 / 100_000;
    // Generous bound for slow CI machines; locally this is a few microseconds.
    expect(perReqUs).toBeLessThan(100);
  });
});

describe('the tripwire page', () => {
  it('hides its text from people and names the URL', () => {
    const page = tripwirePage('/_debug/console/abc');
    expect(page).toContain('<div hidden aria-hidden="true">');
    expect(page).toContain('<!-- ');
    expect(page.match(/\/_debug\/console\/abc/g)?.length).toBe(2);
    expect(page).toContain('<h1>Not Found</h1>');
  });
});

describe('client type', () => {
  it('names attack agents and tools before everything but a verified client', () => {
    expect(classifyClient({ 'user-agent': '', 'x-artex-replay-nonce': '1' })).toEqual({ clientType: 'ai_attack_agent', reasons: ['attack_agent_header:artex-replay'], confidence: 'high' });
    expect(classifyClient({ 'user-agent': 'sqlmap/1.8' })).toEqual({ clientType: 'scanner', reasons: ['ua_attack_tool:sqlmap'], confidence: 'high' });
    expect(classifyClient({ 'user-agent': 'sqlmap/1.8' }, { verifiedAgent: true }).clientType).toBe('verified_agent');
    expect(classifyClient({ 'user-agent': 'Mozilla/5.0' }, { attackMark: 'ai_attack_agent' }).clientType).toBe('ai_attack_agent');
    expect(classifyClient({ 'user-agent': 'nuclei/3' }, { attackMark: 'ai_attack_agent' }).clientType).toBe('ai_attack_agent');
    expect(classifyClient({ 'user-agent': 'python-httpx/0.27' }).clientType).toBe('unverified_automation');
  });
});

// ---- middleware --------------------------------------------------------------

const events: any[] = [];
const KEY = Buffer.from('0123456789abcdef0123456789abcdef');
const keys: EdgeKey[] = [{ kid: '0a1b2c3d', key: KEY }];

function setup(attackAgents: unknown, mode: 'block' | 'monitor' = 'block', extra: Partial<RaspClaims> = {}) {
  configureEngine({ enabled: true, applicationName: 'orders-api', env: {} });
  setEventSink({ add: (e) => events.push(e) });
  const claims = { v: 1, app: 'orders-api', exp: 4_000_000_000, version: 'v-agents', attacks: { ai_attack_agent: mode }, attackAgents, edgeContext: { keys: [{ kid: '0a1b2c3d', key: KEY.toString('base64url') }] }, ...extra } as RaspClaims;
  setRemoteConfig(toRemote(claims));
  setAttackAgentTracker(new AttackAgentTracker());
  setSuspiciousTable(new SuspiciousTable());
}

function contextHeader(method: string, path: string, rid: string, ct = 'human') {
  const now = Math.floor(Date.now() / 1000);
  const payload = Buffer.from(JSON.stringify({ rid, iat: now, exp: now + 30, m: method, ph: pathHash(path), ct, risk: 0, trap: 0, fl: false })).toString('base64url');
  return `v1.0a1b2c3d.${payload}.${createHmac('sha256', KEY).update('s360-ctx|v1|').update(payload).digest('base64url')}`;
}

async function serve(handler: (req: IncomingMessage, res: ServerResponse) => unknown): Promise<{ url: string; close: () => Promise<void> }> {
  const server: Server = createServer(handler as any);
  await new Promise<void>((r) => server.listen(0, '127.0.0.1', () => r()));
  const { port } = server.address() as AddressInfo;
  return {
    url: `http://127.0.0.1:${port}`,
    close: () =>
      new Promise((r) => {
        server.closeAllConnections();
        server.close(() => r());
      }),
  };
}

type Got = { status: number; headers: Record<string, string | string[] | undefined>; body: string };
function get(url: string, headers: Record<string, string> = {}): Promise<Got> {
  return new Promise((ok, fail) => {
    httpRequest(url, { method: 'GET', headers, timeout: 3000 }, (res) => {
      let body = '';
      res.on('data', (c) => (body += c));
      res.on('end', () => ok({ status: res.statusCode || 0, headers: res.headers, body }));
    })
      .on('error', fail)
      .end();
  });
}

const attrs = () => events.map((e) => e.attrs);

describe('middleware (raw http)', () => {
  beforeEach(() => {
    events.length = 0;
  });
  afterAll(() => {
    setEventSink(undefined);
    setRemoteConfig(undefined);
    configureEngine({ enabled: false, applicationName: 'default', env: {} });
    setAttackAgentTracker(new AttackAgentTracker());
  });

  const app = raspHttp((req, res) => {
    if (req.url?.startsWith('/missing')) {
      res.statusCode = 404;
      return res.end('nope');
    }
    res.end('ok');
  });

  it('deters a tool with 429 and Retry-After in block mode, and reports the mark', async () => {
    setup({ retryAfterSeconds: 120 });
    const s = await serve(app);
    try {
      const r = await get(`${s.url}/api/items?id=1`, { 'user-agent': 'sqlmap/1.8.2#stable' });
      expect(r.status).toBe(429);
      expect(r.headers['retry-after']).toBe('120');
      expect(JSON.parse(r.body)).toEqual({ error: 'Too Many Requests' });
      expect(attrs()[0]).toMatchObject({
        'shield360.rasp.attack': 'ai_attack_agent',
        'shield360.rasp.rule': 'attack_agent.fingerprint',
        'shield360.rasp.decision': 'blocked',
        'shield360.rasp.sink': 'http.attack_agent',
        'shield360.rasp.client_kind': 'scanner',
        'shield360.rasp.reason': 'fingerprint',
      });
      // A later request from the same address with a browser User-Agent is still deterred.
      const again = await get(`${s.url}/`, { 'user-agent': 'Mozilla/5.0 Chrome/131' });
      expect(again.status).toBe(429);
      expect(attrs()[1]['shield360.rasp.rule']).toBe('attack_agent.marked');
    } finally {
      await s.close();
    }
  });

  it('only reports in monitor mode', async () => {
    setup({}, 'monitor');
    const s = await serve(app);
    try {
      const r = await get(`${s.url}/x?u=${encodeURIComponent('http://abc.oast.fun/')}`);
      expect(r.status).toBe(200);
      expect(attrs()[0]).toMatchObject({ 'shield360.rasp.rule': 'attack_agent.oast', 'shield360.rasp.decision': 'monitored', 'shield360.rasp.client_kind': 'ai_attack_agent' });
    } finally {
      await s.close();
    }
  });

  it('marks on behavior after the app answers, then deters', async () => {
    setup({ threshold: 5 });
    const s = await serve(app);
    try {
      for (let i = 0; i < 5; i++) expect((await get(`${s.url}/missing/${i}`, { 'user-agent': 'Mozilla/5.0' })).status).toBe(404);
      expect(attrs().map((a) => a['shield360.rasp.rule'])).toEqual(['attack_agent.behavior']);
      expect((await get(`${s.url}/`)).status).toBe(429);
    } finally {
      await s.close();
    }
  });

  it('sends a signed block verdict to Edge on the deter answer', async () => {
    setup({});
    const s = await serve(app);
    try {
      const rid = 'req_attackagent01';
      const r = await get(`${s.url}/api/x`, { 'user-agent': 'nuclei/3.3', 'x-request-id': rid, 'x-shield360-edge-context': contextHeader('GET', '/api/x', rid) });
      expect(r.status).toBe(429);
      const v = verifyVerdict(keys, String(r.headers['x-shield360-verdict']), rid);
      expect(v).toMatchObject({ act: 'block', cat: 'scanner', src: 'rasp', ttl: 1800 });
    } finally {
      await s.close();
    }
  });

  it('never marks a client Edge verified', async () => {
    setup({});
    const s = await serve(app);
    try {
      const rid = 'req_verifiedcrawl1';
      const r = await get(`${s.url}/api/x`, { 'user-agent': 'nuclei/3.3', 'x-request-id': rid, 'x-shield360-edge-context': contextHeader('GET', '/api/x', rid, 'verified_crawler') });
      expect(r.status).toBe(200);
      expect(events).toHaveLength(0);
    } finally {
      await s.close();
    }
  });

  it('does nothing with the attack type off', async () => {
    setup({}, 'block', { attacks: { ai_attack_agent: 'off' } as any });
    const s = await serve(app);
    try {
      expect((await get(`${s.url}/`, { 'user-agent': 'sqlmap/1' })).status).toBe(200);
      expect(events).toHaveLength(0);
    } finally {
      await s.close();
    }
  });

  it('serves the tripwire page on a decoy and marks a client that follows it', async () => {
    setup({ tripwire: true }, 'monitor', { deception: { paths: ['/wp-admin'], action: 'monitor', ttlSeconds: 60 } });
    const s = await serve(app);
    try {
      const d = await get(`${s.url}/wp-admin`);
      expect(d.status).toBe(404);
      const url = /(\/_debug\/console\/[A-Za-z0-9_-]{16})/.exec(d.body)?.[1];
      expect(url).toBeDefined();
      const hit = await get(`${s.url}${url}`);
      expect(hit.status).toBe(404);
      expect(attrs().find((a) => a['shield360.rasp.rule'] === 'attack_agent.tripwire')).toMatchObject({ 'shield360.rasp.client_kind': 'ai_attack_agent', 'shield360.rasp.reason': 'tripwire' });
    } finally {
      await s.close();
    }
  });

  it('serves the plain 404 on a decoy while the tripwire is off', async () => {
    setup({}, 'monitor', { deception: { paths: ['/wp-admin'], action: 'monitor', ttlSeconds: 60 } });
    const s = await serve(app);
    try {
      const d = await get(`${s.url}/wp-admin`);
      expect(d.body).toBe('Not Found');
    } finally {
      await s.close();
    }
  });

  it('follows a signed-in user across addresses', async () => {
    setup({ threshold: 6 });
    const t = setAttackAgentTracker(new AttackAgentTracker());
    const userApp = raspHttp((req, res) => {
      identifyRaspUser('mallory');
      res.statusCode = 403;
      res.end();
    });
    const s = await serve(userApp);
    try {
      for (let i = 0; i < 3; i++) await get(`${s.url}/admin`);
      expect(t.markOf(['u:mallory'], Date.now())).toEqual({ kind: 'ai_attack_agent', reason: 'behavior' });
    } finally {
      await s.close();
    }
  });
});

describe('withRasp (Next.js route handlers)', () => {
  beforeEach(() => {
    events.length = 0;
  });
  it('deters a marked client and scores the handler status', async () => {
    setup({ threshold: 5 });
    const handler = withRasp(async () => new Response('missing', { status: 401 }));
    const r1 = await handler(new Request('http://app.local/api/login', { headers: { 'user-agent': 'Mozilla/5.0' } }), {});
    expect(r1.status).toBe(401);
    // No client address in a route handler: the user key carries the score.
    const deter = await withRasp(async () => new Response('ok'))(new Request('http://app.local/api/x', { headers: { 'x-artex-replay-nonce': 'n' } }), {});
    expect(deter.status).toBe(429);
    expect(deter.headers.get('retry-after')).toBe('300');
  });
});
