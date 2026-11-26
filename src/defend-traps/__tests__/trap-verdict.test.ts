// SHIELD: decoy and trap verdicts (agent-guides/edge-deception-spec.md, "What each layer does"):
// a Defend trap hit behind Edge tells Edge to block the client fleet-wide.
import { createHmac, generateKeyPairSync, sign } from 'crypto';
import { mkdtempSync } from 'fs';
import { tmpdir } from 'os';
import { join } from 'path';
import { createDefend, DEFEND_JWS_TYPE, DEFEND_POLICY_PATH } from '../../defend';
import { pathHash, verifyVerdict, VERDICT_HEADER } from '../../rasp/edge-context';

const SECRET = Buffer.from('0123456789abcdef0123456789abcdef');
const EDGE_KEY = Buffer.from('0123456789abcdef0123456789abcdef');
const KEYS = [{ kid: '0a1b2c3d', key: EDGE_KEY }];

describe('Defend trap verdicts', () => {
  const { publicKey, privateKey } = generateKeyPairSync('ed25519');
  const jwk = { ...(publicKey.export({ format: 'jwk' }) as Record<string, string>), kid: 'k1' };
  const b64 = (o: unknown) => Buffer.from(JSON.stringify(o)).toString('base64url');
  const jws = (claims: Record<string, unknown>) => {
    const head = b64({ alg: 'EdDSA', typ: DEFEND_JWS_TYPE, kid: 'k1' });
    const body = b64(claims);
    return `${head}.${body}.${sign(null, Buffer.from(`${head}.${body}`), privateKey).toString('base64url')}`;
  };
  const make = (mode: string, env: Record<string, string> = {}) => {
    const claims = {
      v: 1, app: 'shop', exp: Math.floor(Date.now() / 1000) + 3600, version: 'v1', listsVersion: 'l1', rules: [], deny: [], allow: [],
      traps: { action: 'block', ttlSeconds: 1800 },
      honeypots: { enabled: true, mode, secret: SECRET.toString('base64url') },
      edgeContext: { keys: [{ kid: '0a1b2c3d', key: EDGE_KEY.toString('base64url') }] },
    };
    return createDefend({
      app: 'shop', url: 'https://s360.test', apiKey: 'test-key', configPublicKey: jwk, env, report: false, cacheDir: mkdtempSync(join(tmpdir(), 'defend-tv-')),
      fetchImpl: (async (u: string) => (String(u).includes(DEFEND_POLICY_PATH) ? new Response(JSON.stringify({ config: jws(claims), keys: [jwk] })) : new Response(JSON.stringify({ version: 'l1' })))) as unknown as typeof fetch,
    });
  };
  const ctx = (path: string, over: Record<string, unknown> = {}) => {
    const now = Math.floor(Date.now() / 1000);
    const rid = `req_${Math.random().toString(36).slice(2, 12)}`;
    const payload = Buffer.from(JSON.stringify({ rid, iat: now, exp: now + 30, m: 'GET', ph: pathHash(path), ct: 'unknown', risk: 0, trap: 0, fl: false, ...over })).toString('base64url');
    return { rid, headers: { 'x-shield360-edge-context': `v1.0a1b2c3d.${payload}.${createHmac('sha256', EDGE_KEY).update('s360-ctx|v1|').update(payload).digest('base64url')}`, 'x-request-id': rid, 'user-agent': 'agent/1' } };
  };

  it('a crumb hit behind Edge carries a block verdict (cat trap, src defend, the trap TTL) on the decoy answer', async () => {
    const shield = make('block');
    await shield.ready();
    const ip = '203.0.113.40';
    const path = shield.crumbs({ method: 'GET', url: '/', ip, headers: { 'user-agent': 'agent/1' } })!.path;
    const c = ctx(path);
    const r = await shield.defend({ method: 'GET', url: path, ip, headers: c.headers });
    expect(r.decoy).toBeDefined();
    expect(verifyVerdict(KEYS, r.verdict!, c.rid)).toMatchObject({ act: 'block', cat: 'trap', src: 'defend', ttl: 1800 });
    // The fetch answer carries it to Edge.
    const c2 = ctx(path);
    const res = await shield.respond(new Request(`https://shop.test${path}`, { headers: { ...c2.headers, 'x-forwarded-for': '203.0.113.41' } }), { ip: '203.0.113.41' });
    expect(verifyVerdict(KEYS, res!.headers.get(VERDICT_HEADER)!, c2.rid)).toMatchObject({ act: 'block', cat: 'trap' });
    await shield.close();
  });

  it('flags instead in monitor mode, and sends nothing without Edge, for a verified crawler, a red team run or the simulated client', async () => {
    const quiet = make('block', { SHIELD360_DEFEND: 'monitor' });
    await quiet.ready();
    const qp = quiet.crumbs({ method: 'GET', url: '/', ip: '203.0.113.42', headers: { 'user-agent': 'agent/1' } })!.path;
    const qc = ctx(qp);
    const flagged = await quiet.defend({ method: 'GET', url: qp, ip: '203.0.113.42', headers: qc.headers });
    expect(verifyVerdict(KEYS, flagged.verdict!, qc.rid)).toMatchObject({ act: 'flag', cat: 'trap', src: 'defend' });
    await quiet.close();

    const shield = make('block');
    await shield.ready();
    const hit = async (ip: string, over: Record<string, unknown> | null) => {
      const path = shield.crumbs({ method: 'GET', url: '/', ip, headers: { 'user-agent': 'agent/1' } })!.path;
      const headers = over ? ctx(path, over).headers : { 'user-agent': 'agent/1' };
      return shield.defend({ method: 'GET', url: path, ip, headers });
    };
    expect((await hit('203.0.113.43', null)).verdict).toBeUndefined();
    expect((await hit('203.0.113.44', { ct: 'verified_crawler' })).verdict).toBeUndefined();
    expect((await hit('203.0.113.45', { rt: 'crun12345678' })).verdict).toBeUndefined();
    const sim = await hit('192.0.2.1', {});
    expect(sim.decoy).toBeDefined();
    expect(sim.verdict).toBeUndefined();
    await shield.close();
  });
});
