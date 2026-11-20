import { generateKeyPairSync, sign } from 'crypto';
import { mkdtempSync } from 'fs';
import { tmpdir } from 'os';
import { join } from 'path';
import { createDefend, DEFEND_JWS_TYPE, DEFEND_POLICY_PATH } from '../../defend';
import { fingerprint } from '../crumb';
import { Honeypots, parseHoneypots } from '../honeypots';

const SECRET = Buffer.from('0123456789abcdef0123456789abcdef');
const settings = (mode: 'monitor' | 'challenge' | 'block' = 'block') => parseHoneypots({ enabled: true, mode, secret: SECRET.toString('base64url') })!;
const DAY = 86_400_000;

describe('honeypots', () => {
  it('reads the policy section, off unless enabled with a usable secret', () => {
    expect(parseHoneypots({ enabled: false, secret: SECRET.toString('base64url') })).toBeNull();
    expect(parseHoneypots({ enabled: true, secret: 'short' })).toBeNull();
    expect(settings().mode).toBe('block');
  });

  it('serves per-client crumbs that verify, with depth, attribution and rotation', () => {
    let t = 20000 * DAY;
    const hp = new Honeypots(settings(), ['orders', 'invoices'], () => t);
    const c = hp.crumbsFor('203.0.113.5', 'agent/1');
    const fp = fingerprint('203.0.113.5', 'agent/1').toString('hex');
    expect(c.path).toMatch(/^\/(orders|invoices)\/_internal\/[a-z2-7]{32}$/);
    expect(c.apiKey).toMatch(/^key_[a-z2-7]{32}$/);
    // Recon, a followed trail, a fake credential, the tripwire.
    expect(hp.check({ path: '/.env', headers: {} }, fp)?.level).toBe(1);
    expect(hp.check({ path: c.path, headers: {} }, fp)).toMatchObject({ level: 2, state: 'fresh', foreign: false });
    expect(hp.check({ path: '/api/orders', headers: { authorization: `Bearer ${c.apiKey}` } }, fp)?.level).toBe(3);
    const trip = /GET (\S+)/.exec(c.tripwire)?.[1] as string;
    expect(hp.check({ path: trip, headers: {} }, fp)?.level).toBe(4);
    // Another client presenting this client's crumb: one actor across addresses.
    expect(hp.check({ path: c.path, headers: {} }, fingerprint('198.51.100.7', 'agent/1').toString('hex'))).toMatchObject({ level: 3, foreign: true });
    // Rotation: still current for the grace window, then burned (level 3).
    t += DAY;
    expect(hp.check({ path: c.path, headers: {} }, fp)?.state).toBe('grace');
    t += DAY;
    expect(hp.check({ path: c.path, headers: {} }, fp)).toMatchObject({ state: 'burned', level: 3 });
    expect(hp.check({ path: '/orders/list', headers: {} }, fp)).toBeNull();
  });

  it('decoys answer harmless fake data with deeper crumbs; fake secrets match no real key format', () => {
    const hp = new Honeypots(settings(), [], () => 20000 * DAY);
    const env = hp.serve('/.env', '203.0.113.5', 'a');
    expect(env?.body).toContain('key_');
    expect(env?.body).not.toMatch(/AKIA|ghp_|sk_live_|xox[bp]-|eyJ/);
    expect(hp.serve('/orders', '203.0.113.5', 'a')).toBeNull();
  });

  it('acts by mode and level', () => {
    expect(new Honeypots(settings('monitor')).actionFor(4)).toBe('monitor');
    expect(new Honeypots(settings('challenge')).actionFor(1)).toBe('challenge');
    expect(new Honeypots(settings('challenge')).actionFor(2)).toBe('block');
    expect(new Honeypots(settings('block')).actionFor(1)).toBe('block');
  });
});

describe('honeypots in Defend', () => {
  const { publicKey, privateKey } = generateKeyPairSync('ed25519');
  const jwk = { ...(publicKey.export({ format: 'jwk' }) as Record<string, string>), kid: 'k1' };
  const b64 = (o: unknown) => Buffer.from(JSON.stringify(o)).toString('base64url');
  const jws = (claims: Record<string, unknown>) => {
    const head = b64({ alg: 'EdDSA', typ: DEFEND_JWS_TYPE, kid: 'k1' });
    const body = b64(claims);
    return `${head}.${body}.${sign(null, Buffer.from(`${head}.${body}`), privateKey).toString('base64url')}`;
  };
  const make = (mode: string, reports: unknown[] = []) => {
    const claims = { v: 1, app: 'shop', exp: Math.floor(Date.now() / 1000) + 3600, version: 'v1', listsVersion: 'l1', rules: [], deny: [], allow: ['198.51.100.200'], honeypots: { enabled: true, mode, secret: SECRET.toString('base64url') } };
    return createDefend({
      app: 'shop', url: 'https://s360.test', apiKey: 'test-key', configPublicKey: jwk, env: {}, cacheDir: mkdtempSync(join(tmpdir(), 'defend-hp-')),
      fetchImpl: (async (u: string, init?: RequestInit) => {
        if (String(u).includes(DEFEND_POLICY_PATH)) return new Response(JSON.stringify({ config: jws(claims), keys: [jwk] }));
        if (String(u).includes('/api/defend/report')) reports.push(JSON.parse(String(init?.body)));
        return new Response(JSON.stringify({ version: 'l1' }));
      }) as unknown as typeof fetch,
    });
  };

  it('blocks the next request of a client that followed a crumb, at once, while answering the crumb with fake data', async () => {
    const reports: { events: { kind: string; reasons: string[] }[] }[] = [];
    const shield = make('block', reports);
    await shield.ready();
    const req = (url: string, ip = '203.0.113.5') => ({ method: 'GET', url, ip, headers: { 'user-agent': 'agent/1' } });
    const crumbs = shield.crumbs(req('/'));
    expect(crumbs).not.toBeNull();
    const started = Date.now();
    const onCrumb = await shield.defend(req(crumbs!.path));
    expect(onCrumb.decoy?.status).toBe(200);
    const next = await shield.defend(req('/api/users'));
    expect(next).toMatchObject({ decision: 'deny', reasons: ['trap_hit'] });
    expect(Date.now() - started).toBeLessThan(50);
    await shield.close();
    expect(reports.flatMap((r) => r.events).find((e) => e.kind === 'trap_hit')?.reasons).toEqual(expect.arrayContaining(['trap:honeypot', 'level:2', 'crumb:fresh']));
  });

  it('never traps verified agents, trusted or private clients; monitor mode only reports', async () => {
    const shield = make('block');
    await shield.ready();
    expect(shield.crumbs({ method: 'GET', url: '/', ip: '198.51.100.200', headers: {} })).toBeNull();
    expect(shield.crumbs({ method: 'GET', url: '/', ip: '10.0.0.4', headers: {} })).toBeNull();
    expect((await shield.defend({ method: 'GET', url: '/.env', ip: '10.0.0.4', headers: {} })).decoy).toBeUndefined();
    await shield.close();
    const quiet = make('monitor');
    await quiet.ready();
    const c = quiet.crumbs({ method: 'GET', url: '/', ip: '203.0.113.9', headers: {} })!;
    await quiet.defend({ method: 'GET', url: c.path, ip: '203.0.113.9', headers: {} });
    expect((await quiet.defend({ method: 'GET', url: '/x', ip: '203.0.113.9', headers: {} })).decision).toBe('allow');
    await quiet.close();
  });
});
