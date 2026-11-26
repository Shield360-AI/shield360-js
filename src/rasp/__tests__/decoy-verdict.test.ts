/**
 * SHIELD: decoy and trap verdicts (sdk/rasp/README.md "Deception", "Protection
 * triangle"): a decoy hit behind Edge carries a signed verdict, so Edge blocks
 * the client fleet-wide; never without a verified context, for a verified
 * crawler, a red team run or the simulated client.
 */
import { createHmac } from 'crypto';
import { createServer, request as httpRequest, type Server } from 'http';
import type { AddressInfo } from 'net';
import { checkDeception, setSuspiciousTable, SuspiciousTable } from '../deception';
import { pathHash, verifyVerdict, VERDICT_HEADER } from '../edge-context';
import { configureEngine, setEventSink, setRemoteConfig } from '../engine';
import { toRemote } from '../index';
import { raspHttp, withRasp } from '../middleware';
import type { RaspClaims } from '../config-client';

const EDGE_KEY = Buffer.from('0123456789abcdef0123456789abcdef');
const KEYS = [{ kid: '0a1b2c3d', key: EDGE_KEY }];
const events: { attrs: Record<string, unknown> }[] = [];

function setup(action: 'block' | 'monitor', keyed = true) {
  configureEngine({ enabled: true, applicationName: 'orders-api', env: {} });
  setEventSink({ add: (e) => events.push(e as never) });
  const claims = { v: 1, app: 'orders-api', exp: 4_000_000_000, version: 'v-dv', attacks: { ai_attack_agent: 'off' }, deception: { paths: ['/wp-admin'], action, ttlSeconds: 1200 }, ...(keyed ? { edgeContext: { keys: [{ kid: '0a1b2c3d', key: EDGE_KEY.toString('base64url') }] } } : {}) } as unknown as RaspClaims;
  setRemoteConfig(toRemote(claims));
  setSuspiciousTable(new SuspiciousTable());
}

function ctx(path: string, over: Record<string, unknown> = {}) {
  const now = Math.floor(Date.now() / 1000);
  const rid = `req_${Math.random().toString(36).slice(2, 12)}`;
  const payload = Buffer.from(JSON.stringify({ rid, iat: now, exp: now + 30, m: 'GET', ph: pathHash(path), ct: 'unknown', risk: 0, trap: 0, fl: false, ...over })).toString('base64url');
  return { rid, headers: { 'x-shield360-edge-context': `v1.0a1b2c3d.${payload}.${createHmac('sha256', EDGE_KEY).update('s360-ctx|v1|').update(payload).digest('base64url')}`, 'x-request-id': rid } };
}

const hit = (path: string, ip: string, headers: Record<string, string>) => checkDeception({ framework: 'test', method: 'GET', url: path, ip, headers });

beforeEach(() => {
  events.length = 0;
});
afterAll(() => {
  setEventSink(undefined);
  setRemoteConfig(undefined);
  configureEngine({ enabled: false, applicationName: 'default', env: {} });
  setSuspiciousTable(new SuspiciousTable());
});

describe('decoy hit -> verdict', () => {
  it('a blocked decoy hit behind Edge carries block, cat deception, src rasp, the deception TTL', () => {
    setup('block');
    const c = ctx('/wp-admin/setup.php');
    const out = hit('/wp-admin/setup.php', '203.0.113.7', c.headers);
    expect(out.notFound).toBe(true);
    expect(verifyVerdict(KEYS, out.verdict!, c.rid)).toMatchObject({ act: 'block', cat: 'deception', src: 'rasp', ttl: 1200 });
    expect(events[0].attrs['shield360.rasp.rule']).toBe('deception.hit');
  });

  it('a monitored hit flags; no context, a forged one, a verified crawler, a red team run or the simulated client send nothing', () => {
    setup('monitor');
    const c = ctx('/wp-admin');
    expect(verifyVerdict(KEYS, hit('/wp-admin', '203.0.113.8', c.headers).verdict!, c.rid)).toMatchObject({ act: 'flag', cat: 'deception' });
    setup('block');
    expect(hit('/wp-admin', '203.0.113.9', {}).verdict).toBeUndefined();
    const forged = ctx('/wp-admin');
    expect(hit('/wp-admin', '203.0.113.9', { ...forged.headers, 'x-shield360-edge-context': forged.headers['x-shield360-edge-context'].slice(0, -2) + 'xx' }).verdict).toBeUndefined();
    expect(hit('/wp-admin', '203.0.113.10', ctx('/wp-admin', { ct: 'verified_crawler' }).headers).verdict).toBeUndefined();
    expect(hit('/wp-admin', '203.0.113.11', ctx('/wp-admin', { rt: 'crun12345678' }).headers).verdict).toBeUndefined();
    const sim = hit('/wp-admin', '192.0.2.1', ctx('/wp-admin').headers);
    expect(sim.notFound).toBe(true);
    expect(sim.verdict).toBeUndefined();
    // Every hit is still reported.
    expect(events.filter((e) => e.attrs['shield360.rasp.rule'] === 'deception.hit')).toHaveLength(6);
    setup('block', false);
    expect(hit('/wp-admin', '203.0.113.12', ctx('/wp-admin').headers).verdict).toBeUndefined();
  });

  it('the adapters put it on the 404 (raw http, fetch)', async () => {
    setup('block');
    const server: Server = createServer(raspHttp((_req, res) => res.end('ok')));
    await new Promise<void>((r) => server.listen(0, '127.0.0.1', r));
    try {
      const c = ctx('/wp-admin');
      const got = await new Promise<{ status?: number; verdict?: string }>((resolve, reject) => {
        const rq = httpRequest({ host: '127.0.0.1', port: (server.address() as AddressInfo).port, path: '/wp-admin', headers: c.headers }, (res) => {
          res.resume();
          resolve({ status: res.statusCode, verdict: res.headers[VERDICT_HEADER.toLowerCase()] as string | undefined });
        });
        rq.on('error', reject);
        rq.end();
      });
      expect(got.status).toBe(404);
      expect(verifyVerdict(KEYS, got.verdict!, c.rid)).toMatchObject({ act: 'block', cat: 'deception' });
    } finally {
      await new Promise((r) => server.close(r));
    }
    const c2 = ctx('/wp-admin');
    const res = await withRasp(async () => new Response('ok'))(new Request('http://localhost/wp-admin', { headers: c2.headers }), {});
    expect(res.status).toBe(404);
    expect(verifyVerdict(KEYS, res.headers.get(VERDICT_HEADER)!, c2.rid)).toMatchObject({ act: 'block', cat: 'deception' });
  });
});
