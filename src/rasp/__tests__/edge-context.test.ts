/**
 * SHIELD: the protection triangle — Edge's signed context header and the
 * app's signed verdict (edge-context.ts): verification, binding, replay,
 * the shared test vector, tightening monitor to block for a client Edge
 * flagged, the verdict header on the response, and the fail-safe (a header
 * that does not verify changes nothing).
 */
import { createServer, type IncomingMessage, type ServerResponse } from 'http';
import type { AddressInfo } from 'net';
import { createHmac } from 'crypto';
import { captureRequest } from '../capture';
import { storage } from '../context';
import { configureEngine, handleFinding, setEventSink, setRemoteConfig } from '../engine';
import { parseEdgeKeys, pathHash, ReplayCache, signVerdict, verifyEdgeContext, verifyVerdict, VERDICT_HEADER, type EdgeKey } from '../edge-context';
import { raspHttp } from '../middleware';
import { RaspBlockedError } from '../types';

const KEY = Buffer.from('0123456789abcdef0123456789abcdef');
const keys: EdgeKey[] = [{ kid: '0a1b2c3d', key: KEY }];
const NOW = 1_800_000_000_000;

function contextHeader(over: Record<string, unknown> = {}, key = KEY, kid = '0a1b2c3d') {
  const payload = Buffer.from(JSON.stringify({ rid: 'req_0123456789', iat: NOW / 1000, exp: NOW / 1000 + 30, m: 'POST', ph: pathHash('/api/orders'), ct: 'suspected_agent', risk: 80, trap: 2, fl: true, ...over })).toString('base64url');
  const sig = createHmac('sha256', key).update('s360-ctx|v1|').update(payload).digest('base64url');
  return `v1.${kid}.${payload}.${sig}`;
}
const req = { method: 'POST', path: '/api/orders', requestId: 'req_0123456789' };

describe('context header', () => {
  it('verifies, and is bound to the request, fresh and used once', () => {
    expect(verifyEdgeContext(keys, contextHeader(), req, NOW, new ReplayCache())).toMatchObject({ rid: 'req_0123456789', risk: 80, trap: 2, fl: true });
    expect(verifyEdgeContext(keys, contextHeader(), { ...req, path: '/api/admin' }, NOW, null)).toBeNull();
    expect(verifyEdgeContext(keys, contextHeader(), { ...req, method: 'GET' }, NOW, null)).toBeNull();
    expect(verifyEdgeContext(keys, contextHeader(), { ...req, requestId: 'req_someone_else' }, NOW, null)).toBeNull();
    expect(verifyEdgeContext(keys, contextHeader(), req, NOW + 60_000, null)).toBeNull();
    expect(verifyEdgeContext(keys, contextHeader({}, Buffer.from('f'.repeat(32))), req, NOW, null)).toBeNull();
    expect(verifyEdgeContext(keys, contextHeader({}, KEY, 'deadbeef'), req, NOW, null)).toBeNull();
    expect(verifyEdgeContext(keys, contextHeader({ extra: 1 }), req, NOW, null)).toBeNull();
    expect(verifyEdgeContext([], contextHeader(), req, NOW, null)).toBeNull();
    const cache = new ReplayCache();
    expect(verifyEdgeContext(keys, contextHeader(), req, NOW, cache)).not.toBeNull();
    expect(verifyEdgeContext(keys, contextHeader(), req, NOW, cache)).toBeNull(); // replay
  });

  it('reads keys from the signed config strictly', () => {
    expect(parseEdgeKeys({ keys: [{ kid: '0a1b2c3d', key: KEY.toString('base64url') }] })).toHaveLength(1);
    expect(parseEdgeKeys({ keys: [{ kid: 'bad', key: KEY.toString('base64url') }] })).toEqual([]);
    expect(parseEdgeKeys(undefined)).toEqual([]);
  });
});

describe('verdict header', () => {
  it('matches the Go test vector byte for byte', () => {
    const v = signVerdict(keys, { rid: 'req_0123456789', iat: 1800000000, act: 'block', cat: 'sql_injection', src: 'rasp', ttl: 600 });
    expect(v).toBe('v1.0a1b2c3d.eyJyaWQiOiJyZXFfMDEyMzQ1Njc4OSIsImlhdCI6MTgwMDAwMDAwMCwiYWN0IjoiYmxvY2siLCJjYXQiOiJzcWxfaW5qZWN0aW9uIiwic3JjIjoicmFzcCIsInR0bCI6NjAwfQ.oMGW2qT7G2DmQ6YrtxWyfCwzxWUhrAZUAo2cfbf5Nj8');
    expect(verifyVerdict(keys, v as string, 'req_0123456789', 1800000000_000)).toMatchObject({ act: 'block' });
    expect(verifyVerdict(keys, v as string, 'req_other_1234', 1800000000_000)).toBeNull();
    expect(signVerdict(keys, { rid: 'x', iat: 1, act: 'block', cat: 'sql_injection', src: 'rasp', ttl: 1 })).toBeNull();
  });
});

describe('RASP with Edge in front', () => {
  const events: any[] = [];
  beforeEach(() => {
    events.length = 0;
    configureEngine({ enabled: true, applicationName: 'orders-api', attacks: { sql_injection: 'monitor' }, env: {} });
    setRemoteConfig({ version: 'v', exp: Math.floor(Date.now() / 1000) + 3600, killSwitch: false, snippets: false, attacks: { sql_injection: 'monitor' }, rules: null, edgeKeys: keys });
    setEventSink({ add: (e) => events.push(e) });
  });
  afterAll(() => {
    setEventSink(undefined);
    configureEngine({ enabled: false, applicationName: 'default', env: {} });
  });

  const live = (over: Record<string, unknown> = {}) => {
    const now = Date.now();
    const payload = Buffer.from(JSON.stringify({ rid: `req_${now}abc`, iat: Math.floor(now / 1000), exp: Math.floor(now / 1000) + 30, m: 'POST', ph: pathHash('/api/orders'), ct: 'suspected_agent', risk: 80, trap: 2, fl: true, ...over })).toString('base64url');
    return { rid: `req_${now}abc`, header: `v1.0a1b2c3d.${payload}.${createHmac('sha256', KEY).update('s360-ctx|v1|').update(payload).digest('base64url')}` };
  };

  it('tightens monitor to block for a client Edge flagged, and tells Edge in a signed verdict', async () => {
    const { rid, header } = live();
    const server = createServer(
      raspHttp((_req: IncomingMessage, res: ServerResponse) => {
        try {
          handleFinding({ attack: 'sql_injection', rule: 'sql.tautology' }, 'sql.query');
          res.end('ok');
        } catch (e) {
          res.statusCode = e instanceof RaspBlockedError ? 403 : 500;
          res.end();
        }
      }) as any,
    );
    await new Promise<void>((r) => server.listen(0, '127.0.0.1', () => r()));
    const { port } = server.address() as AddressInfo;
    try {
      const res = await fetch(`http://127.0.0.1:${port}/api/orders`, { method: 'POST', headers: { 'x-shield360-edge-context': header, 'x-shield360-request-id': rid } });
      expect(res.status).toBe(403);
      const verdict = res.headers.get(VERDICT_HEADER);
      expect(verifyVerdict(keys, verdict as string, rid)).toMatchObject({ act: 'block', cat: 'sql_injection', src: 'rasp' });
      expect(events[0].attrs['shield360.rasp.tightened_by_edge']).toBe('true');
      expect(events[0].attrs['shield360.edge.request_id']).toBe(rid);
    } finally {
      await new Promise((r) => server.close(r));
    }
  });

  it('changes nothing when the header does not verify (fail-safe), or when Edge trusts the client', () => {
    for (const header of [live().header.slice(0, -3) + 'AAA', live({ fl: false, trap: 0, risk: 10 }).header]) {
      const ctx = captureRequest({ framework: 'http', method: 'POST', url: '/api/orders', headers: { 'x-shield360-edge-context': header } });
      const set: string[] = [];
      ctx.setHeader = (n) => set.push(n);
      const decision = storage.run(ctx, () => handleFinding({ attack: 'sql_injection', rule: 'sql.tautology' }, 'sql.query'));
      expect(decision).toBe('monitored');
      if (!ctx.edge) expect(set).toEqual([]);
    }
  });
});
