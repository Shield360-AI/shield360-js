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
import { raspHttp, withRasp } from '../middleware';
import { currentEdgeIds } from '../../otel/edge-request';
import { RaspBlockedError } from '../types';
import { BUILT_IN_RULES, type VpRequest } from '../vpatch';
import { requestFor } from './corpus';

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
    // Edge always sends X-Request-Id: a context without it is never trusted (lifted onto another request).
    expect(verifyEdgeContext(keys, contextHeader(), { ...req, requestId: undefined }, NOW, null)).toBeNull();
    expect(verifyEdgeContext(keys, contextHeader(), req, NOW + 60_000, null)).toBeNull();
    expect(verifyEdgeContext(keys, contextHeader({}, Buffer.from('f'.repeat(32))), req, NOW, null)).toBeNull();
    expect(verifyEdgeContext(keys, contextHeader({}, KEY, 'deadbeef'), req, NOW, null)).toBeNull();
    expect(verifyEdgeContext(keys, contextHeader({ extra: 1 }), req, NOW, null)).toBeNull();
    expect(verifyEdgeContext([], contextHeader(), req, NOW, null)).toBeNull();
    const cache = new ReplayCache();
    expect(verifyEdgeContext(keys, contextHeader(), req, NOW, cache)).not.toBeNull();
    expect(verifyEdgeContext(keys, contextHeader(), req, NOW, cache)).toBeNull(); // replay
  });

  it('verifies once per request: a second layer on the same request gets the same context, another request is a replay', () => {
    const cache = new ReplayCache();
    const scope = {};
    const first = verifyEdgeContext(keys, contextHeader(), { ...req, scope }, NOW, cache);
    expect(first).toMatchObject({ rid: 'req_0123456789', trap: 2 });
    // RASP and Defend (or the zero-code capture and a framework middleware) both verify the same request.
    expect(verifyEdgeContext(keys, contextHeader(), { ...req, scope }, NOW, cache)).toEqual(first);
    // The same header lifted onto another request is still refused.
    expect(verifyEdgeContext(keys, contextHeader(), { ...req, scope: {} }, NOW, cache)).toBeNull();
    expect(verifyEdgeContext(keys, contextHeader(), req, NOW, cache)).toBeNull();
    // The shared result is still bound to the request it verified for.
    expect(verifyEdgeContext(keys, contextHeader(), { ...req, path: '/api/admin', scope }, NOW, cache)).toBeNull();
    expect(verifyEdgeContext(keys, contextHeader(), { ...req, requestId: 'req_someone_else', scope }, NOW, cache)).toBeNull();
    expect(verifyEdgeContext(keys, contextHeader({ risk: 1 }), { ...req, scope }, NOW, cache)).toBeNull();
    expect(verifyEdgeContext(keys, contextHeader(), { ...req, scope }, NOW + 60_000, cache)).toBeNull();
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

  let seq = 0;
  const live = (over: Record<string, unknown> = {}, method = 'POST', path = '/api/orders') => {
    const now = Date.now();
    const rid = `req_${now}_${++seq}`; // unique: the replay cache refuses a header seen before
    const payload = Buffer.from(JSON.stringify({ rid, iat: Math.floor(now / 1000), exp: Math.floor(now / 1000) + 30, m: method, ph: pathHash(path), ct: 'suspected_agent', risk: 80, trap: 2, fl: true, ...over })).toString('base64url');
    return { rid, header: `v1.0a1b2c3d.${payload}.${createHmac('sha256', KEY).update('s360-ctx|v1|').update(payload).digest('base64url')}` };
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
      const res = await fetch(`http://127.0.0.1:${port}/api/orders`, { method: 'POST', headers: { 'x-shield360-edge-context': header, 'x-request-id': rid } });
      expect(res.status).toBe(403);
      const verdict = res.headers.get(VERDICT_HEADER);
      expect(verifyVerdict(keys, verdict as string, rid)).toMatchObject({ act: 'block', cat: 'sql_injection', src: 'rasp' });
      expect(events[0].attrs['shield360.rasp.tightened_by_edge']).toBe('true');
      expect(events[0].attrs['shield360.edge.request_id']).toBe(rid);
    } finally {
      await new Promise((r) => server.close(r));
    }
  });

  it("keeps Edge's context when the zero-code capture and a framework middleware both capture the request", () => {
    const { rid, header } = live();
    const headers = { 'x-shield360-edge-context': header, 'x-request-id': rid };
    expect(captureRequest({ framework: 'http', method: 'POST', url: '/api/orders', headers }).edge).toMatchObject({ rid, trap: 2 });
    expect(captureRequest({ framework: 'express', method: 'POST', url: '/api/orders', headers }).edge).toMatchObject({ rid, trap: 2 });
    // Another request carrying the same header is a replay.
    expect(captureRequest({ framework: 'express', method: 'POST', url: '/api/orders', headers: { ...headers } }).edge).toBeUndefined();
  });

  it('raw http: a request a virtual patch blocks still carries the verdict', async () => {
    // A head rule: raw http leaves the body to the handler.
    const shape: VpRequest = requestFor(BUILT_IN_RULES.find((r) => r.example)!);
    setRemoteConfig({ version: 'v', exp: Math.floor(Date.now() / 1000) + 3600, killSwitch: false, snippets: false, attacks: { virtual_patch: 'block' }, rules: null, edgeKeys: keys });
    const { rid, header } = live({}, shape.method, '/checkout');
    const server = createServer(raspHttp((_req: IncomingMessage, res: ServerResponse) => res.end('ran')) as any);
    await new Promise<void>((r) => server.listen(0, '127.0.0.1', () => r()));
    const { port } = server.address() as AddressInfo;
    try {
      const res = await fetch(`http://127.0.0.1:${port}/checkout`, { method: shape.method, headers: { ...(shape.headers as Record<string, string>), 'x-shield360-edge-context': header, 'x-request-id': rid } });
      expect(res.status).toBe(403);
      expect(verifyVerdict(keys, res.headers.get(VERDICT_HEADER) as string, rid)).toMatchObject({ act: 'block', cat: 'virtual_patch' });
    } finally {
      await new Promise((r) => server.close(r));
    }
  });

  describe('Next.js route handlers (withRasp)', () => {
    const request = (rid: string, header: string, method = 'POST', path = '/api/orders', init: RequestInit = {}) =>
      new Request(`http://localhost${path}`, { method, ...init, headers: { 'x-shield360-edge-context': header, 'x-request-id': rid, ...((init.headers as Record<string, string>) ?? {}) } });

    it('tightens for a client Edge flagged and answers the 403 with a signed verdict', async () => {
      const { rid, header } = live();
      const handler = withRasp(async () => {
        handleFinding({ attack: 'sql_injection', rule: 'sql.tautology' }, 'sql.query');
        return new Response('ok');
      });
      const res = await handler(request(rid, header), {});
      expect(res.status).toBe(403);
      expect(verifyVerdict(keys, res.headers.get(VERDICT_HEADER) as string, rid)).toMatchObject({ act: 'block', cat: 'sql_injection', src: 'rasp' });
      expect(events[0].attrs['shield360.rasp.tightened_by_edge']).toBe('true');
      expect(events[0].attrs['shield360.edge.request_id']).toBe(rid);
    });

    it("puts a flag verdict on the handler's own Response, copying one with immutable headers", async () => {
      const { rid, header } = live({ fl: false, trap: 0, risk: 10 });
      const flagged = withRasp(async () => {
        expect(handleFinding({ attack: 'sql_injection', rule: 'sql.tautology' }, 'sql.query')).toBe('monitored');
        return new Response('ok', { status: 201 });
      });
      const res = await flagged(request(rid, header), {});
      expect(res.status).toBe(201);
      expect(await res.text()).toBe('ok');
      expect(verifyVerdict(keys, res.headers.get(VERDICT_HEADER) as string, rid)).toMatchObject({ act: 'flag', cat: 'sql_injection' });

      const second = live({ fl: false, trap: 0, risk: 10 });
      const redirect = withRasp(async () => {
        handleFinding({ attack: 'sql_injection', rule: 'sql.tautology' }, 'sql.query');
        return Response.redirect('http://localhost/next', 302);
      });
      const r2 = await redirect(request(second.rid, second.header), {});
      expect(r2.status).toBe(302);
      expect(r2.headers.get('location')).toBe('http://localhost/next');
      expect(verifyVerdict(keys, r2.headers.get(VERDICT_HEADER) as string, second.rid)).toMatchObject({ act: 'flag' });
    });

    it('stamps Edge request id on what the handler logs, and sends no verdict without a verified context', async () => {
      const { rid, header } = live();
      let ids: ReturnType<typeof currentEdgeIds> | undefined;
      const handler = withRasp(async () => {
        ids = currentEdgeIds();
        return new Response('ok');
      });
      await handler(request(rid, header, 'POST', '/api/orders', { headers: { traceparent: '00-0af7651916cd43dd8448eb211c80319c-b7ad6b7169203331-01' } }), {});
      expect(ids).toMatchObject({ requestId: rid });

      const plain = withRasp(async () => {
        ids = currentEdgeIds();
        handleFinding({ attack: 'sql_injection', rule: 'sql.tautology' }, 'sql.query');
        return new Response('ok');
      });
      const res = await plain(new Request('http://localhost/api/orders', { method: 'POST', headers: { 'x-request-id': '3f2a9c0d1e4b5a6978c0d1e2f3a4b5c6', traceparent: '00-0af7651916cd43dd8448eb211c80319c-b7ad6b7169203331-01' } }), {});
      expect(res.status).toBe(200);
      expect(res.headers.get(VERDICT_HEADER)).toBeNull();
      expect(ids).toMatchObject({ requestId: '3f2a9c0d1e4b5a6978c0d1e2f3a4b5c6', traceId: '0af7651916cd43dd8448eb211c80319c', spanActive: false });
    });

    it('a request a virtual patch blocks still carries the verdict', async () => {
      const rule = BUILT_IN_RULES.find((r) => r.id === 'vp.react2shell')!;
      const shape: VpRequest = requestFor(rule);
      setRemoteConfig({ version: 'v', exp: Math.floor(Date.now() / 1000) + 3600, killSwitch: false, snippets: false, attacks: { virtual_patch: 'block' }, rules: null, edgeKeys: keys });
      const { rid, header } = live({}, shape.method, '/checkout');
      const res = await withRasp(async () => new Response('ran'))(request(rid, header, shape.method, '/checkout', { headers: shape.headers as Record<string, string>, body: shape.body }), {});
      expect(res.status).toBe(403);
      expect(verifyVerdict(keys, res.headers.get(VERDICT_HEADER) as string, rid)).toMatchObject({ act: 'block', cat: 'virtual_patch' });
    });
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
