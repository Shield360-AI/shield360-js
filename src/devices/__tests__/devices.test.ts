import { createPublicKey, verify } from 'node:crypto';
import { mkdtempSync, readFileSync, statSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { DeviceError, DevicesClient, createDeviceSigner, passExpiry, signingMessage } from '..';

type Call = { url: string; init: RequestInit };

function fakeFetch(answers: Array<{ status?: number; body?: unknown; headers?: Record<string, string> }>) {
  const calls: Call[] = [];
  const fn = (async (url: string, init: RequestInit = {}) => {
    calls.push({ url, init });
    const a = answers.shift() ?? { status: 200, body: {} };
    return new Response(a.body === undefined ? null : JSON.stringify(a.body), { status: a.status ?? 200, headers: a.headers });
  }) as unknown as typeof fetch;
  return { fn, calls };
}

describe('DevicesClient', () => {
  const opts = (f: typeof fetch) => ({ url: 'https://s360.test/', apiKey: 'shield360-test', fetch: f });

  it('registers with the API key and returns the kid', async () => {
    const { fn, calls } = fakeFetch([{ status: 201, body: { kid: 'cldevice000001', expiresAt: '2027-01-01T00:00:00.000Z' } }]);
    const client = new DevicesClient(opts(fn));
    const res = await client.register({ publicKey: 'MFkw', userRef: 'user_1', label: 'Phone', scope: { paths: ['/app'] } });
    expect(res.kid).toBe('cldevice000001');
    expect(calls[0].url).toBe('https://s360.test/api/devices');
    expect(calls[0].init.method).toBe('POST');
    expect((calls[0].init.headers as Record<string, string>).Authorization).toBe('Bearer shield360-test');
    expect(JSON.parse(String(calls[0].init.body))).toEqual({ publicKey: 'MFkw', userRef: 'user_1', label: 'Phone', scope: { paths: ['/app'] } });
  });

  it('revokes, revokes a user, lists and confirms a pairing on the right routes', async () => {
    const { fn, calls } = fakeFetch([
      { body: { revoked: true } },
      { body: { revoked: 3 } },
      { body: { devices: [{ kid: 'cldevice000001' }] } },
      { status: 201, body: { kid: 'cldevice000002', label: 'Lobby' } },
    ]);
    const client = new DevicesClient(opts(fn));
    expect(await client.revoke('cldevice000001')).toBe(true);
    expect(await client.revokeUser('user_1')).toBe(3);
    expect(await client.list('user_1')).toHaveLength(1);
    expect(await client.confirmPairing('123-456', 'user_1', { label: 'Lobby' })).toEqual({ kid: 'cldevice000002', label: 'Lobby' });
    expect(calls.map((c) => `${c.init.method} ${c.url}`)).toEqual([
      'DELETE https://s360.test/api/devices/cldevice000001',
      'DELETE https://s360.test/api/devices?userRef=user_1',
      'GET https://s360.test/api/devices?userRef=user_1',
      'POST https://s360.test/api/devices/pairings/confirm',
    ]);
    expect(JSON.parse(String(calls[3].init.body))).toEqual({ code: '123456', userRef: 'user_1', label: 'Lobby' });
  });

  it('refuses emails, bad kids and bad codes before calling, and turns refusals into DeviceError', async () => {
    const { fn, calls } = fakeFetch([{ status: 409, body: { err: 'revoked key', code: 'revoked' } }]);
    const client = new DevicesClient(opts(fn));
    await expect(client.register({ publicKey: 'x', userRef: 'ada@example.com' })).rejects.toMatchObject({ code: 'user_ref' });
    await expect(client.revoke('no!')).rejects.toBeInstanceOf(DeviceError);
    await expect(client.confirmPairing('12345', 'user_1')).rejects.toMatchObject({ code: 'code' });
    expect(calls).toHaveLength(0);
    await expect(client.register({ publicKey: 'x', userRef: 'user_1' })).rejects.toMatchObject({ status: 409, code: 'revoked', message: 'revoked key' });
  });

  it('says when it is not configured or cannot reach Shield360', async () => {
    const saved = { url: process.env.SHIELD360_URL, key: process.env.SHIELD360_API_KEY };
    delete process.env.SHIELD360_URL;
    delete process.env.SHIELD360_API_KEY;
    try {
      await expect(new DevicesClient().list('user_1')).rejects.toMatchObject({ code: 'not_configured' });
    } finally {
      if (saved.url !== undefined) process.env.SHIELD360_URL = saved.url;
      if (saved.key !== undefined) process.env.SHIELD360_API_KEY = saved.key;
    }
    const failing = (async () => {
      throw new Error('ECONNREFUSED');
    }) as unknown as typeof fetch;
    await expect(new DevicesClient(opts(failing)).list('user_1')).rejects.toMatchObject({ status: 0, code: 'network' });
  });
});

describe('createDeviceSigner (Node devices and kiosks)', () => {
  const keyFile = () => join(mkdtempSync(join(tmpdir(), 's360-dev-')), 'nested', 'device.json');

  it('makes a key once, keeps it in a 0600 file and gives its SPKI public key', () => {
    const file = keyFile();
    const a = createDeviceSigner({ keyFile: file });
    const b = createDeviceSigner({ keyFile: file });
    expect(a.getDevicePublicKey()).toBe(b.getDevicePublicKey());
    expect(createPublicKey({ key: Buffer.from(a.getDevicePublicKey(), 'base64'), format: 'der', type: 'spki' }).asymmetricKeyDetails?.namedCurve).toBe('prime256v1');
    if (process.platform !== 'win32') expect(statSync(file).mode & 0o777).toBe(0o600);
    a.setDeviceKid('cldevice000001');
    expect(createDeviceSigner({ keyFile: file }).kid).toBe('cldevice000001');
    expect(readFileSync(file, 'utf8')).toContain('PRIVATE KEY');
  });

  it('refuses a secret API key as the pairing credential', () => {
    expect(() => createDeviceSigner({ keyFile: keyFile(), browserKey: 'shield360-secret' })).toThrow(/secret API key/);
  });

  it('signs Edge\'s message so the public key verifies it', () => {
    const now = 1_800_000_000_000;
    const d = createDeviceSigner({ keyFile: keyFile(), now: () => now });
    d.setDeviceKid('cldevice000001');
    const header = d.proofHeader('get', 'https://app.example.com/display/today?x=1');
    const m = /^kid=cldevice000001, ts=(\d+), sig=([A-Za-z0-9_-]+)$/.exec(header)!;
    expect(Number(m[1])).toBe(now / 1000);
    const key = createPublicKey({ key: Buffer.from(d.getDevicePublicKey(), 'base64'), format: 'der', type: 'spki' });
    expect(Buffer.from(m[2], 'base64url')).toHaveLength(64);
    expect(verify('sha256', Buffer.from(signingMessage(now / 1000, 'GET', '/display/today')), { key, dsaEncoding: 'ieee-p1363' }, Buffer.from(m[2], 'base64url'))).toBe(true);
  });

  it('pairs: sends its key and proof with the browser key, shows the code, starts over on expiry, keeps the kid', async () => {
    const { fn, calls } = fakeFetch([
      { status: 201, body: { pairingId: 'p1', code: '111111', expiresAt: 'x' } },
      { body: { status: 'expired' } },
      { status: 201, body: { pairingId: 'p2', code: '222222', expiresAt: 'y' } },
      { body: { status: 'pending' } },
      { body: { status: 'confirmed', kid: 'cldevice000009' } },
    ]);
    const file = keyFile();
    const d = createDeviceSigner({ keyFile: file, shield360Url: 'https://s360.test', browserKey: 's360_web_abc', label: 'Lobby', fetch: fn });
    const codes: string[] = [];
    const kid = await d.pair({ onCode: (c) => codes.push(c), sleep: async () => undefined });
    expect(kid).toBe('cldevice000009');
    expect(codes).toEqual(['111111', '222222']);
    expect(createDeviceSigner({ keyFile: file }).kid).toBe('cldevice000009');
    expect(calls[0].url).toBe('https://s360.test/api/devices/pairings?key=s360_web_abc');
    expect(calls[1].url).toBe('https://s360.test/api/devices/pairings/p1?key=s360_web_abc');
    const body = JSON.parse(String(calls[0].init.body));
    expect(body.publicKey).toBe(d.getDevicePublicKey());
    expect(body.label).toBe('Lobby');
    const key = createPublicKey({ key: Buffer.from(body.publicKey, 'base64'), format: 'der', type: 'spki' });
    expect(verify('sha256', Buffer.from(signingMessage(body.ts, 'POST', '/api/devices/pairings')), { key, dsaEncoding: 'ieee-p1363' }, Buffer.from(body.sig, 'base64url'))).toBe(true);
    expect(JSON.stringify(calls.map((c) => c.init.headers ?? {}))).not.toMatch(/authorization/i);
  });

  it('signs until Edge gives a pass, sends the pass back, and signs again near its expiry or after a 401', async () => {
    let now = 1_800_000_000_000;
    const exp = now / 1000 + 600;
    const { fn, calls } = fakeFetch([
      { body: {}, headers: { 'Shield360-Device-Pass': `cldevice000001.${exp}.mac` } },
      { body: {} },
      { status: 401, body: {} },
      { body: {} },
    ]);
    const d = createDeviceSigner({ keyFile: keyFile(), fetch: fn, now: () => now });
    d.setDeviceKid('cldevice000001');
    await d.signedFetch('https://app.example.com/a');
    await d.signedFetch('https://app.example.com/b', { method: 'POST', body: '{}' });
    const h = (i: number) => new Headers(calls[i].init.headers);
    expect(h(0).get('Shield360-Device')).toMatch(/^kid=cldevice000001, ts=/);
    expect(h(1).get('Shield360-Device')).toBeNull();
    expect(h(1).get('Shield360-Device-Pass')).toBe(`cldevice000001.${exp}.mac`);
    now += 590_000; // inside the margin before expiry
    await d.signedFetch('https://app.example.com/c');
    expect(h(2).get('Shield360-Device')).not.toBeNull();
    await d.signedFetch('https://app.example.com/d');
    expect(h(3).get('Shield360-Device')).not.toBeNull();
    expect(passExpiry('a.b.c')).toBe(0);
    expect(passExpiry(`k.${exp}.m`)).toBe(exp);
  });

  it('sends nothing extra before it has a kid', async () => {
    const { fn, calls } = fakeFetch([{ body: {} }]);
    const d = createDeviceSigner({ keyFile: keyFile(), fetch: fn });
    await d.signedFetch('https://app.example.com/a');
    expect(new Headers(calls[0].init.headers).get('Shield360-Device')).toBeNull();
  });
});
