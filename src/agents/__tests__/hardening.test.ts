/**
 * Verifier hardening: the clock skew is bounded, and Web Bot Auth signatures
 * (which anyone can mint) never share the default replay store with passport
 * ids, so a flood of them cannot push a remembered passport out.
 */
import { generateKeyPairSync, KeyObject, randomUUID, sign } from 'crypto';
import { agentVerifier, MAX_CLOCK_SKEW_SECONDS, MemoryReplayStore } from '../index';
import { jwkThumbprint } from '../web-bot-auth';

const ISS = 'https://app.shield360.ai';
const T0 = Date.UTC(2026, 9, 28, 12, 0, 0);
const NOW = Math.floor(T0 / 1000);

type Keys = { kid: string; privateKey: KeyObject; jwk: Record<string, unknown> };

function makeKey(kid = 'k1'): Keys {
  const { privateKey, publicKey } = generateKeyPairSync('ed25519');
  return { kid, privateKey, jwk: { ...publicKey.export({ format: 'jwk' }), kid } };
}

const b64 = (v: unknown) => Buffer.from(JSON.stringify(v)).toString('base64url');

function passport(key: Keys, over: Record<string, unknown> = {}): string {
  const h = b64({ alg: 'EdDSA', typ: 'shield360-agent+jwt', kid: key.kid });
  const p = b64({
    iss: ISS,
    sub: 'agent:a1',
    aud: 'api.servflo.ai',
    iat: NOW,
    exp: NOW + 120,
    jti: randomUUID(),
    agent: { id: 'a1', name: 'bot' },
    operator: { id: 'org_1', name: 'Acme', domain: 'acme.com' },
    ...over,
  });
  return `${h}.${p}.${sign(null, Buffer.from(`${h}.${p}`), key.privateKey).toString('base64url')}`;
}

function fetchFor(key: Keys) {
  return (async (url: string) => {
    if (new URL(url).pathname === '/api/agent-passports/keys') return new Response(JSON.stringify({ keys: [key.jwk] }), { status: 200 });
    throw new Error(`unexpected ${url}`);
  }) as unknown as typeof fetch;
}

describe('clock skew bound', () => {
  it('lowers a huge clockSkewSeconds to MAX_CLOCK_SKEW_SECONDS', async () => {
    const key = makeKey();
    const expiredAnHourAgo = passport(key, { iat: NOW - 3700, exp: NOW - 3600 });
    const v = agentVerifier({ audience: 'api.servflo.ai', fetch: fetchFor(key), clock: () => T0, clockSkewSeconds: 86_400 });
    expect(await v.check(expiredAnHourAgo)).toMatchObject({ status: 'invalid', reason: 'expired' });
    // Inside the bound it still applies.
    const justExpired = passport(key, { iat: NOW - 200, exp: NOW - MAX_CLOCK_SKEW_SECONDS + 10 });
    expect((await v.check(justExpired)).status).toBe('verified');
  });

  it('treats a non-finite skew as the default', async () => {
    const key = makeKey();
    const v = agentVerifier({ audience: 'api.servflo.ai', fetch: fetchFor(key), clock: () => T0, clockSkewSeconds: Number.POSITIVE_INFINITY });
    expect(await v.check(passport(key, { iat: NOW - 3700, exp: NOW - 3600 }))).toMatchObject({ reason: 'expired' });
  });
});

describe('replay stores', () => {
  afterEach(() => jest.restoreAllMocks());

  it('keeps passports and Web Bot Auth signatures in separate default stores', async () => {
    const calls: { store: MemoryReplayStore; id: string }[] = [];
    const seen = MemoryReplayStore.prototype.seen;
    jest.spyOn(MemoryReplayStore.prototype, 'seen').mockImplementation(function (this: MemoryReplayStore, jti: string, until: number) {
      calls.push({ store: this, id: jti });
      return seen.call(this, jti, until);
    });
    const key = makeKey();
    // A Web Bot Auth signer: any host with a key directory.
    const { privateKey, publicKey } = generateKeyPairSync('ed25519');
    const jwk = publicKey.export({ format: 'jwk' }) as { kty: string; crv: string; x: string };
    const keyId = jwkThumbprint(jwk);
    const signer = 'https://signer.example.com';
    const f = (async (url: string) => {
      const u = new URL(url);
      if (u.pathname === '/api/agent-passports/keys') return new Response(JSON.stringify({ keys: [key.jwk] }), { status: 200 });
      if (u.origin === signer) return new Response(JSON.stringify({ keys: [jwk] }), { status: 200, headers: { 'content-type': 'application/http-message-signatures-directory+json' } });
      throw new Error(`unexpected ${url}`);
    }) as unknown as typeof fetch;
    const params = `;created=${NOW};expires=${NOW + 60};keyid="${keyId}";alg="ed25519";nonce="n-1";tag="web-bot-auth"`;
    const sigParams = `("@authority" "signature-agent")${params}`;
    const base = [`"@authority": api.servflo.ai`, `"signature-agent": "${signer}"`, `"@signature-params": ${sigParams}`].join('\n');
    const headers = {
      host: 'api.servflo.ai',
      'signature-agent': `"${signer}"`,
      'signature-input': `sig1=${sigParams}`,
      signature: `sig1=:${sign(null, Buffer.from(base), privateKey).toString('base64')}:`,
    };
    const v = agentVerifier({ audience: 'api.servflo.ai', fetch: f, clock: () => T0 });
    expect((await v.check(passport(key))).status).toBe('verified');
    expect((await v.check(headers)).status).toBe('verified');
    expect(calls).toHaveLength(2);
    expect(calls[1].id.startsWith('wba:')).toBe(true);
    expect(calls[0].store).not.toBe(calls[1].store);
  });

  it('uses one caller-supplied store for both, unchanged', async () => {
    const shared = new MemoryReplayStore({ clock: () => T0 });
    const spy = jest.spyOn(shared, 'seen');
    const key = makeKey();
    const v = agentVerifier({ audience: 'api.servflo.ai', fetch: fetchFor(key), clock: () => T0, replay: shared });
    await v.check(passport(key));
    expect(spy).toHaveBeenCalledTimes(1);
  });
});
