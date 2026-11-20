/**
 * Property tests for the SDK's JWS verifiers: the agent passport
 * (agents/passport.ts + the verifier) and the signed RASP config
 * (rasp/config-client.ts). Properties, for any mutation of a valid token:
 *
 *   1. Nothing throws.
 *   2. Nothing but the exact signed token verifies: a flipped character, a
 *      re-encoded part, another alg (`none`, `HS256` keyed with the public
 *      key, `ES256`), another typ, an unknown or missing kid, a `crit`
 *      header, a stripped or doubled signature are all refused.
 */
import { createHmac, generateKeyPairSync, KeyObject, randomUUID, sign } from 'crypto';
import { agentVerifier } from '../../agents';
import { parsePassport, verifySignature } from '../../agents/passport';
import { JWS_TYPE, parsePublicKeys, verifyConfigJws } from '../../rasp/config-client';
import { FUZZ_ITERATIONS, FUZZ_SEED, rand, type Rand } from './fuzz-kit';

const T0 = Date.UTC(2026, 10, 19, 12, 0, 0);
const NOW = Math.floor(T0 / 1000);
const B64 = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_';

const b64 = (v: unknown) => Buffer.from(typeof v === 'string' ? v : JSON.stringify(v)).toString('base64url');

function keys() {
  const { privateKey, publicKey } = generateKeyPairSync('ed25519');
  const jwk = publicKey.export({ format: 'jwk' }) as { x: string };
  return { privateKey, publicKey, x: jwk.x };
}

function signWith(privateKey: KeyObject, header: unknown, claims: unknown): string {
  const input = `${b64(header)}.${b64(claims)}`;
  return `${input}.${sign(null, Buffer.from(input), privateKey).toString('base64url')}`;
}

/** Ways to break a token, each a classic JWS mistake or a random corruption. */
function mutate(r: Rand, token: string, ctx: { x: string; privateKey: KeyObject; header: Record<string, unknown>; claims: Record<string, unknown> }): string {
  const [h, p, s] = token.split('.');
  switch (r.int(14)) {
    case 0: {
      const parts = [h, p, s];
      const i = r.int(3);
      const chars = Array.from(parts[i]);
      if (!chars.length) return token;
      const at = r.int(chars.length);
      let c = r.pick(Array.from(B64));
      if (c === chars[at]) c = c === 'A' ? 'B' : 'A';
      chars[at] = c;
      parts[i] = chars.join('');
      return parts.join('.');
    }
    case 1:
      return `${b64({ ...ctx.header, alg: 'none' })}.${p}.`;
    case 2:
      return `${b64({ ...ctx.header, alg: 'none' })}.${p}.${s}`;
    case 3: {
      // HS256 keyed with the public key: the classic algorithm confusion.
      const head = b64({ ...ctx.header, alg: 'HS256' });
      const secret = Buffer.from(ctx.x, 'base64url');
      return `${head}.${p}.${createHmac('sha256', secret).update(`${head}.${p}`).digest('base64url')}`;
    }
    case 4:
      return signWith(ctx.privateKey, { ...ctx.header, alg: r.pick(['ES256', 'RS256', 'eddsa', 'EdDSA ', 'Ed25519', '']) }, ctx.claims);
    case 5:
      return signWith(ctx.privateKey, { ...ctx.header, typ: r.pick(['JWT', 'jwt', '', 'shield360-other+jwt']) }, ctx.claims);
    case 6:
      return signWith(ctx.privateKey, { ...ctx.header, crit: ['exp'] }, ctx.claims);
    case 7:
      return `${h}.${p}`;
    case 8:
      return `${h}.${p}.${s}.${s}`;
    case 9:
      return `${h}.${b64({ ...ctx.claims, [r.pick(Object.keys(ctx.claims))]: r.pick([null, 0, '', [], {}, 'x'.repeat(5000), Number.MAX_VALUE]) })}.${s}`;
    case 10:
      return `${h}.${p}.${b64(r.string('\u0000ÿ', 64))}`;
    case 11:
      // Same claims, padded base64 (standard alphabet) instead of base64url.
      return `${Buffer.from(JSON.stringify(ctx.header)).toString('base64')}.${p}.${s}`;
    case 12:
      return r.string(`${B64}.=+/ `, 200);
    default: {
      // A different, unpinned key signing the same claims.
      const other = generateKeyPairSync('ed25519').privateKey;
      return signWith(other, ctx.header, ctx.claims);
    }
  }
}

describe('agent passport verifier properties', () => {
  const k = keys();
  const kid = 'k1';
  const header = { alg: 'EdDSA', typ: 'shield360-agent+jwt', kid };
  const claims = {
    iss: 'https://app.shield360.ai',
    sub: 'agent:a1',
    aud: 'api.servflo.ai',
    iat: NOW,
    exp: NOW + 120,
    jti: randomUUID(),
    agent: { id: 'a1', name: 'bot' },
    operator: { id: 'org_1', name: 'Acme', domain: 'acme.com' },
  };
  const valid = signWith(k.privateKey, header, claims);
  const jwk = { ...k.publicKey.export({ format: 'jwk' }), kid };

  it('only the exact signed token verifies, and nothing throws', () => {
    const parsed = parsePassport(valid);
    expect(parsed.ok && verifySignature(parsed.passport, k.publicKey)).toBe(true);
    const r = rand(FUZZ_SEED);
    for (let i = 0; i < FUZZ_ITERATIONS * 5; i++) {
      const t = mutate(r, valid, { x: k.x, privateKey: k.privateKey, header, claims });
      if (t === valid) continue;
      let ok: boolean;
      try {
        const p = parsePassport(t);
        ok = p.ok && verifySignature(p.passport, k.publicKey);
      } catch (e) {
        throw new Error(`seed ${FUZZ_SEED} iteration ${i}: threw on ${JSON.stringify(t.slice(0, 200))}: ${String(e)}`);
      }
      // A re-encoding that decodes to the same bytes is the same token; anything else must fail.
      if (ok) {
        const [h1, p1, s1] = t.split('.');
        const same = Buffer.from(h1, 'base64url').equals(Buffer.from(valid.split('.')[0], 'base64url')) && p1 === valid.split('.')[1] && Buffer.from(s1, 'base64url').equals(Buffer.from(valid.split('.')[2], 'base64url'));
        if (!same) throw new Error(`seed ${FUZZ_SEED} iteration ${i}: a mutated passport verified: ${t}`);
      }
    }
  });

  it('the verifier end to end refuses alg none and HS256 confusion', async () => {
    const fetch = (async () => new Response(JSON.stringify({ keys: [jwk] }), { status: 200 })) as unknown as typeof globalThis.fetch;
    const v = agentVerifier({ audience: 'api.servflo.ai', fetch, clock: () => T0 });
    const [, p] = valid.split('.');
    const none = `${b64({ ...header, alg: 'none' })}.${p}.`;
    const hsHead = b64({ ...header, alg: 'HS256' });
    const hs = `${hsHead}.${p}.${createHmac('sha256', Buffer.from(k.x, 'base64url')).update(`${hsHead}.${p}`).digest('base64url')}`;
    expect((await v.check(none)).status).toBe('invalid');
    expect(await v.check(hs)).toMatchObject({ status: 'invalid', reason: 'unsupported_alg' });
    expect((await v.check(valid)).status).toBe('verified');
  });
});

describe('signed RASP config verifier properties', () => {
  const k = keys();
  const header = { alg: 'EdDSA', typ: JWS_TYPE, kid: 'k1' };
  const claims = { v: 1, app: 'orders-api', iat: NOW, exp: NOW + 3600, version: 'v1', killSwitch: false, mode: 'block' };
  const valid = signWith(k.privateKey, header, claims);
  const pinned = parsePublicKeys({ kty: 'OKP', crv: 'Ed25519', x: k.x, kid: 'k1' });

  it('only the exact signed config verifies, and nothing throws', () => {
    expect(verifyConfigJws(valid, pinned, 'orders-api', NOW).ok).toBe(true);
    const r = rand(FUZZ_SEED ^ 0x5bd1e995);
    for (let i = 0; i < FUZZ_ITERATIONS * 5; i++) {
      const t = mutate(r, valid, { x: k.x, privateKey: k.privateKey, header, claims });
      if (t === valid) continue;
      let res: ReturnType<typeof verifyConfigJws>;
      try {
        res = verifyConfigJws(t, pinned, 'orders-api', NOW);
      } catch (e) {
        throw new Error(`seed ${FUZZ_SEED} iteration ${i}: threw: ${String(e)}`);
      }
      if (res.ok) {
        const [h1, p1, s1] = t.split('.');
        const same = Buffer.from(h1, 'base64url').equals(Buffer.from(valid.split('.')[0], 'base64url')) && p1 === valid.split('.')[1] && Buffer.from(s1, 'base64url').equals(Buffer.from(valid.split('.')[2], 'base64url'));
        if (!same) throw new Error(`seed ${FUZZ_SEED} iteration ${i}: a mutated config verified: ${t}`);
      }
    }
  });

  it('never trusts an empty key list or an unpinned key', () => {
    expect(verifyConfigJws(valid, [], 'orders-api', NOW)).toEqual({ ok: false, reason: 'no_key' });
    const other = keys();
    expect(verifyConfigJws(valid, parsePublicKeys(other.x), 'orders-api', NOW)).toEqual({ ok: false, reason: 'signature' });
  });
});
