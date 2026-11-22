import { createPrivateKey, createPublicKey, generateKeyPairSync, sign, type KeyObject } from 'node:crypto';
import { chmodSync, mkdirSync, readFileSync, renameSync, writeFileSync } from 'node:fs';
import { dirname } from 'node:path';

/**
 * A trusted device in Node: a kiosk (a Raspberry Pi showing a dashboard), a
 * service or a CLI that Shield360 Edge should trust.
 *
 *   import { createDeviceSigner } from 'shield360/devices';
 *   const device = createDeviceSigner({
 *     keyFile: '/var/lib/kiosk/shield360-device.json',
 *     shield360Url: 'https://app.shield360.ai',
 *     browserKey: 's360_web_…',          // the app's PUBLIC browser key; never a secret API key
 *     label: 'Lobby display',
 *   });
 *   if (!device.kid) await device.pair({ onCode: (code) => showOnScreen(code) });
 *   const res = await device.signedFetch('https://app.example.com/display/today');
 *
 * The private key is a P-256 key made on first use and kept in `keyFile`
 * (mode 0600) with the device's kid; it never leaves the machine. Pairing
 * shows a 6-digit code that someone signed in to the app confirms; the app's
 * server calls `Shield360.devices.confirmPairing(code, userRef)`.
 *
 * `signedFetch` signs a request (the `Shield360-Device` header) only while it
 * holds no device pass. Edge answers a good signature with a 10-minute pass in
 * the `Shield360-Device-Pass` header, which is kept in memory and sent back
 * until it is about to expire, so the key signs about once per 10 minutes.
 */

export const DEVICE_HEADER = 'Shield360-Device';
export const DEVICE_PASS_HEADER = 'Shield360-Device-Pass';
const PAIRING_PATH = '/api/devices/pairings';
/** Sign again this long before a pass expires. */
const PASS_MARGIN_S = 30;

export interface DeviceSignerOptions {
  /** Where the key and kid are kept (JSON, mode 0600). Made on first use. */
  keyFile: string;
  /** Shield360's URL, for pairing. */
  shield360Url?: string;
  /** The app's public browser key (s360_web_…), for pairing. */
  browserKey?: string;
  /** Shown to whoever confirms the pairing and in the console. */
  label?: string;
  /** For tests: the fetch to use and the clock (ms). */
  fetch?: typeof fetch;
  now?: () => number;
}

export interface PairingStart {
  pairingId: string;
  code: string;
  expiresAt: string;
}

type Stored = { v: 1; privateKey: string; kid?: string };

function b64url(buf: Buffer): string {
  return buf.toString('base64url');
}

/** The message a device signs (Edge's wire format). */
export function signingMessage(ts: number, method: string, path: string): string {
  return `${ts}\n${method.toUpperCase()}\n${path}`;
}

/** The pass's expiry (unix seconds) from `<kid>.<exp>.<mac>`, or 0. */
export function passExpiry(pass: string | null | undefined): number {
  const parts = (pass || '').split('.');
  const exp = parts.length === 3 ? Number(parts[1]) : NaN;
  return Number.isInteger(exp) && exp > 0 ? exp : 0;
}

export class DeviceSigner {
  private key!: KeyObject;
  private stored!: Stored;
  private pass: { value: string; exp: number } | null = null;
  private readonly now: () => number;
  private readonly doFetch: typeof fetch;

  constructor(private readonly options: DeviceSignerOptions) {
    if (!options || typeof options.keyFile !== 'string' || !options.keyFile) throw new Error('createDeviceSigner needs a keyFile.');
    if (options.browserKey && options.browserKey.trim().startsWith('shield360-')) {
      throw new Error('That is a secret API key. Never put it on a device: pair with the app\'s public browser key (s360_web_…).');
    }
    this.now = options.now ?? Date.now;
    this.doFetch = options.fetch ?? fetch;
    this.load();
  }

  private load(): void {
    let stored: Stored | null = null;
    try {
      const parsed = JSON.parse(readFileSync(this.options.keyFile, 'utf8')) as Stored;
      if (parsed && parsed.v === 1 && typeof parsed.privateKey === 'string') stored = parsed;
    } catch {
      stored = null;
    }
    if (!stored) {
      const { privateKey } = generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
      stored = { v: 1, privateKey: privateKey.export({ format: 'pem', type: 'pkcs8' }).toString() };
      this.stored = stored;
      this.save();
    }
    this.stored = stored;
    this.key = createPrivateKey(stored.privateKey);
  }

  private save(): void {
    mkdirSync(dirname(this.options.keyFile), { recursive: true, mode: 0o700 });
    const tmp = `${this.options.keyFile}.tmp`;
    writeFileSync(tmp, JSON.stringify(this.stored), { mode: 0o600 });
    chmodSync(tmp, 0o600);
    renameSync(tmp, this.options.keyFile);
  }

  /** The kid Shield360 gave this device, once registered or paired. */
  get kid(): string | undefined {
    return this.stored.kid;
  }

  /** The public key, SPKI DER in base64: what the app's server registers. */
  getDevicePublicKey(): string {
    return (createPublicKey(this.key).export({ format: 'der', type: 'spki' }) as Buffer).toString('base64');
  }

  /** Keeps the kid (after the app's server registered the key) in the key file. */
  setDeviceKid(kid: string): void {
    if (typeof kid !== 'string' || !/^[A-Za-z0-9_-]{8,64}$/.test(kid)) throw new Error('That is not a device id.');
    this.stored.kid = kid;
    this.pass = null;
    this.save();
  }

  /** Forgets the key and kid (after revoking): the next use makes a new key. */
  reset(): void {
    const { privateKey } = generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
    this.stored = { v: 1, privateKey: privateKey.export({ format: 'pem', type: 'pkcs8' }).toString() };
    this.key = createPrivateKey(this.stored.privateKey);
    this.pass = null;
    this.save();
  }

  /** The signature (base64url, raw r||s) over Edge's message. */
  sign(ts: number, method: string, path: string): string {
    return b64url(sign('sha256', Buffer.from(signingMessage(ts, method, path), 'utf8'), { key: this.key, dsaEncoding: 'ieee-p1363' }));
  }

  /** The `Shield360-Device` header value for one request. */
  proofHeader(method: string, url: string): string {
    if (!this.stored.kid) throw new Error('This device has no kid yet: pair it or call setDeviceKid first.');
    const ts = Math.floor(this.now() / 1000);
    return `kid=${this.stored.kid}, ts=${ts}, sig=${this.sign(ts, method, new URL(url).pathname)}`;
  }

  private pairingUrl(path: string): string {
    const base = (this.options.shield360Url || process.env.SHIELD360_URL || '').trim().replace(/\/+$/, '');
    const key = (this.options.browserKey || '').trim();
    if (!base || !key) throw new Error('Pairing needs shield360Url and the app\'s public browser key.');
    return `${base}${path}?key=${encodeURIComponent(key)}`;
  }

  /** Asks Shield360 for a pairing code to show. */
  async startPairing(): Promise<PairingStart> {
    const ts = Math.floor(this.now() / 1000);
    const res = await this.doFetch(this.pairingUrl(PAIRING_PATH), {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ publicKey: this.getDevicePublicKey(), label: this.options.label ?? '', ts, sig: this.sign(ts, 'POST', PAIRING_PATH) }),
    });
    const body = (await res.json().catch(() => ({}))) as Record<string, unknown>;
    if (!res.ok) throw new Error(typeof body.err === 'string' ? body.err : `Pairing refused (${res.status}).`);
    return body as unknown as PairingStart;
  }

  /** One look at a pairing: pending, confirmed (with kid, which is kept) or expired. */
  async pairingStatus(pairingId: string): Promise<{ status: 'pending' | 'confirmed' | 'expired'; kid?: string }> {
    const res = await this.doFetch(this.pairingUrl(`${PAIRING_PATH}/${encodeURIComponent(pairingId)}`));
    const body = (await res.json().catch(() => ({}))) as { status?: string; kid?: string; err?: string };
    if (res.status === 404) return { status: 'expired' };
    if (!res.ok) throw new Error(body.err || `Pairing status refused (${res.status}).`);
    if (body.status === 'confirmed' && body.kid) {
      this.setDeviceKid(body.kid);
      return { status: 'confirmed', kid: body.kid };
    }
    return { status: body.status === 'expired' ? 'expired' : 'pending' };
  }

  /**
   * Pairs the device: shows a code through `onCode`, waits until someone
   * confirms it in the app, and starts over with a new code when one expires.
   * Resolves to the kid.
   */
  async pair(opts: { onCode: (code: string, expiresAt: string) => void; intervalMs?: number; signal?: AbortSignal; sleep?: (ms: number) => Promise<void> }): Promise<string> {
    const sleep = opts.sleep ?? ((ms: number) => new Promise<void>((r) => setTimeout(r, ms)));
    const interval = Math.max(1000, opts.intervalMs ?? 3000);
    for (;;) {
      const started = await this.startPairing();
      opts.onCode(started.code, started.expiresAt);
      for (;;) {
        if (opts.signal?.aborted) throw new Error('Pairing stopped.');
        await sleep(interval);
        const state = await this.pairingStatus(started.pairingId);
        if (state.status === 'confirmed' && state.kid) return state.kid;
        if (state.status === 'expired') break;
      }
    }
  }

  /**
   * fetch, with the device's proof or pass. Keeps the pass Edge answers with
   * and sends it back until it nearly expires; a 401 drops it so the next
   * request signs again.
   */
  async signedFetch(input: string | URL, init: RequestInit = {}): Promise<Response> {
    const url = typeof input === 'string' ? input : input.href;
    const method = (init.method || 'GET').toUpperCase();
    const headers = new Headers(init.headers);
    const nowS = Math.floor(this.now() / 1000);
    if (this.pass && this.pass.exp - PASS_MARGIN_S > nowS) headers.set(DEVICE_PASS_HEADER, this.pass.value);
    else if (this.stored.kid) headers.set(DEVICE_HEADER, this.proofHeader(method, url));
    const res = await this.doFetch(url, { ...init, method, headers });
    const pass = res.headers.get(DEVICE_PASS_HEADER);
    const exp = passExpiry(pass);
    if (pass && exp > nowS) this.pass = { value: pass, exp };
    else if (res.status === 401) this.pass = null;
    return res;
  }
}

export function createDeviceSigner(options: DeviceSignerOptions): DeviceSigner {
  return new DeviceSigner(options);
}
