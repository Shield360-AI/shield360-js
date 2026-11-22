import Shield360Config from '../config';

/**
 * Trusted devices, server side: your app's server registers its users'
 * devices with Shield360 so Shield360 Edge trusts the requests they sign.
 * End users never see a key: the device makes its own key pair (the
 * `@shield360/web` SDK in a browser, `@shield360/react-native-devices` in an
 * app, `createDeviceSigner` on a kiosk) and sends only its public key with the
 * sign-in request.
 *
 *   import Shield360 from 'shield360';
 *   // after a successful sign-in, with the public key the client sent:
 *   const { kid } = await Shield360.devices.register({ publicKey, userRef: user.pseudonymousId, label: 'Chrome on macOS' });
 *   // reply with kid; the client calls setDeviceKid(kid) and signs from then on.
 *   // at sign-out:
 *   await Shield360.devices.revoke(kid);           // this device
 *   await Shield360.devices.revokeUser(userRef);   // every device of the user
 *
 * Call it from your server, with the environment's API key (init()'s
 * shield360ApiKey or SHIELD360_API_KEY), never from a browser. Every method
 * throws a `DeviceError` when Shield360 refuses or cannot be reached; catch it
 * so a sign-in never fails because of it.
 *
 * `userRef` is your own pseudonymous id for the user (1 to 128 letters,
 * digits and . _ : -). Never an email address: Shield360 refuses any value
 * with "@".
 */

export type DeviceTrust = 'software' | 'hardware';

export interface DeviceScope {
  /** Only this app (Edge route `app`). */
  app?: string;
  /** Only these Edge route names. */
  routes?: string[];
  /** Only these path prefixes, each starting with "/". */
  paths?: string[];
}

export interface RegisterDeviceInput {
  /** SPKI DER in base64 (what the Shield360 device SDKs give), a P-256 JWK, or the 65-byte point. */
  publicKey: string | { kty: 'EC'; crv: 'P-256'; x: string; y: string };
  userRef: string;
  /** Shown in the console and your own settings screen, up to 80 characters. */
  label?: string;
  /** Default software. */
  trust?: DeviceTrust;
  scope?: DeviceScope;
  /** 1 to 3650; default 365. */
  expiresInDays?: number;
}

export interface DeviceInfo {
  kid: string;
  label: string;
  trust: string;
  scope: { app: string; routes: string[]; paths: string[] };
  createdAt: string;
  lastSeenAt: string | null;
  expiresAt: string | null;
}

export interface ConfirmPairingOptions {
  label?: string;
  scope?: DeviceScope;
  expiresInDays?: number;
}

export interface DevicesOptions {
  /** Shield360's URL; defaults to init()'s shield360Url, then SHIELD360_URL. */
  url?: string;
  /** The environment's API key; defaults to init()'s shield360ApiKey, then SHIELD360_API_KEY. */
  apiKey?: string;
  /** Per-request timeout in milliseconds. Default 5,000. */
  timeoutMs?: number;
  /** For tests: the fetch to use. */
  fetch?: typeof fetch;
}

/** Shield360 refused the request (status 4xx/5xx) or could not be reached (status 0). */
export class DeviceError extends Error {
  readonly status: number;
  readonly code?: string;
  constructor(message: string, status: number, code?: string) {
    super(message);
    this.name = 'DeviceError';
    this.status = status;
    this.code = code;
  }
}

const USER_REF = /^[A-Za-z0-9._:-]{1,128}$/;
const KID = /^[A-Za-z0-9_-]{8,64}$/;

function checkUserRef(userRef: unknown): string {
  if (typeof userRef !== 'string' || !USER_REF.test(userRef)) {
    throw new DeviceError('userRef must be a pseudonymous id (1-128 of A-Z a-z 0-9 . _ : -), never an email address.', 400, 'user_ref');
  }
  return userRef;
}

export class DevicesClient {
  constructor(private readonly options: DevicesOptions = {}) {}

  private settings() {
    const url = (this.options.url || Shield360Config.shield360Url || process.env.SHIELD360_URL || '').trim().replace(/\/+$/, '');
    const apiKey = (this.options.apiKey || Shield360Config.shield360ApiKey || process.env.SHIELD360_API_KEY || '').trim();
    if (!url || !apiKey) throw new DeviceError('Shield360 URL and API key are needed (init() or SHIELD360_URL / SHIELD360_API_KEY).', 0, 'not_configured');
    return { url, apiKey };
  }

  private async call<T>(method: string, path: string, body?: unknown): Promise<T> {
    const { url, apiKey } = this.settings();
    const doFetch = this.options.fetch ?? fetch;
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), this.options.timeoutMs ?? 5000);
    let response: Response;
    try {
      response = await doFetch(`${url}${path}`, {
        method,
        headers: { Authorization: `Bearer ${apiKey}`, ...(body === undefined ? {} : { 'Content-Type': 'application/json' }) },
        body: body === undefined ? undefined : JSON.stringify(body),
        signal: controller.signal,
      });
    } catch (err) {
      throw new DeviceError(`Shield360 could not be reached: ${err instanceof Error ? err.message : String(err)}`, 0, 'network');
    } finally {
      clearTimeout(timer);
    }
    let json: Record<string, unknown> = {};
    try {
      json = (await response.json()) as Record<string, unknown>;
    } catch {
      // An empty or non-JSON answer: the status says enough.
    }
    if (!response.ok) {
      throw new DeviceError(typeof json.err === 'string' ? json.err : `Shield360 answered ${response.status}.`, response.status, typeof json.code === 'string' ? json.code : undefined);
    }
    return json as T;
  }

  /** Registers a device's public key for a user. The same key again keeps its kid. */
  async register(input: RegisterDeviceInput): Promise<{ kid: string; expiresAt: string }> {
    if (!input || typeof input !== 'object') throw new DeviceError('register() needs { publicKey, userRef }.', 400, 'shape');
    checkUserRef(input.userRef);
    return this.call('POST', '/api/devices', input);
  }

  /** Revokes one device. Resolves true when revoked (or already revoked); throws 404 for an unknown kid. */
  async revoke(kid: string): Promise<boolean> {
    if (typeof kid !== 'string' || !KID.test(kid)) throw new DeviceError('That is not a device id.', 400, 'kid');
    const res = await this.call<{ revoked: boolean }>('DELETE', `/api/devices/${encodeURIComponent(kid)}`);
    return res.revoked === true;
  }

  /** Revokes every device of a user (sign out everywhere). Resolves to the number revoked. */
  async revokeUser(userRef: string): Promise<number> {
    const res = await this.call<{ revoked: number }>('DELETE', `/api/devices?userRef=${encodeURIComponent(checkUserRef(userRef))}`);
    return Number(res.revoked) || 0;
  }

  /** A user's live devices, for your own settings screen. */
  async list(userRef: string): Promise<DeviceInfo[]> {
    const res = await this.call<{ devices: DeviceInfo[] }>('GET', `/api/devices?userRef=${encodeURIComponent(checkUserRef(userRef))}`);
    return Array.isArray(res.devices) ? res.devices : [];
  }

  /** Confirms the 6-digit code a signed-in user typed from a kiosk; the kiosk's key is registered for them. */
  async confirmPairing(code: string, userRef: string, options: ConfirmPairingOptions = {}): Promise<{ kid: string; label: string }> {
    const digits = typeof code === 'string' ? code.replace(/[\s-]/g, '') : '';
    if (!/^[0-9]{6}$/.test(digits)) throw new DeviceError('code must be the 6 digits the kiosk shows.', 400, 'code');
    return this.call('POST', '/api/devices/pairings/confirm', { code: digits, userRef: checkUserRef(userRef), ...options });
  }
}

/** The default client, configured by init() or the environment. */
export const devices = new DevicesClient();
