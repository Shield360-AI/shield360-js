/**
 * Dynamic honeypot crumbs, byte for byte the shared specification
 * (agent-guides/edge-deception-spec.md) that Shield360 Edge implements in Go
 * (cli/internal/edge/honeypot/crumb.go): a crumb Edge served is recognized
 * here and the other way round. Stateless: the secret and the clock verify a
 * crumb; nothing is stored per crumb.
 */
import { createHash, createHmac, timingSafeEqual } from 'crypto';

export type CrumbKind = 'p' | 'c' | 'h' | 't' | 'n' | 'd';
export type CrumbState = 'fresh' | 'grace' | 'burned';
export type Crumb = { kind: CrumbKind; epoch: number; owner: string; state: CrumbState };

export const TOKEN_LEN = 32;
export const DEFAULT_EPOCH_S = 86_400;
export const MIN_EPOCH_S = 3600;
export const MAX_EPOCH_S = 604_800;
export const DEFAULT_GRACE = 1;
export const MAX_GRACE = 3;
const MAX_UA = 256;
const MAX_CANDIDATES = 8;
const KINDS = new Set(['p', 'c', 'h', 't', 'n', 'd']);
const ALPHA = 'abcdefghijklmnopqrstuvwxyz234567';

function b32encode(b: Buffer): string {
  let bits = 0;
  let value = 0;
  let out = '';
  for (const byte of b) {
    value = ((value << 8) | byte) & 0xffff;
    bits += 8;
    while (bits >= 5) {
      out += ALPHA[(value >>> (bits - 5)) & 31];
      bits -= 5;
    }
  }
  if (bits > 0) out += ALPHA[(value << (5 - bits)) & 31];
  return out;
}

function b32decode(s: string): Buffer | null {
  let bits = 0;
  let value = 0;
  const out: number[] = [];
  for (const ch of s) {
    const v = ALPHA.indexOf(ch);
    if (v < 0) return null;
    value = ((value << 5) | v) & 0xffff;
    bits += 5;
    if (bits >= 8) {
      out.push((value >>> (bits - 8)) & 0xff);
      bits -= 8;
    }
  }
  return Buffer.from(out);
}

/** An address as Go's netip prints it after Unmap: IPv4-mapped IPv6 as IPv4, IPv6 compressed lower case (RFC 5952). */
export function canonicalIp(ip: string): string {
  let s = ip.trim().toLowerCase();
  if (s.startsWith('[') && s.endsWith(']')) s = s.slice(1, -1);
  const mapped = /^::ffff:(\d+\.\d+\.\d+\.\d+)$/.exec(s);
  if (mapped) return mapped[1];
  if (!s.includes(':')) return s;
  const [head, tail] = s.split('::');
  const h = head ? head.split(':') : [];
  const t = tail !== undefined && tail ? tail.split(':') : [];
  const groups = tail !== undefined ? [...h, ...new Array(Math.max(0, 8 - h.length - t.length)).fill('0'), ...t] : h;
  const g = groups.map((x) => parseInt(x || '0', 16).toString(16));
  let best = -1;
  let len = 0;
  for (let i = 0; i < g.length; ) {
    if (g[i] !== '0') {
      i++;
      continue;
    }
    let j = i;
    while (j < g.length && g[j] === '0') j++;
    if (j - i > len && j - i >= 2) {
      best = i;
      len = j - i;
    }
    i = j;
  }
  if (best < 0) return g.join(':');
  return `${g.slice(0, best).join(':')}::${g.slice(best + len).join(':')}`;
}

/** fp = SHA-256("s360-fp|v1|" + ip + "|" + ua)[0:6]; ua lower-cased and cut to 256 bytes. */
export function fingerprint(ip: string, ua: string): Buffer {
  const u = Buffer.from(ua.toLowerCase(), 'utf8').subarray(0, MAX_UA);
  return createHash('sha256')
    .update(Buffer.concat([Buffer.from(`s360-fp|v1|${canonicalIp(ip)}|`), u]))
    .digest()
    .subarray(0, 6);
}

export class Crumbs {
  private readonly secret: Buffer;

  constructor(
    secret: Buffer,
    private readonly epochSeconds = DEFAULT_EPOCH_S,
    private readonly grace = DEFAULT_GRACE,
    private readonly now: () => number = Date.now,
  ) {
    if (secret.length !== 32) throw new Error('the honeypot secret must be 32 bytes');
    if (epochSeconds < MIN_EPOCH_S || epochSeconds > MAX_EPOCH_S) throw new Error('the honeypot epoch must be between 1h and 7 days');
    if (grace < 0 || grace > MAX_GRACE) throw new Error('the honeypot grace must be 0 to 3 epochs');
    this.secret = Buffer.from(secret);
  }

  epoch(): number {
    return Math.floor(this.now() / 1000 / this.epochSeconds) >>> 0;
  }

  private mac(head: Buffer): Buffer {
    return createHmac('sha256', this.secret).update('s360-crumb|').update(head).digest().subarray(0, 8);
  }

  tokenAt(epoch: number, kind: CrumbKind, fp: Buffer): string {
    const b = Buffer.alloc(20);
    b[0] = 1;
    b.writeUInt32BE(epoch >>> 0, 1);
    b[5] = kind.charCodeAt(0);
    fp.copy(b, 6, 0, 6);
    this.mac(b.subarray(0, 12)).copy(b, 12);
    return b32encode(b);
  }

  token(kind: CrumbKind, fp: Buffer): string {
    return this.tokenAt(this.epoch(), kind, fp);
  }

  /** The crumb a token is, or null when it is not one of this secret (or is from more than one epoch ahead). */
  verify(tok: string): Crumb | null {
    if (typeof tok !== 'string' || tok.length !== TOKEN_LEN || !/^[a-z2-7]+$/.test(tok)) return null;
    const raw = b32decode(tok);
    if (!raw || raw.length !== 20 || raw[0] !== 1) return null;
    if (!timingSafeEqual(raw.subarray(12), this.mac(raw.subarray(0, 12)))) return null;
    const kind = String.fromCharCode(raw[5]);
    if (!KINDS.has(kind)) return null;
    const epoch = raw.readUInt32BE(1);
    const now = this.epoch();
    if (epoch > now + 1) return null;
    const state: CrumbState = epoch >= now ? 'fresh' : now - epoch <= this.grace ? 'grace' : 'burned';
    return { kind: kind as CrumbKind, epoch, owner: raw.subarray(6, 12).toString('hex'), state };
  }
}

/** Runs of exactly 32 base32 characters in a string, at most 8: what a token could be. */
export function candidates(s: string): string[] {
  const out: string[] = [];
  let run = 0;
  for (let i = 0; i <= s.length; i++) {
    const c = i < s.length ? s.charCodeAt(i) : 0;
    if ((c >= 97 && c <= 122) || (c >= 50 && c <= 55)) {
      run++;
      continue;
    }
    if (run === TOKEN_LEN) {
      out.push(s.slice(i - TOKEN_LEN, i));
      if (out.length === MAX_CANDIDATES) return out;
    }
    run = 0;
  }
  return out;
}
