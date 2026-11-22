/**
 * SHIELD: the protection triangle (agent-guides/edge-deception-spec.md,
 * "Protection triangle"). Shield360 Edge in front of the app sends a signed,
 * short-lived `X-Shield360-Edge-Context` header with what it knows about the
 * client; the app's RASP verifies it and may tighten on it (a borderline
 * SQL injection from a client Edge already flagged is blocked, not only
 * reported). When RASP or Defend detects an attack in a request that came
 * through Edge, it answers with a signed `X-Shield360-Verdict` header so
 * Edge blocks that client on its next request, and every Edge within
 * seconds. Edge strips the verdict before the response reaches the client.
 *
 * Both headers are `v1.<kid>.<base64url payload>.<base64url HMAC-SHA-256>`
 * with the environment's key from the signed config (`edgeContext`). A
 * header that does not verify is ignored: the app then acts on its own, as
 * it does with no Edge in front. Never throws.
 */
import { createHash, createHmac, timingSafeEqual } from 'crypto';

export const CONTEXT_HEADER = 'x-shield360-edge-context';
export const VERDICT_HEADER = 'X-Shield360-Verdict';
// Edge's own request id, which Edge always sends upstream; the signed
// context's rid must equal it (a context lifted onto another request is refused).
export const REQUEST_ID_HEADER = 'x-request-id';

const CONTEXT_TTL_S = 30;
const SKEW_S = 5;
const MAX_HEADER = 4096;
const MAX_VERDICT_TTL_S = 86_400;
const KID = /^[0-9a-f]{8}$/;
const RID = /^[A-Za-z0-9_-]{8,64}$/;
const CAT = /^[a-z][a-z0-9_]{0,39}$/;
const CLIENTS = new Set(['human', 'verified_crawler', 'verified_agent', 'automation', 'suspected_agent', 'unknown']);
const CONTEXT_KEYS = new Set(['rid', 'iat', 'exp', 'm', 'ph', 'ct', 'risk', 'waf', 'trap', 'fl', 'tp', 'rt', 'sid', 'fp', 'dk', 'dt']);
// A red team run id (rt): Edge verified the request's X-Shield360-Red-Team header.
const RUN = /^[a-z0-9]{8,40}$/;
// Edge's security session (sid, the s360_sid cookie) and request fingerprint (fp).
const SID = /^[A-Za-z0-9_-]{22}$/;
const FP = /^[0-9a-f]{16}$/;
// Edge's trusted device key (dk, its id) and trust level (dt).
const DK = /^[A-Za-z0-9_-]{8,64}$/;
const TRUSTS = new Set(['software', 'hardware', 'attested']);
const VERDICT_KEYS = new Set(['rid', 'iat', 'act', 'cat', 'src', 'ttl']);

export type EdgeKey = { kid: string; key: Buffer };

export type EdgeContext = {
  rid: string;
  iat: number;
  exp: number;
  m: string;
  ph: string;
  ct: string;
  risk: number;
  waf?: string[];
  trap: number;
  fl: boolean;
  tp?: string;
  /** The red team run Edge verified this request belongs to (its X-Shield360-Red-Team header). */
  rt?: string;
  /** Edge's security session (the s360_sid cookie), on routes with Edge's security cookie on. */
  sid?: string;
  /** Edge's request fingerprint, on routes with Edge's security cookie on. */
  fp?: string;
  /** The trusted device key Edge verified the request comes from, on routes with trusted devices on. */
  dk?: string;
  /** That device's trust level: software, hardware or attested. */
  dt?: string;
};

export type EdgeVerdict = { rid: string; iat: number; act: 'block' | 'flag'; cat: string; src: 'rasp' | 'sdk' | 'defend'; ttl: number };

/** Reads the signed config's `edgeContext` keys: [{ kid, key: base64url }], at most two. */
export function parseEdgeKeys(raw: unknown): EdgeKey[] {
  const list = raw && typeof raw === 'object' && Array.isArray((raw as { keys?: unknown }).keys) ? (raw as { keys: unknown[] }).keys : [];
  const out: EdgeKey[] = [];
  for (const k of list.slice(0, 2)) {
    if (!k || typeof k !== 'object') return [];
    const { kid, key } = k as { kid?: unknown; key?: unknown };
    if (typeof kid !== 'string' || !KID.test(kid) || typeof key !== 'string' || !/^[A-Za-z0-9_-]{43}$/.test(key)) return [];
    const buf = Buffer.from(key, 'base64url');
    if (buf.length !== 32) return [];
    out.push({ kid, key: buf });
  }
  return out;
}

export const pathHash = (path: string) => createHash('sha256').update(path).digest().subarray(0, 8).toString('hex');

const mac = (k: EdgeKey, label: string, payload: string) => createHmac('sha256', k.key).update(label).update(payload).digest();

function open(keys: EdgeKey[], label: string, value: string, allowed: Set<string>): Record<string, unknown> | null {
  if (!value || value.length > MAX_HEADER) return null;
  const parts = value.split('.');
  if (parts.length !== 4 || parts[0] !== 'v1' || !KID.test(parts[1])) return null;
  const k = keys.find((x) => x.kid === parts[1]);
  if (!k) return null;
  let sig: Buffer;
  try {
    sig = Buffer.from(parts[3], 'base64url');
  } catch {
    return null;
  }
  const want = mac(k, label, parts[2]);
  if (sig.length !== want.length || !timingSafeEqual(sig, want)) return null;
  try {
    const obj = JSON.parse(Buffer.from(parts[2], 'base64url').toString('utf8'));
    if (!obj || typeof obj !== 'object' || Array.isArray(obj) || Object.keys(obj).some((x) => !allowed.has(x))) return null;
    return obj as Record<string, unknown>;
  } catch {
    return null;
  }
}

/** Remembers ids until they expire; bounded. */
export class ReplayCache {
  private readonly seen = new Map<string, number>();
  constructor(private readonly max = 10_000) {}
  first(id: string, expMs: number, nowMs: number): boolean {
    const t = this.seen.get(id);
    if (t !== undefined && t > nowMs) return false;
    if (this.seen.size >= this.max) {
      for (const [k, v] of this.seen) if (v <= nowMs) this.seen.delete(k);
      while (this.seen.size >= this.max) this.seen.delete(this.seen.keys().next().value as string);
    }
    this.seen.set(id, expMs);
    return true;
  }
}

const replay = new ReplayCache();

/**
 * Verifies the context header for this request: method, path and Edge's
 * request id (X-Request-Id), which must be present and equal the signed rid.
 * Null when absent or not valid.
 */
export function verifyEdgeContext(keys: EdgeKey[], value: unknown, req: { method: string; path: string; requestId?: string }, nowMs = Date.now(), cache: ReplayCache | null = replay): EdgeContext | null {
  try {
    if (typeof value !== 'string' || !keys.length) return null;
    const c = open(keys, 's360-ctx|v1|', value, CONTEXT_KEYS) as Partial<EdgeContext> | null;
    if (!c) return null;
    const now = Math.floor(nowMs / 1000);
    if (typeof c.rid !== 'string' || !RID.test(c.rid) || typeof c.ct !== 'string' || !CLIENTS.has(c.ct)) return null;
    if (typeof c.iat !== 'number' || typeof c.exp !== 'number' || c.iat > now + SKEW_S || c.exp < now - SKEW_S || c.exp - c.iat > CONTEXT_TTL_S) return null;
    // Bound to this request: method, path and Edge's X-Request-Id, which must be present.
    if (c.m !== req.method || c.ph !== pathHash(req.path) || typeof req.requestId !== 'string' || req.requestId !== c.rid) return null;
    if (typeof c.risk !== 'number' || c.risk < 0 || c.risk > 100 || typeof c.trap !== 'number' || c.trap < 0 || c.trap > 4) return null;
    if (c.waf !== undefined && (!Array.isArray(c.waf) || c.waf.length > 16 || !c.waf.every((w) => typeof w === 'string' && CAT.test(w)))) return null;
    if (c.rt !== undefined && (typeof c.rt !== 'string' || !RUN.test(c.rt))) return null;
    if (c.sid !== undefined && (typeof c.sid !== 'string' || !SID.test(c.sid))) return null;
    if (c.fp !== undefined && (typeof c.fp !== 'string' || !FP.test(c.fp))) return null;
    if (c.dk !== undefined && (typeof c.dk !== 'string' || !DK.test(c.dk))) return null;
    if (c.dt !== undefined && (typeof c.dt !== 'string' || !TRUSTS.has(c.dt))) return null;
    if (cache && !cache.first(`c:${c.rid}`, (c.exp + SKEW_S) * 1000, nowMs)) return null;
    return { rid: c.rid, iat: c.iat, exp: c.exp, m: c.m, ph: c.ph, ct: c.ct, risk: c.risk, trap: c.trap, fl: c.fl === true, ...(c.waf ? { waf: c.waf } : {}), ...(typeof c.tp === 'string' ? { tp: c.tp } : {}), ...(c.rt ? { rt: c.rt } : {}), ...(c.sid ? { sid: c.sid } : {}), ...(c.fp ? { fp: c.fp } : {}), ...(c.dk ? { dk: c.dk } : {}), ...(c.dt ? { dt: c.dt } : {}) };
  } catch {
    return null;
  }
}

/** Signs a verdict for Edge with the current key. Null when there is no key or a value is out of bounds. */
export function signVerdict(keys: EdgeKey[], v: EdgeVerdict): string | null {
  try {
    const k = keys[0];
    if (!k || !RID.test(v.rid) || !CAT.test(v.cat) || (v.act !== 'block' && v.act !== 'flag') || !['rasp', 'sdk', 'defend'].includes(v.src) || v.ttl < 0 || v.ttl > MAX_VERDICT_TTL_S) return null;
    const payload = Buffer.from(JSON.stringify({ rid: v.rid, iat: v.iat, act: v.act, cat: v.cat, src: v.src, ttl: v.ttl })).toString('base64url');
    return `v1.${k.kid}.${payload}.${mac(k, 's360-verdict|v1|', payload).toString('base64url')}`;
  } catch {
    return null;
  }
}

/** Verifies a verdict (tests and other Shield360 layers); null when not valid. */
export function verifyVerdict(keys: EdgeKey[], value: string, rid: string, nowMs = Date.now()): EdgeVerdict | null {
  const v = open(keys, 's360-verdict|v1|', value, VERDICT_KEYS) as Partial<EdgeVerdict> | null;
  if (!v || v.rid !== rid || typeof v.iat !== 'number' || Math.abs(Math.floor(nowMs / 1000) - v.iat) > 60) return null;
  return v as EdgeVerdict;
}

/** Edge's view says this client is already suspect: RASP tightens monitor to block for injection-class attacks. */
export function edgeSaysSuspect(c: EdgeContext | undefined): boolean {
  return !!c && c.ct !== 'verified_crawler' && c.ct !== 'verified_agent' && (c.fl || c.trap >= 2 || c.risk >= 70);
}
