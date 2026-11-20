/**
 * Upload policy and deep scan settings (README "Uploads", "Upload policy and
 * deep scan"): the signed config's `uploads` block, else the local options,
 * read into one shape, and the policy that applies to a request's route.
 */
import { isAbsolute } from 'path';
import { tmpdir } from 'os';
import { join } from 'path';
import { compileSignatures, type CompiledSignature } from './upload-signatures';
import { UPLOAD_KINDS, UPLOAD_TYPES, DEFAULT_SCAN_BYTES, MAX_SCAN_BYTES } from './upload-inspect';
import type { RaspMode } from './types';

export type ScanTiming = 'sync' | 'async';
export type FailMode = 'open' | 'closed';
export type ClamAddress = { kind: 'unix'; path: string } | { kind: 'tcp'; host: string; port: number };

export type DeepScan = {
  mode: RaspMode;
  scan: ScanTiming;
  timeoutMs: number;
  failMode: FailMode;
  clamav: ClamAddress | null;
  reputation: boolean;
  testId: string | null;
};

export type RoutePolicy = {
  route: string;
  allow?: string[];
  maxBytes?: number;
  mode?: RaspMode;
  deepScan?: RaspMode;
  scan?: ScanTiming;
  timeoutMs?: number;
  failMode?: FailMode;
};

export type UploadConfig = {
  maxBytes: number | null;
  allow: string[];
  servedDirs: string[];
  trusted: Set<string>;
  rules: CompiledSignature[];
  deepScan: DeepScan;
  routes: RoutePolicy[];
};

/** `init({ rasp: { uploads } })`: used without a signed config; `scanBytes` and `quarantineDir` always. */
export type UploadOptions = {
  maxBytes?: number;
  allow?: string[];
  servedDirs?: string[];
  scanBytes?: number;
  quarantineDir?: string;
  deepScan?: Partial<{ mode: RaspMode; scan: ScanTiming; timeoutMs: number; failMode: FailMode; clamav: { address: string } | string; reputation: boolean }>;
  routes?: RoutePolicy[];
};

const MODES = ['off', 'monitor', 'block'];
const SHA = /^[0-9a-f]{64}$/;
const TEST_ID = /^[A-Za-z0-9_-]{8,64}$/;
const ALLOWED = new Set<string>([...UPLOAD_KINDS, ...UPLOAD_TYPES]);

const mode = (v: unknown): RaspMode | undefined => (typeof v === 'string' && MODES.includes(v) ? (v as RaspMode) : undefined);
const posInt = (v: unknown): number | undefined => (typeof v === 'number' && Number.isInteger(v) && v >= 1 ? v : undefined);
const timeout = (v: unknown): number | undefined => (typeof v === 'number' && Number.isFinite(v) ? Math.min(60_000, Math.max(100, Math.floor(v))) : undefined);
const list = (v: unknown, max: number, keep: (s: string) => boolean) =>
  Array.isArray(v) ? v.filter((x): x is string => typeof x === 'string' && keep(x)).slice(0, max) : [];

/** `unix:/path` or `tcp:host:port`; null otherwise. */
export function parseClamAddress(v: unknown): ClamAddress | null {
  const s = typeof v === 'object' && v !== null ? (v as { address?: unknown }).address : v;
  if (typeof s !== 'string') return null;
  if (s.startsWith('unix:')) {
    const path = s.slice(5);
    return path && isAbsolute(path) ? { kind: 'unix', path } : null;
  }
  const m = /^tcp:([A-Za-z0-9.-]{1,253}|\[[0-9a-fA-F:.]{2,45}\]):(\d{1,5})$/.exec(s);
  if (!m) return null;
  const port = Number(m[2]);
  return port >= 1 && port <= 65535 ? { kind: 'tcp', host: m[1].replace(/^\[|\]$/g, ''), port } : null;
}

function parseDeepScan(v: unknown): DeepScan {
  const o = v && typeof v === 'object' && !Array.isArray(v) ? (v as Record<string, unknown>) : {};
  return {
    mode: mode(o.mode) ?? 'off',
    scan: o.scan === 'async' ? 'async' : 'sync',
    timeoutMs: timeout(o.timeoutMs) ?? 5000,
    failMode: o.failMode === 'closed' ? 'closed' : 'open',
    clamav: parseClamAddress(o.clamav),
    reputation: o.reputation === true,
    testId: typeof o.testId === 'string' && TEST_ID.test(o.testId) ? o.testId : null,
  };
}

function parseRoutes(v: unknown): RoutePolicy[] {
  if (!Array.isArray(v)) return [];
  const out: RoutePolicy[] = [];
  for (const r of v) {
    if (out.length >= 64) break;
    if (!r || typeof r !== 'object' || Array.isArray(r)) continue;
    const o = r as Record<string, unknown>;
    if (typeof o.route !== 'string' || !o.route.startsWith('/') || o.route.length > 256) continue;
    const p: RoutePolicy = { route: o.route };
    if (Array.isArray(o.allow)) p.allow = list(o.allow, 64, (s) => ALLOWED.has(s));
    if (posInt(o.maxBytes)) p.maxBytes = posInt(o.maxBytes);
    if (mode(o.mode)) p.mode = mode(o.mode);
    if (mode(o.deepScan)) p.deepScan = mode(o.deepScan);
    if (o.scan === 'sync' || o.scan === 'async') p.scan = o.scan;
    if (timeout(o.timeoutMs)) p.timeoutMs = timeout(o.timeoutMs);
    if (o.failMode === 'open' || o.failMode === 'closed') p.failMode = o.failMode;
    out.push(p);
  }
  return out;
}

/** The signed config's `uploads` block (README "Upload policy and deep scan"); null when absent. */
export function parseUploadsBlock(v: unknown): UploadConfig | null {
  if (!v || typeof v !== 'object' || Array.isArray(v)) return null;
  const o = v as Record<string, unknown>;
  return {
    maxBytes: posInt(o.maxBytes) ?? null,
    allow: list(o.allow, 64, (s) => ALLOWED.has(s)),
    servedDirs: list(o.servedDirs, 32, (s) => isAbsolute(s) && s.length <= 512),
    trusted: new Set(list(o.trusted, 1000, (s) => SHA.test(s))),
    rules: compileSignatures(o.rules).signatures,
    deepScan: parseDeepScan(o.deepScan),
    routes: parseRoutes(o.routes),
  };
}

/** The local options in the same shape. */
export function localUploadConfig(o: UploadOptions | undefined): UploadConfig {
  const d = o?.deepScan ?? {};
  return (
    parseUploadsBlock({
      maxBytes: o?.maxBytes,
      allow: o?.allow,
      servedDirs: o?.servedDirs,
      deepScan: { ...d, clamav: typeof d.clamav === 'string' ? { address: d.clamav } : d.clamav },
      routes: o?.routes,
    }) as UploadConfig
  );
}

let local: UploadConfig = localUploadConfig(undefined);
let remote: UploadConfig | null = null;
let scanBytes = DEFAULT_SCAN_BYTES;
let quarantineDir = join(tmpdir(), 'shield360-quarantine');

export function configureUploads(o: UploadOptions | undefined): void {
  local = localUploadConfig(o);
  remote = null;
  scanBytes = typeof o?.scanBytes === 'number' && o.scanBytes > 0 ? Math.min(o.scanBytes, MAX_SCAN_BYTES) : DEFAULT_SCAN_BYTES;
  quarantineDir = typeof o?.quarantineDir === 'string' && isAbsolute(o.quarantineDir) ? o.quarantineDir : join(tmpdir(), 'shield360-quarantine');
}

/** The verified signed config's block; undefined or null: the local options again. */
export function setRemoteUploads(v: unknown): void {
  remote = parseUploadsBlock(v);
}

export function uploadConfig(): UploadConfig {
  return remote ?? local;
}

export const uploadScanBytes = () => scanBytes;
export const uploadQuarantineDir = () => quarantineDir;

/** The first route policy whose route equals the event route, or is a prefix ending in `*` of it. */
export function routePolicy(route: string | undefined, c: UploadConfig = uploadConfig()): RoutePolicy | null {
  if (!route) return null;
  for (const r of c.routes) {
    if (r.route.endsWith('*') ? route.startsWith(r.route.slice(0, -1)) : route === r.route) return r;
  }
  return null;
}

/** What applies to one upload: the route's fields, else the app's. */
export type EffectivePolicy = {
  allow: string[];
  maxBytes: number | null;
  /** The route's mode for built-in findings; undefined: the attack mode. */
  mode?: RaspMode;
  deepScan: DeepScan;
};

export function effectivePolicy(route: string | undefined, c: UploadConfig = uploadConfig()): EffectivePolicy {
  const r = routePolicy(route, c);
  return {
    allow: r?.allow ?? c.allow,
    maxBytes: r?.maxBytes ?? c.maxBytes,
    ...(r?.mode ? { mode: r.mode } : {}),
    deepScan: {
      ...c.deepScan,
      ...(r?.deepScan ? { mode: r.deepScan } : {}),
      ...(r?.scan ? { scan: r.scan } : {}),
      ...(r?.timeoutMs ? { timeoutMs: r.timeoutMs } : {}),
      ...(r?.failMode ? { failMode: r.failMode } : {}),
    },
  };
}

const SERVED_SEGMENTS = new Set(['public', 'static', 'www', 'wwwroot', 'htdocs', 'webroot', 'public_html']);

/** Whether a resolved path is inside a served directory (README: `servedDirs`, else the default segments). */
export function isServed(resolved: string, c: UploadConfig = uploadConfig()): boolean {
  const p = resolved.replace(/\\/g, '/');
  if (c.servedDirs.length) {
    return c.servedDirs.some((d) => {
      const root = d.replace(/\\/g, '/').replace(/\/+$/, '');
      return p === root || p.startsWith(`${root}/`);
    });
  }
  const segs = p.split('/');
  return segs.slice(0, -1).some((s) => SERVED_SEGMENTS.has(s.toLowerCase()));
}
