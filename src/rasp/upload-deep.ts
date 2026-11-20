/**
 * Deep scan (README "Uploads", "Upload policy and deep scan", "Scanner
 * status"): the customer's own ClamAV (clamd, over a Unix socket or TCP) and
 * the hash reputation lookup, both opt-in and off by default. Files are
 * scanned where the app runs; the platform never receives a file, only a hash
 * when reputation is on. Every engine call is bounded by the deep scan's
 * timeout, and an engine that cannot answer is reported, never silent.
 */
import * as fs from 'fs';
import { connect, type Socket } from 'net';
import { join } from 'path';
import { reportRecord } from './engine';
import type { ClamAddress, DeepScan, FailMode } from './upload-policy';
import { uploadQuarantineDir } from './upload-policy';
import type { UploadFinding } from './upload-inspect';

// Captured at load, before any later file-system hook, so the SDK's own reads never trip RASP.
const openSync = fs.openSync.bind(fs);
const readSync = fs.readSync.bind(fs);
const closeSync = fs.closeSync.bind(fs);
const renameSync = fs.renameSync.bind(fs);
const mkdirSync = fs.mkdirSync.bind(fs);
const chmodSync = fs.chmodSync.bind(fs);
const copyFileSync = fs.copyFileSync.bind(fs);
const unlinkSync = fs.unlinkSync.bind(fs);

export const SCANNER_EVENT = 'shield360.rasp.scanner';
export type Engine = 'clamav' | 'reputation';
export type EngineStatus = 'ok' | 'unreachable' | 'timeout' | 'error';

/** What one scan found: a finding, an engine that failed, or nothing. */
export type DeepResult = { finding: UploadFinding | null; failed: Engine[] };

// ---- clamd -------------------------------------------------------------------

const CHUNK = 64 * 1024;
const MAX_REPLY = 4096;

class EngineError extends Error {
  constructor(readonly status: Exclude<EngineStatus, 'ok'>) {
    super(status);
  }
}

function open(address: ClamAddress, timeoutMs: number): Promise<Socket> {
  return new Promise((resolve, reject) => {
    const s = address.kind === 'unix' ? connect({ path: address.path }) : connect({ host: address.host, port: address.port });
    const timer = setTimeout(() => {
      s.destroy();
      reject(new EngineError('timeout'));
    }, timeoutMs);
    s.once('connect', () => {
      clearTimeout(timer);
      resolve(s);
    });
    s.once('error', () => {
      clearTimeout(timer);
      reject(new EngineError('unreachable'));
    });
  });
}

/** Sends `request` (a function that writes to the socket) and reads clamd's NUL-ended reply. */
async function clamd(address: ClamAddress, timeoutMs: number, request: (s: Socket) => void): Promise<string> {
  const deadline = Date.now() + timeoutMs;
  const s = await open(address, timeoutMs);
  return new Promise<string>((resolve, reject) => {
    let reply = '';
    const timer = setTimeout(() => {
      s.destroy();
      reject(new EngineError('timeout'));
    }, Math.max(1, deadline - Date.now()));
    s.on('data', (d: Buffer) => {
      reply += d.toString('latin1');
      const end = reply.indexOf('\u0000');
      if (end >= 0 || reply.length > MAX_REPLY) {
        clearTimeout(timer);
        s.destroy();
        resolve((end >= 0 ? reply.slice(0, end) : reply).trim());
      }
    });
    s.once('error', () => {
      clearTimeout(timer);
      reject(new EngineError('error'));
    });
    s.once('end', () => {
      clearTimeout(timer);
      const end = reply.indexOf('\u0000');
      resolve((end >= 0 ? reply.slice(0, end) : reply).trim());
    });
    try {
      request(s);
    } catch {
      clearTimeout(timer);
      s.destroy();
      reject(new EngineError('error'));
    }
  });
}

function frame(data: Uint8Array): Buffer {
  const len = Buffer.alloc(4);
  len.writeUInt32BE(data.byteLength, 0);
  return Buffer.concat([len, Buffer.from(data.buffer, data.byteOffset, data.byteLength)]);
}

/** The bytes to send: in memory, or read from a file in pieces. */
export type ScanSource = { bytes: Uint8Array } | { path: string };

function writeSource(s: Socket, src: ScanSource): void {
  s.write('zINSTREAM\u0000');
  if ('bytes' in src) {
    for (let i = 0; i < src.bytes.byteLength; i += CHUNK) s.write(frame(src.bytes.subarray(i, i + CHUNK)));
  } else {
    const fd = openSync(src.path, 'r');
    try {
      const buf = Buffer.alloc(CHUNK);
      for (;;) {
        const n = readSync(fd, buf, 0, CHUNK, null);
        if (n <= 0) break;
        s.write(frame(buf.subarray(0, n)));
      }
    } finally {
      closeSync(fd);
    }
  }
  s.write(Buffer.alloc(4));
}

const CLAM_NAME = /^[A-Za-z0-9._:/-]{1,128}$/;

/** clamd `zINSTREAM`: null when clean, the signature name when found; throws EngineError otherwise. */
export async function clamScan(address: ClamAddress, src: ScanSource, timeoutMs: number): Promise<string | null> {
  const reply = await clamd(address, timeoutMs, (s) => writeSource(s, src));
  if (/:\s*OK$/.test(reply)) return null;
  const m = /:\s*(.+?)\s+FOUND$/.exec(reply);
  if (m) return CLAM_NAME.test(m[1]) ? m[1] : 'unnamed';
  throw new EngineError('error');
}

/** clamd `zPING`: true for `PONG`. */
export async function clamPing(address: ClamAddress, timeoutMs: number): Promise<boolean> {
  return (await clamd(address, timeoutMs, (s) => s.write('zPING\u0000'))) === 'PONG';
}

// ---- reputation --------------------------------------------------------------

export type ReputationVerdict = 'malicious' | 'suspicious' | 'clean' | 'unknown';
type ReputationClient = { url: string; apiKey: string; fetchImpl?: typeof fetch };
let reputationClient: ReputationClient | null = null;
const reputationCache = new Map<string, { verdict: ReputationVerdict; until: number }>();
const REPUTATION_TTL_MS = 60 * 60 * 1000;
const REPUTATION_CACHE = 1000;

/** Where the reputation lookup goes: the Shield360 URL and API key the SDK already has. */
export function setReputationClient(c: ReputationClient | null): void {
  reputationClient = c;
  reputationCache.clear();
}

/** Asks the platform about a hash (only the hash leaves the app). Throws EngineError when it cannot answer. */
export async function reputationOf(sha256: string, timeoutMs: number): Promise<ReputationVerdict> {
  const cached = reputationCache.get(sha256);
  if (cached && cached.until > Date.now()) return cached.verdict;
  const c = reputationClient;
  if (!c) throw new EngineError('unreachable');
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  let res: Response;
  try {
    res = await (c.fetchImpl ?? fetch)(`${c.url.replace(/\/+$/, '')}/api/rasp/upload-reputation`, {
      method: 'POST',
      headers: { authorization: `Bearer ${c.apiKey}`, 'content-type': 'application/json' },
      body: JSON.stringify({ sha256 }),
      signal: controller.signal,
    });
  } catch {
    throw new EngineError(controller.signal.aborted ? 'timeout' : 'unreachable');
  } finally {
    clearTimeout(timer);
  }
  if (!res.ok) throw new EngineError('error');
  const body = (await res.json().catch(() => null)) as { verdict?: unknown } | null;
  const v = body?.verdict;
  const verdict: ReputationVerdict = v === 'malicious' || v === 'suspicious' || v === 'clean' ? v : 'unknown';
  if (reputationCache.size >= REPUTATION_CACHE) reputationCache.delete(reputationCache.keys().next().value as string);
  reputationCache.set(sha256, { verdict, until: Date.now() + REPUTATION_TTL_MS });
  return verdict;
}

// ---- status ------------------------------------------------------------------

type State = { status: EngineStatus; since: number; failures: number; lastSent: number; failMode: FailMode };
const states = new Map<Engine, State>();
const REPEAT_MS = 5 * 60 * 1000;
let lastTestId: string | null = null;

/** Tests only. */
export function resetScannerStatus(): void {
  states.clear();
  lastTestId = null;
  reputationCache.clear();
}

function send(engine: Engine, s: State, testId?: string): void {
  s.lastSent = Date.now();
  reportRecord(SCANNER_EVENT, {
    'shield360.rasp.scanner.engine': engine,
    'shield360.rasp.scanner.status': s.status,
    'shield360.rasp.scanner.fail_mode': s.failMode,
    'shield360.rasp.scanner.since': new Date(s.since).toISOString(),
    'shield360.rasp.scanner.failures': String(s.failures),
    ...(testId ? { 'shield360.rasp.scanner.test_id': testId } : {}),
  });
}

/** Records an engine's outcome: reported when the status changes, and every 5 minutes while it is not ok. */
export function noteEngine(engine: Engine, status: EngineStatus, failMode: FailMode, testId?: string): void {
  const now = Date.now();
  let s = states.get(engine);
  if (!s || s.status !== status) {
    s = { status, since: now, failures: status === 'ok' ? 0 : 1, lastSent: 0, failMode };
    states.set(engine, s);
    send(engine, s, testId);
    return;
  }
  s.failMode = failMode;
  if (status !== 'ok') s.failures++;
  if (testId || (status !== 'ok' && now - s.lastSent >= REPEAT_MS)) send(engine, s, testId);
}

export const engineStatus = (engine: Engine): EngineStatus | undefined => states.get(engine)?.status;

/** A new `testId` in the config: tests each engine once and reports with the id. Never throws. */
export async function runConnectionTest(d: DeepScan): Promise<void> {
  if (!d.testId || d.testId === lastTestId) return;
  lastTestId = d.testId;
  const id = d.testId;
  if (d.clamav) {
    try {
      const ok = await clamPing(d.clamav, Math.min(d.timeoutMs, 5000));
      noteEngine('clamav', ok ? 'ok' : 'error', d.failMode, id);
    } catch (e) {
      noteEngine('clamav', e instanceof EngineError ? e.status : 'error', d.failMode, id);
    }
  }
  if (d.reputation) {
    // A well-formed hash of nothing: tests the path to the platform, never a real file.
    try {
      await reputationOf('e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855', Math.min(d.timeoutMs, 5000));
      noteEngine('reputation', 'ok', d.failMode, id);
    } catch (e) {
      noteEngine('reputation', e instanceof EngineError ? e.status : 'error', d.failMode, id);
    }
  }
}

// ---- scan --------------------------------------------------------------------

/**
 * Runs the deep scan engines that are on, within one timeout. The first
 * finding wins (ClamAV, then reputation); engines that could not answer are
 * listed in `failed` (and reported by status).
 */
export async function deepScan(d: DeepScan, src: ScanSource, sha256: string | undefined): Promise<DeepResult> {
  const failed: Engine[] = [];
  const deadline = Date.now() + d.timeoutMs;
  const left = () => Math.max(1, deadline - Date.now());
  if (d.clamav) {
    try {
      const name = await clamScan(d.clamav, src, left());
      noteEngine('clamav', 'ok', d.failMode);
      if (name) return { finding: { rule: 'upload.malware', engine: 'clamav', signature: name }, failed };
    } catch (e) {
      noteEngine('clamav', e instanceof EngineError ? e.status : 'error', d.failMode);
      failed.push('clamav');
    }
  }
  if (d.reputation && sha256) {
    try {
      const v = await reputationOf(sha256, left());
      noteEngine('reputation', 'ok', d.failMode);
      if (v === 'malicious') return { finding: { rule: 'upload.reputation', engine: 'reputation' }, failed };
    } catch (e) {
      noteEngine('reputation', e instanceof EngineError ? e.status : 'error', d.failMode);
      failed.push('reputation');
    }
  }
  return { finding: null, failed };
}

// ---- quarantine --------------------------------------------------------------

/**
 * Moves a file to the quarantine directory (README "Upload policy and deep
 * scan"): renamed to its SHA-256 (or a time stamp), mode 0600, the directory
 * 0700. Returns whether it moved. Never throws.
 */
export function quarantine(path: string, sha256?: string): boolean {
  try {
    const dir = uploadQuarantineDir();
    mkdirSync(dir, { recursive: true, mode: 0o700 });
    const target = join(dir, `${sha256 ?? `upload-${Date.now()}`}.quarantined`);
    try {
      renameSync(path, target);
    } catch {
      // Another file system: copy, then remove.
      copyFileSync(path, target);
      unlinkSync(path);
    }
    chmodSync(target, 0o600);
    return true;
  } catch {
    return false;
  }
}
